package com.example.mybiometric

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import android.widget.Toast
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.isVisible
import com.example.mybiometric.databinding.ActivityMainBinding
import java.security.KeyStore
import java.util.concurrent.Executor
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding

    private var failedAttempts = 0
    private val maxFailedAttempts = 5
    private lateinit var biometricPrompt: BiometricPrompt

    companion object {
        private const val KEY_ALIAS = "MyKeyAlias"
        private const val IV_SIZE = 12
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setupFullscreen()

        binding.btnLogin.setOnClickListener {
            val username = binding.edtUsername.text.toString()
            val password = binding.edtPassword.text.toString()

            if (username.isBlank() || password.isBlank()) {
                Toast.makeText(this, "Username dan password harus diisi", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            dummyLoginApi(username, password) { success, token ->
                runOnUiThread {
                    if (success) {
                        Toast.makeText(this, "Login berhasil, token diterima", Toast.LENGTH_SHORT)
                            .show()
                        val encrypted = encryptData(token!!)
                        storeEncryptedData(encrypted)
                    } else {
                        Toast.makeText(
                            this,
                            "Login gagal, cek username & password",
                            Toast.LENGTH_SHORT
                        ).show()
                    }
                }
            }
        }

        binding.btnLoginWithBio.setOnClickListener {
            authenticateBiometric()
        }

        binding.btnLoginWithBio.isVisible = isBiometricAvailable()

        binding.btnGotoBio.setOnClickListener {
            startActivity(Intent(Settings.ACTION_SECURITY_SETTINGS))
        }

        binding.btnGotoNext.setOnClickListener {
            startActivity(Intent(this, BiometricActivity::class.java))
        }

        binding.tvBuildNumber.text = "${Build.MANUFACTURER}, ${Build.MODEL}, ${Build.VERSION.SDK_INT}"
//        Log.d("MainActivity", "Build Number: ${Build.MANUFACTURER} ${Build.MODEL}")
    }

    private fun isBiometricAvailable(): Boolean {
        val biometricManager = BiometricManager.from(this)
        return biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
                BiometricManager.BIOMETRIC_SUCCESS
    }

    private fun authenticateBiometric() {
        val executor: Executor = ContextCompat.getMainExecutor(this)

        biometricPrompt =
            BiometricPrompt(this, executor, object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    failedAttempts = 0

                    val encryptedData = getEncryptedData()
                    if (encryptedData != null) {
                        try {
                            val decrypted = decryptData(encryptedData)
                            Toast.makeText(
                                this@MainActivity,
                                "Token didekripsi: $decrypted",
                                Toast.LENGTH_LONG
                            )
                                .show()

                            validateTokenApi(decrypted) { isValid ->
                                runOnUiThread {
                                    if (isValid) {
                                        Toast.makeText(
                                            this@MainActivity,
                                            "Token valid, login sukses",
                                            Toast.LENGTH_SHORT
                                        ).show()
                                    } else {
                                        Toast.makeText(
                                            this@MainActivity,
                                            "Token tidak valid, login ulang manual",
                                            Toast.LENGTH_LONG
                                        ).show()
                                        clearEncryptedData()
                                    }
                                }
                            }
                        } catch (e: KeyPermanentlyInvalidatedException) {
                            e.printStackTrace()
                            Toast.makeText(
                                this@MainActivity,
                                "Biometrik Anda telah berubah. Harap login ulang.",
                                Toast.LENGTH_LONG
                            ).show()
                            clearEncryptedData()
                        } catch (e: Exception) {
                            e.printStackTrace()
                            Toast.makeText(
                                this@MainActivity,
                                "Gagal mendekripsi data. Mungkin karena data rusak atau kunci tidak valid.",
                                Toast.LENGTH_LONG
                            ).show()
                        }

                    } else {
                        Toast.makeText(
                            this@MainActivity,
                            "Belum ada token terenkripsi, silakan login manual dulu",
                            Toast.LENGTH_LONG
                        ).show()
                    }
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    failedAttempts++
//        Toast.makeText(
//          this@MainActivity,
//          "Autentikasi gagal ($failedAttempts/$maxFailedAttempts)",
//          Toast.LENGTH_SHORT
//        ).show()

                    if (failedAttempts >= maxFailedAttempts) {
                        Toast.makeText(
                            this@MainActivity,
                            "Terlalu banyak percobaan gagal. Autentikasi ditutup.",
                            Toast.LENGTH_LONG
                        ).show()
                        biometricPrompt.cancelAuthentication()
                    }
                }

            })

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Autentikasi Biometrik")
            .setSubtitle("Gunakan sidik jari atau wajah Anda untuk masuk")
            .setNegativeButtonText("Batal")
            .setConfirmationRequired(false)
            .setAllowedAuthenticators(
                BiometricManager.Authenticators.BIOMETRIC_STRONG or
                        BiometricManager.Authenticators.BIOMETRIC_WEAK
            )
            .build()

        biometricPrompt.authenticate(promptInfo)
    }

    private fun setupFullscreen() {
        enableEdgeToEdge()
        setContentView(binding.root)
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }
    }

    private fun dummyLoginApi(
        username: String,
        password: String,
        callback: (success: Boolean, token: String?) -> Unit
    ) {
        Thread {
            Thread.sleep(1000)
            if (username == "user" && password == "pass") {
                callback(true, "DummyToken123456")
            } else {
                callback(false, null)
            }
        }.start()
    }

    fun createKey(): SecretKey {
        val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val keyGenSpec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
            .build()
        keyGen.init(keyGenSpec)
        return keyGen.generateKey()
    }

    fun getEncryptCipher(): Cipher {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getSecretKey())
        return cipher
    }

    fun getDecryptCipher(iv: ByteArray): Cipher {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.DECRYPT_MODE, getSecretKey(), spec)
        return cipher
    }

    private fun getSecretKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        return keyStore.getKey(KEY_ALIAS, null) as SecretKey? ?: createKey()
    }

    fun encryptData(data: String): ByteArray {
        val cipher = getEncryptCipher()
        val iv = cipher.iv
        val encryptedBytes = cipher.doFinal(data.toByteArray(Charsets.UTF_8))
        return iv + encryptedBytes
    }

    fun storeEncryptedData(encryptedData: ByteArray) {
        val prefs = getSharedPreferences("secure_prefs", MODE_PRIVATE)
        prefs.edit()
            .putString("encrypted_token", Base64.encodeToString(encryptedData, Base64.DEFAULT))
            .apply()
    }

    fun getEncryptedData(): ByteArray? {
        val prefs = getSharedPreferences("secure_prefs", MODE_PRIVATE)
        val base64 = prefs.getString("encrypted_token", null)
        return base64?.let { Base64.decode(it, Base64.DEFAULT) }
    }

    fun decryptData(encryptedData: ByteArray): String {
        val iv = encryptedData.copyOfRange(0, IV_SIZE)
        val ciphertext = encryptedData.copyOfRange(IV_SIZE, encryptedData.size)

        val cipher = getDecryptCipher(iv)
        val decryptedBytes = cipher.doFinal(ciphertext)
        return String(decryptedBytes, Charsets.UTF_8)
    }

    private fun validateTokenApi(token: String, callback: (Boolean) -> Unit) {
        Thread {
            Thread.sleep(1000)
            val isValid = token == "DummyToken123456"
            callback(isValid)
        }.start()
    }

    fun clearEncryptedData() {
        val prefs = getSharedPreferences("secure_prefs", MODE_PRIVATE)
        prefs.edit().remove("encrypted_token").apply()
    }
}
