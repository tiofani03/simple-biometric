package com.example.mybiometric

import android.os.Bundle
import android.widget.Toast
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricPrompt
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import com.example.mybiometric.databinding.ActivityMainBinding

class BiometricActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding
    private lateinit var cryptoManager: CryptoManager
    private lateinit var biometricHelper: BiometricHelper

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        setupFullscreen()

        cryptoManager = CryptoManager(this)
        biometricHelper = BiometricHelper(this)


        binding.btnLogin.setOnClickListener {
            val username = binding.edtUsername.text.toString()
            val password = binding.edtPassword.text.toString()
            if (username == "user" && password == "pass") {
                val cipher = cryptoManager.getEncryptCipher()
                val (prompt, promptInfo) = biometricHelper.createPrompt(
                    title = "Simpan Token",
                    subtitle = "Verifikasi biometrik diperlukan",
                    onSuccess = { result ->
                        val token = "DummyToken123456"
                        val encrypted = result.cryptoObject!!.cipher!!.doFinal(token.toByteArray())
                        val iv = result.cryptoObject!!.cipher!!.iv
                        cryptoManager.storeEncryptedData(iv + encrypted)
                        Toast.makeText(this, "Token disimpan", Toast.LENGTH_SHORT).show()
                    },
                    onError = {
                        Toast.makeText(this, "Gagal: $it", Toast.LENGTH_SHORT).show()
                    }
                )
                if (cipher != null) {
                    prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
                } else {
                    Toast.makeText(this, "Key tidak tersedia. Silakan login ulang.", Toast.LENGTH_LONG).show()
                }
            }
        }

        binding.btnLoginWithBio.setOnClickListener {
            val data = cryptoManager.getEncryptedData()
            if (data != null) {
                val iv = data.copyOfRange(0, 12)
                val cipher = cryptoManager.getDecryptCipher(iv)
                val (prompt, promptInfo) = biometricHelper.createPrompt(
                    title = "Login",
                    subtitle = "Autentikasi biometrik untuk login",
                    onSuccess = { result ->
                        val decrypted =
                            result.cryptoObject!!.cipher!!.doFinal(data.copyOfRange(12, data.size))
                        val token = String(decrypted)
                        Toast.makeText(this, "Token valid: $token", Toast.LENGTH_SHORT).show()
                    },
                    onError = {
                        Toast.makeText(this, "Gagal: $it", Toast.LENGTH_SHORT).show()
                    }
                )
                if (cipher != null) {
                    prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
                } else {
                    Toast.makeText(this, "Key tidak tersedia. Silakan login ulang.", Toast.LENGTH_LONG).show()
                }
            } else {
                Toast.makeText(this, "Tidak ada token", Toast.LENGTH_SHORT).show()
            }
        }
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
}