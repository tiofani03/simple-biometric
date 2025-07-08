package com.example.mybiometric

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import androidx.core.content.edit

class CryptoManager(private val context: Context) {
    companion object {
        private const val KEY_ALIAS = "MyKeyAlias"
        private const val IV_SIZE = 12
    }

    fun createKey(): SecretKey {
        Log.d("BIOGES", "createKey() DIPANGGIL")
        val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val keyGenSpec = KeyGenParameterSpec.Builder(KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
            .build()
        keyGen.init(keyGenSpec)
        return keyGen.generateKey()
    }

    fun getSecretKeyOrNull(): SecretKey? {
        Log.d("BIOGES", "getSecretKey() DIPANGGIL")
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        return try {
            keyStore.getKey(KEY_ALIAS, null) as? SecretKey ?: createKey()
        } catch (e: KeyPermanentlyInvalidatedException) {
            deleteKey()
            clearEncryptedData()
            null // penting agar tidak lempar exception lagi
        }
    }

    fun getEncryptCipher(): Cipher? {
        val key = getSecretKeyOrNull() ?: return null
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            cipher
        } catch (e: KeyPermanentlyInvalidatedException) {
            Log.e("BIOGES", "Key invalid saat inisialisasi cipher (kemungkinan biometrik berubah)")
            deleteKey()
            clearEncryptedData()
            return getEncryptCipher()
        } catch (e: Exception) {
            Log.e("BIOGES", "Gagal inisialisasi cipher: ${e.message}")
            e.printStackTrace()
            null
        }
    }


    fun getDecryptCipher(iv: ByteArray): Cipher? {
        val key = getSecretKeyOrNull() ?: return null
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
            cipher
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    fun decryptData(encryptedData: ByteArray): String? {
        return try {
            val iv = encryptedData.copyOfRange(0, IV_SIZE)
            val cipherText = encryptedData.copyOfRange(IV_SIZE, encryptedData.size)
            val cipher = getDecryptCipher(iv) ?: return null
            val decrypted = cipher.doFinal(cipherText)
            String(decrypted, Charsets.UTF_8)
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    fun storeEncryptedData(bytes: ByteArray) {
        val prefs = context.getSharedPreferences("secure_prefs", Context.MODE_PRIVATE)
        prefs.edit().putString("encrypted_token", Base64.encodeToString(bytes, Base64.DEFAULT)).apply()
    }

    fun getEncryptedData(): ByteArray? {
        val prefs = context.getSharedPreferences("secure_prefs", Context.MODE_PRIVATE)
        val base64 = prefs.getString("encrypted_token", null)
        return base64?.let { Base64.decode(it, Base64.DEFAULT) }
    }

    fun deleteKey() {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        keyStore.deleteEntry(KEY_ALIAS)
    }

    fun clearEncryptedData() {
        val prefs = context.getSharedPreferences("secure_prefs", Context.MODE_PRIVATE)
        prefs.edit { remove("encrypted_token") }
    }

    fun isKeyInHardware(key: SecretKey): Boolean {
        return try {
            val factory = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
            val keyInfo = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
            keyInfo.isInsideSecureHardware
        } catch (e: Exception) {
            e.printStackTrace()
            false
        }
    }
}
