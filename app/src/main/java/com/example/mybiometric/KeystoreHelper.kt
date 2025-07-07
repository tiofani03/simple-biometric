package com.example.mybiometric

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

object KeystoreHelper {
  private const val KEY_ALIAS = "secure_token_key"

  fun generateKey() {
    val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
    val parameterSpec = KeyGenParameterSpec.Builder(
      KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    ).setBlockModes(KeyProperties.BLOCK_MODE_CBC)
      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
      .setUserAuthenticationRequired(true) // biometrik wajib
      .build()

    keyGenerator.init(parameterSpec)
    keyGenerator.generateKey()
  }

  fun getCipher(mode: Int): Cipher {
    val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
    val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val secretKey = keyStore.getKey(KEY_ALIAS, null) as SecretKey

    if (mode == Cipher.ENCRYPT_MODE) {
      cipher.init(mode, secretKey)
    } else {
      val iv = Base64.decode(SharedPrefs.iv, Base64.DEFAULT)
      cipher.init(mode, secretKey, IvParameterSpec(iv))
    }
    return cipher
  }
}

object SharedPrefs {
  var tokenEncrypted: String? = null
  var iv: String? = null
}