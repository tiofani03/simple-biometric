package com.example.mybiometric

import androidx.biometric.BiometricPrompt
import androidx.biometric.BiometricPrompt.AuthenticationCallback
import androidx.biometric.BiometricPrompt.AuthenticationResult
import androidx.fragment.app.FragmentActivity
import java.util.concurrent.Executors
import javax.crypto.Cipher

class BiometricHelper(private val activity: FragmentActivity) {
  fun authenticate(cipher: Cipher, onSuccess: (Cipher) -> Unit, onError: (String) -> Unit) {
    val biometricPrompt = BiometricPrompt(activity, Executors.newSingleThreadExecutor(),
      object : AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: AuthenticationResult) {
          onSuccess(result.cryptoObject?.cipher!!)
        }

        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
          onError(errString.toString())
        }
      })

    val promptInfo = BiometricPrompt.PromptInfo.Builder()
      .setTitle("Autentikasi Biometrik")
      .setSubtitle("Gunakan fingerprint atau Face ID")
      .setNegativeButtonText("Batal")
      .build()

    biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
  }
}
