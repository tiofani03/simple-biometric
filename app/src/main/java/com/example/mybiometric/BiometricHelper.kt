package com.example.mybiometric

import android.content.Context
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat

class BiometricHelper(private val context: Context) {

  fun createPrompt(
    title: String,
    subtitle: String,
    onSuccess: (BiometricPrompt.AuthenticationResult) -> Unit,
    onError: (String) -> Unit
  ): Pair<BiometricPrompt, BiometricPrompt.PromptInfo> {
    val executor = ContextCompat.getMainExecutor(context)
    val prompt = BiometricPrompt(
      context as androidx.fragment.app.FragmentActivity, executor,
      object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
          onSuccess(result)
        }

        override fun onAuthenticationError(code: Int, errString: CharSequence) {
          onError(errString.toString())
        }
      })

    val promptInfo = BiometricPrompt.PromptInfo.Builder()
      .setTitle(title)
      .setSubtitle(subtitle)
      .setNegativeButtonText("Batal")
      .build()

    return Pair(prompt, promptInfo)
  }
}
