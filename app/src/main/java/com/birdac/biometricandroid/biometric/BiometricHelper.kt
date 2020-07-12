package com.birdac.biometricandroid.biometric

import android.content.Context
import android.os.Build
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import java.lang.Exception
import javax.crypto.Cipher

interface BiometricHelperCallback {
    fun biometricAuthenticationValueStored()
    fun biometricAuthenticationSucceed(authenticatedValue: String)
    fun biometricAuthenticationError(errorMessage: String)
    fun biometricAuthenticationFailed(errorMessage: String)
}

class BiometricHelper( private val context: Context,
                       private val callback: BiometricHelperCallback,
                       private val activity: AppCompatActivity ) {
    private val biometricKeyStoreAlias = "KEY_AUTH_ALIAS"
    private val biometricKeyStoreValue = "KEY_AUTH_VALUE"
    private var biometricPrompt:BiometricPrompt? = null

    private fun getEncryptedValue(): String? {
        return context.getSharedPreferences("BIOMETRIC", Context.MODE_PRIVATE)
            .getString(biometricKeyStoreValue, null)
    }

    private fun storeEncryptedValue(authValue: String) {
        val editor = context.getSharedPreferences("BIOMETRIC", Context.MODE_PRIVATE).edit()
        editor.putString(biometricKeyStoreValue, authValue)
        editor.apply()
    }

    private fun isFingeprintAuthAvailable(): Boolean {
        if(Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return false
        }
        val biometricStatus = BiometricManager.from(context).canAuthenticate()
        return biometricStatus == BiometricManager.BIOMETRIC_SUCCESS
    }

    fun isFingerprintDecodeAuthAvailable(): Boolean{
        return isFingeprintAuthAvailable() &&
                KeyStoreHelper.getInstance().isKeystoreContainAlias(biometricKeyStoreAlias) ?: false &&
                getEncryptedValue() != null
    }


    fun saveAuthenticationValue(authValue: String){
        KeyStoreHelper.getInstance().deleteKey(biometricKeyStoreAlias)
        val cipher = KeyStoreHelper.getInstance().getEncodeCipher(biometricKeyStoreAlias)
        if(cipher != null) {
            val encryptedValue = KeyStoreHelper.getInstance()
                    .encodeSensitiveInformationWithCipher(authValue, cipher!!)
            if (encryptedValue != null) {
                storeEncryptedValue(encryptedValue)
                callback.biometricAuthenticationValueStored()
            } else {
                callback.biometricAuthenticationError("Cipher is null")
            }
        }
    }

    private fun getCryptoObject(cipher: Cipher): BiometricPrompt.CryptoObject{
        return BiometricPrompt.CryptoObject(cipher);
    }

    fun startAuthenticationForDecode(){
        val cipher = KeyStoreHelper.getInstance().getDecodeCipher(biometricKeyStoreAlias)
        if(cipher != null) {
            try {
                val cryptoObject = getCryptoObject(cipher)
                val promptInfo = BiometricPrompt.PromptInfo.Builder()
                    .setTitle("Continue with biometric")
                    .setNegativeButtonText("Cancel")
                    .build()
                val executor = ContextCompat.getMainExecutor(context)

                biometricPrompt = BiometricPrompt(activity!!, executor,
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationError(errorCode: Int,
                                                           errString: CharSequence) {
                            super.onAuthenticationError(errorCode, errString)
                            callback.biometricAuthenticationError(errString.toString())
                        }

                        override fun onAuthenticationSucceeded(
                            result: BiometricPrompt.AuthenticationResult) {
                            super.onAuthenticationSucceeded(result)
                            val decodeCipher = result.cryptoObject?.cipher
                            if(decodeCipher != null){
                                val authValue:String? = KeyStoreHelper.getInstance()
                                    .decodeSensitiveInformationWithCipher(getEncryptedValue(), decodeCipher)
                                callback.biometricAuthenticationSucceed(authValue!!)
                            } else {
                                callback.biometricAuthenticationError("DecodeCipher is null")
                            }
                        }

                        override fun onAuthenticationFailed() {
                            super.onAuthenticationFailed()
                            callback.biometricAuthenticationFailed("Auth Failed")
                        }
                    })
                biometricPrompt?.authenticate(promptInfo, cryptoObject)
            } catch (e: Exception){
                e.printStackTrace()
                callback.biometricAuthenticationError(e.message!!)
            }
        } else {
            callback.biometricAuthenticationError("Cipher is null")
        }
    }

    private fun cancelBiometricAuthenticationSequence() {
        biometricPrompt?.cancelAuthentication()
    }

    fun onStop(){
        cancelBiometricAuthenticationSequence()
    }
}