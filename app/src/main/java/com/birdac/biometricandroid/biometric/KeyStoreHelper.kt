package com.birdac.biometricandroid.biometric

import android.annotation.TargetApi
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.*
import java.security.spec.MGF1ParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

class KeyStoreHelper private constructor() {
    private val newCipherInstance: Cipher?
        get() = try {
            Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        } catch (e: Exception) { //Bad example using general exception
            e.printStackTrace()
            null
        }

    private fun loadKeyStore(): KeyStore? {
        return try {
            val keyStore = KeyStore.getInstance(AUTHENTICATION_KEYSTORE_NAME)
            keyStore.load(null)
            keyStore
        } catch (e: Exception) { //Bad example using general exception
            e.printStackTrace()
            null
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    fun generateKey(alias: String){

        val keyGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
        keyGenerator.initialize(
                KeyGenParameterSpec.Builder(alias,
                        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                        .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                        .setUserAuthenticationRequired(true)
                        .build())
        keyGenerator.generateKeyPair()
    }

    private fun generateKeyIfNotExist(keyStore: KeyStore, alias: String) {
        try {
            if(!keyStore.containsAlias(alias))
                generateKey(alias)
        } catch (e: KeyStoreException) {
            e.printStackTrace()
        }
    }

    fun getEncodeCipher(alias: String): Cipher? {
        val cipher = newCipherInstance
        val keyStore = loadKeyStore() ?: return null

        if(!keyStore.containsAlias(alias))
            generateKeyIfNotExist(keyStore, alias)

        return if(initEncodeCipher(cipher, alias, keyStore)) {
            cipher
        } else {
            null
        }
    }

    fun getDecodeCipher(alias: String, withCipher: Cipher? = null): Cipher? {
        val cipher: Cipher? = withCipher ?: newCipherInstance
        val keyStore = loadKeyStore() ?: return null

        if(!keyStore.containsAlias(alias))
            generateKeyIfNotExist(keyStore, alias)

        return if(initDecodeCipher(cipher, alias, keyStore)) {
            cipher
        } else {
            null
        }
    }

    private fun initDecodeCipher(cipher: Cipher?, alias: String, keyStore: KeyStore): Boolean {
        return try {
            val key: PrivateKey = keyStore.getKey(alias, null) as PrivateKey
            cipher!!.init(Cipher.DECRYPT_MODE, key)
            true
        } catch (e: Exception) { //Bad example using general exception
            e.printStackTrace()
            false
        }
    }

    private fun initEncodeCipher(cipher: Cipher?, alias: String, keyStore: KeyStore): Boolean {
        return try {
            val key = keyStore.getCertificate(alias).publicKey
//            https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.html#known-issues
            val unrestricted = KeyFactory.getInstance(key.algorithm).generatePublic(
                    X509EncodedKeySpec(key.encoded))
            val spec = OAEPParameterSpec("SHA-256", "MGF1",
                    MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)
            cipher!!.init(Cipher.ENCRYPT_MODE, unrestricted, spec)
            true
        } catch (e: Exception) {
            e.printStackTrace()
            false
        }
    }

    fun encodeSensitiveInformationWithCipher(input: String, cipher: Cipher): String? {
        return try {
            val bytes = cipher.doFinal(input.toByteArray())
            Base64.encodeToString(bytes, Base64.NO_WRAP)
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    fun decodeSensitiveInformationWithCipher(encodedString: String?, cipher: Cipher): String? {
        return try {
            val bytes: ByteArray = Base64.decode(encodedString, Base64.NO_WRAP)
            String(cipher.doFinal(bytes))
        } catch (e: Exception) { //Bad example using general exception
            e.printStackTrace()
            null
        }
    }

    fun isKeystoreContainAlias(alias: String?): Boolean? {
        return try {
            val keyStore = loadKeyStore()!!
            keyStore.containsAlias(alias)
        } catch (e: KeyStoreException) {
            e.printStackTrace()
            null
        }
    }

    fun deleteKey(alias: String?) {
        val keyStore = loadKeyStore()
        try {
            keyStore!!.deleteEntry(alias)
        } catch (e: KeyStoreException) {
            e.printStackTrace()
        }
    }

    companion object {
        private var myInstance: KeyStoreHelper? = null
        private const val AUTHENTICATION_KEYSTORE_NAME = "AndroidKeyStore"

        fun getInstance(): KeyStoreHelper {
            if(myInstance == null) {
                myInstance = KeyStoreHelper()
            }

            return myInstance!!
        }
    }
}