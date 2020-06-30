package com.birdac.biometricandroid.activity

import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.birdac.biometricandroid.R
import com.birdac.biometricandroid.biometric.BiometricHelper
import com.birdac.biometricandroid.biometric.BiometricHelperCallback
import kotlinx.android.synthetic.main.activity_main.*

class MainActivity : AppCompatActivity(), BiometricHelperCallback {
    lateinit var biometricHelper: BiometricHelper

    private fun savePassword() {
        val stringPass = password.text.toString()
        biometricHelper.saveAuthenticationValue(stringPass)
    }

    private fun loadPassword() {
        if(biometricHelper.isFingerprintDecodeAuthAvailable()) {
            biometricHelper.startAuthenticationForDecode()
        } else {
            Toast.makeText(this, "Its either you haven't store any password, or you haven't set any fingeprint, " +
                    "or your device doesn't support biometric", Toast.LENGTH_SHORT).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        btn_load.setOnClickListener { loadPassword() }
        btn_save.setOnClickListener { savePassword() }
        biometricHelper = BiometricHelper(this, this, this)
    }

    override fun onStop() {
        biometricHelper.onStop()
        super.onStop()
    }

    override fun biometricAuthenticationValueStored() {
        Toast.makeText(this, "Password Stored!", Toast.LENGTH_SHORT).show()
    }

    override fun biometricAuthenticationSucceed(authenticatedValue: String) {
        Toast.makeText(this, "Passoword: $authenticatedValue", Toast.LENGTH_SHORT).show()
    }

    override fun biometricAuthenticationError(errorMessage: String) {
        Toast.makeText(this, errorMessage, Toast.LENGTH_SHORT).show()
    }

    override fun biometricAuthenticationFailed(errorMessage: String) {
        Toast.makeText(this, errorMessage, Toast.LENGTH_SHORT).show()
    }
}