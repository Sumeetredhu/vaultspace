package com.vaultspace.app

import android.app.Activity
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Fingerprint / face unlock.
 *
 * A key is created inside the phone's secure hardware (Android Keystore). It can never be
 * exported, and the hardware only lets the app use it right after a successful strong biometric
 * check. It encrypts {device id, device token, vault key} on this phone. The device token tells
 * the server this phone is trusted and can be revoked any time from Profile > Devices.
 * Adding a new fingerprint to the phone permanently disables the key.
 */
object DeviceUnlock {
    private const val ALIAS = "vaultspace-device-key"

    fun available(activity: Activity): Boolean {
        val bm = activity.getSystemService(BiometricManager::class.java) ?: return false
        return if (Build.VERSION.SDK_INT >= 30) {
            bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS
        } else {
            @Suppress("DEPRECATION")
            bm.canAuthenticate() == BiometricManager.BIOMETRIC_SUCCESS
        }
    }

    fun isSetUp() = Prefs.deviceBlob != null

    /** Fingerprint unlock is tied to one account, so it can never open someone else's vault. */
    fun isSetUpFor(email: String) = isSetUp() && Prefs.deviceEmail == email

    fun forgetFor(email: String) {
        if (Prefs.deviceEmail == email) forget()
    }

    private fun keyStore() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun newKey(): SecretKey {
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
            .apply { if (Build.VERSION.SDK_INT >= 30) setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG) }
            .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply { init(spec) }.generateKey()
    }

    fun forget() {
        Prefs.deviceBlob = null
        Prefs.deviceId = null
        Prefs.deviceEmail = null
        runCatching { keyStore().deleteEntry(ALIAS) }
    }

    /** Asks for a biometric, then stores `secret` encrypted with the hardware key. */
    fun enroll(activity: Activity, secret: ByteArray, done: (Boolean, String?) -> Unit) {
        val cipher = try {
            Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, newKey()) }
        } catch (e: Exception) {
            return done(false, "Fingerprint unlock is not available on this phone.")
        }
        prompt(activity, "Turn on fingerprint unlock", cipher, { c ->
            Prefs.deviceBlob = Crypto.b64(c.iv) + "." + Crypto.b64(c.doFinal(secret))
            done(true, null)
        }, { done(false, it) })
    }

    /** Asks for a biometric and returns the decrypted secret, or null with a reason. */
    fun unlock(activity: Activity, done: (ByteArray?, String?) -> Unit) {
        val parts = Prefs.deviceBlob?.split(".") ?: return done(null, "Fingerprint unlock is not set up.")
        val cipher = try {
            val key = keyStore().getKey(ALIAS, null) as SecretKey
            Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, Crypto.unb64(parts[0]))) }
        } catch (e: KeyPermanentlyInvalidatedException) {
            forget()
            return done(null, "Your fingerprints changed, so fingerprint unlock was turned off. Log in with your password.")
        } catch (e: Exception) {
            forget()
            return done(null, "Fingerprint unlock is no longer available. Log in with your password.")
        }
        prompt(activity, "Unlock VaultSpace", cipher, { c -> done(c.doFinal(Crypto.unb64(parts[1])), null) }, { done(null, it) })
    }

    private fun prompt(activity: Activity, title: String, cipher: Cipher, ok: (Cipher) -> Unit, fail: (String?) -> Unit) {
        val exec = activity.mainExecutor
        var finished = false
        val once = { block: () -> Unit -> if (!finished) { finished = true; block() } }
        val builder = BiometricPrompt.Builder(activity).setTitle(title).setSubtitle("Confirm it's you")
        if (Build.VERSION.SDK_INT >= 30) builder.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        builder.setNegativeButton("Use password", exec) { _, _ -> once { fail(null) } }
        builder.build().authenticate(BiometricPrompt.CryptoObject(cipher), CancellationSignal(), exec,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = once {
                    try {
                        ok(result.cryptoObject?.cipher ?: throw IllegalStateException("no cipher"))
                    } catch (e: Exception) {
                        fail("Fingerprint unlock failed. Use your password.")
                    }
                }

                override fun onAuthenticationError(code: Int, msg: CharSequence) = once {
                    val cancelled = code == BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED || code == BiometricPrompt.BIOMETRIC_ERROR_CANCELED
                    fail(if (cancelled) null else msg.toString())
                }
            })
    }
}
