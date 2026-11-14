package com.vaultspace.app

import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

class TamperedException : Exception("This data is damaged or was changed by someone. It was not opened.")

/**
 * All cryptography in VaultSpace. Only the Android framework's primitives are used
 * (AES-GCM, PBKDF2, HMAC-SHA256, ECDH on P-256). This file defines how they are combined:
 *
 *  password --PBKDF2--> master --HKDF--> authKey (sent to server, which stores a hash of it)
 *                                 \--HKDF--> kek (never leaves the phone) --wraps--> vaultKey
 *  vaultKey wraps: each file key, the user's private key, and a copy of the recovery key
 *  fileKey  encrypts the file in 1 MiB chunks, and its metadata (name, type, category)
 *  sharing: fileKey is wrapped for the recipient's public key with ECIES (ECDH + HKDF + AES-GCM)
 */
object Crypto {
    const val KDF_ITERS = 600_000          // OWASP 2023 recommendation for PBKDF2-HMAC-SHA256
    private const val PASS_ITERS = 200_000 // for share passphrases
    private val rng = SecureRandom()

    fun random(n: Int) = ByteArray(n).also { rng.nextBytes(it) }
    fun b64(b: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(b)
    fun unb64(s: String): ByteArray = Base64.getUrlDecoder().decode(s)

    // ---- key derivation ---------------------------------------------------------------
    fun pbkdf2(secret: CharArray, salt: ByteArray, iterations: Int): ByteArray {
        val spec = PBEKeySpec(secret, salt, iterations, 256)
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
        }
    }

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").run { init(SecretKeySpec(key, "HmacSHA256")); doFinal(data) }

    /** HKDF-SHA256 (RFC 5869), one 32-byte block: turns one secret into independent keys by "info" label. */
    fun hkdf(ikm: ByteArray, info: String, salt: ByteArray = ByteArray(32)): ByteArray =
        hmac(hmac(salt, ikm), info.toByteArray() + byteArrayOf(1))

    /** Two keys from one secret: one to prove it to the server, one to encrypt with. */
    class KeyPairOfSecrets(val auth: ByteArray, val kek: ByteArray)

    fun passwordKeys(password: CharArray, salt: ByteArray, iterations: Int = KDF_ITERS): KeyPairOfSecrets {
        val master = pbkdf2(password, salt, iterations)
        return KeyPairOfSecrets(hkdf(master, "vs-auth"), hkdf(master, "vs-kek")).also { master.fill(0) }
    }

    fun recoveryKeys(rk: ByteArray) = KeyPairOfSecrets(hkdf(rk, "vs-rk-auth"), hkdf(rk, "vs-rk-kek"))

    fun passphraseKeys(passphrase: String, salt: ByteArray): KeyPairOfSecrets {
        val p = pbkdf2(passphrase.toCharArray(), salt, PASS_ITERS)
        return KeyPairOfSecrets(hkdf(p, "vs-pass-auth"), hkdf(p, "vs-pass-kek")).also { p.fill(0) }
    }

    // ---- authenticated encryption -----------------------------------------------------
    // Output = 12-byte random nonce || ciphertext || 16-byte tag. The "aad" label binds the
    // ciphertext to its purpose and place, so it cannot be swapped with another one.
    fun seal(key: ByteArray, plain: ByteArray, aad: String): ByteArray {
        val iv = random(12)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        c.updateAAD(aad.toByteArray())
        return iv + c.doFinal(plain)
    }

    fun open(key: ByteArray, blob: ByteArray, aad: String): ByteArray {
        if (blob.size < 28) throw TamperedException()
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, blob, 0, 12))
        c.updateAAD(aad.toByteArray())
        try {
            return c.doFinal(blob, 12, blob.size - 12)
        } catch (e: AEADBadTagException) {
            throw TamperedException()
        }
    }

    // ---- public-key crypto (P-256) ------------------------------------------------------
    fun newKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    fun publicKey(der: ByteArray): PublicKey = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(der))
    fun privateKey(der: ByteArray): PrivateKey = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(der))

    private fun ecdh(priv: PrivateKey, pub: PublicKey): ByteArray =
        KeyAgreement.getInstance("ECDH").run { init(priv); doPhase(pub, true); generateSecret() }

    /**
     * ECIES: encrypts a file key so only the recipient's private key can recover it.
     * A fresh one-time key pair is made for every share, so two shares never reuse a key.
     * Returns (one-time public key, wrapped file key).
     */
    fun wrapFor(recipientPub: ByteArray, fileKey: ByteArray, fileId: String): Pair<String, ByteArray> {
        val eph = newKeyPair()
        val ephDer = eph.public.encoded
        val k = hkdf(ecdh(eph.private, publicKey(recipientPub)), "vs-share", ephDer)
        return b64(ephDer) to seal(k, fileKey, "vs-share|$fileId")
    }

    fun unwrapFrom(priv: PrivateKey, ephPub: String, wrapped: ByteArray, fileId: String): ByteArray {
        val ephDer = unb64(ephPub)
        val k = hkdf(ecdh(priv, publicKey(ephDer)), "vs-share", ephDer)
        return open(k, wrapped, "vs-share|$fileId")
    }

    /** First 16 bytes of SHA-256 of a public key, shown as a "security code" both people can compare. */
    fun fingerprint(pubKeyB64: String): String {
        val h = java.security.MessageDigest.getInstance("SHA-256").digest(unb64(pubKeyB64))
        return h.take(10).joinToString("") { "%02X".format(it) }.chunked(4).joinToString(" ")
    }
}

/**
 * The recovery key: 20 random bytes (160 bits) written as 32 Crockford base32 characters in
 * groups of four, e.g. 7KQ2-M9XD-.... Crockford's alphabet leaves out I, L, O and U, so it is
 * hard to misread, and typing O/I/L by mistake is corrected automatically.
 */
object RecoveryKey {
    private const val ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

    fun generate(): ByteArray = Crypto.random(20)

    fun format(key: ByteArray): String {
        val sb = StringBuilder()
        var bits = 0
        var value = 0
        for (b in key) {
            value = (value shl 8) or (b.toInt() and 0xFF)
            bits += 8
            while (bits >= 5) {
                sb.append(ALPHABET[(value ushr (bits - 5)) and 31])
                bits -= 5
            }
            value = value and ((1 shl bits) - 1)
        }
        return sb.chunked(4).joinToString("-")
    }

    /** Uppercase, no spaces or dashes, and the easily-confused letters O, I, L read as 0, 1, 1. */
    fun normalise(text: String) = text.uppercase().filter { !it.isWhitespace() && it != '-' }
        .map { when (it) { 'O' -> '0'; 'I', 'L' -> '1'; else -> it } }.joinToString("")

    fun parse(text: String): ByteArray? {
        val clean = normalise(text)
        if (clean.length != 32 || clean.any { it !in ALPHABET }) return null
        val out = ByteArray(20)
        var bits = 0
        var value = 0
        var i = 0
        for (ch in clean) {
            value = (value shl 5) or ALPHABET.indexOf(ch)
            bits += 5
            if (bits >= 8) {
                out[i++] = (value ushr (bits - 8)).toByte()
                bits -= 8
                value = value and ((1 shl bits) - 1)
            }
        }
        return out
    }
}

/** Password rules, checked on the phone because the server never sees the password. */
object PasswordCheck {
    private val COMMON = listOf(
        "password", "passw0rd", "123456", "12345678", "qwerty", "abc123", "111111", "iloveyou", "admin",
        "welcome", "letmein", "monkey", "dragon", "football", "cricket", "sunshine", "princess", "master",
        "baseball", "shadow", "superman", "trustno1", "india", "vaultspace", "iiitd", "qwertyuiop", "asdfgh",
        "zxcvbn", "1q2w3e", "987654", "000000", "secret", "computer",
    )

    fun problem(pw: String, email: String): String? {
        val lower = pw.lowercase()
        val name = email.substringBefore('@').lowercase()
        return when {
            pw.length < 12 -> "Use at least 12 characters. Tip: 3 or 4 random words work well."
            pw.length > 128 -> "Use at most 128 characters."
            COMMON.any { lower.contains(it) } -> "Avoid common passwords and words like \"password\" or \"123456\"."
            name.length >= 3 && lower.contains(name) -> "Don't use your email name inside your password."
            pw.toSet().size < 6 -> "Use more different characters."
            Regex("(.)\\1{3,}").containsMatchIn(pw) -> "Avoid repeating the same character."
            else -> null
        }
    }

    /** 0..4 for the strength bar. */
    fun score(pw: String): Int {
        var classes = 0
        if (pw.any { it.isLowerCase() }) classes++
        if (pw.any { it.isUpperCase() }) classes++
        if (pw.any { it.isDigit() }) classes++
        if (pw.any { !it.isLetterOrDigit() }) classes++
        val s = when {
            pw.length >= 20 -> 3
            pw.length >= 16 -> 2
            pw.length >= 12 -> 1
            else -> 0
        } + if (classes >= 3) 1 else 0
        return s.coerceIn(0, 4)
    }
}
