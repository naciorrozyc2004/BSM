package com.example.secretlab.secure

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Minimal local authenticated encryption helper.
 *
 * Encoding format (for the lab): `iv || ciphertextAndTag` as raw bytes.
 */
class SecretBox(
    private val keyProvider: KeyProvider,
    private val random: SecureRandom = SecureRandom(),
) {
    fun generateIv(): ByteArray {
        // TODO(L05-7): generate a fresh random IV of length `IV_BYTES`.
        // Requirements checked by tests:
        // - returns a ByteArray of length IV_BYTES
        // - successive calls should not return the same IV
        return ByteArray(IV_BYTES)
    }

    fun encrypt(plaintext: ByteArray, iv: ByteArray): ByteArray {
        // TODO(L05-1): implement AES/GCM/NoPadding encryption using the key from `keyProvider`.
        // Requirements checked by tests:
        // - Uses the provided IV (do not generate a new one inside the function).
        // - Rejects invalid IV length with IllegalArgumentException.
        // - Output layout is `iv || ciphertextAndTag`.
        // - Must be deterministic for identical inputs (since IV is provided).
        if (iv.size != IV_BYTES) {
            throw IllegalArgumentException("IV must be $IV_BYTES bytes")
        }

        val cipher = cipherEncrypt(iv)
        val ciphertextAndTag = cipher.doFinal(plaintext)

        return iv + ciphertextAndTag
    }

    fun decrypt(message: ByteArray): ByteArray? {
        // TODO(L05-2): implement AES/GCM/NoPadding decryption for the `iv || ciphertextAndTag` format.
        // Requirements checked by tests:
        // - Returns null when the message is too short to contain an IV + tag.
        // - Returns null when authentication fails (tamper detected).
        // musi być przynajmniej IV + coś (ciphertext+tag)
        if (message.size < IV_BYTES + 1) {
        return null
        }

        val iv = message.copyOfRange(0, IV_BYTES)
        val ciphertextAndTag = message.copyOfRange(IV_BYTES, message.size)

        return try {
            val cipher = cipherDecrypt(iv)
            cipher.doFinal(ciphertextAndTag)
            } catch (e: Exception) {
            null
        }
    }

    fun encryptBound(plaintext: ByteArray, iv: ByteArray, context: ByteArray): ByteArray {
        // TODO(L05-5): same as encrypt(...), but bind the ciphertext to `context` using AAD.
        // Requirements checked by tests:
        // - Uses cipher.updateAAD(context) before doFinal(...).
        // - Decryption must fail (return null) if context differs.
        return encrypt(plaintext, iv)
    }

    fun decryptBound(message: ByteArray, context: ByteArray): ByteArray? {
        // TODO(L05-6): same as decrypt(...), but uses the provided `context` as AAD.
        return decrypt(message)
    }

    private fun cipherEncrypt(iv: ByteArray): Cipher {
        val key = SecretKeySpec(keyProvider.getOrCreateAesKey(), "AES")
        return Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
        }
    }

    private fun cipherDecrypt(iv: ByteArray): Cipher {
        val key = SecretKeySpec(keyProvider.getOrCreateAesKey(), "AES")
        return Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
        }
    }

    companion object {
        const val IV_BYTES: Int = 12
        private const val TAG_BITS: Int = 128
    }
}
