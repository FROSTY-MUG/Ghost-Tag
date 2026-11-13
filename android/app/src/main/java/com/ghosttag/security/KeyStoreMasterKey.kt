package com.ghosttag.security

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Hardware-backed Master Key Manager leveraging Android KeyStore (TEE / StrongBox).
 *
 * Encapsulates the root encryption key inside secure hardware (TrustZone / Secure Element)
 * so that raw key material cannot be extracted even if local storage files are dumped.
 */
object KeyStoreMasterKey {
    private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    private const val MASTER_KEY_ALIAS = "GhostTag_HW_MasterKey_v1"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_TAG_LENGTH_BITS = 128
    private const val IV_LENGTH_BYTES = 12

    init {
        ensureKeyExists()
    }

    /**
     * Guarantees that a hardware-backed master key is present in Android KeyStore.
     */
    private fun ensureKeyExists() {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        if (!keyStore.containsAlias(MASTER_KEY_ALIAS)) {
            generateHardwareKey()
        }
    }

    private fun generateHardwareKey() {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            KEYSTORE_PROVIDER
        )

        val builder = KeyGenParameterSpec.Builder(
            MASTER_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)

        // Attempt StrongBox Keymaster hardware backing on Android 9+ (API 28+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                builder.setIsStrongBoxBacked(true)
                keyGenerator.init(builder.build())
                keyGenerator.generateKey()
                return
            } catch (e: Exception) {
                // StrongBox not available on this device; fallback to standard TEE
                builder.setIsStrongBoxBacked(false)
            }
        }

        keyGenerator.init(builder.build())
        keyGenerator.generateKey()
    }

    private fun getSecretKey(): SecretKey {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        return keyStore.getKey(MASTER_KEY_ALIAS, null) as SecretKey
    }

    /**
     * Encrypts plaintext bytes using hardware-backed AES-256-GCM.
     * Output format: [12 bytes IV] + [Ciphertext + 16 bytes GCM Tag]
     */
    fun encrypt(plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getSecretKey())
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(plaintext)

        val result = ByteArray(iv.size + ciphertext.size)
        System.arraycopy(iv, 0, result, 0, iv.size)
        System.arraycopy(ciphertext, 0, result, iv.size, ciphertext.size)
        return result
    }

    /**
     * Decrypts combined IV + Ciphertext using hardware-backed AES-256-GCM.
     */
    fun decrypt(encryptedPayload: ByteArray): ByteArray {
        require(encryptedPayload.size > IV_LENGTH_BYTES) { "Encrypted payload is too short" }

        val iv = ByteArray(IV_LENGTH_BYTES)
        System.arraycopy(encryptedPayload, 0, iv, 0, IV_LENGTH_BYTES)

        val ciphertext = ByteArray(encryptedPayload.size - IV_LENGTH_BYTES)
        System.arraycopy(encryptedPayload, IV_LENGTH_BYTES, ciphertext, 0, ciphertext.size)

        val cipher = Cipher.getInstance(TRANSFORMATION)
        val spec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv)
        cipher.init(Cipher.DECRYPT_MODE, getSecretKey(), spec)

        return cipher.doFinal(ciphertext)
    }
}

