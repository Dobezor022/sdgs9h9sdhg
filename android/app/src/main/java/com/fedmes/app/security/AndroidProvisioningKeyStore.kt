package com.fedmes.app.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import javax.crypto.Cipher

/**
 * Separate non-exportable RSA key used only for receiving ARK/device-provisioning
 * packages. It is never reused as the request-signing identity.
 */
class AndroidProvisioningKeyStore(private val context: Context) {
    data class PublicIdentity(val algorithm: String, val publicKeySpkiBase64: String)

    fun getOrCreate(serverUrl: String, username: String): PublicIdentity = synchronized(lock) {
        val alias = alias(serverUrl, username)
        val store = keyStore()
        if (!store.containsAlias(alias)) {
            val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEY_STORE)
            generator.initialize(
                KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_ENCRYPT,
                )
                    .setKeySize(3072)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA1)
                    .setUserAuthenticationRequired(false)
                    .build(),
            )
            generator.generateKeyPair()
        }
        val encoded = store.getCertificate(alias)?.publicKey?.encoded
            ?: throw IllegalStateException("Provisioning public key is unavailable")
        PublicIdentity(ALGORITHM, Base64.encodeToString(encoded, Base64.NO_WRAP))
    }

    fun decrypt(serverUrl: String, username: String, ciphertext: ByteArray): ByteArray = synchronized(lock) {
        require(ciphertext.isNotEmpty() && ciphertext.size <= 16 * 1024)
        val privateKey = keyStore().getKey(alias(serverUrl, username), null) as? PrivateKey
            ?: throw IllegalStateException("Provisioning private key is unavailable")
        Cipher.getInstance(TRANSFORMATION).run {
            init(Cipher.DECRYPT_MODE, privateKey)
            doFinal(ciphertext)
        }
    }

    fun delete(serverUrl: String, username: String) = synchronized(lock) {
        keyStore().deleteEntry(alias(serverUrl, username))
    }

    private fun alias(serverUrl: String, username: String): String =
        "$ALIAS_PREFIX.${AccountKeyScope.aliasSuffix(serverUrl, username)}"

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }

    companion object {
        const val ALGORITHM = "rsa-oaep-sha256"
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
        private const val ALIAS_PREFIX = "fedmes.provisioning.rsa.v1"
        private val lock = Any()
    }
}
