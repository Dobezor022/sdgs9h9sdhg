package com.fedmes.app.messaging

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import com.fedmes.app.security.AccountKeyScope
import com.fedmes.app.security.SessionStore
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

/** RSA message-key storage isolated per server/account pair. */
class AndroidMessageKeyStore(
    context: Context,
    private val sessionStore: SessionStore,
) {
    private val preferences = context.applicationContext.getSharedPreferences(
        KEY_OWNERSHIP_PREFERENCES,
        Context.MODE_PRIVATE,
    )

    /** Used while redeeming a QR before the new account has been persisted. */
    fun getOrCreatePublicKeySpkiBase64(serverUrl: String, username: String): String = synchronized(lock) {
        val keyStore = loadKeyStore()
        val alias = provisioningAlias(keyStore, serverUrl, username)
        certificateBase64(keyStore, alias) ?: certificateBase64(keyStore, generate(alias))
            ?: error("Message encryption key was not generated")
    }

    /** Used by normal messaging after a session has been persisted. */
    fun getOrCreatePublicKeySpkiBase64(): String = synchronized(lock) {
        val account = sessionStore.loadAccount() ?: error("Account is not available")
        val keyStore = loadKeyStore()
        val alias = existingAlias(
            keyStore,
            account.serverUrl,
            account.username,
            claimLegacyOwner = true,
        ) ?: scopedAlias(account.serverUrl, account.username)
        certificateBase64(keyStore, alias) ?: certificateBase64(keyStore, generate(alias))
            ?: error("Message encryption key was not generated")
    }

    fun unwrapMessageKey(ciphertext: ByteArray): ByteArray = synchronized(lock) {
        val account = sessionStore.loadAccount() ?: error("Account is not available")
        val keyStore = loadKeyStore()
        val alias = existingAlias(
            keyStore,
            account.serverUrl,
            account.username,
            claimLegacyOwner = true,
        ) ?: error("Message encryption key is unavailable")
        val privateKey = keyStore.getKey(alias, null) as? PrivateKey
            ?: error("Message encryption key is unavailable")
        Cipher.getInstance(RSA_TRANSFORMATION).run {
            init(Cipher.DECRYPT_MODE, privateKey, oaepParameters())
            doFinal(ciphertext)
        }
    }

    private fun provisioningAlias(keyStore: KeyStore, serverUrl: String, username: String): String {
        val scoped = scopedAlias(serverUrl, username)
        if (keyStore.containsAlias(scoped)) return scoped
        val requestedOwner = AccountKeyScope.hashHex(serverUrl, username)
        val owner = preferences.getString(LEGACY_MESSAGE_OWNER, null)
        if (owner == requestedOwner && keyStore.containsAlias(LEGACY_KEY_ALIAS)) return LEGACY_KEY_ALIAS
        return scoped
    }

    private fun existingAlias(
        keyStore: KeyStore,
        serverUrl: String,
        username: String,
        claimLegacyOwner: Boolean,
    ): String? {
        val scoped = scopedAlias(serverUrl, username)
        if (keyStore.containsAlias(scoped)) return scoped
        if (!keyStore.containsAlias(LEGACY_KEY_ALIAS)) return null

        val requestedOwner = AccountKeyScope.hashHex(serverUrl, username)
        val owner = preferences.getString(LEGACY_MESSAGE_OWNER, null)
        if (owner == requestedOwner) return LEGACY_KEY_ALIAS
        if (owner == null && claimLegacyOwner) {
            preferences.edit().putString(LEGACY_MESSAGE_OWNER, requestedOwner).commit()
            return LEGACY_KEY_ALIAS
        }
        return null
    }

    private fun generate(alias: String): String {
        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA,
            ANDROID_KEY_STORE,
        )
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setKeySize(RSA_BITS)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA1)
            .setUserAuthenticationRequired(false)
            .build()
        generator.initialize(spec)
        generator.generateKeyPair()
        return alias
    }

    private fun certificateBase64(keyStore: KeyStore, alias: String): String? =
        keyStore.getCertificate(alias)?.publicKey?.encoded?.let {
            Base64.encodeToString(it, Base64.NO_WRAP)
        }

    private fun loadKeyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }

    private fun scopedAlias(serverUrl: String, username: String): String =
        "$SCOPED_ALIAS_PREFIX.${AccountKeyScope.aliasSuffix(serverUrl, username)}"

    companion object {
        const val ALGORITHM = "rsa-oaep-sha256"
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val LEGACY_KEY_ALIAS = "fedmes.message.encryption.rsa.v1"
        private const val SCOPED_ALIAS_PREFIX = "fedmes.message.encryption.rsa.v2"
        private const val KEY_OWNERSHIP_PREFERENCES = "fedmes.keystore.ownership.v1"
        private const val LEGACY_MESSAGE_OWNER = "legacy_message_owner"
        private const val RSA_BITS = 3072
        private const val RSA_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
        private val lock = Any()

        fun oaepParameters(): OAEPParameterSpec = OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA1,
            PSource.PSpecified.DEFAULT,
        )
    }
}
