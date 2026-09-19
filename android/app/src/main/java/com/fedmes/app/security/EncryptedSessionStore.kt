package com.fedmes.app.security

import android.annotation.SuppressLint
import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import com.fedmes.app.provisioning.ProvisionedAccount
import org.json.JSONObject
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

interface SessionStore {
    /** READY accounts are committed as active; incomplete accounts are staged separately. */
    fun save(account: ProvisionedAccount)
    fun loadAccount(): ProvisionedAccount?
    fun loadCandidateAccount(): ProvisionedAccount? = null
    fun clearCandidate() = Unit
    fun clear()
}

class EncryptedSessionStore(
    context: Context,
) : SessionStore {
    private val preferences = context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)

    override fun save(account: ProvisionedAccount) {
        if (account.authenticationState == READY_STATE) {
            saveActive(account)
            clearCandidate()
        } else {
            saveCandidate(account)
        }
    }

    private fun saveActive(account: ProvisionedAccount) {
        val encrypted = encrypt(account)
        try {
            check(
                preferences.edit()
                    .putString(STAGING_IV_KEY, encrypted.iv)
                    .putString(STAGING_CIPHERTEXT_KEY, encrypted.ciphertext)
                    .commit(),
            ) { "Encrypted staging session storage commit failed" }

            val verified = decrypt(encrypted.iv, encrypted.ciphertext)
            check(verified == account) { "Encrypted staging session verification failed" }

            check(
                preferences.edit()
                    .putString(IV_KEY, encrypted.iv)
                    .putString(CIPHERTEXT_KEY, encrypted.ciphertext)
                    .remove(STAGING_IV_KEY)
                    .remove(STAGING_CIPHERTEXT_KEY)
                    .commit(),
            ) { "Encrypted session storage commit failed" }
        } catch (error: Exception) {
            preferences.edit()
                .remove(STAGING_IV_KEY)
                .remove(STAGING_CIPHERTEXT_KEY)
                .commit()
            throw error
        }
    }

    private fun saveCandidate(account: ProvisionedAccount) {
        val encrypted = encrypt(account)
        val verified = decrypt(encrypted.iv, encrypted.ciphertext)
        check(verified == account) { "Encrypted candidate session verification failed" }
        check(
            preferences.edit()
                .putString(CANDIDATE_IV_KEY, encrypted.iv)
                .putString(CANDIDATE_CIPHERTEXT_KEY, encrypted.ciphertext)
                .commit(),
        ) { "Encrypted candidate session storage commit failed" }
    }

    override fun loadAccount(): ProvisionedAccount? {
        discardInterruptedStagingState()
        return loadEncrypted(IV_KEY, CIPHERTEXT_KEY)
    }

    override fun loadCandidateAccount(): ProvisionedAccount? {
        discardInterruptedStagingState()
        return loadEncrypted(CANDIDATE_IV_KEY, CANDIDATE_CIPHERTEXT_KEY)
    }

    private fun loadEncrypted(ivKey: String, ciphertextKey: String): ProvisionedAccount? {
        val encodedIv = preferences.getString(ivKey, null) ?: return null
        val encodedCiphertext = preferences.getString(ciphertextKey, null) ?: return null
        return try {
            decrypt(encodedIv, encodedCiphertext)
        } catch (_: Exception) {
            // Never erase the only stored account after a transient Keystore/device-lock failure.
            null
        }
    }

    @SuppressLint("ApplySharedPref", "UseKtx")
    override fun clearCandidate() {
        check(
            preferences.edit()
                .remove(CANDIDATE_IV_KEY)
                .remove(CANDIDATE_CIPHERTEXT_KEY)
                .commit(),
        ) { "Encrypted candidate session clear failed" }
    }

    @SuppressLint("ApplySharedPref", "UseKtx")
    override fun clear() {
        check(preferences.edit().clear().commit()) { "Encrypted session clear failed" }
    }

    private fun encrypt(account: ProvisionedAccount): EncryptedPayload {
        val plaintext = JSONObject()
            .put("version", STORAGE_VERSION)
            .put("server_url", account.serverUrl)
            .put("username", account.username)
            .put("device_id", account.deviceId)
            .put("session_id", account.sessionId)
            .put("session_token", account.sessionToken)
            .put("session_expires_at", account.sessionExpiresAtEpochMillis)
            .put("authentication_state", account.authenticationState)
            .put("pending_provisioning_request_id", account.pendingProvisioningRequestId ?: JSONObject.NULL)
            .toString()
            .toByteArray(Charsets.UTF_8)
        return try {
            val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, getOrCreateEncryptionKey())
            val ciphertext = cipher.doFinal(plaintext)
            try {
                EncryptedPayload(
                    iv = Base64.encodeToString(cipher.iv, Base64.NO_WRAP),
                    ciphertext = Base64.encodeToString(ciphertext, Base64.NO_WRAP),
                )
            } finally {
                ciphertext.fill(0)
            }
        } finally {
            plaintext.fill(0)
        }
    }

    private fun decrypt(encodedIv: String, encodedCiphertext: String): ProvisionedAccount {
        val iv = Base64.decode(encodedIv, Base64.NO_WRAP)
        val ciphertext = Base64.decode(encodedCiphertext, Base64.NO_WRAP)
        var plaintext: ByteArray? = null
        return try {
            val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION)
            cipher.init(
                Cipher.DECRYPT_MODE,
                getOrCreateEncryptionKey(),
                GCMParameterSpec(GCM_TAG_BITS, iv),
            )
            plaintext = cipher.doFinal(ciphertext)
            val root = JSONObject(plaintext.toString(Charsets.UTF_8))
            val version = root.getInt("version")
            check(version in 1..STORAGE_VERSION)
            check(root.keys().asSequence().toSet() == when (version) { 1 -> LEGACY_STORED_ACCOUNT_KEYS; 2 -> V2_STORED_ACCOUNT_KEYS; else -> STORED_ACCOUNT_KEYS })
            ProvisionedAccount(
                serverUrl = root.getString("server_url"),
                username = root.getString("username"),
                deviceId = root.getString("device_id"),
                sessionId = root.getString("session_id"),
                sessionToken = root.getString("session_token"),
                sessionExpiresAtEpochMillis = root.getLong("session_expires_at"),
                authenticationState = if (version == 1) "READY" else root.getString("authentication_state"),
                pendingProvisioningRequestId = if (version >= 3 && !root.isNull("pending_provisioning_request_id")) {
                    root.getString("pending_provisioning_request_id").takeIf { it.isNotBlank() }
                } else {
                    null
                },
            )
        } finally {
            iv.fill(0)
            ciphertext.fill(0)
            plaintext?.fill(0)
        }
    }

    private fun discardInterruptedStagingState() {
        if (preferences.contains(STAGING_IV_KEY) || preferences.contains(STAGING_CIPHERTEXT_KEY)) {
            preferences.edit()
                .remove(STAGING_IV_KEY)
                .remove(STAGING_CIPHERTEXT_KEY)
                .commit()
        }
    }

    private fun getOrCreateEncryptionKey(): SecretKey = synchronized(keyLock) {
        val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
        (keyStore.getKey(SESSION_KEY_ALIAS, null) as? SecretKey) ?: run {
            val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE)
            val parameters = KeyGenParameterSpec.Builder(
                SESSION_KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(AES_KEY_BITS)
                .setUserAuthenticationRequired(false)
                .build()
            generator.init(parameters)
            generator.generateKey()
        }
    }

    private data class EncryptedPayload(
        val iv: String,
        val ciphertext: String,
    )

    private companion object {
        const val STORAGE_VERSION = 3
        const val PREFERENCES_NAME = "fedmes.secure.session.v1"
        const val IV_KEY = "iv"
        const val CIPHERTEXT_KEY = "ciphertext"
        const val STAGING_IV_KEY = "staging_iv"
        const val STAGING_CIPHERTEXT_KEY = "staging_ciphertext"
        const val CANDIDATE_IV_KEY = "candidate_iv"
        const val CANDIDATE_CIPHERTEXT_KEY = "candidate_ciphertext"
        const val READY_STATE = "READY"
        const val ANDROID_KEY_STORE = "AndroidKeyStore"
        const val SESSION_KEY_ALIAS = "fedmes.session.encryption.v1"
        const val CIPHER_TRANSFORMATION = "AES/GCM/NoPadding"
        const val AES_KEY_BITS = 256
        const val GCM_TAG_BITS = 128
        val STORED_ACCOUNT_KEYS = setOf(
            "version",
            "server_url",
            "username",
            "device_id",
            "session_id",
            "session_token",
            "session_expires_at",
            "authentication_state",
            "pending_provisioning_request_id",
        )
        val V2_STORED_ACCOUNT_KEYS = STORED_ACCOUNT_KEYS - "pending_provisioning_request_id"
        val LEGACY_STORED_ACCOUNT_KEYS = V2_STORED_ACCOUNT_KEYS - "authentication_state"
        val keyLock = Any()
    }
}
