package com.fedmes.app.accountsecurity

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import android.util.Base64
import org.json.JSONObject
import java.io.File
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class AndroidAccountVaultStore(
    context: Context,
) {
    private val root = File(context.noBackupFilesDir, "account-security").apply {
        if (!exists() && !mkdirs()) error("Account security directory could not be created")
    }

    fun hasVault(serverUrl: String, username: String): Boolean = activeFile(serverUrl, username).exists()

    fun hasPendingVault(serverUrl: String, username: String): Boolean = pendingFile(serverUrl, username).exists()

    fun savePendingRecoveryKey(serverUrl: String, username: String, recoveryKey: String) {
        require(recoveryKey.isNotBlank())
        val plaintext = recoveryKey.toByteArray(Charsets.US_ASCII)
        try {
            val encrypted = encryptSecret(serverUrl, username, "recovery-key", plaintext)
            try {
                writeAtomic(AtomicFile(pendingRecoveryKeyFile(serverUrl, username)), encrypted)
            } finally {
                encrypted.fill(0)
            }
        } finally {
            plaintext.fill(0)
        }
    }

    fun loadPendingRecoveryKey(serverUrl: String, username: String): String? {
        val file = pendingRecoveryKeyFile(serverUrl, username)
        if (!file.exists()) return null
        val encoded = file.readBytes()
        val plaintext = try {
            decryptSecret(serverUrl, username, "recovery-key", encoded)
        } finally {
            encoded.fill(0)
        }
        return try {
            plaintext.toString(Charsets.US_ASCII)
        } finally {
            plaintext.fill(0)
        }
    }

    fun clearPendingRecoveryKey(serverUrl: String, username: String) {
        pendingRecoveryKeyFile(serverUrl, username).delete()
    }

    /** Writes and verifies a candidate vault without replacing the active vault. */
    fun savePending(serverUrl: String, username: String, localVault: LocalAccountVault) {
        require(localVault.accountRootKey.size == AccountSecurityProtocol.ACCOUNT_ROOT_KEY_BYTES)
        val encrypted = encrypt(serverUrl, username, localVault)
        try {
            val pending = AtomicFile(pendingFile(serverUrl, username))
            writeAtomic(pending, encrypted)
            val verified = decrypt(serverUrl, username, encrypted)
            try {
                if (!MessageDigest.isEqual(verified.accountRootKey, localVault.accountRootKey) ||
                    verified.vaultRevision != localVault.vaultRevision ||
                    verified.cryptoVersion != localVault.cryptoVersion
                ) {
                    throw AccountSecurityException("local_vault_verification_failed")
                }
            } finally {
                verified.accountRootKey.fill(0)
            }
        } finally {
            encrypted.fill(0)
        }
    }

    /** Atomically promotes a previously verified candidate after the server workflow completed. */
    fun promotePending(serverUrl: String, username: String): LocalAccountVault {
        val pendingPath = pendingFile(serverUrl, username)
        if (!pendingPath.exists()) throw AccountSecurityException("pending_vault_unavailable")
        val encoded = pendingPath.readBytes()
        try {
            val verified = decrypt(serverUrl, username, encoded)
            try {
                writeAtomic(AtomicFile(activeFile(serverUrl, username)), encoded)
            } catch (error: Exception) {
                verified.accountRootKey.fill(0)
                throw error
            }
            if (!pendingPath.delete() && pendingPath.exists()) {
                // The active file is already committed. Keep the verified candidate readable so a
                // later startup can safely retry cleanup instead of rolling back the active vault.
                pendingPath.deleteOnExit()
            }
            return verified
        } finally {
            encoded.fill(0)
        }
    }

    /** Compatibility helper for callers that intentionally commit in one local operation. */
    fun saveStaged(serverUrl: String, username: String, localVault: LocalAccountVault) {
        savePending(serverUrl, username, localVault)
        promotePending(serverUrl, username).accountRootKey.fill(0)
    }

    fun load(serverUrl: String, username: String): LocalAccountVault? = loadFile(activeFile(serverUrl, username), serverUrl, username)

    fun loadPending(serverUrl: String, username: String): LocalAccountVault? =
        loadFile(pendingFile(serverUrl, username), serverUrl, username)

    fun discardPending(serverUrl: String, username: String) {
        pendingFile(serverUrl, username).delete()
    }

    fun deleteLocal(serverUrl: String, username: String) {
        activeFile(serverUrl, username).delete()
        pendingFile(serverUrl, username).delete()
        pendingRecoveryKeyFile(serverUrl, username).delete()
    }

    private fun loadFile(file: File, serverUrl: String, username: String): LocalAccountVault? {
        if (!file.exists()) return null
        val encoded = file.readBytes()
        return try {
            decrypt(serverUrl, username, encoded)
        } finally {
            encoded.fill(0)
        }
    }

    private fun encrypt(serverUrl: String, username: String, localVault: LocalAccountVault): ByteArray {
        val plaintext = JSONObject()
            .put("version", 1)
            .put("server_url", serverUrl)
            .put("username", username)
            .put("vault_revision", localVault.vaultRevision)
            .put("crypto_version", localVault.cryptoVersion)
            .put("account_root_key", Base64.encodeToString(localVault.accountRootKey, Base64.NO_WRAP))
            .toString()
            .toByteArray(Charsets.UTF_8)
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, getOrCreateWrappingKey(serverUrl, username))
            val aad = localAad(serverUrl, username)
            val ciphertext = try {
                cipher.updateAAD(aad)
                cipher.doFinal(plaintext)
            } finally {
                aad.fill(0)
            }
            try {
                JSONObject()
                    .put("version", 1)
                    .put("iv", Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
                    .put("ciphertext", Base64.encodeToString(ciphertext, Base64.NO_WRAP))
                    .toString()
                    .toByteArray(Charsets.UTF_8)
            } finally {
                ciphertext.fill(0)
            }
        } finally {
            plaintext.fill(0)
        }
    }

    private fun decrypt(serverUrl: String, username: String, encoded: ByteArray): LocalAccountVault {
        val envelope = JSONObject(encoded.toString(Charsets.UTF_8))
        if (envelope.getInt("version") != 1) throw AccountSecurityException("local_vault_version")
        val iv = Base64.decode(envelope.getString("iv"), Base64.NO_WRAP)
        val ciphertext = Base64.decode(envelope.getString("ciphertext"), Base64.NO_WRAP)
        val aad = localAad(serverUrl, username)
        val plaintext = try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                getOrCreateWrappingKey(serverUrl, username),
                GCMParameterSpec(128, iv),
            )
            cipher.updateAAD(aad)
            cipher.doFinal(ciphertext)
        } catch (error: Exception) {
            throw AccountSecurityException("local_vault_unavailable", error)
        } finally {
            iv.fill(0)
            ciphertext.fill(0)
            aad.fill(0)
        }
        return try {
            val payload = JSONObject(plaintext.toString(Charsets.UTF_8))
            if (payload.getInt("version") != 1 || payload.getString("server_url") != serverUrl ||
                payload.getString("username") != username
            ) {
                throw AccountSecurityException("local_vault_scope_mismatch")
            }
            val key = Base64.decode(payload.getString("account_root_key"), Base64.NO_WRAP)
            if (key.size != AccountSecurityProtocol.ACCOUNT_ROOT_KEY_BYTES) {
                key.fill(0)
                throw AccountSecurityException("local_vault_key_invalid")
            }
            LocalAccountVault(
                accountRootKey = key,
                vaultRevision = payload.getLong("vault_revision"),
                cryptoVersion = payload.getInt("crypto_version"),
            )
        } finally {
            plaintext.fill(0)
        }
    }

    private fun encryptSecret(
        serverUrl: String,
        username: String,
        purpose: String,
        plaintext: ByteArray,
    ): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateWrappingKey(serverUrl, username))
        val aad = secretAad(serverUrl, username, purpose)
        return try {
            cipher.updateAAD(aad)
            val ciphertext = cipher.doFinal(plaintext)
            try {
                JSONObject()
                    .put("version", 1)
                    .put("iv", Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
                    .put("ciphertext", Base64.encodeToString(ciphertext, Base64.NO_WRAP))
                    .toString()
                    .toByteArray(Charsets.UTF_8)
            } finally {
                ciphertext.fill(0)
            }
        } finally {
            aad.fill(0)
        }
    }

    private fun decryptSecret(
        serverUrl: String,
        username: String,
        purpose: String,
        encoded: ByteArray,
    ): ByteArray {
        val envelope = JSONObject(encoded.toString(Charsets.UTF_8))
        if (envelope.getInt("version") != 1) throw AccountSecurityException("local_secret_version")
        val iv = Base64.decode(envelope.getString("iv"), Base64.NO_WRAP)
        val ciphertext = Base64.decode(envelope.getString("ciphertext"), Base64.NO_WRAP)
        val aad = secretAad(serverUrl, username, purpose)
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                getOrCreateWrappingKey(serverUrl, username),
                GCMParameterSpec(128, iv),
            )
            cipher.updateAAD(aad)
            cipher.doFinal(ciphertext)
        } catch (error: Exception) {
            throw AccountSecurityException("local_secret_unavailable", error)
        } finally {
            iv.fill(0)
            ciphertext.fill(0)
            aad.fill(0)
        }
    }

    private fun getOrCreateWrappingKey(serverUrl: String, username: String): SecretKey = synchronized(KEY_LOCK) {
        val alias = keyAlias(serverUrl, username)
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (keyStore.getKey(alias, null) as? SecretKey) ?: run {
            val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            generator.init(
                KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .setUnlockedDeviceRequired(true)
                    .setUserAuthenticationRequired(false)
                    .build(),
            )
            generator.generateKey()
        }
    }

    private fun activeFile(serverUrl: String, username: String): File =
        File(root, scope(serverUrl, username) + ".vault")

    private fun pendingFile(serverUrl: String, username: String): File =
        File(root, scope(serverUrl, username) + ".pending")

    private fun pendingRecoveryKeyFile(serverUrl: String, username: String): File =
        File(root, scope(serverUrl, username) + ".recovery.pending")

    private fun scope(serverUrl: String, username: String): String = sha256Hex("$serverUrl\n$username")

    private fun keyAlias(serverUrl: String, username: String): String = "fedmes.account.vault.v1.${scope(serverUrl, username)}"

    private fun localAad(serverUrl: String, username: String): ByteArray =
        "fedmes-local-vault-v1\n$serverUrl\n$username".toByteArray(Charsets.UTF_8)

    private fun secretAad(serverUrl: String, username: String, purpose: String): ByteArray =
        "fedmes-local-secret-v1\n$serverUrl\n$username\n$purpose".toByteArray(Charsets.UTF_8)

    private fun writeAtomic(file: AtomicFile, bytes: ByteArray) {
        val output = file.startWrite()
        try {
            output.write(bytes)
            output.fd.sync()
            file.finishWrite(output)
        } catch (error: Exception) {
            file.failWrite(output)
            throw error
        }
    }

    private fun sha256Hex(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private companion object {
        val KEY_LOCK = Any()
    }
}
