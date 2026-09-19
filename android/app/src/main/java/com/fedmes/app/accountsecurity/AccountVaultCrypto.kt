package com.fedmes.app.accountsecurity

import org.json.JSONObject
import java.util.Base64
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

class AccountVaultCrypto(
    private val secureRandom: SecureRandom = SecureRandom(),
) {
    fun generateAccountRootKey(): ByteArray = ByteArray(AccountSecurityProtocol.ACCOUNT_ROOT_KEY_BYTES).also {
        secureRandom.nextBytes(it)
    }

    fun generateRecoveryKeyText(): String {
        val bytes = ByteArray(AccountSecurityProtocol.RECOVERY_KEY_BYTES)
        return try {
            secureRandom.nextBytes(bytes)
            Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
        } finally {
            bytes.fill(0)
        }
    }

    fun encryptVault(
        serverUrl: String,
        username: String,
        accountRootKey: ByteArray,
        previousRevision: Long,
        legacyKeyMaterial: ByteArray? = null,
    ): Pair<EncryptedAccountVault, Long> {
        require(accountRootKey.size == AccountSecurityProtocol.ACCOUNT_ROOT_KEY_BYTES)
        val revision = previousRevision + 1L
        val testRecord = ByteArray(32)
        secureRandom.nextBytes(testRecord)
        val payload = JSONObject()
            .put("version", AccountSecurityProtocol.VAULT_VERSION)
            .put("crypto_version", AccountSecurityProtocol.CRYPTO_VERSION)
            .put("username", username)
            .put("revision", revision)
            .put("test_record", Base64.getEncoder().encodeToString(testRecord))
            .put("room_keys", JSONObject())
            .put("file_keys", JSONObject())
            .put("rotation_state", JSONObject())
            .put(
                "legacy_fmk",
                legacyKeyMaterial?.let { Base64.getEncoder().encodeToString(it) } ?: JSONObject.NULL,
            )
            .toString()
            .toByteArray(Charsets.UTF_8)
        val nonce = ByteArray(AccountSecurityProtocol.NONCE_BYTES)
        secureRandom.nextBytes(nonce)
        val aad = vaultAad(serverUrl, username, revision)
        val ciphertext = try {
            aesGcmEncrypt(accountRootKey, nonce, aad, payload)
        } finally {
            payload.fill(0)
            testRecord.fill(0)
            aad.fill(0)
        }
        val hash = sha256Hex(ciphertext)
        return EncryptedAccountVault(
            revision = revision,
            vaultVersion = AccountSecurityProtocol.VAULT_VERSION,
            cryptoVersion = AccountSecurityProtocol.CRYPTO_VERSION,
            aadVersion = AccountSecurityProtocol.AAD_VERSION,
            nonce = nonce,
            ciphertext = ciphertext,
            ciphertextSha256Hex = hash,
        ) to revision
    }

    fun verifyAndDecryptVault(
        serverUrl: String,
        username: String,
        accountRootKey: ByteArray,
        vault: EncryptedAccountVault,
    ): JSONObject {
        require(accountRootKey.size == AccountSecurityProtocol.ACCOUNT_ROOT_KEY_BYTES)
        if (vault.vaultVersion != AccountSecurityProtocol.VAULT_VERSION ||
            vault.cryptoVersion != AccountSecurityProtocol.CRYPTO_VERSION ||
            vault.aadVersion != AccountSecurityProtocol.AAD_VERSION ||
            vault.revision <= 0L ||
            vault.nonce.size != AccountSecurityProtocol.NONCE_BYTES ||
            vault.ciphertext.size < 17
        ) {
            throw AccountSecurityException("vault_metadata_invalid")
        }
        if (!constantTimeHexEquals(vault.ciphertextSha256Hex, sha256Hex(vault.ciphertext))) {
            throw AccountSecurityException("vault_hash_mismatch")
        }
        val aad = vaultAad(serverUrl, username, vault.revision)
        val plaintext = try {
            aesGcmDecrypt(accountRootKey, vault.nonce, aad, vault.ciphertext)
        } catch (error: Exception) {
            throw AccountSecurityException("vault_decryption_failed", error)
        } finally {
            aad.fill(0)
        }
        return try {
            val root = JSONObject(plaintext.toString(Charsets.UTF_8))
            val testRecord = Base64.getDecoder().decode(root.getString("test_record"))
            try {
                if (root.getInt("version") != vault.vaultVersion ||
                    root.getInt("crypto_version") != vault.cryptoVersion ||
                    root.getString("username") != username ||
                    root.getLong("revision") != vault.revision ||
                    testRecord.size != 32
                ) {
                    throw AccountSecurityException("vault_test_record_invalid")
                }
            } finally {
                testRecord.fill(0)
            }
            root
        } finally {
            plaintext.fill(0)
        }
    }

    fun createRecoveryPackage(
        serverUrl: String,
        username: String,
        recoveryKeyText: String,
        accountRootKey: ByteArray,
        vaultRevision: Long,
    ): EncryptedRecoveryPackage {
        val recoveryKey = parseRecoveryKey(recoveryKeyText)
        val salt = ByteArray(AccountSecurityProtocol.RECOVERY_SALT_BYTES)
        val nonce = ByteArray(AccountSecurityProtocol.NONCE_BYTES)
        secureRandom.nextBytes(salt)
        secureRandom.nextBytes(nonce)
        val wrappingKey = deriveRecoveryWrappingKey(recoveryKey, salt)
        val packageId = AccountSecurityProtocol.newRequestId()
        val aad = recoveryAad(serverUrl, username, packageId, vaultRevision)
        val ciphertext = try {
            aesGcmEncrypt(wrappingKey, nonce, aad, accountRootKey)
        } finally {
            recoveryKey.fill(0)
            wrappingKey.fill(0)
            aad.fill(0)
        }
        return EncryptedRecoveryPackage(
            id = packageId,
            vaultRevision = vaultRevision,
            packageVersion = AccountSecurityProtocol.RECOVERY_PACKAGE_VERSION,
            cryptoVersion = AccountSecurityProtocol.CRYPTO_VERSION,
            aadVersion = AccountSecurityProtocol.AAD_VERSION,
            kdfName = AccountSecurityProtocol.RECOVERY_KDF_NAME,
            kdfParameters = JSONObject()
                .put("iterations", AccountSecurityProtocol.RECOVERY_KDF_ITERATIONS)
                .put("key_bits", 256)
                .put("password_encoding", "base64url-canonical")
                .toString(),
            salt = salt,
            nonce = nonce,
            ciphertext = ciphertext,
            ciphertextSha256Hex = sha256Hex(ciphertext),
        )
    }

    fun recoverAccountRootKey(
        serverUrl: String,
        username: String,
        recoveryKeyText: String,
        recoveryPackage: EncryptedRecoveryPackage,
    ): ByteArray {
        val kdfParameters = runCatching { JSONObject(recoveryPackage.kdfParameters) }
            .getOrElse { throw AccountSecurityException("recovery_package_invalid", it) }
        if (recoveryPackage.kdfName != AccountSecurityProtocol.RECOVERY_KDF_NAME ||
            recoveryPackage.packageVersion != AccountSecurityProtocol.RECOVERY_PACKAGE_VERSION ||
            recoveryPackage.cryptoVersion != AccountSecurityProtocol.CRYPTO_VERSION ||
            recoveryPackage.aadVersion != AccountSecurityProtocol.AAD_VERSION ||
            recoveryPackage.vaultRevision <= 0L ||
            recoveryPackage.salt.size != AccountSecurityProtocol.RECOVERY_SALT_BYTES ||
            recoveryPackage.nonce.size != AccountSecurityProtocol.NONCE_BYTES ||
            recoveryPackage.ciphertext.size != AccountSecurityProtocol.ACCOUNT_ROOT_KEY_BYTES + 16 ||
            kdfParameters.optInt("iterations") != AccountSecurityProtocol.RECOVERY_KDF_ITERATIONS ||
            kdfParameters.optInt("key_bits") != 256 ||
            kdfParameters.optString("password_encoding") != "base64url-canonical" ||
            !constantTimeHexEquals(recoveryPackage.ciphertextSha256Hex, sha256Hex(recoveryPackage.ciphertext))
        ) {
            throw AccountSecurityException("recovery_package_invalid")
        }
        val recoveryKey = parseRecoveryKey(recoveryKeyText)
        val wrappingKey = deriveRecoveryWrappingKey(recoveryKey, recoveryPackage.salt)
        val aad = recoveryAad(
            serverUrl,
            username,
            recoveryPackage.id,
            recoveryPackage.vaultRevision,
        )
        return try {
            aesGcmDecrypt(wrappingKey, recoveryPackage.nonce, aad, recoveryPackage.ciphertext).also {
                if (it.size != AccountSecurityProtocol.ACCOUNT_ROOT_KEY_BYTES) {
                    it.fill(0)
                    throw AccountSecurityException("recovery_key_invalid")
                }
            }
        } catch (error: AccountSecurityException) {
            throw error
        } catch (error: Exception) {
            throw AccountSecurityException("recovery_key_invalid", error)
        } finally {
            recoveryKey.fill(0)
            wrappingKey.fill(0)
            aad.fill(0)
        }
    }

    fun accessVerifier(
        serverUrl: String,
        username: String,
        accountRootKey: ByteArray,
        vaultRevision: Long,
    ): ByteArray {
        require(accountRootKey.size == AccountSecurityProtocol.ACCOUNT_ROOT_KEY_BYTES)
        require(vaultRevision > 0L)
        val context = "fedmes-vault-access-v1\n$serverUrl\n$username\n$vaultRevision"
            .toByteArray(Charsets.UTF_8)
        return try {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(accountRootKey, "HmacSHA256"))
            mac.doFinal(context)
        } finally {
            context.fill(0)
        }
    }

    fun parseRecoveryKey(text: String): ByteArray {
        val normalized = text.trim().replace(" ", "").replace("\n", "").replace("\r", "")
        val decoded = try {
            Base64.getUrlDecoder().decode(normalized)
        } catch (error: IllegalArgumentException) {
            throw AccountSecurityException("recovery_key_invalid", error)
        }
        if (decoded.size != AccountSecurityProtocol.RECOVERY_KEY_BYTES) {
            decoded.fill(0)
            throw AccountSecurityException("recovery_key_invalid")
        }
        return decoded
    }

    private fun deriveRecoveryWrappingKey(recoveryKey: ByteArray, salt: ByteArray): ByteArray {
        val passwordChars = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(recoveryKey)
            .toCharArray()
        val spec = PBEKeySpec(
            passwordChars,
            salt,
            AccountSecurityProtocol.RECOVERY_KDF_ITERATIONS,
            256,
        )
        return try {
            SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        } finally {
            passwordChars.fill('\u0000')
            spec.clearPassword()
        }
    }

    private fun aesGcmEncrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(plaintext)
    }

    private fun aesGcmDecrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, ciphertext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(ciphertext)
    }

    private fun vaultAad(serverUrl: String, username: String, revision: Long): ByteArray =
        listOf(
            "fedmes-vault",
            "protocol=${AccountSecurityProtocol.VERSION}",
            "server=$serverUrl",
            "account=$username",
            "vault_version=${AccountSecurityProtocol.VAULT_VERSION}",
            "revision=$revision",
            "crypto_version=${AccountSecurityProtocol.CRYPTO_VERSION}",
            "aad_version=${AccountSecurityProtocol.AAD_VERSION}",
        ).joinToString("\n").toByteArray(Charsets.UTF_8)

    private fun recoveryAad(
        serverUrl: String,
        username: String,
        packageId: String,
        vaultRevision: Long,
    ): ByteArray = listOf(
        "fedmes-recovery",
        "protocol=${AccountSecurityProtocol.VERSION}",
        "server=$serverUrl",
        "account=$username",
        "package_id=$packageId",
        "vault_version=${AccountSecurityProtocol.VAULT_VERSION}",
        "vault_revision=$vaultRevision",
        "crypto_version=${AccountSecurityProtocol.CRYPTO_VERSION}",
        "aad_version=${AccountSecurityProtocol.AAD_VERSION}",
    ).joinToString("\n").toByteArray(Charsets.UTF_8)

    private fun sha256Hex(value: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(value)
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }

    private fun constantTimeHexEquals(left: String, right: String): Boolean {
        val leftBytes = left.lowercase().toByteArray(Charsets.US_ASCII)
        val rightBytes = right.lowercase().toByteArray(Charsets.US_ASCII)
        return try {
            MessageDigest.isEqual(leftBytes, rightBytes)
        } finally {
            leftBytes.fill(0)
            rightBytes.fill(0)
        }
    }
}
