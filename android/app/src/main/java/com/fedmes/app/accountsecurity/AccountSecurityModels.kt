package com.fedmes.app.accountsecurity

import java.util.UUID

data class AccountSecurityState(
    val username: String,
    val deviceId: String,
    val state: String,
    val protocolVersion: Int,
    val cryptoVersion: Int,
    val vaultRevision: Long,
    val recoveryConfigured: Boolean,
    val opaqueEnrolled: Boolean,
)

data class EncryptedAccountVault(
    val revision: Long,
    val vaultVersion: Int,
    val cryptoVersion: Int,
    val aadVersion: Int,
    val nonce: ByteArray,
    val ciphertext: ByteArray,
    val ciphertextSha256Hex: String,
)

data class EncryptedRecoveryPackage(
    val id: String,
    val vaultRevision: Long,
    val packageVersion: Int,
    val cryptoVersion: Int,
    val aadVersion: Int,
    val kdfName: String,
    val kdfParameters: String,
    val salt: ByteArray,
    val nonce: ByteArray,
    val ciphertext: ByteArray,
    val ciphertextSha256Hex: String,
)

data class LocalAccountVault(
    val accountRootKey: ByteArray,
    val vaultRevision: Long,
    val cryptoVersion: Int,
)

data class RecoveryResult(
    val vaultRevision: Long,
    val authenticationState: String = STATE_READY,
)

class AccountSecurityException(
    val code: String,
    cause: Throwable? = null,
) : Exception(code, cause)

object AccountSecurityProtocol {
    const val VERSION = 3
    const val STATE_AUTHENTICATED_NO_KEYS = "AUTHENTICATED_NO_KEYS"
    const val STATE_KEY_TRANSFER_PENDING = "KEY_TRANSFER_PENDING"
    const val STATE_RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
    const val STATE_READY = "READY"
    const val VAULT_VERSION = 1
    const val CRYPTO_VERSION = 2
    const val AAD_VERSION = 1
    const val RECOVERY_PACKAGE_VERSION = 1
    const val RECOVERY_KDF_NAME = "PBKDF2-HMAC-SHA256"
    const val RECOVERY_KDF_ITERATIONS = 310_000
    const val RECOVERY_SALT_BYTES = 32
    const val ACCOUNT_ROOT_KEY_BYTES = 32
    const val RECOVERY_KEY_BYTES = 32
    const val NONCE_BYTES = 12

    fun newRequestId(): String = UUID.randomUUID().toString()
}

const val STATE_READY = AccountSecurityProtocol.STATE_READY
