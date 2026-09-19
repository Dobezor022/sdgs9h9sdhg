package com.fedmes.app.provisioning

data class ProvisioningInvite(
    val serverUrl: String,
    val username: String,
    val token: String,
    val expiresAtEpochMillis: Long,
)

data class DeviceIdentity(
    val algorithm: String,
    val publicKeySpkiBase64: String,
)

data class MessageEncryptionIdentity(
    val algorithm: String,
    val publicKeySpkiBase64: String,
)

data class DeviceAuthenticationChallenge(
    val id: String,
    val deviceId: String,
    val audience: String,
    val purpose: String,
    val nonce: String,
    val expiresAtEpochMillis: Long,
)

data class ProvisionedAccount(
    val serverUrl: String,
    val username: String,
    val deviceId: String,
    val sessionId: String,
    val sessionToken: String,
    val sessionExpiresAtEpochMillis: Long,
    val authenticationState: String = AUTHENTICATION_STATE_READY,
    val pendingProvisioningRequestId: String? = null,
)

data class AccountSummary(
    val serverUrl: String,
    val username: String,
    val deviceId: String,
    val sessionExpiresAtEpochMillis: Long,
    val authenticationState: String = AUTHENTICATION_STATE_READY,
)

const val AUTHENTICATION_STATE_READY = "READY"
const val AUTHENTICATION_STATE_REGISTRATION_PENDING = "REGISTRATION_PENDING"

enum class ProvisioningFailure {
    INVALID_QR,
    UNSUPPORTED_QR,
    EXPIRED_QR,
    INSECURE_SERVER,
    INVALID_USER,
    INVITATION_USED,
    INVITATION_REJECTED,
    NETWORK,
    SERVER,
    INVALID_RESPONSE,
    DEVICE_SECURITY,
    SESSION_RECOVERY,
    SECURE_STORAGE,
    CAMERA,
}

class ProvisioningException(
    val failure: ProvisioningFailure,
    cause: Throwable? = null,
) : Exception(failure.name, cause)
