package com.fedmes.app.accountsecurity

data class PendingDeviceRequest(
    val id: String,
    val username: String,
    val targetDeviceId: String,
    val displayName: String,
    val platform: String,
    val networkHint: String,
    val requestedAt: String,
    val expiresAt: String,
    val signingAlgorithm: String,
    val signingPublicKeySpkiBase64: String,
    val signingFingerprintHex: String,
    val keyAgreementAlgorithm: String,
    val keyAgreementPublicKeySpkiBase64: String,
    val keyAgreementFingerprintHex: String,
)

data class ProvisioningPackageResponse(
    val requestId: String,
    val targetDeviceId: String,
    val encryptedPackage: ByteArray,
    val nonce: ByteArray,
    val aadVersion: Int,
    val packageVersion: Int,
    val certificateId: String,
    val certificatePayload: ByteArray,
    val certificateSignature: ByteArray,
    val signatureAlgorithm: String,
    val issuerDeviceId: String,
)
