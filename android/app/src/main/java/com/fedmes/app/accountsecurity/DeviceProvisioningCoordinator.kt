package com.fedmes.app.accountsecurity

import android.util.Base64
import com.fedmes.app.provisioning.ProvisionedAccount
import com.fedmes.app.security.AndroidDeviceIdentity
import com.fedmes.app.security.SessionStore
import org.json.JSONObject
import java.security.MessageDigest
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.UUID

class DeviceProvisioningCoordinator(
    private val sessionStore: SessionStore,
    private val api: DeviceProvisioningHttpApi,
    private val identity: AndroidDeviceIdentity,
    private val crypto: DeviceProvisioningCrypto,
    private val securityApi: AccountSecurityHttpApi,
    private val vaultCrypto: AccountVaultCrypto,
    private val vaultStore: AndroidAccountVaultStore,
) {
    fun listPending(account: ProvisionedAccount): List<PendingDeviceRequest> {
        require(account.authenticationState == AccountSecurityProtocol.STATE_READY)
        return api.list(account)
    }

    fun approve(account: ProvisionedAccount, request: PendingDeviceRequest) {
        require(account.authenticationState == AccountSecurityProtocol.STATE_READY)
        require(request.username == account.username && Instant.parse(request.expiresAt).isAfter(Instant.now()))
        val local = vaultStore.load(account.serverUrl, account.username)
            ?: throw AccountSecurityException("local_vault_required")
        val issuerIdentity = identity.getOrCreate(account.serverUrl, account.username)
        val certificateId = UUID.randomUUID().toString()
        val issuedAt = Instant.now().truncatedTo(ChronoUnit.MILLIS)
        val certificate = JSONObject()
            .put("version", 1)
            .put("certificate_id", certificateId)
            .put("username", account.username)
            .put("issuer_device_id", account.deviceId)
            .put("issuer_signing_algorithm", issuerIdentity.algorithm)
            .put("issuer_signing_public_key_spki", issuerIdentity.publicKeySpkiBase64)
            .put("subject_device_id", request.targetDeviceId)
            .put("subject_signing_algorithm", request.signingAlgorithm)
            .put("subject_signing_fingerprint", request.signingFingerprintHex)
            .put("subject_key_agreement_algorithm", request.keyAgreementAlgorithm)
            .put("subject_key_agreement_fingerprint", request.keyAgreementFingerprintHex)
            .put("issued_at", issuedAt.toString())
            .put("expires_at", issuedAt.plus(3650, ChronoUnit.DAYS).toString())
            .toString().toByteArray(Charsets.UTF_8)
        var encrypted: DeviceProvisioningCrypto.Encrypted? = null
        var certificateSignature: ByteArray? = null
        var requestSignature: ByteArray? = null
        try {
            encrypted = crypto.encryptFor(request, account.deviceId, local.accountRootKey, local.vaultRevision)
            certificateSignature = decodeStandard(
                identity.signSha256EcdsaBase64(account.serverUrl, account.username, certificate),
            )
            val packageHash = MessageDigest.getInstance("SHA-256").digest(encrypted.blob)
            val certificateHash = MessageDigest.getInstance("SHA-256").digest(certificate)
            val canonical = listOf(
                "fedmes-device-approval-v1",
                request.id,
                account.deviceId,
                request.targetDeviceId,
                request.signingFingerprintHex.lowercase(),
                request.keyAgreementFingerprintHex.lowercase(),
                "1",
                packageHash.toHex(),
                certificateHash.toHex(),
            ).joinToString("\n").toByteArray(Charsets.UTF_8)
            try {
                requestSignature = decodeStandard(
                    identity.signSha256EcdsaBase64(account.serverUrl, account.username, canonical),
                )
            } finally { canonical.fill(0); packageHash.fill(0); certificateHash.fill(0) }
            api.approve(
                account, request.id, certificateId, certificate, certificateSignature,
                issuerIdentity.algorithm, encrypted.blob, encrypted.nonce, requestSignature,
            )
        } finally {
            local.accountRootKey.fill(0)
            certificate.fill(0)
            encrypted?.blob?.fill(0)
            encrypted?.nonce?.fill(0)
            certificateSignature?.fill(0)
            requestSignature?.fill(0)
        }
    }

    fun reject(account: ProvisionedAccount, requestId: String) = api.reject(account, requestId)

    fun restoreApproved(candidate: ProvisionedAccount): ProvisionedAccount {
        val requestId = candidate.pendingProvisioningRequestId
            ?: throw AccountSecurityException("provisioning_request_missing")
        val request = api.get(candidate, requestId)
        if (request.targetDeviceId != candidate.deviceId || request.username != candidate.username) {
            throw AccountSecurityException("provisioning_request_scope")
        }
        val pkg = api.getPackage(candidate, requestId)
        if (pkg.requestId != requestId || pkg.targetDeviceId != candidate.deviceId ||
            pkg.packageVersion != 1 || pkg.aadVersion != 1
        ) throw AccountSecurityException("provisioning_package_invalid")

        val certificate = crypto.verifyCertificate(pkg.certificatePayload, pkg.certificateSignature, pkg.signatureAlgorithm)
        if (certificate.getInt("version") != 1 || certificate.getString("certificate_id") != pkg.certificateId ||
            certificate.getString("username") != candidate.username ||
            certificate.getString("subject_device_id") != candidate.deviceId ||
            certificate.getString("issuer_device_id") != pkg.issuerDeviceId ||
            certificate.getString("subject_signing_fingerprint") != request.signingFingerprintHex ||
            certificate.getString("subject_key_agreement_fingerprint") != request.keyAgreementFingerprintHex
        ) throw AccountSecurityException("device_certificate_scope")
        val vault = securityApi.getVault(candidate)
        val recovered = crypto.decrypt(
            serverUrl = candidate.serverUrl,
            username = candidate.username,
            requestId = requestId,
            targetDeviceId = candidate.deviceId,
            encrypted = pkg.encryptedPackage,
            nonce = pkg.nonce,
            expectedVaultRevision = vault.revision,
        )
        try {
            vaultCrypto.verifyAndDecryptVault(candidate.serverUrl, candidate.username, recovered.accountRootKey, vault)
            vaultStore.savePending(
                candidate.serverUrl, candidate.username,
                LocalAccountVault(recovered.accountRootKey, vault.revision, vault.cryptoVersion),
            )
            val verifier = vaultCrypto.accessVerifier(candidate.serverUrl, candidate.username, recovered.accountRootKey, vault.revision)
            try { api.complete(candidate, requestId, vault.revision, verifier) } finally { verifier.fill(0) }
            val promoted = vaultStore.promotePending(candidate.serverUrl, candidate.username)
            promoted.accountRootKey.fill(0)
            val ready = candidate.copy(
                authenticationState = AccountSecurityProtocol.STATE_READY,
                pendingProvisioningRequestId = null,
            )
            sessionStore.save(ready)
            return ready
        } catch (error: Throwable) {
            vaultStore.discardPending(candidate.serverUrl, candidate.username)
            throw error
        } finally {
            recovered.accountRootKey.fill(0)
            pkg.encryptedPackage.fill(0); pkg.nonce.fill(0)
            pkg.certificatePayload.fill(0); pkg.certificateSignature.fill(0)
        }
    }

    private fun decodeStandard(value: String): ByteArray = Base64.decode(value, Base64.NO_WRAP)
    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
