package com.fedmes.app.accountsecurity

import android.util.Base64
import com.fedmes.app.cryptocore.FedMesCryptoCore
import com.fedmes.app.provisioning.ProvisionedAccount
import com.fedmes.app.security.AndroidDeviceIdentity
import com.fedmes.app.security.AndroidProvisioningKeyStore
import com.fedmes.app.security.SessionStore
import java.security.MessageDigest
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** Completes RFC 9807 OPAQUE while keeping history recovery a separate step. */
class OpaqueAuthCoordinator internal constructor(
    private val sessionStore: SessionStore,
    private val core: FedMesCryptoCore,
    private val api: OpaqueAuthHttpApi,
    private val identity: AndroidDeviceIdentity,
    private val provisioningKeys: AndroidProvisioningKeyStore,
    private val securityApi: AccountSecurityHttpApi,
    private val vaultCrypto: AccountVaultCrypto,
    private val vaultStore: AndroidAccountVaultStore,
    private val opaqueRecoveryCrypto: OpaqueRecoveryCrypto,
) {
    fun enroll(account: ProvisionedAccount, password: CharArray) = register(account, password, false)
    fun changePassword(account: ProvisionedAccount, password: CharArray) = register(account, password, true)

    private fun register(account: ProvisionedAccount, password: CharArray, passwordChange: Boolean) {
        require(account.authenticationState == AccountSecurityProtocol.STATE_READY)
        val local = vaultStore.load(account.serverUrl, account.username)
            ?: throw AccountSecurityException("local_vault_required")
        var handle: String? = null
        var exportKey: ByteArray? = null
        try {
            val started = core.opaqueRegistrationStart(password)
            handle = started.handle
            val server = api.registrationStart(account, started.message, passwordChange)
            if (server.suite != started.suite) throw AccountSecurityException("opaque_suite_mismatch")
            val finished = core.opaqueRegistrationFinish(started.handle, server.message, account.username, account.serverUrl)
            if (finished.suite != started.suite) throw AccountSecurityException("opaque_suite_mismatch")
            exportKey = decodeRawUrl(finished.exportKey, 32, 128)
            api.registrationFinish(account, server.attemptId, finished.message, passwordChange)
            val encrypted = opaqueRecoveryCrypto.encrypt(
                serverUrl = account.serverUrl,
                username = account.username,
                exportKey = exportKey,
                accountRootKey = local.accountRootKey,
                vaultRevision = local.vaultRevision,
            )
            api.putRecoveryPackage(account, OpaqueAuthHttpApi.OpaqueRecoveryPackage(
                vaultRevision = encrypted.vaultRevision,
                packageVersion = encrypted.packageVersion,
                nonce = encrypted.nonce,
                ciphertext = encrypted.ciphertext,
                ciphertextSha256Hex = encrypted.ciphertextHash.joinToString("") { "%02x".format(it.toInt() and 0xff) },
            ))
        } finally {
            handle?.let { runCatching { core.opaqueCancel(it) } }
            exportKey?.fill(0)
            local.accountRootKey.fill(0)
            password.fill('\u0000')
        }
    }

    /**
     * Password authentication creates AUTHENTICATED_NO_KEYS first. The candidate
     * session is committed only after an OPAQUE-protected ARK package and the
     * encrypted vault have both been decrypted and verified locally.
     */
    fun loginAndRestore(
        serverUrl: String,
        username: String,
        password: CharArray,
        displayName: String,
    ): ProvisionedAccount {
        val old = sessionStore.loadAccount()
        val deviceId = UUID.randomUUID().toString()
        val signing = identity.getOrCreate(serverUrl, username)
        val agreement = provisioningKeys.getOrCreate(serverUrl, username)
        var handle: String? = null
        var sessionKey: ByteArray? = null
        var exportKey: ByteArray? = null
        var candidate: ProvisionedAccount? = null
        try {
            val started = core.opaqueLoginStart(password)
            handle = started.handle
            val server = api.loginStart(
                serverUrl, username, started.message, deviceId, displayName, "android",
                signing.algorithm, signing.publicKeySpkiBase64,
                agreement.algorithm, agreement.publicKeySpkiBase64,
            )
            if (server.suite != started.suite || server.serverIdentity.isNullOrBlank()) {
                throw AccountSecurityException("opaque_suite_mismatch")
            }
            val finished = core.opaqueLoginFinish(started.handle, server.message, username, server.serverIdentity)
            sessionKey = finished.sessionKey?.let { decodeRawUrl(it, 32, 128) }
                ?: throw AccountSecurityException("opaque_session_key_missing")
            exportKey = decodeRawUrl(finished.exportKey, 32, 128)
            val login = api.loginFinish(serverUrl, server.attemptId, finished.message)
            if (login.username != username || login.deviceId != deviceId ||
                login.authenticationState != AccountSecurityProtocol.STATE_AUTHENTICATED_NO_KEYS
            ) throw AccountSecurityException("invalid_response")
            verifyServerProof(sessionKey, server.attemptId, login)
            candidate = ProvisionedAccount(
                serverUrl = serverUrl,
                username = username,
                deviceId = login.deviceId,
                sessionId = login.sessionId,
                sessionToken = login.sessionToken,
                sessionExpiresAtEpochMillis = login.expiresAtEpochMillis,
                authenticationState = login.authenticationState,
                pendingProvisioningRequestId = login.provisioningRequestId,
            )

            val opaquePackage = api.getRecoveryPackage(candidate)
            val expectedHash = opaquePackage.ciphertextSha256Hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            val rootKey = opaqueRecoveryCrypto.decrypt(serverUrl, username, exportKey, OpaqueRecoveryEnvelope(
                vaultRevision = opaquePackage.vaultRevision,
                packageVersion = opaquePackage.packageVersion,
                nonce = opaquePackage.nonce,
                ciphertext = opaquePackage.ciphertext,
                ciphertextHash = expectedHash,
            ))
            expectedHash.fill(0)
            try {
                val vault = securityApi.getVault(candidate)
                if (vault.revision != opaquePackage.vaultRevision) throw AccountSecurityException("vault_revision_mismatch")
                vaultCrypto.verifyAndDecryptVault(serverUrl, username, rootKey, vault)
                vaultStore.savePending(serverUrl, username, LocalAccountVault(rootKey, vault.revision, vault.cryptoVersion))
                val verifier = vaultCrypto.accessVerifier(serverUrl, username, rootKey, vault.revision)
                try { securityApi.completeRecovery(candidate, vault.revision, verifier) } finally { verifier.fill(0) }
                val promoted = vaultStore.promotePending(serverUrl, username)
                promoted.accountRootKey.fill(0)
                val ready = candidate.copy(authenticationState = AccountSecurityProtocol.STATE_READY, pendingProvisioningRequestId = null)
                sessionStore.save(ready)
                return ready
            } finally { rootKey.fill(0) }
        } catch (error: Throwable) {
            candidate?.let { vaultStore.discardPending(it.serverUrl, it.username) }
            if (old != null) sessionStore.save(old)
            throw error
        } finally {
            handle?.let { runCatching { core.opaqueCancel(it) } }
            sessionKey?.fill(0)
            exportKey?.fill(0)
            password.fill('\u0000')
        }
    }

    private fun verifyServerProof(sessionKey: ByteArray, attemptId: String, login: OpaqueAuthHttpApi.LoginResult) {
        val canonical = "fedmes-opaque-server-proof-v1\n$attemptId\n${login.deviceId}\n${login.sessionId}"
            .toByteArray(Charsets.UTF_8)
        val expected = try {
            Mac.getInstance("HmacSHA256").run {
                init(SecretKeySpec(sessionKey, "HmacSHA256"))
                doFinal(canonical)
            }
        } finally { canonical.fill(0) }
        val actual = decodeRawUrl(login.serverProof, 32, 32)
        try {
            if (!MessageDigest.isEqual(expected, actual)) throw AccountSecurityException("opaque_server_proof_invalid")
        } finally { expected.fill(0); actual.fill(0) }
    }

    private fun decodeRawUrl(value: String, minimum: Int, maximum: Int): ByteArray {
        val bytes = try { Base64.decode(value, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING) }
        catch (error: Exception) { throw AccountSecurityException("invalid_response", error) }
        if (bytes.size !in minimum..maximum) { bytes.fill(0); throw AccountSecurityException("invalid_response") }
        return bytes
    }
}
