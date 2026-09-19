package com.fedmes.app.provisioning

import com.fedmes.app.security.DeviceIdentityStore
import com.fedmes.app.security.SessionStore
import java.io.IOException
import java.security.GeneralSecurityException

class ProvisioningCoordinator(
    private val inviteParser: ProvisioningInviteParser,
    private val deviceIdentity: DeviceIdentityStore,
    private val messageEncryptionIdentityProvider: (serverUrl: String, username: String) -> MessageEncryptionIdentity,
    private val provisioningApi: ProvisioningApi,
    private val authenticationApi: DeviceAuthenticationApi,
    private val sessionStore: SessionStore,
    private val allowInsecureHttp: Boolean,
    private val nowEpochMillis: () -> Long = System::currentTimeMillis,
) {
    fun redeem(rawQrPayload: String): AccountSummary {
        val invite = inviteParser.parse(rawQrPayload, allowInsecureHttp)
        val identity = getOrCreateIdentity(invite.serverUrl, invite.username)
        val encryptionIdentity = try {
            messageEncryptionIdentityProvider(invite.serverUrl, invite.username)
        } catch (error: GeneralSecurityException) {
            throw ProvisioningException(ProvisioningFailure.DEVICE_SECURITY, error)
        } catch (error: IllegalStateException) {
            throw ProvisioningException(ProvisioningFailure.DEVICE_SECURITY, error)
        }
        val account = try {
            provisioningApi.redeem(invite, identity, encryptionIdentity)
        } catch (error: IOException) {
            recoverConsumedInvitation(invite, identity)
                ?: throw ProvisioningException(ProvisioningFailure.NETWORK, error)
        } catch (error: ProvisioningException) {
            if (error.failure != ProvisioningFailure.INVITATION_USED) throw error
            recoverConsumedInvitation(invite, identity) ?: throw error
        }
        saveAccount(account)
        val committed = completeBootstrapIfPending(account)
        return committed.summary()
    }

    fun restoreSession(): AccountSummary? {
        val storedAccount = sessionStore.loadCandidateAccount() ?: sessionStore.loadAccount() ?: return null
        if (storedAccount.sessionExpiresAtEpochMillis > nowEpochMillis() + REFRESH_SKEW_MILLIS) {
            return storedAccount.summary()
        }
        val identity = try {
            deviceIdentity.getExisting(storedAccount.serverUrl, storedAccount.username)
        } catch (error: GeneralSecurityException) {
            throw ProvisioningException(ProvisioningFailure.DEVICE_SECURITY, error)
        } catch (error: IllegalStateException) {
            throw ProvisioningException(ProvisioningFailure.DEVICE_SECURITY, error)
        } ?: throw ProvisioningException(ProvisioningFailure.DEVICE_SECURITY)

        val refreshed = try {
            refreshSession(
                serverUrl = storedAccount.serverUrl,
                username = storedAccount.username,
                identity = identity,
                expectedDeviceId = storedAccount.deviceId,
            )
        } catch (error: IOException) {
            throw ProvisioningException(ProvisioningFailure.NETWORK, error)
        }
        saveAccount(refreshed)
        val committed = completeBootstrapIfPending(refreshed)
        return committed.summary()
    }

    private fun recoverConsumedInvitation(
        invite: ProvisioningInvite,
        identity: DeviceIdentity,
    ): ProvisionedAccount? = try {
        refreshSession(
            serverUrl = invite.serverUrl,
            username = invite.username,
            identity = identity,
            expectedDeviceId = null,
        )
    } catch (_: IOException) {
        null
    } catch (_: ProvisioningException) {
        null
    } catch (_: GeneralSecurityException) {
        null
    } catch (_: IllegalStateException) {
        null
    }

    private fun refreshSession(
        serverUrl: String,
        username: String,
        identity: DeviceIdentity,
        expectedDeviceId: String?,
    ): ProvisionedAccount {
        val challenge = authenticationApi.requestSessionChallenge(serverUrl, username, identity)
        if (expectedDeviceId != null && challenge.deviceId != expectedDeviceId) {
            throw ProvisioningException(ProvisioningFailure.DEVICE_SECURITY)
        }
        if (challenge.expiresAtEpochMillis <= nowEpochMillis()) {
            throw ProvisioningException(ProvisioningFailure.SERVER)
        }
        val canonicalPayload = DeviceAuthenticationCanonicalizer.sessionRefresh(
            audience = challenge.audience,
            username = username,
            deviceId = challenge.deviceId,
            challengeId = challenge.id,
            nonce = challenge.nonce,
        )
        val signature = try {
            deviceIdentity.signSha256EcdsaBase64(serverUrl, username, canonicalPayload)
        } finally {
            canonicalPayload.fill(0)
        }
        return authenticationApi.createSession(
            serverUrl = serverUrl,
            username = username,
            identity = identity,
            challenge = challenge,
            signatureBase64 = signature,
        )
    }

    private fun completeBootstrapIfPending(account: ProvisionedAccount): ProvisionedAccount {
        if (account.authenticationState != AUTHENTICATION_STATE_REGISTRATION_PENDING) return account
        val payload = DeviceAuthenticationCanonicalizer.bootstrapCommit(
            serverUrl = account.serverUrl,
            username = account.username,
            deviceId = account.deviceId,
            sessionId = account.sessionId,
        )
        val signature = try {
            deviceIdentity.signSha256EcdsaBase64(account.serverUrl, account.username, payload)
        } finally {
            payload.fill(0)
        }
        val committed = provisioningApi.commitBootstrap(account, signature)
        saveAccount(committed)
        return committed
    }

    private fun getOrCreateIdentity(serverUrl: String, username: String): DeviceIdentity = try {
        deviceIdentity.getOrCreate(serverUrl, username)
    } catch (error: GeneralSecurityException) {
        throw ProvisioningException(ProvisioningFailure.DEVICE_SECURITY, error)
    } catch (error: IllegalStateException) {
        throw ProvisioningException(ProvisioningFailure.DEVICE_SECURITY, error)
    }

    private fun saveAccount(account: ProvisionedAccount) {
        try {
            sessionStore.save(account)
        } catch (error: GeneralSecurityException) {
            throw ProvisioningException(ProvisioningFailure.SECURE_STORAGE, error)
        } catch (error: IllegalStateException) {
            throw ProvisioningException(ProvisioningFailure.SECURE_STORAGE, error)
        }
    }

    private fun ProvisionedAccount.summary(): AccountSummary = AccountSummary(
        serverUrl = serverUrl,
        username = username,
        deviceId = deviceId,
        sessionExpiresAtEpochMillis = sessionExpiresAtEpochMillis,
        authenticationState = authenticationState,
    )

    private companion object {
        const val REFRESH_SKEW_MILLIS = 30_000L
    }
}
