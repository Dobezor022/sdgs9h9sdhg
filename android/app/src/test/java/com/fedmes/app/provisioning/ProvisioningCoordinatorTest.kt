package com.fedmes.app.provisioning

import com.fedmes.app.security.DeviceIdentityStore
import com.fedmes.app.security.SessionStore
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import java.io.IOException

class ProvisioningCoordinatorTest {
    @Test
    fun `expired encrypted account is refreshed with existing identity`() {
        val stored = account(expiresAt = NOW - 1)
        val sessionStore = FakeSessionStore(stored)
        val identityStore = FakeIdentityStore()
        val authenticationApi = FakeAuthenticationApi(account(expiresAt = NOW + 900_000))
        val coordinator = coordinator(
            sessionStore = sessionStore,
            identityStore = identityStore,
            provisioningApi = SuccessfulProvisioningApi,
            authenticationApi = authenticationApi,
        )

        val restored = coordinator.restoreSession()

        assertNotNull(restored)
        assertEquals(NOW + 900_000, restored?.sessionExpiresAtEpochMillis)
        assertEquals(authenticationApi.result, sessionStore.saved)
        assertEquals(EXPECTED_CANONICAL, identityStore.lastSignedPayload)
    }

    @Test
    fun `pending bootstrap is committed before account becomes ready`() {
        val sessionStore = FakeSessionStore(null)
        val identityStore = FakeIdentityStore()
        val pending = account(expiresAt = NOW + 900_000).copy(
            authenticationState = AUTHENTICATION_STATE_REGISTRATION_PENDING,
            pendingProvisioningRequestId = "bootstrap-request",
        )
        val provisioningApi = RecordingProvisioningApi(pending)
        val coordinator = coordinator(
            sessionStore = sessionStore,
            identityStore = identityStore,
            provisioningApi = provisioningApi,
            authenticationApi = FakeAuthenticationApi(account(expiresAt = NOW + 900_000)),
        )

        val summary = coordinator.redeem(validQr())

        assertEquals(AUTHENTICATION_STATE_READY, summary.authenticationState)
        assertEquals(AUTHENTICATION_STATE_READY, sessionStore.saved?.authenticationState)
        assertEquals(null, sessionStore.saved?.pendingProvisioningRequestId)
        assertEquals(1, provisioningApi.commitCount)
        assertEquals(EXPECTED_BOOTSTRAP_CANONICAL, identityStore.lastSignedPayload)
    }

    @Test
    fun `lost redeem response recovers session using bound public key`() {
        val sessionStore = FakeSessionStore(null)
        val authenticationApi = FakeAuthenticationApi(account(expiresAt = NOW + 900_000))
        val coordinator = coordinator(
            sessionStore = sessionStore,
            identityStore = FakeIdentityStore(),
            provisioningApi = object : ProvisioningApi {
                override fun redeem(
                    invite: ProvisioningInvite,
                    identity: DeviceIdentity,
                    encryptionIdentity: MessageEncryptionIdentity,
                ): ProvisionedAccount = throw IOException("response lost")

                override fun commitBootstrap(
                    account: ProvisionedAccount,
                    signatureBase64: String,
                ): ProvisionedAccount = account.copy(
                    authenticationState = AUTHENTICATION_STATE_READY,
                    pendingProvisioningRequestId = null,
                )
            },
            authenticationApi = authenticationApi,
        )

        val summary = coordinator.redeem(validQr())

        assertEquals(DEVICE_ID, summary.deviceId)
        assertEquals(authenticationApi.result, sessionStore.saved)
    }

    private fun coordinator(
        sessionStore: SessionStore,
        identityStore: DeviceIdentityStore,
        provisioningApi: ProvisioningApi,
        authenticationApi: DeviceAuthenticationApi,
    ) = ProvisioningCoordinator(
        inviteParser = ProvisioningInviteParser(nowEpochMillis = { NOW }),
        deviceIdentity = identityStore,
        messageEncryptionIdentityProvider = { _, _ -> ENCRYPTION_IDENTITY },
        provisioningApi = provisioningApi,
        authenticationApi = authenticationApi,
        sessionStore = sessionStore,
        allowInsecureHttp = false,
        nowEpochMillis = { NOW },
    )

    private fun validQr(): String = """
        {"version":1,"type":"fedmes.provisioning","server_url":"https://family.example","username":"grisha","token":"$NONCE","expires_at":"2030-01-01T01:00:00Z"}
    """.trimIndent()

    private fun account(expiresAt: Long) = ProvisionedAccount(
        serverUrl = "https://family.example",
        username = "grisha",
        deviceId = DEVICE_ID,
        sessionId = "63572a46-9352-4379-a81c-0845f3b3ca09",
        sessionToken = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        sessionExpiresAtEpochMillis = expiresAt,
    )

    private class FakeSessionStore(private val loaded: ProvisionedAccount?) : SessionStore {
        var saved: ProvisionedAccount? = null

        override fun save(account: ProvisionedAccount) {
            saved = account
        }

        override fun loadAccount(): ProvisionedAccount? = loaded

        override fun clear() = Unit
    }

    private class FakeIdentityStore : DeviceIdentityStore {
        private val identity = DeviceIdentity("ecdsa-p256-sha256", "dGVzdA==")
        var lastSignedPayload = ""

        override fun getOrCreate(serverUrl: String, username: String): DeviceIdentity = identity

        override fun getExisting(serverUrl: String, username: String): DeviceIdentity = identity

        override fun signSha256EcdsaBase64(serverUrl: String, username: String, payload: ByteArray): String {
            lastSignedPayload = payload.toString(Charsets.UTF_8)
            return SIGNATURE
        }
    }

    private class FakeAuthenticationApi(val result: ProvisionedAccount) : DeviceAuthenticationApi {
        override fun requestSessionChallenge(
            serverUrl: String,
            username: String,
            identity: DeviceIdentity,
        ) = DeviceAuthenticationChallenge(
            id = CHALLENGE_ID,
            deviceId = DEVICE_ID,
            audience = "family.example",
            purpose = "session.refresh",
            nonce = NONCE,
            expiresAtEpochMillis = NOW + 10_000,
        )

        override fun createSession(
            serverUrl: String,
            username: String,
            identity: DeviceIdentity,
            challenge: DeviceAuthenticationChallenge,
            signatureBase64: String,
        ): ProvisionedAccount = result
    }


    private class RecordingProvisioningApi(
        private val redeemed: ProvisionedAccount,
    ) : ProvisioningApi {
        var commitCount = 0

        override fun redeem(
            invite: ProvisioningInvite,
            identity: DeviceIdentity,
            encryptionIdentity: MessageEncryptionIdentity,
        ): ProvisionedAccount = redeemed

        override fun commitBootstrap(
            account: ProvisionedAccount,
            signatureBase64: String,
        ): ProvisionedAccount {
            commitCount += 1
            return account.copy(
                authenticationState = AUTHENTICATION_STATE_READY,
                pendingProvisioningRequestId = null,
            )
        }
    }

    private object SuccessfulProvisioningApi : ProvisioningApi {
        override fun redeem(
            invite: ProvisioningInvite,
            identity: DeviceIdentity,
            encryptionIdentity: MessageEncryptionIdentity,
        ): ProvisionedAccount = error("Not used")

        override fun commitBootstrap(
            account: ProvisionedAccount,
            signatureBase64: String,
        ): ProvisionedAccount = account.copy(
            authenticationState = AUTHENTICATION_STATE_READY,
            pendingProvisioningRequestId = null,
        )
    }

    private companion object {
        val ENCRYPTION_IDENTITY = MessageEncryptionIdentity(
            algorithm = "rsa-oaep-sha256",
            publicKeySpkiBase64 = "ZW5jcnlwdGlvbg==",
        )
        const val NOW = 1_893_456_000_000L
        const val DEVICE_ID = "128d9a52-5b9a-4f4f-b441-ae2bfd68b174"
        const val CHALLENGE_ID = "4577d0a9-fb11-49c4-b6e0-3ea3e17e5cc1"
        const val NONCE = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        const val SIGNATURE = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
        const val EXPECTED_CANONICAL = "fedmes-device-auth-v1\nfamily.example\ngrisha\n$DEVICE_ID\n$CHALLENGE_ID\nsession.refresh\n$NONCE"
        const val EXPECTED_BOOTSTRAP_CANONICAL = "fedmes-bootstrap-commit-v1\nhttps://family.example\ngrisha\n$DEVICE_ID\n63572a46-9352-4379-a81c-0845f3b3ca09"
    }
}
