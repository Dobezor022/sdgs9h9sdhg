package com.fedmes.app.provisioning

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class ProvisioningHttpApiTest {
    @Test
    fun `redeem uses exact endpoint and request contract`() {
        var capturedUrl = ""
        var capturedBody = ""
        val api = ProvisioningHttpApi(
            transport = JsonHttpTransport { url, body ->
                capturedUrl = url
                capturedBody = body.toString(Charsets.UTF_8)
                JsonHttpResponse(201, successResponse())
            },
            nowEpochMillis = { NOW },
        )

        val account = api.redeem(invite(), identity(), encryptionIdentity())

        assertEquals("https://family.example/api/v1/provisioning/redeem", capturedUrl)
        val request = JSONObject(capturedBody)
        assertEquals(setOf("version", "idempotency_key", "username", "token", "device", "encryption"), request.keys().asSequence().toSet())
        assertEquals(3, request.getInt("version"))
        assertEquals(43, request.getString("idempotency_key").length)
        assertEquals("ecdsa-p256-sha256", request.getJSONObject("device").getString("algorithm"))
        assertEquals("rsa-oaep-sha256", request.getJSONObject("encryption").getString("algorithm"))
        assertEquals("ZW5jcnlwdGlvbg==", request.getJSONObject("encryption").getString("public_key_spki"))
        assertEquals("grisha", account.username)
        assertEquals(DEVICE_ID, account.deviceId)
        assertEquals(SESSION_TOKEN, account.sessionToken)
        assertEquals("READY", account.authenticationState)
    }

    @Test
    fun `stable server error is mapped without response details`() {
        val api = ProvisioningHttpApi(
            transport = JsonHttpTransport { _, _ ->
                JsonHttpResponse(409, """{"error":{"code":"invitation_used"}}""")
            },
        )

        val error = assertThrows(ProvisioningException::class.java) {
            api.redeem(invite(), identity(), encryptionIdentity())
        }

        assertEquals(ProvisioningFailure.INVITATION_USED, error.failure)
    }

    @Test
    fun `unexpected success fields are rejected`() {
        val body = JSONObject(successResponse()).put("token", "leak").toString()
        val api = ProvisioningHttpApi(
            transport = JsonHttpTransport { _, _ -> JsonHttpResponse(201, body) },
            nowEpochMillis = { NOW },
        )

        val error = assertThrows(ProvisioningException::class.java) {
            api.redeem(invite(), identity(), encryptionIdentity())
        }

        assertEquals(ProvisioningFailure.INVALID_RESPONSE, error.failure)
    }

    @Test
    fun `server cannot substitute a different device fingerprint`() {
        val body = JSONObject(successResponse()).apply {
            getJSONObject("device").put("key_fingerprint", "b".repeat(64))
        }.toString()
        val api = ProvisioningHttpApi(
            transport = JsonHttpTransport { _, _ -> JsonHttpResponse(201, body) },
            nowEpochMillis = { NOW },
        )

        val error = assertThrows(ProvisioningException::class.java) {
            api.redeem(invite(), identity(), encryptionIdentity())
        }

        assertEquals(ProvisioningFailure.INVALID_RESPONSE, error.failure)
    }

    @Test
    fun `challenge and signed session use exact authentication contract`() {
        val requests = mutableListOf<Pair<String, String>>()
        val api = ProvisioningHttpApi(
            transport = JsonHttpTransport { url, body ->
                requests += url to body.toString(Charsets.UTF_8)
                if (url.endsWith("/challenge")) {
                    JsonHttpResponse(201, challengeResponse())
                } else {
                    JsonHttpResponse(201, successResponse(version = 1))
                }
            },
            nowEpochMillis = { NOW },
        )

        val challenge = api.requestSessionChallenge(
            serverUrl = "https://family.example",
            username = "grisha",
            identity = identity(),
        )
        val account = api.createSession(
            serverUrl = "https://family.example",
            username = "grisha",
            identity = identity(),
            challenge = challenge,
            signatureBase64 = SIGNATURE,
        )

        assertEquals("https://family.example/api/v1/auth/challenge", requests[0].first)
        val challengeRequest = JSONObject(requests[0].second)
        assertEquals(
            setOf("version", "username", "device", "purpose"),
            challengeRequest.keys().asSequence().toSet(),
        )
        assertEquals("session.refresh", challengeRequest.getString("purpose"))
        assertEquals("https://family.example/api/v1/auth/session", requests[1].first)
        val sessionRequest = JSONObject(requests[1].second)
        assertEquals(
            setOf("version", "username", "device_id", "challenge_id", "nonce", "purpose", "signature"),
            sessionRequest.keys().asSequence().toSet(),
        )
        assertEquals(CHALLENGE_ID, sessionRequest.getString("challenge_id"))
        assertEquals(SIGNATURE, sessionRequest.getString("signature"))
        assertEquals(DEVICE_ID, account.deviceId)
    }

    @Test
    fun `challenge audience must match normalized server authority`() {
        val wrongAudience = JSONObject(challengeResponse()).apply {
            getJSONObject("challenge").put("audience", "attacker.example")
        }.toString()
        val api = ProvisioningHttpApi(
            transport = JsonHttpTransport { _, _ -> JsonHttpResponse(201, wrongAudience) },
            nowEpochMillis = { NOW },
        )

        val error = assertThrows(ProvisioningException::class.java) {
            api.requestSessionChallenge("https://family.example", "grisha", identity())
        }

        assertEquals(ProvisioningFailure.INVALID_RESPONSE, error.failure)
    }

    private fun invite() = ProvisioningInvite(
        serverUrl = "https://family.example",
        username = "grisha",
        token = INVITATION_TOKEN,
        expiresAtEpochMillis = 1_925_000_000_000,
    )

    private fun identity() = DeviceIdentity(
        algorithm = "ecdsa-p256-sha256",
        publicKeySpkiBase64 = "dGVzdA==",
    )

    private fun encryptionIdentity() = MessageEncryptionIdentity(
        algorithm = "rsa-oaep-sha256",
        publicKeySpkiBase64 = "ZW5jcnlwdGlvbg==",
    )

    private fun successResponse(version: Int = 3): String = JSONObject()
        .put("version", version)
        .apply { if (version >= 3) put("authentication_state", "READY") }
        .put(
            "device",
            JSONObject()
                .put("id", DEVICE_ID)
                .put("username", "grisha")
                .put("key_algorithm", "ecdsa-p256-sha256")
                .put("key_fingerprint", PUBLIC_KEY_FINGERPRINT)
                .put("bound_by_invitation_id", INVITATION_ID)
                .put("bound_at", "2030-01-01T00:00:00Z"),
        )
        .put(
            "session",
            JSONObject()
                .put("id", SESSION_ID)
                .put("token", SESSION_TOKEN)
                .put("issued_at", "2030-01-01T00:00:00Z")
                .put("expires_at", "2030-01-01T01:00:00Z"),
        )
        .toString()

    private fun challengeResponse(): String = JSONObject()
        .put("version", 1)
        .put(
            "challenge",
            JSONObject()
                .put("id", CHALLENGE_ID)
                .put("device_id", DEVICE_ID)
                .put("audience", "family.example")
                .put("purpose", "session.refresh")
                .put("nonce", INVITATION_TOKEN)
                .put("expires_at", "2030-01-01T00:00:10Z"),
        )
        .toString()

    private companion object {
        const val NOW = 1_893_456_000_000L
        const val DEVICE_ID = "128d9a52-5b9a-4f4f-b441-ae2bfd68b174"
        const val INVITATION_ID = "31c5b50c-8d4c-4a16-8731-42ccac4a2360"
        const val SESSION_ID = "63572a46-9352-4379-a81c-0845f3b3ca09"
        const val CHALLENGE_ID = "4577d0a9-fb11-49c4-b6e0-3ea3e17e5cc1"
        const val INVITATION_TOKEN = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        const val SESSION_TOKEN = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        const val PUBLIC_KEY_FINGERPRINT = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        const val SIGNATURE = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
    }
}
