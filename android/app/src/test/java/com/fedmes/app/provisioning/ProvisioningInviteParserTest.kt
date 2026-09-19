package com.fedmes.app.provisioning

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class ProvisioningInviteParserTest {
    private val parser = ProvisioningInviteParser(nowEpochMillis = { NOW })

    @Test
    fun `valid HTTPS invitation is parsed`() {
        val invite = parser.parse(payload(), allowInsecureHttp = false)

        assertEquals("https://family.example", invite.serverUrl)
        assertEquals("grisha", invite.username)
        assertEquals(TOKEN, invite.token)
    }

    @Test
    fun `debug accepts RFC1918 HTTP server`() {
        val invite = parser.parse(payload(serverUrl = "http://192.168.1.50:8008"), true)

        assertEquals("http://192.168.1.50:8008", invite.serverUrl)
    }

    @Test
    fun `debug accepts and canonicalizes local development hosts`() {
        val localhost = parser.parse(payload(serverUrl = "http://LOCALHOST.:8008/"), true)
        val linkLocal = parser.parse(payload(serverUrl = "http://169.254.10.20:8008"), true)
        val ulaIpv6 = parser.parse(payload(serverUrl = "http://[fd00::1]:8008"), true)

        assertEquals("http://localhost:8008", localhost.serverUrl)
        assertEquals("http://169.254.10.20:8008", linkLocal.serverUrl)
        assertEquals("http://[fd00::1]:8008", ulaIpv6.serverUrl)
    }

    @Test
    fun `release rejects HTTP and debug rejects public HTTP`() {
        assertFailure(
            expected = ProvisioningFailure.INSECURE_SERVER,
            raw = payload(serverUrl = "http://192.168.1.50:8008"),
            allowInsecureHttp = false,
        )
        assertFailure(
            expected = ProvisioningFailure.INSECURE_SERVER,
            raw = payload(serverUrl = "http://203.0.113.20:8008"),
            allowInsecureHttp = true,
        )
    }

    @Test
    fun `unknown fields and padded tokens are rejected`() {
        val unknownField = JSONObject(payload()).put("admin_token", "forbidden").toString()
        assertFailure(ProvisioningFailure.INVALID_QR, unknownField)
        assertFailure(ProvisioningFailure.INVALID_QR, payload(token = "$TOKEN="))
    }

    @Test
    fun `zero port is rejected`() {
        assertFailure(ProvisioningFailure.INVALID_QR, payload(serverUrl = "https://family.example:0"))
    }

    @Test
    fun `wrong type and expired invitation have stable failures`() {
        assertFailure(ProvisioningFailure.UNSUPPORTED_QR, payload(type = "fedmes.other"))
        assertFailure(
            ProvisioningFailure.EXPIRED_QR,
            payload(expiresAt = "2029-01-01T00:00:00Z"),
        )
    }

    private fun assertFailure(
        expected: ProvisioningFailure,
        raw: String,
        allowInsecureHttp: Boolean = false,
    ) {
        val error = assertThrows(ProvisioningException::class.java) {
            parser.parse(raw, allowInsecureHttp)
        }
        assertEquals(expected, error.failure)
    }

    private fun payload(
        serverUrl: String = "https://family.example",
        token: String = TOKEN,
        type: String = "fedmes.provisioning",
        expiresAt: String = "2031-01-01T00:00:00Z",
    ): String = JSONObject()
        .put("version", 1)
        .put("type", type)
        .put("server_url", serverUrl)
        .put("username", "grisha")
        .put("token", token)
        .put("expires_at", expiresAt)
        .toString()

    private companion object {
        const val NOW = 1_893_456_000_000L
        const val TOKEN = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    }
}
