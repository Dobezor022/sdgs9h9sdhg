package com.fedmes.app.provisioning

import org.json.JSONException
import org.json.JSONObject
import java.net.URI
import java.net.URISyntaxException
import java.util.Locale

class ProvisioningInviteParser(
    private val nowEpochMillis: () -> Long = System::currentTimeMillis,
) {
    fun parse(rawPayload: String, allowInsecureHttp: Boolean): ProvisioningInvite {
        if (rawPayload.length !in MIN_QR_PAYLOAD_LENGTH..MAX_QR_PAYLOAD_LENGTH) {
            throw ProvisioningException(ProvisioningFailure.INVALID_QR)
        }
        val root = try {
            JSONObject(rawPayload)
        } catch (error: JSONException) {
            throw ProvisioningException(ProvisioningFailure.INVALID_QR, error)
        }
        requireExactKeys(root, REQUIRED_KEYS)

        val version = root.exactLong("version")
        val type = root.exactString("type")
        if (version != PROTOCOL_VERSION || type != INVITATION_TYPE) {
            throw ProvisioningException(ProvisioningFailure.UNSUPPORTED_QR)
        }

        val username = root.exactString("username")
        if (username !in FIXED_USERS) {
            throw ProvisioningException(ProvisioningFailure.INVALID_USER)
        }

        val token = root.exactString("token")
        if (!isValidOpaqueToken(token)) {
            throw ProvisioningException(ProvisioningFailure.INVALID_QR)
        }

        val expiresAt = ProtocolTime.parseRfc3339(root.exactString("expires_at"))
            ?: throw ProvisioningException(ProvisioningFailure.INVALID_QR)
        if (expiresAt <= nowEpochMillis()) {
            throw ProvisioningException(ProvisioningFailure.EXPIRED_QR)
        }

        return ProvisioningInvite(
            serverUrl = validateServerUrl(
                rawUrl = root.exactString("server_url"),
                allowInsecureHttp = allowInsecureHttp,
            ),
            username = username,
            token = token,
            expiresAtEpochMillis = expiresAt,
        )
    }

    private fun validateServerUrl(rawUrl: String, allowInsecureHttp: Boolean): String {
        if (rawUrl.isBlank() || rawUrl != rawUrl.trim() || rawUrl.length > MAX_SERVER_URL_LENGTH) {
            throw ProvisioningException(ProvisioningFailure.INVALID_QR)
        }
        val uri = try {
            URI(rawUrl)
        } catch (error: URISyntaxException) {
            throw ProvisioningException(ProvisioningFailure.INVALID_QR, error)
        }
        val scheme = uri.scheme?.lowercase(Locale.US)
            ?: throw ProvisioningException(ProvisioningFailure.INVALID_QR)
        if (scheme != HTTPS_SCHEME && !(allowInsecureHttp && scheme == HTTP_SCHEME)) {
            throw ProvisioningException(ProvisioningFailure.INSECURE_SERVER)
        }
        if (
            uri.isOpaque ||
            uri.host.isNullOrBlank() ||
            uri.rawUserInfo != null ||
            uri.rawQuery != null ||
            uri.rawFragment != null ||
            (uri.rawPath.isNotEmpty() && uri.rawPath != "/") ||
            uri.rawAuthority?.endsWith(':') == true ||
            uri.port == 0 ||
            uri.port > MAX_PORT
        ) {
            throw ProvisioningException(ProvisioningFailure.INVALID_QR)
        }
        val canonicalHost = uri.host.lowercase(Locale.US)
            .removePrefix("[")
            .removeSuffix("]")
            .removeSuffix(".")
        if (scheme == HTTP_SCHEME && !isLocalDevelopmentHost(canonicalHost)) {
            throw ProvisioningException(ProvisioningFailure.INSECURE_SERVER)
        }
        return URI(
            scheme,
            null,
            canonicalHost,
            uri.port,
            null,
            null,
            null,
        ).toASCIIString()
    }

    private fun isLocalDevelopmentHost(rawHost: String): Boolean {
        val host = rawHost.lowercase(Locale.US).removePrefix("[").removeSuffix("]")
        if (host == "localhost" || host == "::1") return true
        if (host.startsWith("fc") || host.startsWith("fd") || host.startsWith("fe8") || host.startsWith("fe9") || host.startsWith("fea") || host.startsWith("feb")) {
            return host.contains(':')
        }
        val octets = host.split('.')
        if (octets.size != IPV4_OCTET_COUNT) return false
        val numbers = octets.map { it.toIntOrNull() ?: return false }
        if (numbers.any { it !in IPV4_OCTET_RANGE }) return false
        return numbers[0] == 10 ||
            numbers[0] == 127 ||
            (numbers[0] == 169 && numbers[1] == 254) ||
            (numbers[0] == 172 && numbers[1] in 16..31) ||
            (numbers[0] == 192 && numbers[1] == 168)
    }

    private fun requireExactKeys(root: JSONObject, expected: Set<String>) {
        val actual = root.keys().asSequence().toSet()
        if (actual != expected) {
            throw ProvisioningException(ProvisioningFailure.INVALID_QR)
        }
    }

    private fun JSONObject.exactString(key: String): String {
        val value = try {
            get(key)
        } catch (error: JSONException) {
            throw ProvisioningException(ProvisioningFailure.INVALID_QR, error)
        }
        return (value as? String)
            ?.takeIf(String::isNotBlank)
            ?: throw ProvisioningException(ProvisioningFailure.INVALID_QR)
    }

    private fun JSONObject.exactLong(key: String): Long {
        val value = try {
            get(key)
        } catch (error: JSONException) {
            throw ProvisioningException(ProvisioningFailure.INVALID_QR, error)
        }
        return when (value) {
            is Int -> value.toLong()
            is Long -> value
            else -> throw ProvisioningException(ProvisioningFailure.INVALID_QR)
        }
    }

    private fun isValidOpaqueToken(token: String): Boolean {
        if (token.length !in MIN_TOKEN_CHARACTERS..MAX_TOKEN_CHARACTERS) return false
        if (!BASE64_URL_PATTERN.matches(token)) return false
        if (token.length % 4 == 1) return false
        val decodedBytes = (token.length * BITS_PER_BASE64_CHARACTER) / BITS_PER_BYTE
        return decodedBytes in MIN_TOKEN_BYTES..MAX_TOKEN_BYTES
    }

    private companion object {
        const val PROTOCOL_VERSION = 1L
        const val INVITATION_TYPE = "fedmes.provisioning"
        const val HTTPS_SCHEME = "https"
        const val HTTP_SCHEME = "http"
        const val MAX_PORT = 65_535
        const val MAX_SERVER_URL_LENGTH = 2_048
        const val MIN_QR_PAYLOAD_LENGTH = 2
        const val MAX_QR_PAYLOAD_LENGTH = 4_096
        const val MIN_TOKEN_BYTES = 32
        const val MAX_TOKEN_BYTES = 64
        const val MIN_TOKEN_CHARACTERS = 43
        const val MAX_TOKEN_CHARACTERS = 86
        const val BITS_PER_BASE64_CHARACTER = 6
        const val BITS_PER_BYTE = 8
        const val IPV4_OCTET_COUNT = 4
        val IPV4_OCTET_RANGE = 0..255
        val BASE64_URL_PATTERN = Regex("^[A-Za-z0-9_-]+$")
        val REQUIRED_KEYS = setOf(
            "version",
            "type",
            "server_url",
            "username",
            "token",
            "expires_at",
        )
        val FIXED_USERS = setOf("grisha", "papa", "mama", "yura", "vasya")
    }
}
