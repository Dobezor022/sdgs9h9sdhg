package com.fedmes.app.provisioning

import java.util.Base64
import org.json.JSONException
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.util.Locale
import java.util.UUID

interface ProvisioningApi {
    @Throws(IOException::class, ProvisioningException::class)
    fun redeem(
        invite: ProvisioningInvite,
        identity: DeviceIdentity,
        encryptionIdentity: MessageEncryptionIdentity,
    ): ProvisionedAccount

    @Throws(IOException::class, ProvisioningException::class)
    fun commitBootstrap(account: ProvisionedAccount, signatureBase64: String): ProvisionedAccount
}

interface DeviceAuthenticationApi {
    @Throws(IOException::class, ProvisioningException::class)
    fun requestSessionChallenge(
        serverUrl: String,
        username: String,
        identity: DeviceIdentity,
    ): DeviceAuthenticationChallenge

    @Throws(IOException::class, ProvisioningException::class)
    fun createSession(
        serverUrl: String,
        username: String,
        identity: DeviceIdentity,
        challenge: DeviceAuthenticationChallenge,
        signatureBase64: String,
    ): ProvisionedAccount
}

data class JsonHttpResponse(
    val statusCode: Int,
    val body: String,
)

fun interface JsonHttpTransport {
    @Throws(IOException::class)
    fun post(url: String, body: ByteArray): JsonHttpResponse
}

class UrlConnectionJsonHttpTransport : JsonHttpTransport {
    override fun post(url: String, body: ByteArray): JsonHttpResponse {
        val connection = URL(url).openConnection() as HttpURLConnection
        try {
            connection.requestMethod = "POST"
            connection.instanceFollowRedirects = false
            connection.connectTimeout = CONNECT_TIMEOUT_MILLIS
            connection.readTimeout = READ_TIMEOUT_MILLIS
            connection.doOutput = true
            connection.setFixedLengthStreamingMode(body.size)
            connection.setRequestProperty("Accept", JSON_CONTENT_TYPE)
            connection.setRequestProperty("Content-Type", JSON_CONTENT_TYPE)
            connection.outputStream.use { output -> output.write(body) }

            val statusCode = connection.responseCode
            val stream = if (statusCode in SUCCESS_STATUS_RANGE) {
                connection.inputStream
            } else {
                connection.errorStream
            }
            val responseBody = stream?.use(::readBoundedUtf8).orEmpty()
            return JsonHttpResponse(statusCode = statusCode, body = responseBody)
        } finally {
            connection.disconnect()
        }
    }

    private fun readBoundedUtf8(input: java.io.InputStream): String {
        val buffer = ByteArray(MAX_RESPONSE_BYTES + 1)
        var total = 0
        return try {
            while (true) {
                val count = input.read(buffer, total, buffer.size - total)
                if (count == -1) break
                total += count
                if (total > MAX_RESPONSE_BYTES) {
                    throw IOException("Provisioning response is too large")
                }
            }
            String(buffer, offset = 0, length = total, charset = Charsets.UTF_8)
        } finally {
            buffer.fill(0)
        }
    }

    private companion object {
        const val CONNECT_TIMEOUT_MILLIS = 10_000
        const val READ_TIMEOUT_MILLIS = 15_000
        const val MAX_RESPONSE_BYTES = 64 * 1_024
        const val JSON_CONTENT_TYPE = "application/json"
        val SUCCESS_STATUS_RANGE = 200..299
    }
}

class ProvisioningHttpApi(
    private val transport: JsonHttpTransport,
    private val nowEpochMillis: () -> Long = System::currentTimeMillis,
) : ProvisioningApi, DeviceAuthenticationApi {
    override fun redeem(
        invite: ProvisioningInvite,
        identity: DeviceIdentity,
        encryptionIdentity: MessageEncryptionIdentity,
    ): ProvisionedAccount {
        val idempotencyKey = registrationIdempotencyKey(invite, identity, encryptionIdentity)
        val requestBytes = JSONObject()
            .put("version", PROVISIONING_PROTOCOL_VERSION)
            .put("idempotency_key", idempotencyKey)
            .put("username", invite.username)
            .put("token", invite.token)
            .put(
                "device",
                JSONObject()
                    .put("algorithm", identity.algorithm)
                    .put("public_key_spki", identity.publicKeySpkiBase64),
            )
            .put(
                "encryption",
                JSONObject()
                    .put("algorithm", encryptionIdentity.algorithm)
                    .put("public_key_spki", encryptionIdentity.publicKeySpkiBase64),
            )
            .toString()
            .toByteArray(Charsets.UTF_8)
        val response = try {
            transport.post(
                url = invite.serverUrl + REDEEM_PATH,
                body = requestBytes,
            )
        } finally {
            requestBytes.fill(0)
        }
        if (response.statusCode != CREATED_STATUS) {
            throw ProvisioningException(mapServerFailure(response.statusCode, response.body))
        }
        return parseSuccessfulSessionResponse(
            serverUrl = invite.serverUrl,
            username = invite.username,
            identity = identity,
            expectedDeviceId = null,
            expectedVersion = PROVISIONING_PROTOCOL_VERSION,
            body = response.body,
        )
    }

    override fun commitBootstrap(account: ProvisionedAccount, signatureBase64: String): ProvisionedAccount {
        val requestBytes = JSONObject()
            .put("version", 1)
            .put("signature", signatureBase64)
            .toString()
            .toByteArray(Charsets.UTF_8)
        val connection = URL(account.serverUrl + BOOTSTRAP_COMMIT_PATH).openConnection() as HttpURLConnection
        val response = try {
            connection.requestMethod = "POST"
            connection.instanceFollowRedirects = false
            connection.connectTimeout = 10_000
            connection.readTimeout = 15_000
            connection.doOutput = true
            connection.setFixedLengthStreamingMode(requestBytes.size)
            connection.setRequestProperty("Accept", "application/json")
            connection.setRequestProperty("Content-Type", "application/json")
            connection.setRequestProperty("Authorization", "Bearer ${account.sessionToken}")
            connection.outputStream.use { it.write(requestBytes) }
            val status = connection.responseCode
            val responseStream = if (status in 200..299) connection.inputStream else connection.errorStream
            val body = responseStream?.use(::readProvisioningResponseBounded).orEmpty()
            JsonHttpResponse(status, body)
        } finally {
            requestBytes.fill(0)
            connection.disconnect()
        }
        if (response.statusCode !in 200..299) {
            throw ProvisioningException(mapServerFailure(response.statusCode, response.body))
        }
        val root = try { JSONObject(response.body) } catch (_: JSONException) { invalidResponse() }
        if (root.optInt("version") != 1 || root.optString("authentication_state") != AUTHENTICATION_STATE_READY) invalidResponse()
        return account.copy(authenticationState = AUTHENTICATION_STATE_READY, pendingProvisioningRequestId = null)
    }

    override fun requestSessionChallenge(
        serverUrl: String,
        username: String,
        identity: DeviceIdentity,
    ): DeviceAuthenticationChallenge {
        val requestBytes = JSONObject()
            .put("version", AUTH_PROTOCOL_VERSION)
            .put("username", username)
            .put(
                "device",
                JSONObject()
                    .put("algorithm", identity.algorithm)
                    .put("public_key_spki", identity.publicKeySpkiBase64),
            )
            .put("purpose", DeviceAuthenticationCanonicalizer.SESSION_REFRESH_PURPOSE)
            .toString()
            .toByteArray(Charsets.UTF_8)
        val response = try {
            transport.post(serverUrl + CHALLENGE_PATH, requestBytes)
        } finally {
            requestBytes.fill(0)
        }
        if (response.statusCode != CREATED_STATUS) {
            throw ProvisioningException(mapServerFailure(response.statusCode, response.body))
        }
        return parseChallengeResponse(
            serverUrl = serverUrl,
            body = response.body,
        )
    }

    override fun createSession(
        serverUrl: String,
        username: String,
        identity: DeviceIdentity,
        challenge: DeviceAuthenticationChallenge,
        signatureBase64: String,
    ): ProvisionedAccount {
        if (
            challenge.audience != expectedAudience(serverUrl) ||
            challenge.purpose != DeviceAuthenticationCanonicalizer.SESSION_REFRESH_PURPOSE ||
            !CHALLENGE_NONCE_PATTERN.matches(challenge.nonce) ||
            challenge.expiresAtEpochMillis <= nowEpochMillis()
        ) {
            throw ProvisioningException(ProvisioningFailure.INVALID_RESPONSE)
        }
        if (!STANDARD_BASE64_PATTERN.matches(signatureBase64) || signatureBase64.length % BASE64_QUANTUM != 0) {
            throw ProvisioningException(ProvisioningFailure.DEVICE_SECURITY)
        }
        val requestBytes = JSONObject()
            .put("version", AUTH_PROTOCOL_VERSION)
            .put("username", username)
            .put("device_id", challenge.deviceId)
            .put("challenge_id", challenge.id)
            .put("nonce", challenge.nonce)
            .put("purpose", DeviceAuthenticationCanonicalizer.SESSION_REFRESH_PURPOSE)
            .put("signature", signatureBase64)
            .toString()
            .toByteArray(Charsets.UTF_8)
        val response = try {
            transport.post(serverUrl + SESSION_PATH, requestBytes)
        } finally {
            requestBytes.fill(0)
        }
        if (response.statusCode != CREATED_STATUS) {
            throw ProvisioningException(mapServerFailure(response.statusCode, response.body))
        }
        return parseSuccessfulSessionResponse(
            serverUrl = serverUrl,
            username = username,
            identity = identity,
            expectedDeviceId = challenge.deviceId,
            expectedVersion = AUTH_PROTOCOL_VERSION,
            body = response.body,
        )
    }

    private fun readProvisioningResponseBounded(input: java.io.InputStream): String {
        val buffer = ByteArray(64 * 1024 + 1)
        var total = 0
        return try {
            while (true) {
                val count = input.read(buffer, total, buffer.size - total)
                if (count == -1) break
                total += count
                if (total > 64 * 1024) throw IOException("Provisioning response is too large")
            }
            String(buffer, 0, total, Charsets.UTF_8)
        } finally {
            buffer.fill(0)
        }
    }

    private fun parseChallengeResponse(
        serverUrl: String,
        body: String,
    ): DeviceAuthenticationChallenge {
        try {
            val root = JSONObject(body)
            root.requireExactKeys(setOf("version", "challenge"))
            if (root.exactLong("version") != AUTH_PROTOCOL_VERSION.toLong()) invalidResponse()
            val challenge = root.getJSONObject("challenge")
            challenge.requireExactKeys(
                setOf("id", "device_id", "audience", "purpose", "nonce", "expires_at"),
            )
            val challengeId = challenge.exactString("id").requireCanonicalUuid()
            val deviceId = challenge.exactString("device_id").requireCanonicalUuid()
            val audience = challenge.exactString("audience")
            if (audience != expectedAudience(serverUrl)) invalidResponse()
            val purpose = challenge.exactString("purpose")
            if (purpose != DeviceAuthenticationCanonicalizer.SESSION_REFRESH_PURPOSE) invalidResponse()
            val nonce = challenge.exactString("nonce")
            if (!CHALLENGE_NONCE_PATTERN.matches(nonce)) invalidResponse()
            val expiresAt = ProtocolTime.parseRfc3339(challenge.exactString("expires_at"))
                ?: invalidResponse()
            val now = nowEpochMillis()
            if (expiresAt <= now || expiresAt > now + MAX_CHALLENGE_LIFETIME_MILLIS) invalidResponse()
            return DeviceAuthenticationChallenge(
                id = challengeId,
                deviceId = deviceId,
                audience = audience,
                purpose = purpose,
                nonce = nonce,
                expiresAtEpochMillis = expiresAt,
            )
        } catch (error: ProvisioningException) {
            throw error
        } catch (error: JSONException) {
            throw ProvisioningException(ProvisioningFailure.INVALID_RESPONSE, error)
        } catch (error: IllegalArgumentException) {
            throw ProvisioningException(ProvisioningFailure.INVALID_RESPONSE, error)
        }
    }

    private fun parseSuccessfulSessionResponse(
        serverUrl: String,
        username: String,
        identity: DeviceIdentity,
        expectedDeviceId: String?,
        expectedVersion: Int,
        body: String,
    ): ProvisionedAccount {
        try {
            val root = JSONObject(body)
            val responseKeys = if (expectedVersion >= 3) {
                setOf("version", "device", "session", "authentication_state")
            } else {
                setOf("version", "device", "session")
            }
            root.requireExactKeys(responseKeys)
            if (root.exactLong("version") != expectedVersion.toLong()) invalidResponse()
            val authenticationState = if (expectedVersion >= 3) {
                root.exactString("authentication_state").also { state ->
                    if (state !in AUTHENTICATION_STATES) invalidResponse()
                }
            } else {
                AUTHENTICATION_STATE_READY
            }

            val device = root.getJSONObject("device")
            device.requireExactKeys(
                setOf(
                    "id",
                    "username",
                    "key_algorithm",
                    "key_fingerprint",
                    "bound_by_invitation_id",
                    "bound_at",
                ),
            )
            val deviceId = device.exactString("id").requireCanonicalUuid()
            if (expectedDeviceId != null && deviceId != expectedDeviceId) invalidResponse()
            if (device.exactString("username") != username) invalidResponse()
            if (device.exactString("key_algorithm") != identity.algorithm) invalidResponse()
            val returnedFingerprint = device.exactString("key_fingerprint")
            if (!FINGERPRINT_PATTERN.matches(returnedFingerprint)) invalidResponse()
            if (returnedFingerprint.lowercase(Locale.US) != identity.spkiSha256Fingerprint()) {
                invalidResponse()
            }
            device.exactString("bound_by_invitation_id").requireCanonicalUuid()
            ProtocolTime.parseRfc3339(device.exactString("bound_at")) ?: invalidResponse()

            val session = root.getJSONObject("session")
            session.requireExactKeys(setOf("id", "token", "issued_at", "expires_at"))
            val sessionId = session.exactString("id").requireCanonicalUuid()
            val sessionToken = session.exactString("token")
            if (!SESSION_TOKEN_PATTERN.matches(sessionToken)) invalidResponse()
            val issuedAt = ProtocolTime.parseRfc3339(session.exactString("issued_at"))
                ?: invalidResponse()
            val expiresAt = ProtocolTime.parseRfc3339(session.exactString("expires_at"))
                ?: invalidResponse()
            if (expiresAt <= issuedAt || expiresAt <= nowEpochMillis()) invalidResponse()

            return ProvisionedAccount(
                serverUrl = serverUrl,
                username = username,
                deviceId = deviceId,
                sessionId = sessionId,
                sessionToken = sessionToken,
                sessionExpiresAtEpochMillis = expiresAt,
                authenticationState = authenticationState,
            )
        } catch (error: ProvisioningException) {
            throw error
        } catch (error: JSONException) {
            throw ProvisioningException(ProvisioningFailure.INVALID_RESPONSE, error)
        } catch (error: IllegalArgumentException) {
            throw ProvisioningException(ProvisioningFailure.INVALID_RESPONSE, error)
        }
    }

    private fun registrationIdempotencyKey(
        invite: ProvisioningInvite,
        identity: DeviceIdentity,
        encryptionIdentity: MessageEncryptionIdentity,
    ): String {
        val digest = MessageDigest.getInstance("SHA-256")
        fun update(value: String) {
            val bytes = value.toByteArray(Charsets.UTF_8)
            try {
                digest.update(bytes)
                digest.update(0)
            } finally {
                bytes.fill(0)
            }
        }
        update("fedmes-registration-idempotency-v1")
        update(invite.serverUrl)
        update(invite.username)
        update(invite.token)
        update(identity.algorithm)
        update(identity.publicKeySpkiBase64)
        update(encryptionIdentity.algorithm)
        update(encryptionIdentity.publicKeySpkiBase64)
        val result = digest.digest()
        return try {
            Base64.getUrlEncoder().withoutPadding().encodeToString(result)
        } finally {
            result.fill(0)
        }
    }

    private fun expectedAudience(serverUrl: String): String =
        try {
            java.net.URI(serverUrl).rawAuthority ?: invalidResponse()
        } catch (error: java.net.URISyntaxException) {
            throw ProvisioningException(ProvisioningFailure.INVALID_RESPONSE, error)
        }

    private fun mapServerFailure(statusCode: Int, body: String): ProvisioningFailure {
        val code = try {
            val root = JSONObject(body)
            root.optJSONObject("error")?.optString("code")
                ?.takeIf(String::isNotBlank)
                ?: root.optString("code").takeIf(String::isNotBlank)
        } catch (_: JSONException) {
            null
        }
        return when (code) {
            "invitation_expired" -> ProvisioningFailure.EXPIRED_QR
            "invitation_used" -> ProvisioningFailure.INVITATION_USED
            "unknown_user", "invitation_user_mismatch" -> ProvisioningFailure.INVALID_USER
            "invalid_invitation_token",
            "invitation_not_found",
            "invalid_device_public_key",
            "unknown_device",
            "challenge_not_found",
            "challenge_expired",
            "challenge_used",
            "challenge_context_mismatch",
            -> ProvisioningFailure.SESSION_RECOVERY
            "invalid_device_signature", "invalid_message_encryption_key" -> ProvisioningFailure.DEVICE_SECURITY
            else -> if (statusCode == HTTP_TOO_MANY_REQUESTS || statusCode >= SERVER_ERROR_START) {
                ProvisioningFailure.SERVER
            } else {
                ProvisioningFailure.INVITATION_REJECTED
            }
        }
    }

    private fun JSONObject.requireExactKeys(expected: Set<String>) {
        if (keys().asSequence().toSet() != expected) invalidResponse()
    }

    private fun JSONObject.exactString(key: String): String {
        val value = get(key)
        return (value as? String)?.takeIf(String::isNotBlank) ?: invalidResponse()
    }

    private fun JSONObject.exactLong(key: String): Long = when (val value = get(key)) {
        is Int -> value.toLong()
        is Long -> value
        else -> invalidResponse()
    }

    private fun String.requireCanonicalUuid(): String {
        val normalized = lowercase(Locale.US)
        if (UUID.fromString(this).toString() != normalized) invalidResponse()
        return normalized
    }

    private fun DeviceIdentity.spkiSha256Fingerprint(): String {
        val decoded = decodeStandardBase64(publicKeySpkiBase64)
        return try {
            MessageDigest.getInstance("SHA-256")
                .digest(decoded)
                .joinToString(separator = "") { byte -> "%02x".format(Locale.US, byte.toInt() and 0xff) }
        } finally {
            decoded.fill(0)
        }
    }

    private fun decodeStandardBase64(value: String): ByteArray {
        if (value.isEmpty() || value.length % BASE64_QUANTUM != 0) invalidResponse()
        val padding = when {
            value.endsWith("==") -> 2
            value.endsWith('=') -> 1
            else -> 0
        }
        val output = ByteArray(value.length / BASE64_QUANTUM * 3 - padding)
        var outputIndex = 0
        for (index in value.indices step BASE64_QUANTUM) {
            val lastQuantum = index + BASE64_QUANTUM == value.length
            val first = decodeBase64Character(value[index])
            val second = decodeBase64Character(value[index + 1])
            val thirdPadding = value[index + 2] == '='
            val fourthPadding = value[index + 3] == '='
            if ((thirdPadding || fourthPadding) && !lastQuantum) invalidResponse()
            if (thirdPadding && !fourthPadding) invalidResponse()
            val third = if (thirdPadding) 0 else decodeBase64Character(value[index + 2])
            val fourth = if (fourthPadding) 0 else decodeBase64Character(value[index + 3])
            if (thirdPadding && second and 0x0f != 0) invalidResponse()
            if (fourthPadding && !thirdPadding && third and 0x03 != 0) invalidResponse()
            val combined = (first shl 18) or (second shl 12) or (third shl 6) or fourth
            if (outputIndex < output.size) output[outputIndex++] = (combined shr 16).toByte()
            if (outputIndex < output.size) output[outputIndex++] = (combined shr 8).toByte()
            if (outputIndex < output.size) output[outputIndex++] = combined.toByte()
        }
        return output
    }

    private fun decodeBase64Character(character: Char): Int = when (character) {
        in 'A'..'Z' -> character - 'A'
        in 'a'..'z' -> character - 'a' + 26
        in '0'..'9' -> character - '0' + 52
        '+' -> 62
        '/' -> 63
        else -> invalidResponse()
    }

    private fun invalidResponse(): Nothing =
        throw ProvisioningException(ProvisioningFailure.INVALID_RESPONSE)

    private companion object {
        const val PROVISIONING_PROTOCOL_VERSION = 3
        const val AUTH_PROTOCOL_VERSION = 1
        const val CREATED_STATUS = 201
        const val HTTP_TOO_MANY_REQUESTS = 429
        const val SERVER_ERROR_START = 500
        const val REDEEM_PATH = "/api/v1/provisioning/redeem"
        const val BOOTSTRAP_COMMIT_PATH = "/api/v1/provisioning/bootstrap-commit"
        const val CHALLENGE_PATH = "/api/v1/auth/challenge"
        const val SESSION_PATH = "/api/v1/auth/session"
        const val BASE64_QUANTUM = 4
        const val MAX_CHALLENGE_LIFETIME_MILLIS = 30_000L
        val FINGERPRINT_PATTERN = Regex("^[a-fA-F0-9]{64}$")
        val SESSION_TOKEN_PATTERN = Regex("^[A-Za-z0-9_-]{43}$")
        val CHALLENGE_NONCE_PATTERN = Regex("^[A-Za-z0-9_-]{43}$")
        val STANDARD_BASE64_PATTERN = Regex("^[A-Za-z0-9+/]{80,160}={0,2}$")
        val AUTHENTICATION_STATES = setOf(
            "UNREGISTERED",
            "REGISTRATION_PENDING",
            "AUTHENTICATED_NO_KEYS",
            "KEY_TRANSFER_PENDING",
            "KEYS_RESTORED",
            "READY",
            "REVOKED",
            "RECOVERY_REQUIRED",
        )
    }
}
