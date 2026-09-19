package com.fedmes.app.accountsecurity

import android.util.Base64
import com.fedmes.app.provisioning.ProvisionedAccount
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.time.Instant

class OpaqueAuthHttpApi {
    data class StartResult(
        val attemptId: String,
        val message: String,
        val suite: String,
        val serverIdentity: String?,
        val expiresAtEpochMillis: Long,
    )

    data class LoginResult(
        val username: String,
        val deviceId: String,
        val sessionId: String,
        val sessionToken: String,
        val authenticationState: String,
        val provisioningRequestId: String,
        val serverProof: String,
        val expiresAtEpochMillis: Long,
    )

    data class OpaqueRecoveryPackage(
        val vaultRevision: Long,
        val packageVersion: Int,
        val nonce: ByteArray,
        val ciphertext: ByteArray,
        val ciphertextSha256Hex: String,
    )

    fun registrationStart(account: ProvisionedAccount, passwordMessage: String, passwordChange: Boolean): StartResult {
        val path = if (passwordChange) "/api/v3/auth/opaque/password-change/start" else "/api/v3/auth/opaque/registration/start"
        val body = JSONObject()
            .put("version", VERSION)
            .put("request_id", AccountSecurityProtocol.newRequestId())
            .put("username", account.username)
            .put("message", passwordMessage)
        return parseStart(request(account.serverUrl, "POST", path, body, account.sessionToken), requireIdentity = false)
    }

    fun registrationFinish(account: ProvisionedAccount, attemptId: String, record: String, passwordChange: Boolean) {
        val path = if (passwordChange) "/api/v3/auth/opaque/password-change/finish" else "/api/v3/auth/opaque/registration/finish"
        val body = JSONObject().put("version", VERSION).put("attempt_id", attemptId).put("message", record)
        request(account.serverUrl, "POST", path, body, account.sessionToken)
    }

    fun loginStart(
        serverUrl: String,
        username: String,
        ke1: String,
        deviceId: String,
        displayName: String,
        platform: String,
        signingAlgorithm: String,
        signingPublicKeySpkiBase64: String,
        agreementAlgorithm: String,
        agreementPublicKeySpkiBase64: String,
    ): StartResult {
        val body = JSONObject()
            .put("version", VERSION)
            .put("request_id", AccountSecurityProtocol.newRequestId())
            .put("username", username)
            .put("message", ke1)
            .put("device_id", deviceId)
            .put("display_name", displayName)
            .put("platform", platform)
            .put("signing_algorithm", signingAlgorithm)
            .put("signing_public_key_spki", toRawUrlBase64(signingPublicKeySpkiBase64))
            .put("key_agreement_algorithm", agreementAlgorithm)
            .put("key_agreement_public_key_spki", toRawUrlBase64(agreementPublicKeySpkiBase64))
        return parseStart(request(serverUrl, "POST", "/api/v3/auth/opaque/login/start", body, null), requireIdentity = true)
    }

    fun loginFinish(serverUrl: String, attemptId: String, ke3: String): LoginResult {
        val body = JSONObject().put("version", VERSION).put("attempt_id", attemptId).put("message", ke3)
        val root = request(serverUrl, "POST", "/api/v3/auth/opaque/login/finish", body, null)
        requireVersion(root)
        return LoginResult(
            username = root.getString("username"),
            deviceId = root.getString("device_id"),
            sessionId = root.getString("session_id"),
            sessionToken = root.getString("session_token"),
            authenticationState = root.getString("authentication_state"),
            provisioningRequestId = root.getString("provisioning_request_id"),
            serverProof = root.getString("server_proof"),
            expiresAtEpochMillis = Instant.parse(root.getString("expires_at")).toEpochMilli(),
        )
    }

    fun getRecoveryPackage(account: ProvisionedAccount): OpaqueRecoveryPackage {
        val root = request(account.serverUrl, "GET", "/api/v3/security/opaque-recovery-package", null, account.sessionToken)
        requireVersion(root)
        return OpaqueRecoveryPackage(
            vaultRevision = root.getLong("vault_revision"),
            packageVersion = root.getInt("package_version"),
            nonce = decodeRawUrl(root.getString("nonce"), 12, 24),
            ciphertext = decodeRawUrl(root.getString("ciphertext"), 48, 1024 * 1024),
            ciphertextSha256Hex = root.getString("ciphertext_sha256"),
        )
    }

    fun putRecoveryPackage(account: ProvisionedAccount, value: OpaqueRecoveryPackage) {
        val body = JSONObject()
            .put("version", VERSION)
            .put("vault_revision", value.vaultRevision)
            .put("package_version", value.packageVersion)
            .put("nonce", rawUrl(value.nonce))
            .put("ciphertext", rawUrl(value.ciphertext))
            .put("ciphertext_sha256", value.ciphertextSha256Hex)
        request(account.serverUrl, "PUT", "/api/v3/security/opaque-recovery-package", body, account.sessionToken)
    }

    private fun parseStart(root: JSONObject, requireIdentity: Boolean): StartResult {
        requireVersion(root)
        val identity = root.optString("server_identity").takeIf(String::isNotBlank)
        if (requireIdentity && identity == null) invalidResponse()
        return StartResult(
            attemptId = root.getString("attempt_id"),
            message = root.getString("message"),
            suite = root.getString("suite"),
            serverIdentity = identity,
            expiresAtEpochMillis = Instant.parse(root.getString("expires_at")).toEpochMilli(),
        )
    }

    private fun request(serverUrl: String, method: String, path: String, body: JSONObject?, bearer: String?): JSONObject {
        val base = serverUrl.trimEnd('/')
        if (!base.startsWith("https://")) throw AccountSecurityException("https_required")
        val connection = URL(base + path).openConnection() as HttpURLConnection
        try {
            connection.requestMethod = method
            connection.instanceFollowRedirects = false
            connection.connectTimeout = 10_000
            connection.readTimeout = 25_000
            connection.setRequestProperty("Accept", "application/json")
            if (!bearer.isNullOrBlank()) connection.setRequestProperty("Authorization", "Bearer $bearer")
            if (body != null) {
                val bytes = body.toString().toByteArray(Charsets.UTF_8)
                try {
                    connection.doOutput = true
                    connection.setRequestProperty("Content-Type", "application/json")
                    connection.setFixedLengthStreamingMode(bytes.size)
                    connection.outputStream.use { it.write(bytes) }
                } finally { bytes.fill(0) }
            }
            val status = connection.responseCode
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
            val response = read(stream)
            if (status !in 200..299) {
                val code = runCatching { JSONObject(response).getJSONObject("error").getString("code") }
                    .getOrDefault(if (status == 401) "authentication_failed" else "opaque_request_failed")
                throw AccountSecurityException(code)
            }
            return try { JSONObject(response) } catch (error: Exception) {
                throw AccountSecurityException("invalid_response", error)
            }
        } catch (error: AccountSecurityException) {
            throw error
        } catch (error: IOException) {
            throw AccountSecurityException("network_error", error)
        } finally { connection.disconnect() }
    }

    private fun read(stream: java.io.InputStream?): String {
        if (stream == null) return ""
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        try {
            stream.use { input ->
                var total = 0
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    total += count
                    if (total > 2 * 1024 * 1024) throw AccountSecurityException("response_too_large")
                    output.write(buffer, 0, count)
                }
            }
            val bytes = output.toByteArray()
            return try { bytes.toString(Charsets.UTF_8) } finally { bytes.fill(0) }
        } finally { buffer.fill(0); output.reset() }
    }

    private fun toRawUrlBase64(standard: String): String {
        val bytes = try { Base64.decode(standard, Base64.NO_WRAP) } catch (error: Exception) {
            throw AccountSecurityException("invalid_public_key", error)
        }
        return try { rawUrl(bytes) } finally { bytes.fill(0) }
    }
    private fun rawUrl(value: ByteArray): String = Base64.encodeToString(value, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    private fun decodeRawUrl(value: String, minimum: Int, maximum: Int): ByteArray {
        val decoded = try { Base64.decode(value, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING) } catch (error: Exception) {
            throw AccountSecurityException("invalid_response", error)
        }
        if (decoded.size !in minimum..maximum) { decoded.fill(0); invalidResponse() }
        return decoded
    }
    private fun requireVersion(root: JSONObject) { if (root.optInt("version") != VERSION) invalidResponse() }
    private fun invalidResponse(): Nothing = throw AccountSecurityException("invalid_response")

    companion object { const val VERSION = 4 }
}
