package com.fedmes.app.accountsecurity

import android.util.Base64
import com.fedmes.app.provisioning.ProvisionedAccount
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL

class AccountSecurityHttpApi {
    private val maximumResponseBytes = 18 * 1024 * 1024

    fun getState(account: ProvisionedAccount): AccountSecurityState {
        val response = request(account, "GET", "/api/v2/security/state")
        requireSuccess(response)
        val root = JSONObject(response.body)
        if (root.getInt("version") != AccountSecurityProtocol.VERSION) invalidResponse()
        val state = root.getJSONObject("security")
        return AccountSecurityState(
            username = state.getString("username"),
            deviceId = state.getString("device_id"),
            state = state.getString("state"),
            protocolVersion = state.getInt("protocol_version"),
            cryptoVersion = state.getInt("crypto_version"),
            vaultRevision = state.getLong("vault_revision"),
            recoveryConfigured = state.getBoolean("recovery_configured"),
            opaqueEnrolled = state.getBoolean("opaque_enrolled"),
        ).also {
            if (it.username != account.username || it.deviceId != account.deviceId) invalidResponse()
        }
    }

    fun getVault(account: ProvisionedAccount): EncryptedAccountVault {
        val response = request(account, "GET", "/api/v2/security/vault")
        requireSuccess(response)
        val root = JSONObject(response.body)
        if (root.getInt("version") != AccountSecurityProtocol.VERSION) invalidResponse()
        return EncryptedAccountVault(
            revision = root.getLong("revision"),
            vaultVersion = root.getInt("vault_version"),
            cryptoVersion = root.getInt("crypto_version"),
            aadVersion = root.getInt("aad_version"),
            nonce = decodeBase64(root.getString("nonce"), 12, 24),
            ciphertext = decodeBase64(root.getString("ciphertext"), 16, 16 * 1024 * 1024),
            ciphertextSha256Hex = root.getString("ciphertext_sha256"),
        )
    }

    fun putVault(
        account: ProvisionedAccount,
        expectedPreviousRevision: Long,
        vault: EncryptedAccountVault,
        accessVerifier: ByteArray,
    ): EncryptedAccountVault {
        val body = JSONObject()
            .put("version", AccountSecurityProtocol.VERSION)
            .put("expected_previous_revision", expectedPreviousRevision)
            .put("vault_version", vault.vaultVersion)
            .put("crypto_version", vault.cryptoVersion)
            .put("aad_version", vault.aadVersion)
            .put("nonce", Base64.encodeToString(vault.nonce, Base64.NO_WRAP))
            .put("ciphertext", Base64.encodeToString(vault.ciphertext, Base64.NO_WRAP))
            .put("ciphertext_sha256", vault.ciphertextSha256Hex)
            .put("access_verifier", Base64.encodeToString(accessVerifier, Base64.NO_WRAP))
            .toString()
        val response = request(
            account,
            "PUT",
            "/api/v2/security/vault",
            body,
            AccountSecurityProtocol.newRequestId(),
        )
        requireSuccess(response)
        return parseVaultResponse(response.body)
    }

    fun getRecoveryPackage(account: ProvisionedAccount): EncryptedRecoveryPackage {
        val response = request(account, "GET", "/api/v2/security/recovery-package")
        requireSuccess(response)
        val root = JSONObject(response.body)
        if (root.getInt("version") != AccountSecurityProtocol.VERSION) invalidResponse()
        return EncryptedRecoveryPackage(
            id = root.getString("id"),
            vaultRevision = root.getLong("vault_revision"),
            packageVersion = root.getInt("package_version"),
            cryptoVersion = root.getInt("crypto_version"),
            aadVersion = root.getInt("aad_version"),
            kdfName = root.getString("kdf_name"),
            kdfParameters = root.getString("kdf_parameters"),
            salt = decodeBase64(root.getString("salt"), 16, 64),
            nonce = decodeBase64(root.getString("nonce"), 12, 24),
            ciphertext = decodeBase64(root.getString("ciphertext"), 16, 1024 * 1024),
            ciphertextSha256Hex = root.getString("ciphertext_sha256"),
        )
    }

    fun putRecoveryPackage(
        account: ProvisionedAccount,
        recoveryPackage: EncryptedRecoveryPackage,
    ): EncryptedRecoveryPackage {
        val body = JSONObject()
            .put("version", AccountSecurityProtocol.VERSION)
            .put("id", recoveryPackage.id)
            .put("vault_revision", recoveryPackage.vaultRevision)
            .put("package_version", recoveryPackage.packageVersion)
            .put("crypto_version", recoveryPackage.cryptoVersion)
            .put("aad_version", recoveryPackage.aadVersion)
            .put("kdf_name", recoveryPackage.kdfName)
            .put("kdf_parameters", recoveryPackage.kdfParameters)
            .put("salt", Base64.encodeToString(recoveryPackage.salt, Base64.NO_WRAP))
            .put("nonce", Base64.encodeToString(recoveryPackage.nonce, Base64.NO_WRAP))
            .put("ciphertext", Base64.encodeToString(recoveryPackage.ciphertext, Base64.NO_WRAP))
            .put("ciphertext_sha256", recoveryPackage.ciphertextSha256Hex)
            .toString()
        val response = request(
            account,
            "PUT",
            "/api/v2/security/recovery-package",
            body,
            AccountSecurityProtocol.newRequestId(),
        )
        requireSuccess(response)
        return parseRecoveryResponse(response.body)
    }

    fun completeRecovery(account: ProvisionedAccount, vaultRevision: Long, accessVerifier: ByteArray) {
        val body = JSONObject()
            .put("version", AccountSecurityProtocol.VERSION)
            .put("vault_revision", vaultRevision)
            .put("access_verifier", Base64.encodeToString(accessVerifier, Base64.NO_WRAP))
            .toString()
        val response = request(account, "POST", "/api/v2/security/recovery/complete", body)
        requireSuccess(response)
    }

    private fun parseVaultResponse(body: String): EncryptedAccountVault {
        val root = JSONObject(body)
        if (root.getInt("version") != AccountSecurityProtocol.VERSION) invalidResponse()
        return EncryptedAccountVault(
            revision = root.getLong("revision"),
            vaultVersion = root.getInt("vault_version"),
            cryptoVersion = root.getInt("crypto_version"),
            aadVersion = root.getInt("aad_version"),
            nonce = decodeBase64(root.getString("nonce"), 12, 24),
            ciphertext = decodeBase64(root.getString("ciphertext"), 16, 16 * 1024 * 1024),
            ciphertextSha256Hex = root.getString("ciphertext_sha256"),
        )
    }

    private fun parseRecoveryResponse(body: String): EncryptedRecoveryPackage {
        val root = JSONObject(body)
        if (root.getInt("version") != AccountSecurityProtocol.VERSION) invalidResponse()
        return EncryptedRecoveryPackage(
            id = root.getString("id"),
            vaultRevision = root.getLong("vault_revision"),
            packageVersion = root.getInt("package_version"),
            cryptoVersion = root.getInt("crypto_version"),
            aadVersion = root.getInt("aad_version"),
            kdfName = root.getString("kdf_name"),
            kdfParameters = root.getString("kdf_parameters"),
            salt = decodeBase64(root.getString("salt"), 16, 64),
            nonce = decodeBase64(root.getString("nonce"), 12, 24),
            ciphertext = decodeBase64(root.getString("ciphertext"), 16, 1024 * 1024),
            ciphertextSha256Hex = root.getString("ciphertext_sha256"),
        )
    }

    private fun request(
        account: ProvisionedAccount,
        method: String,
        path: String,
        body: String? = null,
        requestId: String? = null,
    ): Response {
        val base = account.serverUrl.trimEnd('/')
        if (!base.startsWith("https://")) throw AccountSecurityException("https_required")
        val connection = URL(base + path).openConnection() as HttpURLConnection
        try {
            connection.requestMethod = method
            connection.instanceFollowRedirects = false
            connection.connectTimeout = 10_000
            connection.readTimeout = 20_000
            connection.setRequestProperty("Accept", "application/json")
            connection.setRequestProperty("Authorization", "Bearer ${account.sessionToken}")
            if (requestId != null) connection.setRequestProperty("X-FedMes-Request-ID", requestId)
            if (body != null) {
                val bytes = body.toByteArray(Charsets.UTF_8)
                try {
                    connection.doOutput = true
                    connection.setRequestProperty("Content-Type", "application/json")
                    connection.setFixedLengthStreamingMode(bytes.size)
                    connection.outputStream.use { it.write(bytes) }
                } finally {
                    bytes.fill(0)
                }
            }
            val status = connection.responseCode
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
            return Response(status, readResponseBody(stream))
        } catch (error: IOException) {
            throw AccountSecurityException("network_error", error)
        } finally {
            connection.disconnect()
        }
    }


    private fun readResponseBody(stream: InputStream?): String {
        if (stream == null) return ""
        val buffer = ByteArray(8192)
        val output = ByteArrayOutputStream()
        var total = 0
        try {
            stream.use { input ->
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    total += count
                    if (total > maximumResponseBytes) {
                        throw AccountSecurityException("response_too_large")
                    }
                    output.write(buffer, 0, count)
                }
            }
            val bytes = output.toByteArray()
            return try {
                bytes.toString(Charsets.UTF_8)
            } finally {
                bytes.fill(0)
            }
        } finally {
            buffer.fill(0)
            output.reset()
        }
    }

    private fun requireSuccess(response: Response) {
        if (response.status in 200..299) return
        val code = runCatching {
            JSONObject(response.body).getJSONObject("error").getString("code")
        }.getOrDefault("security_request_failed")
        throw AccountSecurityException(code)
    }

    private fun decodeBase64(value: String, minimum: Int, maximum: Int): ByteArray {
        val decoded = try {
            Base64.decode(value, Base64.NO_WRAP)
        } catch (error: IllegalArgumentException) {
            throw AccountSecurityException("invalid_response", error)
        }
        if (decoded.size !in minimum..maximum) {
            decoded.fill(0)
            invalidResponse()
        }
        return decoded
    }

    private fun invalidResponse(): Nothing = throw AccountSecurityException("invalid_response")

    private data class Response(val status: Int, val body: String)
}
