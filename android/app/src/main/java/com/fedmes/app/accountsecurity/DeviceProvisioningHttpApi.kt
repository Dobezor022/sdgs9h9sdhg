package com.fedmes.app.accountsecurity

import android.net.Uri
import android.util.Base64
import com.fedmes.app.provisioning.ProvisionedAccount
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

class DeviceProvisioningHttpApi {
    fun list(account: ProvisionedAccount): List<PendingDeviceRequest> {
        val root = request(account, "GET", "/api/v2/security/device-requests")
        requireVersion(root)
        val array = root.getJSONArray("requests")
        return List(array.length()) { parseRequest(array.getJSONObject(it)) }
    }

    fun get(account: ProvisionedAccount, requestId: String): PendingDeviceRequest {
        val root = request(account, "GET", "/api/v2/security/device-requests/${segment(requestId)}")
        requireVersion(root)
        return parseRequest(root.getJSONObject("request"))
    }

    fun approve(
        account: ProvisionedAccount,
        requestId: String,
        certificateId: String,
        certificatePayload: ByteArray,
        certificateSignature: ByteArray,
        signatureAlgorithm: String,
        encryptedPackage: ByteArray,
        nonce: ByteArray,
        requestSignature: ByteArray,
    ) {
        val body = JSONObject()
            .put("version", AccountSecurityProtocol.VERSION)
            .put("certificate_id", certificateId)
            .put("certificate_version", 1)
            .put("certificate_payload", standard(certificatePayload))
            .put("certificate_signature", standard(certificateSignature))
            .put("signature_algorithm", signatureAlgorithm)
            .put("encrypted_package", standard(encryptedPackage))
            .put("nonce", standard(nonce))
            .put("aad_version", 1)
            .put("package_version", 1)
            .put("request_signature", standard(requestSignature))
        request(account, "POST", "/api/v2/security/device-requests/${segment(requestId)}/approve", body, AccountSecurityProtocol.newRequestId())
    }

    fun reject(account: ProvisionedAccount, requestId: String) {
        request(account, "POST", "/api/v2/security/device-requests/${segment(requestId)}/reject", JSONObject().put("version", AccountSecurityProtocol.VERSION))
    }

    fun getPackage(account: ProvisionedAccount, requestId: String): ProvisioningPackageResponse {
        val root = request(account, "GET", "/api/v2/security/device-requests/${segment(requestId)}/package")
        requireVersion(root)
        return ProvisioningPackageResponse(
            requestId = root.getString("request_id"),
            targetDeviceId = root.getString("target_device_id"),
            encryptedPackage = decode(root.getString("encrypted_package"), 48, 1024 * 1024),
            nonce = decode(root.getString("nonce"), 12, 24),
            aadVersion = root.getInt("aad_version"),
            packageVersion = root.getInt("package_version"),
            certificateId = root.getString("certificate_id"),
            certificatePayload = decode(root.getString("certificate_payload"), 32, 16 * 1024),
            certificateSignature = decode(root.getString("certificate_signature"), 32, 2048),
            signatureAlgorithm = root.getString("signature_algorithm"),
            issuerDeviceId = root.getString("issuer_device_id"),
        )
    }

    fun complete(account: ProvisionedAccount, requestId: String, vaultRevision: Long, accessVerifier: ByteArray) {
        val body = JSONObject()
            .put("version", AccountSecurityProtocol.VERSION)
            .put("vault_revision", vaultRevision)
            .put("access_verifier", standard(accessVerifier))
        request(account, "POST", "/api/v2/security/device-requests/${segment(requestId)}/complete", body)
    }

    private fun parseRequest(value: JSONObject) = PendingDeviceRequest(
        id = value.getString("id"), username = value.getString("username"),
        targetDeviceId = value.getString("target_device_id"), displayName = value.getString("display_name"),
        platform = value.getString("platform"), networkHint = value.optString("network_hint"),
        requestedAt = value.getString("requested_at"), expiresAt = value.getString("expires_at"),
        signingAlgorithm = value.getString("signing_algorithm"),
        signingPublicKeySpkiBase64 = value.getString("signing_public_key_spki"),
        signingFingerprintHex = value.getString("signing_fingerprint"),
        keyAgreementAlgorithm = value.getString("key_agreement_algorithm"),
        keyAgreementPublicKeySpkiBase64 = value.getString("key_agreement_public_key"),
        keyAgreementFingerprintHex = value.getString("key_agreement_fingerprint"),
    )

    private fun request(account: ProvisionedAccount, method: String, path: String, body: JSONObject? = null, requestId: String? = null): JSONObject {
        val base = account.serverUrl.trimEnd('/')
        if (!base.startsWith("https://")) throw AccountSecurityException("https_required")
        val connection = URL(base + path).openConnection() as HttpURLConnection
        try {
            connection.requestMethod = method
            connection.instanceFollowRedirects = false
            connection.connectTimeout = 10_000
            connection.readTimeout = 25_000
            connection.setRequestProperty("Accept", "application/json")
            connection.setRequestProperty("Authorization", "Bearer ${account.sessionToken}")
            requestId?.let { connection.setRequestProperty("X-FedMes-Request-ID", it) }
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
            val text = read(stream)
            if (status !in 200..299) {
                val code = runCatching { JSONObject(text).getJSONObject("error").getString("code") }.getOrDefault("provisioning_failed")
                throw AccountSecurityException(code)
            }
            return if (text.isBlank()) JSONObject() else JSONObject(text)
        } catch (error: AccountSecurityException) { throw error }
        catch (error: IOException) { throw AccountSecurityException("network_error", error) }
        finally { connection.disconnect() }
    }

    private fun read(stream: java.io.InputStream?): String {
        if (stream == null) return ""
        val output = ByteArrayOutputStream(); val buffer = ByteArray(8192)
        try {
            stream.use { input ->
                var total = 0
                while (true) {
                    val count = input.read(buffer); if (count < 0) break
                    total += count; if (total > 2 * 1024 * 1024) throw AccountSecurityException("response_too_large")
                    output.write(buffer, 0, count)
                }
            }
            val bytes = output.toByteArray(); return try { bytes.toString(Charsets.UTF_8) } finally { bytes.fill(0) }
        } finally { buffer.fill(0); output.reset() }
    }
    private fun segment(value: String): String = Uri.encode(value)
    private fun standard(value: ByteArray) = Base64.encodeToString(value, Base64.NO_WRAP)
    private fun decode(value: String, minimum: Int, maximum: Int): ByteArray {
        val bytes = try { Base64.decode(value, Base64.NO_WRAP) } catch (error: Exception) { throw AccountSecurityException("invalid_response", error) }
        if (bytes.size !in minimum..maximum) { bytes.fill(0); throw AccountSecurityException("invalid_response") }
        return bytes
    }
    private fun requireVersion(root: JSONObject) { if (root.optInt("version") != AccountSecurityProtocol.VERSION) throw AccountSecurityException("invalid_response") }
}
