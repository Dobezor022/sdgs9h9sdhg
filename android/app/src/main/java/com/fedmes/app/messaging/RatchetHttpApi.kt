package com.fedmes.app.messaging

import android.util.Base64
import com.fedmes.app.provisioning.ProvisionedAccount
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

class RatchetHttpApi {
    data class OneTimeKey(val keyId: String, val publicKey: String, val signature: ByteArray)
    data class ClaimedKey(
        val deviceId: String,
        val username: String,
        val bundleVersion: Int,
        val curve25519IdentityKey: String,
        val ed25519IdentityKey: String,
        val signedPayload: ByteArray,
        val bundleSignature: ByteArray,
        val oneTimeKey: OneTimeKey,
    )
    data class GroupPackage(
        val chatId: String,
        val roomKeyVersion: Long,
        val sessionId: String,
        val senderDeviceId: String,
        val senderCurve25519Key: String,
        val rotationId: String,
        val olmSessionId: String,
        val messageType: Int,
        val encryptedSessionKey: ByteArray,
    )
    data class GroupKeyUpload(
        val recipientDeviceId: String,
        val olmSessionId: String,
        val messageType: Int,
        val encryptedSessionKey: ByteArray,
    )

    fun putBundle(
        account: ProvisionedAccount,
        bundleVersion: Int,
        curve25519IdentityKey: String,
        ed25519IdentityKey: String,
        signedPayload: ByteArray,
        signature: ByteArray,
        oneTimeKeys: List<OneTimeKey>,
    ) {
        val body = JSONObject()
            .put("version", VERSION)
            .put("bundle_version", bundleVersion)
            .put("curve25519_identity_key", curve25519IdentityKey)
            .put("ed25519_identity_key", ed25519IdentityKey)
            .put("signed_payload", rawUrl(signedPayload))
            .put("signature", rawUrl(signature))
            .put("one_time_keys", JSONArray().apply {
                oneTimeKeys.forEach { key ->
                    put(JSONObject().put("key_id", key.keyId).put("public_key", key.publicKey).put("signature", rawUrl(key.signature)))
                }
            })
        request(account, "PUT", "/api/v3/crypto/ratchet/bundle", body)
    }

    fun claim(account: ProvisionedAccount, targetDeviceId: String): ClaimedKey {
        val root = request(account, "POST", "/api/v3/crypto/ratchet/claim",
            JSONObject().put("version", VERSION).put("target_device_id", targetDeviceId))
        requireVersion(root)
        val one = root.getJSONObject("one_time_key")
        return ClaimedKey(
            deviceId = root.getString("device_id"),
            username = root.getString("username"),
            bundleVersion = root.getInt("bundle_version"),
            curve25519IdentityKey = root.getString("curve25519_identity_key"),
            ed25519IdentityKey = root.getString("ed25519_identity_key"),
            signedPayload = decodeRawUrl(root.getString("signed_payload"), 32, 65536),
            bundleSignature = decodeRawUrl(root.getString("bundle_signature"), 32, 2048),
            oneTimeKey = OneTimeKey(
                keyId = one.getString("key_id"),
                publicKey = one.getString("public_key"),
                signature = decodeRawUrl(one.getString("signature"), 32, 2048),
            ),
        )
    }

    data class GroupVersionReservation(
        val chatId: String,
        val rotationId: String,
        val roomKeyVersion: Long,
    )

    fun reserveGroupVersion(account: ProvisionedAccount, chatId: String, rotationId: String): GroupVersionReservation {
        val root = request(
            account,
            "POST",
            "/api/v3/crypto/megolm/reserve",
            JSONObject().put("version", VERSION).put("chat_id", chatId).put("rotation_id", rotationId),
        )
        requireVersion(root)
        require(root.getString("chat_id") == chatId && root.getString("rotation_id") == rotationId)
        return GroupVersionReservation(chatId, rotationId, root.getLong("room_key_version"))
    }

    fun putGroupSession(
        account: ProvisionedAccount,
        chatId: String,
        roomKeyVersion: Long,
        sessionId: String,
        rotationId: String,
        packages: List<GroupKeyUpload>,
    ) {
        val body = JSONObject().put("version", VERSION).put("chat_id", chatId)
            .put("room_key_version", roomKeyVersion).put("session_id", sessionId).put("rotation_id", rotationId)
            .put("packages", JSONArray().apply {
                packages.forEach { item -> put(JSONObject()
                    .put("recipient_device_id", item.recipientDeviceId)
                    .put("olm_session_id", item.olmSessionId)
                    .put("message_type", item.messageType)
                    .put("encrypted_session_key", rawUrl(item.encryptedSessionKey))) }
            })
        request(account, "POST", "/api/v3/crypto/megolm/sessions", body)
    }

    fun listGroupPackages(account: ProvisionedAccount, limit: Int = 100): List<GroupPackage> {
        val root = request(account, "GET", "/api/v3/crypto/megolm/packages?limit=${limit.coerceIn(1, 200)}", null)
        requireVersion(root)
        val array = root.optJSONArray("packages") ?: JSONArray()
        return List(array.length()) { index ->
            val item = array.getJSONObject(index)
            GroupPackage(
                chatId = item.getString("chat_id"), roomKeyVersion = item.getLong("room_key_version"),
                sessionId = item.getString("session_id"), senderDeviceId = item.getString("sender_device_id"),
                senderCurve25519Key = item.getString("sender_curve25519_key"),
                rotationId = item.getString("rotation_id"), olmSessionId = item.getString("olm_session_id"),
                messageType = item.getInt("message_type"),
                encryptedSessionKey = decodeRawUrl(item.getString("encrypted_session_key"), 16, 65536),
            )
        }
    }

    fun consumeGroupPackage(account: ProvisionedAccount, chatId: String, roomKeyVersion: Long) {
        request(account, "POST", "/api/v3/crypto/megolm/packages/consume",
            JSONObject().put("version", VERSION).put("chat_id", chatId).put("room_key_version", roomKeyVersion))
    }

    private fun request(account: ProvisionedAccount, method: String, path: String, body: JSONObject?): JSONObject {
        val base = account.serverUrl.trimEnd('/')
        if (!base.startsWith("https://")) throw IOException("HTTPS is required")
        val connection = URL(base + path).openConnection() as HttpURLConnection
        try {
            connection.requestMethod = method
            connection.instanceFollowRedirects = false
            connection.connectTimeout = 10_000
            connection.readTimeout = 30_000
            connection.setRequestProperty("Accept", "application/json")
            connection.setRequestProperty("Authorization", "Bearer ${account.sessionToken}")
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
                val code = runCatching { JSONObject(text).getJSONObject("error").getString("code") }
                    .getOrDefault("ratchet_request_failed")
                throw IOException(code)
            }
            return if (text.isBlank()) JSONObject() else JSONObject(text)
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
                    if (total > 2 * 1024 * 1024) throw IOException("response_too_large")
                    output.write(buffer, 0, count)
                }
            }
            val bytes = output.toByteArray()
            return try { bytes.toString(Charsets.UTF_8) } finally { bytes.fill(0) }
        } finally { buffer.fill(0); output.reset() }
    }

    private fun rawUrl(value: ByteArray): String =
        Base64.encodeToString(value, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    private fun decodeRawUrl(value: String, min: Int, max: Int): ByteArray {
        val decoded = Base64.decode(value, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        if (decoded.size !in min..max) { decoded.fill(0); throw IOException("invalid_response") }
        return decoded
    }
    private fun requireVersion(root: JSONObject) { if (root.optInt("version") != VERSION) throw IOException("invalid_response") }
    companion object { const val VERSION = 4 }
}
