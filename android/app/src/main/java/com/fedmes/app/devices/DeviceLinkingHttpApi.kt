package com.fedmes.app.devices

import android.net.Uri
import com.fedmes.app.provisioning.ProvisionedAccount
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

class DeviceLinkingHttpApi {
    fun listDevices(account: ProvisionedAccount): List<AccountDevice> {
        val root = executeJson(account, "GET", "/api/v1/account/devices")
        val array = root.getJSONArray("devices")
        return List(array.length()) { index ->
            val value = array.getJSONObject(index)
            AccountDevice(
                id = value.getString("id"),
                displayName = value.getString("display_name"),
                platform = value.getString("platform"),
                boundAtEpochMillis = parseProtocolTime(value.getString("bound_at")),
                lastSeenAtEpochMillis = value.optString("last_seen_at").takeIf(String::isNotBlank)?.let(::parseProtocolTime),
                current = value.getBoolean("current"),
                approvedByDeviceId = value.optString("approved_by_device_id").takeIf(String::isNotBlank),
                identityFingerprint = value.getString("identity_fingerprint"),
            )
        }
    }

    fun preview(account: ProvisionedAccount, qr: DeviceLinkQr): DeviceLinkPreview {
        val body = JSONObject().put("version", 1).put("secret", qr.secret)
        val root = executeJson(
            account,
            "POST",
            "/api/v1/device-links/${segment(qr.linkId)}/preview",
            body.toString().toByteArray(Charsets.UTF_8),
        )
        return DeviceLinkPreview(
            linkId = root.getString("link_id"),
            secret = qr.secret,
            displayName = root.getString("display_name"),
            platform = root.getString("platform"),
            identityFingerprint = root.getString("identity_fingerprint"),
            encryptionFingerprint = root.getString("encryption_fingerprint"),
            expiresAtEpochMillis = parseProtocolTime(root.getString("expires_at")),
        )
    }

    fun approve(account: ProvisionedAccount, preview: DeviceLinkPreview, signatureBase64: String): AccountDevice {
        val body = JSONObject()
            .put("version", 1)
            .put("secret", preview.secret)
            .put("signature", signatureBase64)
        val root = executeJson(
            account,
            "POST",
            "/api/v1/device-links/${segment(preview.linkId)}/approve",
            body.toString().toByteArray(Charsets.UTF_8),
        )
        val value = root.getJSONObject("device")
        return AccountDevice(
            id = value.getString("id"),
            displayName = value.getString("display_name"),
            platform = value.getString("platform"),
            boundAtEpochMillis = parseProtocolTime(value.getString("bound_at")),
            lastSeenAtEpochMillis = value.optString("last_seen_at").takeIf(String::isNotBlank)?.let(::parseProtocolTime),
            current = value.optBoolean("current", false),
            approvedByDeviceId = value.optString("approved_by_device_id").takeIf(String::isNotBlank),
            identityFingerprint = value.getString("identity_fingerprint"),
        )
    }

    fun revoke(account: ProvisionedAccount, deviceId: String) {
        execute(account, "DELETE", "/api/v1/account/devices/${segment(deviceId)}")
    }

    fun terminateOthers(account: ProvisionedAccount) {
        execute(account, "POST", "/api/v1/account/devices/terminate-others", ByteArray(0))
    }

    private fun executeJson(
        account: ProvisionedAccount,
        method: String,
        path: String,
        body: ByteArray? = null,
    ): JSONObject {
        val response = execute(account, method, path, body)
        return try {
            JSONObject(response)
        } catch (error: Exception) {
            throw IOException("Сервер вернул некорректный ответ", error)
        }
    }

    private fun execute(
        account: ProvisionedAccount,
        method: String,
        path: String,
        body: ByteArray? = null,
    ): String {
        val connection = URL(account.serverUrl + path).openConnection() as HttpURLConnection
        try {
            connection.requestMethod = method
            connection.instanceFollowRedirects = false
            connection.connectTimeout = 10_000
            connection.readTimeout = 20_000
            connection.setRequestProperty("Accept", "application/json")
            connection.setRequestProperty("Authorization", "Bearer ${account.sessionToken}")
            if (body != null) {
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/json")
                connection.setFixedLengthStreamingMode(body.size)
                if (body.isNotEmpty()) connection.outputStream.use { it.write(body) }
            }
            val status = connection.responseCode
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
            val response = stream?.use { input ->
                val output = ByteArrayOutputStream()
                val buffer = ByteArray(8_192)
                try {
                    var total = 0
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        total += count
                        if (total > 256 * 1_024) throw IOException("Ответ сервера слишком большой")
                        output.write(buffer, 0, count)
                    }
                    output.toString(Charsets.UTF_8.name())
                } finally {
                    buffer.fill(0)
                }
            }.orEmpty()
            if (status !in 200..299) {
                val code = runCatching { JSONObject(response).getJSONObject("error").getString("code") }
                    .getOrDefault("server_error")
                throw IOException(serverErrorMessage(code))
            }
            return response
        } finally {
            body?.fill(0)
            connection.disconnect()
        }
    }

    private fun segment(value: String): String = Uri.encode(value)

    private fun serverErrorMessage(code: String): String = when (code) {
        "device_link_not_found" -> "QR входа не найден"
        "device_link_expired" -> "QR входа истёк"
        "device_link_used" -> "QR уже использован"
        "device_link_conflict" -> "Это устройство уже подключено"
        "current_device" -> "Текущее устройство удаляется через выход из аккаунта"
        "device_not_found" -> "Устройство уже отключено"
        "session_invalid" -> "Сессия телефона недействительна"
        "invalid_device_signature" -> "Подтверждение устройства отклонено"
        else -> "Ошибка сервера: $code"
    }
}
