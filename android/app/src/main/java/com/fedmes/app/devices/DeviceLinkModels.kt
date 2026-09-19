package com.fedmes.app.devices

import android.net.Uri
import com.fedmes.app.provisioning.ProtocolTime
import java.util.UUID

data class AccountDevice(
    val id: String,
    val displayName: String,
    val platform: String,
    val boundAtEpochMillis: Long,
    val lastSeenAtEpochMillis: Long?,
    val current: Boolean,
    val approvedByDeviceId: String?,
    val identityFingerprint: String,
)

data class DeviceLinkQr(
    val linkId: String,
    val secret: String,
)

data class DeviceLinkPreview(
    val linkId: String,
    val secret: String,
    val displayName: String,
    val platform: String,
    val identityFingerprint: String,
    val encryptionFingerprint: String,
    val expiresAtEpochMillis: Long,
)

object DeviceLinkQrParser {
    private val secretPattern = Regex("^[A-Za-z0-9_-]{43}$")

    fun parse(raw: String): DeviceLinkQr {
        val uri = Uri.parse(raw.trim())
        require(uri.scheme == "fedmes" && uri.host == "link-device") { "Это не QR входа FedMes Desktop" }
        require(uri.getQueryParameter("v") == "1") { "Версия QR не поддерживается" }
        val allowed = setOf("v", "id", "secret")
        require(uri.queryParameterNames == allowed) { "QR содержит лишние параметры" }
        val id = requireNotNull(uri.getQueryParameter("id")).lowercase()
        require(UUID.fromString(id).toString() == id) { "Некорректный идентификатор входа" }
        val secret = requireNotNull(uri.getQueryParameter("secret"))
        require(secretPattern.matches(secret)) { "Некорректный секрет входа" }
        return DeviceLinkQr(id, secret)
    }
}

internal fun parseProtocolTime(value: String): Long =
    requireNotNull(ProtocolTime.parseRfc3339(value)) { "Сервер вернул некорректное время" }
