package com.fedmes.app.devices

import com.fedmes.app.messaging.MessagingRepository
import com.fedmes.app.provisioning.ProvisionedAccount
import com.fedmes.app.provisioning.ProvisioningCoordinator
import com.fedmes.app.security.DeviceIdentityStore
import com.fedmes.app.security.SessionStore

class DeviceManagerRepository(
    private val sessionStore: SessionStore,
    private val provisioningCoordinator: ProvisioningCoordinator,
    private val deviceIdentity: DeviceIdentityStore,
    private val api: DeviceLinkingHttpApi,
    private val messagingRepository: MessagingRepository,
) {
    fun listDevices(): List<AccountDevice> = api.listDevices(activeAccount())

    fun preview(rawQr: String): DeviceLinkPreview {
        val qr = DeviceLinkQrParser.parse(rawQr)
        return retryTransient { api.preview(activeAccount(), qr) }
    }

    fun approve(preview: DeviceLinkPreview): AccountDevice {
        require(preview.expiresAtEpochMillis > System.currentTimeMillis()) { "QR входа истёк" }
        val account = activeAccount()
        val payload = canonicalApproval(
            linkId = preview.linkId,
            secret = preview.secret,
            approverDeviceId = account.deviceId,
            identityFingerprint = preview.identityFingerprint,
            encryptionFingerprint = preview.encryptionFingerprint,
        )
        val signature = try {
            deviceIdentity.signSha256EcdsaBase64(account.serverUrl, account.username, payload)
        } finally {
            payload.fill(0)
        }
        return retryTransient { api.approve(account, preview, signature) }.also {
            messagingRepository.invalidateEncryptionDeviceCache()
        }
    }

    fun synchronizeHistoryForLinkedDevice() {
        messagingRepository.repairAllChatsForCurrentUserDevices()
    }

    fun revoke(deviceId: String) {
        api.revoke(activeAccount(), deviceId)
        messagingRepository.invalidateEncryptionDeviceCache()
    }

    fun terminateOthers() {
        api.terminateOthers(activeAccount())
        messagingRepository.invalidateEncryptionDeviceCache()
    }

    private fun <T> retryTransient(block: () -> T): T {
        var last: java.io.IOException? = null
        repeat(6) { attempt ->
            try {
                return block()
            } catch (error: java.io.IOException) {
                last = error
                if (attempt == 5) throw error
                try {
                    Thread.sleep((180L shl attempt).coerceAtMost(1_800L))
                } catch (interrupted: InterruptedException) {
                    Thread.currentThread().interrupt()
                    throw java.io.IOException("Операция отменена", interrupted)
                }
            }
        }
        throw last ?: java.io.IOException("Не удалось выполнить запрос")
    }

    private fun activeAccount(): ProvisionedAccount {
        val stored = sessionStore.loadAccount() ?: error("Аккаунт не найден")
        if (stored.sessionExpiresAtEpochMillis > System.currentTimeMillis() + 30_000L) return stored
        provisioningCoordinator.restoreSession()
        return sessionStore.loadAccount() ?: error("Сессия не восстановлена")
    }

    private fun canonicalApproval(
        linkId: String,
        secret: String,
        approverDeviceId: String,
        identityFingerprint: String,
        encryptionFingerprint: String,
    ): ByteArray = listOf(
        "fedmes-device-link-approval-v1",
        linkId,
        secret,
        approverDeviceId,
        identityFingerprint,
        encryptionFingerprint,
    ).joinToString("\n").toByteArray(Charsets.UTF_8)
}
