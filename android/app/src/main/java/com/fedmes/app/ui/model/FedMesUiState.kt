package com.fedmes.app.ui.model

import com.fedmes.app.domain.family.FamilyUser
import com.fedmes.app.provisioning.AccountSummary
import com.fedmes.app.provisioning.ProvisioningFailure
import com.fedmes.app.messaging.ChatSummary
import com.fedmes.app.messaging.DecryptedMessage
import com.fedmes.app.messaging.PresenceState
import com.fedmes.app.messaging.OpenedAttachment
import com.fedmes.app.messaging.TextEntity
import com.fedmes.app.devices.AccountDevice
import com.fedmes.app.devices.DeviceLinkPreview
import com.fedmes.app.accountsecurity.PendingDeviceRequest
import com.fedmes.app.ui.theme.ThemeMode
import com.fedmes.app.calling.CallUiState


enum class SettingsPage {
    NONE,
    ROOT,
    PROFILE,
    SECURITY,
    NOTIFICATIONS,
    DEVICES,
    DEVICE_LINK_SCANNER,
    DEVICE_LINK_APPROVAL,
}

enum class UploadTaskPhase {
    PREPARING,
    UPLOADING,
}

data class UploadTaskUi(
    val id: String,
    val chatId: String,
    val title: String,
    val completedItems: Int,
    val totalItems: Int,
    val phase: UploadTaskPhase,
)

enum class FedMesScreen {
    RESTORING,
    QR_SIGN_IN,
    QR_SCANNER,
    SECURITY_RECOVERY,
    SIGNED_IN,
    RESTORE_ERROR,
}

enum class ScannerPhase {
    SCANNING,
    PROCESSING,
    ERROR,
}

data class MessengerUiState(
    val initialized: Boolean = false,
    val settingsPage: SettingsPage = SettingsPage.NONE,
    val accountDevices: List<AccountDevice> = emptyList(),
    val devicesLoading: Boolean = false,
    val deviceLinkScannerPhase: ScannerPhase = ScannerPhase.SCANNING,
    val deviceLinkFailure: ProvisioningFailure? = null,
    val deviceLinkPreview: DeviceLinkPreview? = null,
    val deviceLinkApproving: Boolean = false,
    val deviceHistorySyncing: Boolean = false,
    val loading: Boolean = false,
    val loadingOlder: Boolean = false,
    val hasMoreOlder: Boolean = false,
    val sending: Boolean = false,
    val draftSpoiler: Boolean = false,
    val uploads: Map<String, UploadTaskUi> = emptyMap(),
    val chats: List<ChatSummary> = emptyList(),
    val selectedChatId: String? = null,
    val messages: List<DecryptedMessage> = emptyList(),
    val presence: List<PresenceState> = emptyList(),
    val previews: Map<String, String> = emptyMap(),
    val unreadCounts: Map<String, Int> = emptyMap(),
    val showExactPresence: Boolean = false,
    val notificationsEnabled: Boolean = true,
    val notificationSoundEnabled: Boolean = true,
    val notificationVibrationEnabled: Boolean = true,
    val groupNotificationsEnabled: Boolean = true,
    val profileAvatarUri: String? = null,
    val profileAvatarMimeType: String? = null,
    val profileNameColorArgb: Long = 0L,
    val securityLoading: Boolean = false,
    val recoveryConfigured: Boolean = false,
    val opaqueEnrolled: Boolean = false,
    val pendingDeviceRequests: List<PendingDeviceRequest> = emptyList(),
    val generatedRecoveryKey: String? = null,
    val securitySettingsError: String? = null,
    val typingUsers: Set<String> = emptySet(),
    val scrollToBottomToken: Int = 0,
    val jumpToMessageId: String? = null,
    val jumpToMessageToken: Int = 0,
    val draft: String = "",
    val draftTextEntities: List<TextEntity> = emptyList(),
    val replyToId: String? = null,
    val editingMessageId: String? = null,
    val selectedMessageIds: Set<String> = emptySet(),
    val downloadingAttachmentId: String? = null,
    val openedAttachment: OpenedAttachment? = null,
    val call: CallUiState? = null,
    val error: String? = null,
)

data class FedMesUiState(
    val screen: FedMesScreen = FedMesScreen.RESTORING,
    val themeMode: ThemeMode = ThemeMode.SYSTEM,
    val familyMembers: List<FamilyUser> = emptyList(),
    val scannerPhase: ScannerPhase = ScannerPhase.SCANNING,
    val failure: ProvisioningFailure? = null,
    val account: AccountSummary? = null,
    val recoveryKeyInput: String = "",
    val securityBusy: Boolean = false,
    val securityError: String? = null,
    val securityNotice: String? = null,
    val generatedRecoveryKey: String? = null,
    val messenger: MessengerUiState = MessengerUiState(),
)

sealed interface FedMesUiAction {
    data object RestoreWithoutAccount : FedMesUiAction
    data class SessionRestored(val account: AccountSummary) : FedMesUiAction
    data class SessionRestoreFailed(val failure: ProvisioningFailure) : FedMesUiAction
    data object RetrySessionRestore : FedMesUiAction
    data object UseNewQr : FedMesUiAction
    data object OpenQrScanner : FedMesUiAction
    data object CloseQrScanner : FedMesUiAction
    data class QrDecoded(val rawPayload: String) : FedMesUiAction
    data class ProvisioningSucceeded(val account: AccountSummary) : FedMesUiAction
    data class ProvisioningFailed(val failure: ProvisioningFailure) : FedMesUiAction
    data object RetryScanner : FedMesUiAction
    data object CameraFailed : FedMesUiAction
    data object SignOut : FedMesUiAction
}

object FedMesUiReducer {
    fun reduce(state: FedMesUiState, action: FedMesUiAction): FedMesUiState = when (action) {
        FedMesUiAction.RestoreWithoutAccount -> state.copy(
            screen = FedMesScreen.QR_SIGN_IN,
            account = null,
        )
        is FedMesUiAction.SessionRestored -> state.copy(
            screen = screenForAccount(action.account),
            account = action.account,
            securityError = null,
        )
        is FedMesUiAction.SessionRestoreFailed -> state.copy(
            screen = FedMesScreen.RESTORE_ERROR,
            failure = action.failure,
        )
        FedMesUiAction.RetrySessionRestore -> state.copy(
            screen = FedMesScreen.RESTORING,
            failure = null,
        )
        FedMesUiAction.UseNewQr -> state.copy(
            screen = FedMesScreen.QR_SIGN_IN,
            failure = null,
            account = null,
        )
        FedMesUiAction.OpenQrScanner -> state.copy(
            screen = FedMesScreen.QR_SCANNER,
            scannerPhase = ScannerPhase.SCANNING,
            failure = null,
        )
        FedMesUiAction.CloseQrScanner -> if (state.scannerPhase == ScannerPhase.PROCESSING) {
            state
        } else {
            state.copy(
                screen = FedMesScreen.QR_SIGN_IN,
                scannerPhase = ScannerPhase.SCANNING,
                failure = null,
            )
        }
        is FedMesUiAction.QrDecoded -> if (
            state.screen == FedMesScreen.QR_SCANNER && state.scannerPhase == ScannerPhase.SCANNING
        ) {
            state.copy(scannerPhase = ScannerPhase.PROCESSING, failure = null)
        } else {
            state
        }
        is FedMesUiAction.ProvisioningSucceeded -> state.copy(
            screen = screenForAccount(action.account),
            scannerPhase = ScannerPhase.SCANNING,
            failure = null,
            account = action.account,
            securityError = null,
        )
        is FedMesUiAction.ProvisioningFailed -> state.copy(
            screen = FedMesScreen.QR_SCANNER,
            scannerPhase = ScannerPhase.ERROR,
            failure = action.failure,
        )
        FedMesUiAction.RetryScanner -> state.copy(
            screen = FedMesScreen.QR_SCANNER,
            scannerPhase = ScannerPhase.SCANNING,
            failure = null,
        )
        FedMesUiAction.CameraFailed -> state.copy(
            scannerPhase = ScannerPhase.ERROR,
            failure = ProvisioningFailure.CAMERA,
        )
        FedMesUiAction.SignOut -> state.copy(
            screen = FedMesScreen.QR_SIGN_IN,
            scannerPhase = ScannerPhase.SCANNING,
            failure = null,
            account = null,
            recoveryKeyInput = "",
            securityBusy = false,
            securityError = null,
            securityNotice = null,
            generatedRecoveryKey = null,
            messenger = MessengerUiState(),
        )
    }

    private fun screenForAccount(account: AccountSummary): FedMesScreen =
        if (account.authenticationState == "READY") FedMesScreen.SIGNED_IN else FedMesScreen.SECURITY_RECOVERY
}
