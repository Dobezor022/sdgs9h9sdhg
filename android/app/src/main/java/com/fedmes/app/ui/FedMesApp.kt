package com.fedmes.app.ui

import androidx.compose.runtime.Composable
import com.fedmes.app.ui.messenger.MessengerActions
import com.fedmes.app.ui.messenger.MessengerScreen
import com.fedmes.app.ui.model.FedMesScreen
import com.fedmes.app.ui.model.FedMesUiAction
import com.fedmes.app.ui.model.FedMesUiState
import com.fedmes.app.ui.provisioning.ProvisioningScreen
import com.fedmes.app.ui.provisioning.QrScannerScaffold
import com.fedmes.app.ui.session.RestoreSessionErrorScreen
import com.fedmes.app.ui.session.RestoringSessionScreen
import com.fedmes.app.ui.session.SecurityRecoveryScreen
import com.fedmes.app.ui.theme.FedMesTheme
import com.fedmes.app.updates.AppUpdateDialog
import com.fedmes.app.updates.AppUpdateUiState

@Composable
fun FedMesApp(
    state: FedMesUiState,
    onAction: (FedMesUiAction) -> Unit,
    messengerActions: MessengerActions,
    updateState: AppUpdateUiState,
    onInstallUpdate: () -> Unit,
    onDismissUpdate: () -> Unit,
    onRecoveryKeyChanged: (String) -> Unit,
    onRecoverAccount: () -> Unit,
    onCancelRecovery: () -> Unit,
) {
    FedMesTheme(themeMode = state.themeMode) {
        when (state.screen) {
            FedMesScreen.RESTORING -> RestoringSessionScreen()
            FedMesScreen.QR_SIGN_IN -> ProvisioningScreen(
                familyMembers = state.familyMembers,
                onSignInWithQr = { onAction(FedMesUiAction.OpenQrScanner) },
            )
            FedMesScreen.QR_SCANNER -> QrScannerScaffold(
                phase = state.scannerPhase,
                failure = state.failure,
                onQrDecoded = { payload -> onAction(FedMesUiAction.QrDecoded(payload)) },
                onCameraError = { onAction(FedMesUiAction.CameraFailed) },
                onRetry = { onAction(FedMesUiAction.RetryScanner) },
                onClose = { onAction(FedMesUiAction.CloseQrScanner) },
            )
            FedMesScreen.SECURITY_RECOVERY -> SecurityRecoveryScreen(
                account = requireNotNull(state.account),
                recoveryKey = state.recoveryKeyInput,
                busy = state.securityBusy,
                error = state.securityError,
                notice = state.securityNotice,
                onRecoveryKeyChanged = onRecoveryKeyChanged,
                onRecover = onRecoverAccount,
                onCancel = onCancelRecovery,
            )
            FedMesScreen.SIGNED_IN -> MessengerScreen(
                account = requireNotNull(state.account),
                familyMembers = state.familyMembers,
                state = state.messenger,
                themeMode = state.themeMode,
                actions = messengerActions,
            )
            FedMesScreen.RESTORE_ERROR -> RestoreSessionErrorScreen(
                failure = requireNotNull(state.failure),
                onRetry = { onAction(FedMesUiAction.RetrySessionRestore) },
                onUseNewQr = { onAction(FedMesUiAction.UseNewQr) },
            )
        }
        AppUpdateDialog(
            state = updateState,
            onUpdate = onInstallUpdate,
            onDismiss = onDismissUpdate,
        )
    }
}
