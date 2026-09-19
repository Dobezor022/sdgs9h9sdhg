package com.fedmes.app

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.fedmes.app.ui.FedMesApp
import com.fedmes.app.ui.FedMesViewModel
import com.fedmes.app.ui.messenger.MessengerActions
import com.fedmes.app.ui.model.FedMesUiAction
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        if (
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), NOTIFICATION_PERMISSION_REQUEST)
        }

        val container = (application as FedMesApplication).appContainer
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                while (isActive) {
                    container.updateCoordinator.checkNow()
                    delay(UPDATE_CHECK_INTERVAL_MILLIS)
                }
            }
        }
        setContent {
            val factory = remember(container) { FedMesViewModel.factory(container) }
            val viewModel: FedMesViewModel = viewModel(factory = factory)
            val state by viewModel.state.collectAsStateWithLifecycle()
            val updateState by container.updateCoordinator.state.collectAsStateWithLifecycle()
            val messengerActions = remember(viewModel) {
                MessengerActions(
                    onOpenChat = viewModel::openChat,
                    onBack = viewModel::closeChat,
                    onDraft = viewModel::updateDraft,
                    onSend = viewModel::sendCurrentMessage,
                    onAttachments = viewModel::sendAttachments,
                    onVoice = viewModel::sendVoice,
                    onRoundVideo = viewModel::sendRoundVideo,
                    onCancelUpload = viewModel::cancelUpload,
                    onOpenAttachment = { message, descriptor -> viewModel.openAttachment(message, descriptor) },
                    onLoadAttachmentPreview = viewModel::loadAttachmentPreview,
                    onLoadAttachmentBytes = viewModel::loadAttachmentBytes,
                    onCloseAttachment = viewModel::closeAttachment,
                    onReply = viewModel::replyTo,
                    onEdit = viewModel::editMessage,
                    onForward = viewModel::forwardMessage,
                    onDeleteMessages = viewModel::deleteMessages,
                    onPin = viewModel::pinMessage,
                    onUnpin = viewModel::unpinMessage,
                    onRequestSpoilerReveal = viewModel::requestSpoilerReveal,
                    onRevealSpoiler = viewModel::revealSpoiler,
                    onToggleSelection = viewModel::toggleSelection,
                    onClearSelection = viewModel::clearSelection,
                    onLoadOlder = viewModel::loadOlderMessages,
                    onJumpToMessage = viewModel::jumpToMessage,
                    onVisibleMessages = viewModel::markVisibleMessagesRead,
                    onCancelComposerMode = viewModel::cancelComposerMode,
                    onClearError = viewModel::clearMessengerError,
                    onShowExactPresence = viewModel::setShowExactPresence,
                    onThemeMode = viewModel::setThemeMode,
                    onOpenSettings = viewModel::openSettings,
                    onCloseSettings = viewModel::closeSettings,
                    onOpenDevices = viewModel::openDevices,
                    onOpenNotifications = viewModel::openNotifications,
                    onOpenSecurity = viewModel::openSecurity,
                    onOpenProfile = viewModel::openProfile,
                    onProfileMedia = viewModel::setProfileMedia,
                    onClearProfileMedia = viewModel::clearProfileMedia,
                    onProfileNameColor = viewModel::setProfileNameColor,
                    onNotificationsEnabled = viewModel::setNotificationsEnabled,
                    onNotificationSound = viewModel::setNotificationSoundEnabled,
                    onNotificationVibration = viewModel::setNotificationVibrationEnabled,
                    onGroupNotifications = viewModel::setGroupNotificationsEnabled,
                    onGenerateRecoveryKey = viewModel::generateRecoveryKey,
                    onConfirmRecoveryKeySaved = viewModel::confirmRecoveryKeySaved,
                    onConfigureOpaquePassword = viewModel::configureOpaquePassword,
                    onApprovePendingDevice = viewModel::approvePendingDevice,
                    onRejectPendingDevice = viewModel::rejectPendingDevice,
                    onDevicesBack = viewModel::backFromDevices,
                    onRefreshDevices = { viewModel.refreshDevices() },
                    onStartDeviceLinkScan = viewModel::startDesktopLinkScan,
                    onDeviceLinkQr = viewModel::handleDesktopLinkQr,
                    onRetryDeviceLinkScanner = viewModel::retryDesktopLinkScanner,
                    onDeviceLinkCameraError = viewModel::deviceLinkCameraFailed,
                    onCloseDeviceLinkFlow = viewModel::closeDesktopLinkFlow,
                    onApproveDeviceLink = viewModel::approveDesktopLink,
                    onRevokeDevice = viewModel::revokeDevice,
                    onTerminateOtherDevices = viewModel::terminateOtherDevices,
                    onStartAudioCall = viewModel::startAudioCall,
                    onStartVideoCall = viewModel::startVideoCall,
                    onAcceptCall = viewModel::acceptCall,
                    onDeclineCall = viewModel::declineCall,
                    onEndCall = viewModel::endCall,
                    onCallMuted = viewModel::setCallMuted,
                    onCallSpeaker = viewModel::setCallSpeaker,
                    onCallCamera = viewModel::setCallCamera,
                    onCallPermissionsGranted = viewModel::callMediaPermissionsGranted,
                    onCallVideoFrame = viewModel::sendCallVideoFrame,
                    onSignOut = { viewModel.dispatch(FedMesUiAction.SignOut) },
                )
            }

            FedMesApp(
                state = state,
                onAction = viewModel::dispatch,
                messengerActions = messengerActions,
                updateState = updateState,
                onInstallUpdate = {
                    lifecycleScope.launch { container.updateCoordinator.downloadAndInstall(this@MainActivity) }
                },
                onDismissUpdate = container.updateCoordinator::dismiss,
                onRecoveryKeyChanged = viewModel::updateRecoveryKeyInput,
                onRecoverAccount = viewModel::recoverAccount,
                onCancelRecovery = viewModel::cancelSecurityRecovery,
            )
        }
    }

    private companion object {
        const val NOTIFICATION_PERMISSION_REQUEST = 41
        const val UPDATE_CHECK_INTERVAL_MILLIS = 10L * 60L * 1000L
    }
}
