package com.fedmes.app.ui

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.createSavedStateHandle
import androidx.lifecycle.viewmodel.CreationExtras
import androidx.lifecycle.viewModelScope
import com.fedmes.app.di.AppContainer
import com.fedmes.app.accountsecurity.AccountSecurityException
import com.fedmes.app.messaging.MIN_ROUND_VIDEO_DURATION_MILLIS
import com.fedmes.app.messaging.AttachmentSelection
import com.fedmes.app.messaging.ChatSummary
import com.fedmes.app.messaging.CallMode
import com.fedmes.app.messaging.DecryptedMessage
import com.fedmes.app.messaging.MessageDeleteScope
import com.fedmes.app.messaging.MessageDeliveryState
import com.fedmes.app.messaging.MessageContent
import com.fedmes.app.messaging.MediaDescriptor
import com.fedmes.app.messaging.MessageKind
import com.fedmes.app.messaging.RecordedMedia
import com.fedmes.app.messaging.VideoPlaybackCache
import com.fedmes.app.messaging.OpenedAttachment
import com.fedmes.app.messaging.PresenceState
import com.fedmes.app.messaging.TextEntity
import com.fedmes.app.messaging.TypingState
import com.fedmes.app.messaging.normalizeFormattedText
import com.fedmes.app.messaging.remapTextEntitiesAfterEdit
import com.fedmes.app.messaging.sanitizeTextEntities
import com.fedmes.app.provisioning.ProvisioningException
import com.fedmes.app.provisioning.ProvisioningFailure
import com.fedmes.app.ui.model.FedMesScreen
import com.fedmes.app.ui.model.FedMesUiAction
import com.fedmes.app.ui.model.FedMesUiReducer
import com.fedmes.app.ui.model.FedMesUiState
import com.fedmes.app.ui.model.MessengerUiState
import com.fedmes.app.ui.model.ScannerPhase
import com.fedmes.app.ui.model.SettingsPage
import com.fedmes.app.ui.model.UploadTaskPhase
import com.fedmes.app.ui.model.UploadTaskUi
import com.fedmes.app.ui.theme.ThemeMode
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.withContext
import java.io.IOException
import java.util.UUID

class FedMesViewModel(
    private val savedStateHandle: SavedStateHandle,
    private val appContainer: AppContainer,
) : ViewModel() {
    private val restoredOnboardingScreen = savedStateHandle.get<String>(SCREEN_KEY)
        ?.let { saved -> FedMesScreen.entries.firstOrNull { it.name == saved } }
        ?.takeIf { it == FedMesScreen.QR_SIGN_IN || it == FedMesScreen.QR_SCANNER }
        ?: FedMesScreen.QR_SIGN_IN

    private val mutableState = MutableStateFlow(
        FedMesUiState(
            familyMembers = appContainer.familyDirectory.members(),
            themeMode = appContainer.userPreferences.themeMode(),
            messenger = MessengerUiState(
                showExactPresence = false,
                notificationsEnabled = appContainer.userPreferences.notificationsEnabled(),
                notificationSoundEnabled = appContainer.userPreferences.notificationSoundEnabled(),
                notificationVibrationEnabled = appContainer.userPreferences.notificationVibrationEnabled(),
                groupNotificationsEnabled = appContainer.userPreferences.groupNotificationsEnabled(),
            ),
        ),
    )
    private var provisioningJob: Job? = null
    private var restoreJob: Job? = null
    private var messengerLoadJob: Job? = null
    private var messengerSyncJob: Job? = null
    private var messengerEphemeralSyncJob: Job? = null
    private var typingJob: Job? = null
    private var prefetchJob: Job? = null
    private var jumpToMessageJob: Job? = null
    private var deviceManagementJob: Job? = null
    private var deviceHistorySyncJob: Job? = null
    private var lastDesktopLinkQrPayload: String? = null
    private var lastDesktopLinkQrAtMillis: Long = 0L
    private val messageCache = mutableMapOf<String, CachedMessages>()
    private val readCursorHighWater = mutableMapOf<String, Long>()
    // Optimistic UI overlay. Server snapshots and long-poll responses may arrive out of order;
    // these tombstones prevent a locally deleted message from flashing back for one frame.
    private val locallyDeletedMessageIds = mutableMapOf<String, MutableSet<String>>()
    // Monotonic local UI revision per chat. It lets a slow snapshot detect that send/delete
    // changed the visible list after the request started and prevents rollback to stale data.
    private val messageMutationGeneration = mutableMapOf<String, Long>()
    private val callScanHighWater = mutableMapOf<String, Long>()
    private var chatNavigationGeneration = 0L
    private val forwardBackStack = ArrayDeque<String>()
    private var draftBeforeEdit: String? = null
    private var draftSpoilerBeforeEdit: Boolean? = null
    private var draftTextEntitiesBeforeEdit: List<TextEntity>? = null
    private val uploadJobs = mutableMapOf<String, Job>()

    val state: StateFlow<FedMesUiState> = mutableState.asStateFlow()

    init {
        viewModelScope.launch {
            appContainer.callCoordinator.state.collect { call ->
                updateMessenger { it.copy(call = call) }
            }
        }
        restoreSession()
    }

    fun dispatch(action: FedMesUiAction) {
        when (action) {
            is FedMesUiAction.QrDecoded -> beginProvisioning(action)
            FedMesUiAction.SignOut -> signOut()
            FedMesUiAction.UseNewQr -> signOut()
            FedMesUiAction.RetrySessionRestore -> {
                applyAction(action)
                restoreSession()
            }
            else -> applyAction(action)
        }
    }

    fun setThemeMode(mode: ThemeMode) {
        appContainer.userPreferences.setThemeMode(mode)
        mutableState.value = mutableState.value.copy(themeMode = mode)
    }

    fun setShowExactPresence(showExact: Boolean) {
        // FedMes 3.0.0 no longer exposes exact last-seen timestamps. Keep the
        // compatibility callback for older UI callers, but persist/send only false.
        appContainer.userPreferences.setShowExactPresence(false)
        updateMessenger { it.copy(showExactPresence = false) }
        viewModelScope.launch {
            runCatching {
                withContext(Dispatchers.IO) {
                    appContainer.messagingRepository.heartbeat(false)
                }
            }.onFailure { error ->
                if (error is CancellationException) throw error
                showMessengerError(error as? Exception ?: IllegalStateException("Presence update failed"))
            }
        }
    }

    fun startAudioCall() = startCall(CallMode.AUDIO)

    fun startVideoCall() {
        val chatId = mutableState.value.messenger.selectedChatId ?: return
        val chat = mutableState.value.messenger.chats.firstOrNull { it.id == chatId } ?: return
        startCall(if (chat.kind == "group") CallMode.GROUP else CallMode.VIDEO)
    }

    private fun startCall(mode: CallMode) {
        val messenger = mutableState.value.messenger
        val chatId = messenger.selectedChatId ?: return
        val chat = messenger.chats.firstOrNull { it.id == chatId } ?: return
        viewModelScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    appContainer.callCoordinator.startOutgoing(chatId, chat.title.ifBlank { "FedMes" }, mode)
                }
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                showMessengerError(error)
            }
        }
    }

    fun acceptCall() {
        viewModelScope.launch {
            runCatching { withContext(Dispatchers.IO) { appContainer.callCoordinator.acceptIncoming() } }
                .onFailure { if (it !is CancellationException) showMessengerError(it as? Exception ?: IllegalStateException("Call accept failed")) }
        }
    }

    fun declineCall() {
        viewModelScope.launch { withContext(Dispatchers.IO) { appContainer.callCoordinator.declineIncoming() } }
    }

    fun endCall() {
        viewModelScope.launch { withContext(Dispatchers.IO) { appContainer.callCoordinator.endCall() } }
    }

    fun setCallMuted(muted: Boolean) = appContainer.callCoordinator.setMuted(muted)
    fun setCallSpeaker(enabled: Boolean) = appContainer.callCoordinator.setSpeaker(enabled)
    fun setCallCamera(enabled: Boolean) = appContainer.callCoordinator.setCameraEnabled(enabled)
    fun callMediaPermissionsGranted() = appContainer.callCoordinator.onMediaPermissionsGranted()
    fun sendCallVideoFrame(jpeg: ByteArray) = appContainer.callCoordinator.sendVideoFrame(jpeg)

    fun openSettings() {
        val username = mutableState.value.account?.username
        updateMessenger {
            it.copy(
                settingsPage = SettingsPage.ROOT,
                profileAvatarUri = username?.let(appContainer.userPreferences::profileAvatarUri),
                profileAvatarMimeType = username?.let(appContainer.userPreferences::profileAvatarMimeType),
                profileNameColorArgb = username?.let(appContainer.userPreferences::profileNameColorArgb) ?: 0L,
                selectedMessageIds = emptySet(),
                error = null,
            )
        }
        refreshDevices(silent = true)
    }

    fun closeSettings() {
        deviceManagementJob?.cancel()
        updateMessenger {
            it.copy(
                settingsPage = SettingsPage.NONE,
                deviceLinkScannerPhase = ScannerPhase.SCANNING,
                deviceLinkFailure = null,
                deviceLinkPreview = null,
                deviceLinkApproving = false,
            )
        }
    }

    fun openProfile() {
        val username = mutableState.value.account?.username ?: return
        updateMessenger {
            it.copy(
                settingsPage = SettingsPage.PROFILE,
                profileAvatarUri = appContainer.userPreferences.profileAvatarUri(username),
                profileAvatarMimeType = appContainer.userPreferences.profileAvatarMimeType(username),
                profileNameColorArgb = appContainer.userPreferences.profileNameColorArgb(username),
                error = null,
            )
        }
    }

    fun setProfileMedia(selection: AttachmentSelection) {
        val username = mutableState.value.account?.username ?: return
        viewModelScope.launch {
            try {
                val persisted = withContext(Dispatchers.IO) {
                    appContainer.deviceAttachmentRepository.persistProfileMedia(selection.item, username)
                }
                appContainer.userPreferences.setProfileAvatar(username, persisted.uri, persisted.mimeType)
                updateMessenger {
                    it.copy(profileAvatarUri = persisted.uri, profileAvatarMimeType = persisted.mimeType, error = null)
                }
            } catch (error: Exception) {
                showMessengerError(error)
            }
        }
    }

    fun clearProfileMedia() {
        val username = mutableState.value.account?.username ?: return
        appContainer.userPreferences.setProfileAvatar(username, null, null)
        updateMessenger { it.copy(profileAvatarUri = null, profileAvatarMimeType = null) }
    }

    fun setProfileNameColor(argb: Long) {
        val username = mutableState.value.account?.username ?: return
        appContainer.userPreferences.setProfileNameColorArgb(username, argb)
        updateMessenger { it.copy(profileNameColorArgb = argb) }
    }

    fun openSecurity() {
        val account = appContainer.sessionStore.loadAccount() ?: return
        updateMessenger {
            it.copy(
                settingsPage = SettingsPage.SECURITY,
                securityLoading = true,
                generatedRecoveryKey = null,
                securitySettingsError = null,
            )
        }
        viewModelScope.launch {
            try {
                val securitySnapshot = withContext(Dispatchers.IO) {
                    val security = appContainer.accountSecurityCoordinator.getSecurityState(account)
                    val pendingRecoveryKey = appContainer.accountSecurityCoordinator.pendingRecoveryKey(account)
                    val pendingDevices = if (security.state == com.fedmes.app.accountsecurity.AccountSecurityProtocol.STATE_READY) {
                        appContainer.deviceProvisioningCoordinator.listPending(account)
                    } else {
                        emptyList()
                    }
                    Triple(security, pendingRecoveryKey, pendingDevices)
                }
                val (security, pendingRecoveryKey, pendingDevices) = securitySnapshot
                updateMessenger {
                    it.copy(
                        securityLoading = false,
                        recoveryConfigured = security.recoveryConfigured,
                        opaqueEnrolled = security.opaqueEnrolled,
                        pendingDeviceRequests = pendingDevices,
                        generatedRecoveryKey = pendingRecoveryKey,
                        securitySettingsError = null,
                    )
                }
            } catch (error: AccountSecurityException) {
                updateMessenger {
                    it.copy(securityLoading = false, securitySettingsError = securityErrorText(error.code))
                }
            } catch (_: Exception) {
                updateMessenger {
                    it.copy(securityLoading = false, securitySettingsError = "Не удалось загрузить состояние безопасности")
                }
            }
        }
    }

    fun generateRecoveryKey() {
        val account = appContainer.sessionStore.loadAccount() ?: return
        if (mutableState.value.messenger.securityLoading) return
        updateMessenger { it.copy(securityLoading = true, securitySettingsError = null) }
        viewModelScope.launch {
            try {
                val recoveryKey = withContext(Dispatchers.IO) {
                    appContainer.accountSecurityCoordinator.enrollRecovery(account)
                }
                updateMessenger {
                    it.copy(
                        securityLoading = false,
                        recoveryConfigured = true,
                        generatedRecoveryKey = recoveryKey,
                        securitySettingsError = null,
                    )
                }
            } catch (error: AccountSecurityException) {
                updateMessenger {
                    it.copy(securityLoading = false, securitySettingsError = securityErrorText(error.code))
                }
            } catch (_: Exception) {
                updateMessenger {
                    it.copy(
                        securityLoading = false,
                        securitySettingsError = "Не удалось создать Recovery Key. Существующие ключи не изменены.",
                    )
                }
            }
        }
    }

    fun confirmRecoveryKeySaved() {
        val account = appContainer.sessionStore.loadAccount() ?: return
        viewModelScope.launch {
            withContext(Dispatchers.IO) {
                appContainer.accountSecurityCoordinator.confirmRecoveryKeySaved(account)
            }
            updateMessenger { it.copy(generatedRecoveryKey = null, recoveryConfigured = true) }
        }
    }

    fun configureOpaquePassword(password: String) {
        val account = appContainer.sessionStore.loadAccount() ?: return
        if (password.length < 12 || password.length > 256 || mutableState.value.messenger.securityLoading) {
            updateMessenger { it.copy(securitySettingsError = "Парольная фраза должна содержать от 12 до 256 символов") }
            return
        }
        val change = mutableState.value.messenger.opaqueEnrolled
        updateMessenger { it.copy(securityLoading = true, securitySettingsError = null) }
        viewModelScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    if (change) appContainer.opaqueAuthCoordinator.changePassword(account, password.toCharArray())
                    else appContainer.opaqueAuthCoordinator.enroll(account, password.toCharArray())
                }
                updateMessenger { it.copy(securityLoading = false, opaqueEnrolled = true, securitySettingsError = null) }
            } catch (error: AccountSecurityException) {
                updateMessenger { it.copy(securityLoading = false, securitySettingsError = securityErrorText(error.code)) }
            } catch (_: Exception) {
                updateMessenger { it.copy(securityLoading = false, securitySettingsError = "Не удалось сохранить парольную фразу. Существующие ключи не изменены.") }
            }
        }
    }

    fun approvePendingDevice(requestId: String) {
        val account = appContainer.sessionStore.loadAccount() ?: return
        val request = mutableState.value.messenger.pendingDeviceRequests.firstOrNull { it.id == requestId } ?: return
        updateMessenger { it.copy(securityLoading = true, securitySettingsError = null) }
        viewModelScope.launch {
            try {
                withContext(Dispatchers.IO) { appContainer.deviceProvisioningCoordinator.approve(account, request) }
                openSecurity()
            } catch (error: AccountSecurityException) {
                updateMessenger { it.copy(securityLoading = false, securitySettingsError = securityErrorText(error.code)) }
            } catch (_: Exception) {
                updateMessenger { it.copy(securityLoading = false, securitySettingsError = "Не удалось подтвердить устройство") }
            }
        }
    }

    fun rejectPendingDevice(requestId: String) {
        val account = appContainer.sessionStore.loadAccount() ?: return
        updateMessenger { it.copy(securityLoading = true, securitySettingsError = null) }
        viewModelScope.launch {
            try {
                withContext(Dispatchers.IO) { appContainer.deviceProvisioningCoordinator.reject(account, requestId) }
                openSecurity()
            } catch (_: Exception) {
                updateMessenger { it.copy(securityLoading = false, securitySettingsError = "Не удалось отклонить устройство") }
            }
        }
    }

    fun openNotifications() {
        updateMessenger { it.copy(settingsPage = SettingsPage.NOTIFICATIONS, error = null) }
    }

    fun setNotificationsEnabled(enabled: Boolean) {
        appContainer.userPreferences.setNotificationsEnabled(enabled)
        updateMessenger { it.copy(notificationsEnabled = enabled) }
    }

    fun setNotificationSoundEnabled(enabled: Boolean) {
        appContainer.userPreferences.setNotificationSoundEnabled(enabled)
        updateMessenger { it.copy(notificationSoundEnabled = enabled) }
    }

    fun setNotificationVibrationEnabled(enabled: Boolean) {
        appContainer.userPreferences.setNotificationVibrationEnabled(enabled)
        updateMessenger { it.copy(notificationVibrationEnabled = enabled) }
    }

    fun setGroupNotificationsEnabled(enabled: Boolean) {
        appContainer.userPreferences.setGroupNotificationsEnabled(enabled)
        updateMessenger { it.copy(groupNotificationsEnabled = enabled) }
    }

    fun openDevices() {
        updateMessenger { it.copy(settingsPage = SettingsPage.DEVICES, error = null) }
        refreshDevices()
    }

    fun backFromDevices() {
        updateMessenger { it.copy(settingsPage = SettingsPage.ROOT, error = null) }
    }

    fun startDesktopLinkScan() {
        updateMessenger {
            it.copy(
                settingsPage = SettingsPage.DEVICE_LINK_SCANNER,
                deviceLinkScannerPhase = ScannerPhase.SCANNING,
                deviceLinkFailure = null,
                deviceLinkPreview = null,
                error = null,
            )
        }
    }

    fun closeDesktopLinkFlow() {
        deviceManagementJob?.cancel()
        updateMessenger {
            it.copy(
                settingsPage = SettingsPage.DEVICES,
                deviceLinkScannerPhase = ScannerPhase.SCANNING,
                deviceLinkFailure = null,
                deviceLinkPreview = null,
                deviceLinkApproving = false,
            )
        }
    }

    fun retryDesktopLinkScanner() {
        lastDesktopLinkQrPayload = null
        lastDesktopLinkQrAtMillis = 0L
        updateMessenger {
            it.copy(
                settingsPage = SettingsPage.DEVICE_LINK_SCANNER,
                deviceLinkScannerPhase = ScannerPhase.SCANNING,
                deviceLinkFailure = null,
                deviceLinkPreview = null,
                error = null,
            )
        }
    }

    fun deviceLinkCameraFailed() {
        updateMessenger {
            it.copy(
                deviceLinkScannerPhase = ScannerPhase.ERROR,
                deviceLinkFailure = ProvisioningFailure.CAMERA,
                error = "Не удалось открыть камеру",
            )
        }
    }

    fun handleDesktopLinkQr(rawPayload: String) {
        val normalizedPayload = rawPayload.trim()
        if (normalizedPayload.isEmpty()) return
        val current = mutableState.value.messenger
        if (current.settingsPage != SettingsPage.DEVICE_LINK_SCANNER ||
            current.deviceLinkScannerPhase != ScannerPhase.SCANNING
        ) return
        val now = System.currentTimeMillis()
        if (normalizedPayload == lastDesktopLinkQrPayload && now - lastDesktopLinkQrAtMillis < 2_000L) return
        lastDesktopLinkQrPayload = normalizedPayload
        lastDesktopLinkQrAtMillis = now
        deviceManagementJob?.cancel()
        updateMessenger { it.copy(deviceLinkScannerPhase = ScannerPhase.PROCESSING, error = null) }
        deviceManagementJob = viewModelScope.launch {
            try {
                val preview = withContext(Dispatchers.IO) {
                    appContainer.deviceManagerRepository.preview(normalizedPayload)
                }
                updateMessenger {
                    it.copy(
                        settingsPage = SettingsPage.DEVICE_LINK_APPROVAL,
                        deviceLinkScannerPhase = ScannerPhase.SCANNING,
                        deviceLinkFailure = null,
                        deviceLinkPreview = preview,
                        deviceLinkApproving = false,
                    )
                }
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                lastDesktopLinkQrPayload = null
                lastDesktopLinkQrAtMillis = 0L
                updateMessenger {
                    it.copy(
                        settingsPage = SettingsPage.DEVICE_LINK_SCANNER,
                        deviceLinkScannerPhase = ScannerPhase.ERROR,
                        deviceLinkFailure = when (error) {
                            is IllegalArgumentException -> ProvisioningFailure.INVALID_QR
                            is IOException -> ProvisioningFailure.NETWORK
                            else -> ProvisioningFailure.SERVER
                        },
                        error = error.message ?: "QR входа отклонён",
                    )
                }
            }
        }
    }

    fun approveDesktopLink() {
        val preview = mutableState.value.messenger.deviceLinkPreview ?: return
        if (mutableState.value.messenger.deviceLinkApproving) return
        deviceManagementJob?.cancel()
        updateMessenger { it.copy(deviceLinkApproving = true, error = null) }
        deviceManagementJob = viewModelScope.launch {
            try {
                val linkedDevice = withContext(Dispatchers.IO) {
                    appContainer.deviceManagerRepository.approve(preview)
                }
                val devices = withContext(Dispatchers.IO) {
                    runCatching { appContainer.deviceManagerRepository.listDevices() }
                        .getOrElse { listOf(linkedDevice) }
                }
                updateMessenger {
                    it.copy(
                        settingsPage = SettingsPage.DEVICES,
                        accountDevices = devices,
                        devicesLoading = false,
                        deviceLinkScannerPhase = ScannerPhase.SCANNING,
                        deviceLinkFailure = null,
                        deviceLinkPreview = null,
                        deviceLinkApproving = false,
                        deviceHistorySyncing = true,
                    )
                }
                deviceHistorySyncJob?.cancel()
                deviceHistorySyncJob = launch {
                    try {
                        withContext(Dispatchers.IO) {
                            appContainer.deviceManagerRepository.synchronizeHistoryForLinkedDevice()
                        }
                    } catch (error: CancellationException) {
                        throw error
                    } catch (error: Exception) {
                        showMessengerError(error)
                    } finally {
                        updateMessenger { it.copy(deviceHistorySyncing = false) }
                    }
                }
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                updateMessenger { it.copy(deviceLinkApproving = false) }
                showMessengerError(error)
            }
        }
    }

    fun refreshDevices(silent: Boolean = false) {
        deviceManagementJob?.cancel()
        if (!silent) updateMessenger { it.copy(devicesLoading = true, error = null) }
        deviceManagementJob = viewModelScope.launch {
            try {
                val devices = withContext(Dispatchers.IO) {
                    appContainer.deviceManagerRepository.listDevices()
                }
                updateMessenger { it.copy(accountDevices = devices, devicesLoading = false) }
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                updateMessenger { it.copy(devicesLoading = false) }
                if (!silent) showMessengerError(error)
            }
        }
    }

    fun revokeDevice(deviceId: String) {
        deviceManagementJob?.cancel()
        updateMessenger { it.copy(devicesLoading = true, error = null) }
        deviceManagementJob = viewModelScope.launch {
            try {
                withContext(Dispatchers.IO) { appContainer.deviceManagerRepository.revoke(deviceId) }
                val devices = withContext(Dispatchers.IO) { appContainer.deviceManagerRepository.listDevices() }
                updateMessenger { it.copy(accountDevices = devices, devicesLoading = false) }
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                updateMessenger { it.copy(devicesLoading = false) }
                showMessengerError(error)
            }
        }
    }

    fun terminateOtherDevices() {
        deviceManagementJob?.cancel()
        updateMessenger { it.copy(devicesLoading = true, error = null) }
        deviceManagementJob = viewModelScope.launch {
            try {
                withContext(Dispatchers.IO) { appContainer.deviceManagerRepository.terminateOthers() }
                val devices = withContext(Dispatchers.IO) { appContainer.deviceManagerRepository.listDevices() }
                updateMessenger { it.copy(accountDevices = devices, devicesLoading = false) }
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                updateMessenger { it.copy(devicesLoading = false) }
                showMessengerError(error)
            }
        }
    }

    fun openChat(chatId: String) {
        forwardBackStack.clear()
        openChatInternal(chatId)
    }

    private fun openChatInternal(chatId: String) {
        chatNavigationGeneration++
        jumpToMessageJob?.cancel()
        savedStateHandle[CHAT_KEY] = chatId
        val cached = messageCache[chatId]
        updateMessenger {
            it.copy(
                selectedChatId = chatId,
                messages = cached?.messages.orEmpty().filterNot { message -> isLocallyDeleted(chatId, message.id) },
                loading = cached == null,
                loadingOlder = false,
                hasMoreOlder = cached?.hasMoreOlder ?: false,
                selectedMessageIds = emptySet(),
                typingUsers = emptySet(),
                error = null,
                scrollToBottomToken = it.scrollToBottomToken + 1,
                jumpToMessageId = null,
            )
        }
        loadInitialChat(chatId)
    }

    fun closeChat() {
        val previousForwardChat = forwardBackStack.removeLastOrNull()
        if (previousForwardChat != null) {
            openChatInternal(previousForwardChat)
            return
        }
        chatNavigationGeneration++
        jumpToMessageJob?.cancel()
        draftBeforeEdit = null
        val chatId = mutableState.value.messenger.selectedChatId
        typingJob?.cancel()
        if (chatId != null) {
            viewModelScope.launch(Dispatchers.IO) {
                runCatching { appContainer.messagingRepository.setTyping(chatId, false) }
            }
        }
        mutableState.value.messenger.openedAttachment?.plaintext?.fill(0)
        savedStateHandle.remove<String>(CHAT_KEY)
        updateMessenger {
            it.copy(
                selectedChatId = null,
                messages = emptyList(),
                draft = "",
                replyToId = null,
                editingMessageId = null,
                selectedMessageIds = emptySet(),
                openedAttachment = null,
                downloadingAttachmentId = null,
                typingUsers = emptySet(),
                loadingOlder = false,
                hasMoreOlder = false,
                jumpToMessageId = null,
            )
        }
    }

    fun jumpToMessage(messageId: String) {
        val initial = mutableState.value.messenger
        val chatId = initial.selectedChatId ?: return
        jumpToMessageJob?.cancel()
        jumpToMessageJob = viewModelScope.launch {
            var messages = mutableState.value.messenger.messages
            var hasMore = mutableState.value.messenger.hasMoreOlder
            if (messages.none { it.id == messageId }) {
                updateMessenger { current ->
                    if (current.selectedChatId == chatId) current.copy(loadingOlder = true) else current
                }
                try {
                    while (hasMore && messages.none { it.id == messageId }) {
                        ensureActive()
                        val before = messages.firstOrNull()?.sequence ?: break
                        val page = withContext(Dispatchers.IO) {
                            appContainer.messagingRepository.loadOlderMessages(chatId, before)
                        }
                        val existingIDs = messages.asSequence().map(DecryptedMessage::id).toHashSet()
                        val older = page.messages.filterNot { it.id in existingIDs || isLocallyDeleted(chatId, it.id) }
                        messages = older + messages
                        hasMore = page.hasMoreBefore
                        messageCache[chatId] = CachedMessages(messages, hasMore)
                        updateMessenger { current ->
                            if (current.selectedChatId != chatId) current else current.copy(
                                messages = messages,
                                hasMoreOlder = hasMore,
                                loadingOlder = hasMore && messages.none { it.id == messageId },
                            )
                        }
                        if (older.isEmpty()) break
                    }
                } catch (error: CancellationException) {
                    throw error
                } catch (error: Exception) {
                    showMessengerError(error)
                } finally {
                    updateMessenger { current ->
                        if (current.selectedChatId == chatId) current.copy(loadingOlder = false) else current
                    }
                }
            }
            val found = mutableState.value.messenger.messages.any { it.id == messageId }
            if (found) {
                updateMessenger { current ->
                    if (current.selectedChatId != chatId) current else current.copy(
                        jumpToMessageId = messageId,
                        jumpToMessageToken = current.jumpToMessageToken + 1,
                    )
                }
            } else {
                showMessengerError(IllegalStateException("Исходное сообщение недоступно"))
            }
        }
    }

    fun loadOlderMessages() {
        val messenger = mutableState.value.messenger
        val chatId = messenger.selectedChatId ?: return
        val before = messenger.messages.firstOrNull()?.sequence ?: return
        if (messenger.loadingOlder || !messenger.hasMoreOlder) return
        updateMessenger { it.copy(loadingOlder = true) }
        viewModelScope.launch {
            try {
                val page = withContext(Dispatchers.IO) {
                    appContainer.messagingRepository.loadOlderMessages(chatId, before)
                }
                updateMessenger { current ->
                    if (current.selectedChatId != chatId) return@updateMessenger current
                    val existingIDs = current.messages.asSequence().map(DecryptedMessage::id).toHashSet()
                    val older = page.messages.filterNot { it.id in existingIDs || isLocallyDeleted(chatId, it.id) }
                    val merged = older + current.messages
                    messageCache[chatId] = CachedMessages(merged, page.hasMoreBefore)
                    current.copy(
                        messages = merged,
                        loadingOlder = false,
                        hasMoreOlder = page.hasMoreBefore,
                    )
                }
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                showMessengerError(error)
                updateMessenger { it.copy(loadingOlder = false) }
            }
        }
    }

    fun markVisibleMessagesRead(messageIds: Set<String>) {
        if (messageIds.isEmpty()) return
        val messenger = mutableState.value.messenger
        val chatId = messenger.selectedChatId ?: return
        val username = mutableState.value.account?.username ?: return
        val maxSequence = messenger.messages.asSequence()
            .filter { message ->
                message.id in messageIds &&
                    message.senderUsername != username &&
                    message.decryptable
            }
            .maxOfOrNull(DecryptedMessage::sequence)
            ?: return
        val previous = readCursorHighWater[chatId] ?: 0L
        if (maxSequence <= previous) return
        readCursorHighWater[chatId] = maxSequence
        appContainer.userPreferences.setLastReadSequence(username, chatId, maxSequence)
        updateMessenger { state ->
            state.copy(unreadCounts = state.unreadCounts + (chatId to 0))
        }
        viewModelScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    appContainer.messagingRepository.markMessagesRead(
                        chatId,
                        messenger.messages.filter { it.sequence <= maxSequence },
                    )
                }
            } catch (error: CancellationException) {
                throw error
            } catch (_: Exception) {
                if (readCursorHighWater[chatId] == maxSequence) {
                    readCursorHighWater[chatId] = previous
                }
            }
        }
    }

    fun updateDraft(value: String) {
        val current = mutableState.value.messenger
        updateDraft(
            value,
            remapTextEntitiesAfterEdit(current.draft, value, current.draftTextEntities),
        )
    }

    fun updateDraft(value: String, textEntities: List<TextEntity>) {
        val normalized = value.take(MAX_DRAFT_LENGTH)
        val safeEntities = sanitizeTextEntities(normalized, textEntities)
        updateMessenger { it.copy(draft = normalized, draftTextEntities = safeEntities) }
        updateTypingLoop(normalized.isNotBlank())
    }

    fun toggleDraftSpoiler() {
        updateMessenger { it.copy(draftSpoiler = !it.draftSpoiler) }
    }

    fun replyTo(messageId: String) {
        updateMessenger { it.copy(replyToId = messageId, editingMessageId = null) }
    }

    fun editMessage(message: DecryptedMessage) {
        if (message.senderUsername != mutableState.value.account?.username || message.content.kind != MessageKind.TEXT) {
            return
        }
        if (mutableState.value.messenger.editingMessageId == null) {
            draftBeforeEdit = mutableState.value.messenger.draft
            draftSpoilerBeforeEdit = mutableState.value.messenger.draftSpoiler
            draftTextEntitiesBeforeEdit = mutableState.value.messenger.draftTextEntities
        }
        updateMessenger {
            it.copy(
                editingMessageId = message.id,
                replyToId = message.content.replyToId,
                draft = message.content.text,
                draftSpoiler = message.content.spoiler,
                draftTextEntities = message.content.textEntities,
                selectedMessageIds = emptySet(),
            )
        }
        updateTypingLoop(true)
    }

    fun cancelComposerMode() {
        updateMessenger { current ->
            val editing = current.editingMessageId != null
            val restoredDraft = if (editing) draftBeforeEdit.orEmpty() else current.draft
            val restoredSpoiler = if (editing) draftSpoilerBeforeEdit ?: false else current.draftSpoiler
            val restoredEntities = if (editing) draftTextEntitiesBeforeEdit.orEmpty() else current.draftTextEntities
            draftBeforeEdit = null
            draftSpoilerBeforeEdit = null
            draftTextEntitiesBeforeEdit = null
            current.copy(
                replyToId = null,
                editingMessageId = null,
                draft = restoredDraft,
                draftSpoiler = restoredSpoiler,
                draftTextEntities = restoredEntities,
            )
        }
    }

    fun sendCurrentMessage() {
        val messenger = mutableState.value.messenger
        val chatId = messenger.selectedChatId ?: return
        val normalized = normalizeFormattedText(messenger.draft, messenger.draftTextEntities)
        val text = normalized.text
        if (text.isEmpty()) return
        val wasEditing = messenger.editingMessageId != null
        if (wasEditing && messenger.sending) return
        val draftAfterSend = if (wasEditing) draftBeforeEdit.orEmpty() else ""
        val spoilerAfterSend = if (wasEditing) draftSpoilerBeforeEdit ?: false else false
        val entitiesAfterSend = if (wasEditing) draftTextEntitiesBeforeEdit.orEmpty() else emptyList()
        val account = mutableState.value.account ?: return
        val pendingId = if (wasEditing) null else appContainer.messagingRepository.allocateOutgoingMessageId(chatId)
        val pendingMessage = pendingId?.let { id ->
            DecryptedMessage(
                sequence = (messenger.messages.maxOfOrNull(DecryptedMessage::sequence) ?: 0L) + 1L,
                id = id,
                chatId = chatId,
                senderUsername = account.username,
                senderDeviceId = account.deviceId,
                content = MessageContent(
                    kind = MessageKind.TEXT,
                    text = text,
                    replyToId = messenger.replyToId,
                    media = null,
                    spoiler = messenger.draftSpoiler,
                    textEntities = normalized.entities,
                ),
                createdAt = System.currentTimeMillis(),
                editedAt = null,
                decryptable = true,
                envelopeDeviceIds = emptySet(),
                deliveryState = MessageDeliveryState.PENDING,
            )
        }
        if (pendingMessage != null) markMessageMutation(chatId)
        updateMessenger { current ->
            current.copy(
                // Normal text sends are optimistic and never lock the composer. Edits remain
                // single-flight because they mutate an existing ratchet-backed object.
                sending = wasEditing,
                error = null,
                draft = if (wasEditing) current.draft else "",
                draftSpoiler = if (wasEditing) current.draftSpoiler else false,
                draftTextEntities = if (wasEditing) current.draftTextEntities else emptyList(),
                replyToId = if (wasEditing) current.replyToId else null,
                messages = pendingMessage?.let { current.messages + it } ?: current.messages,
                scrollToBottomToken = if (pendingMessage != null) current.scrollToBottomToken + 1 else current.scrollToBottomToken,
            )
        }
        stopTyping(chatId)
        if (!wasEditing && pendingMessage != null) appContainer.interfaceSoundPlayer.playSend()
        viewModelScope.launch {
            try {
                val sentMessage = withContext(Dispatchers.IO) {
                    if (messenger.editingMessageId == null) {
                        appContainer.messagingRepository.sendTextMessage(
                            chatId = chatId,
                            text = text,
                            replyToId = messenger.replyToId,
                            spoiler = messenger.draftSpoiler,
                            textEntities = normalized.entities,
                            messageId = requireNotNull(pendingId),
                        )
                    } else {
                        appContainer.messagingRepository.editText(
                            chatId = chatId,
                            messageId = messenger.editingMessageId,
                            text = text,
                            replyToId = messenger.replyToId,
                            spoiler = messenger.draftSpoiler,
                            textEntities = normalized.entities,
                        )
                        null
                    }
                }
                draftBeforeEdit = null
                draftSpoilerBeforeEdit = null
                draftTextEntitiesBeforeEdit = null
                if (sentMessage != null) markMessageMutation(chatId)
                updateMessenger { current ->
                    val chatStillSelected = current.selectedChatId == chatId
                    val nextMessages = if (chatStillSelected) {
                        sentMessage?.let { message ->
                            (current.messages.filterNot { it.id == message.id } + message)
                                .sortedBy(DecryptedMessage::sequence)
                        } ?: current.messages
                    } else {
                        current.messages
                    }
                    val nextChats = sentMessage?.let { message ->
                        current.chats.map { chat ->
                            if (chat.id == chatId) {
                                chat.copy(
                                    lastSequence = maxOf(chat.lastSequence, message.sequence),
                                    lastMessageAt = message.createdAt,
                                )
                            } else chat
                        }
                    } ?: current.chats
                    val nextPreviews = sentMessage?.let { message ->
                        current.previews + (chatId to message.previewText())
                    } ?: current.previews
                    current.copy(
                        sending = false,
                        // For a normal optimistic send the composer was cleared before the request.
                        // Never overwrite text the user typed while this message was in flight.
                        draft = if (chatStillSelected && wasEditing) draftAfterSend else current.draft,
                        draftSpoiler = if (chatStillSelected && wasEditing) spoilerAfterSend else current.draftSpoiler,
                        draftTextEntities = if (chatStillSelected && wasEditing) entitiesAfterSend else current.draftTextEntities,
                        replyToId = if (chatStillSelected && wasEditing) null else current.replyToId,
                        editingMessageId = if (chatStillSelected && wasEditing) null else current.editingMessageId,
                        chats = nextChats,
                        messages = nextMessages,
                        previews = nextPreviews,
                        scrollToBottomToken = if (chatStillSelected && !wasEditing) {
                            current.scrollToBottomToken + 1
                        } else {
                            current.scrollToBottomToken
                        },
                    )
                }
                if (sentMessage != null) {
                    val cached = messageCache[chatId]
                    val baseMessages = cached?.messages ?: messenger.messages
                    messageCache[chatId] = CachedMessages(
                        messages = (baseMessages.filterNot { it.id == sentMessage.id } + sentMessage)
                            .sortedBy(DecryptedMessage::sequence),
                        hasMoreOlder = cached?.hasMoreOlder ?: messenger.hasMoreOlder,
                    )
                }
                if (wasEditing) syncMessenger(showLoading = false)
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                updateMessenger { current ->
                    val chatStillSelected = current.selectedChatId == chatId
                    val withoutPending = if (chatStillSelected) {
                        pendingId?.let { id -> current.messages.filterNot { it.id == id } } ?: current.messages
                    } else {
                        current.messages
                    }
                    current.copy(
                        sending = false,
                        messages = withoutPending,
                        draft = if (chatStillSelected && !wasEditing && current.draft.isBlank()) messenger.draft else current.draft,
                        draftSpoiler = if (chatStillSelected && !wasEditing && current.draft.isBlank()) messenger.draftSpoiler else current.draftSpoiler,
                        draftTextEntities = if (chatStillSelected && !wasEditing && current.draft.isBlank()) normalized.entities else current.draftTextEntities,
                    )
                }
                showMessengerError(error)
            }
        }
    }

    fun sendAttachment(fileName: String, mimeType: String, bytes: ByteArray) {
        val messenger = mutableState.value.messenger
        val chatId = messenger.selectedChatId ?: run {
            bytes.fill(0)
            return
        }
        val taskId = UUID.randomUUID().toString()
        addUploadTask(
            UploadTaskUi(
                id = taskId,
                chatId = chatId,
                title = fileName,
                completedItems = 0,
                totalItems = 1,
                phase = UploadTaskPhase.UPLOADING,
            ),
        )
        stopTyping(chatId)
        val job = viewModelScope.launch {
            try {
                val sentMessage = runInterruptible(Dispatchers.IO) {
                    appContainer.messagingRepository.sendAttachmentMessage(
                        chatId = chatId,
                        fileName = fileName,
                        mimeType = mimeType,
                        plaintext = bytes,
                        caption = messenger.draft,
                        replyToId = messenger.replyToId,
                        captionEntities = messenger.draftTextEntities,
                    )
                }
                updateUploadProgress(taskId, 1, UploadTaskPhase.UPLOADING)
                clearComposerAfterUpload(chatId, messenger.draft)
                commitSentMessage(chatId, sentMessage)
                removeUploadTask(taskId)
                appContainer.interfaceSoundPlayer.playSend()
            } catch (error: CancellationException) {
                removeUploadTask(taskId)
                throw error
            } catch (error: Exception) {
                removeUploadTask(taskId)
                showMessengerError(error)
            } finally {
                bytes.fill(0)
                uploadJobs.remove(taskId)
            }
        }
        uploadJobs[taskId] = job
    }

    fun sendAttachments(selections: List<AttachmentSelection>) {
        val messenger = mutableState.value.messenger
        val chatId = messenger.selectedChatId ?: return
        val normalized = selections.take(MAX_ATTACHMENT_SELECTION)
        if (normalized.isEmpty()) return
        val taskId = UUID.randomUUID().toString()
        val title = when (normalized.size) {
            1 -> normalized.first().item.name
            else -> "Медиа и файлы: ${normalized.size}"
        }
        addUploadTask(
            UploadTaskUi(
                id = taskId,
                chatId = chatId,
                title = title,
                completedItems = 0,
                totalItems = normalized.size,
                phase = UploadTaskPhase.PREPARING,
            ),
        )
        stopTyping(chatId)
        val job = viewModelScope.launch {
            try {
                val sentMessages = withContext(Dispatchers.IO) {
                    val completedMessages = mutableListOf<DecryptedMessage>()
                    val selectionBatches = mutableListOf<List<AttachmentSelection>>()
                    var mediaBatch = mutableListOf<AttachmentSelection>()
                    fun flushMedia() {
                        if (mediaBatch.isNotEmpty()) {
                            selectionBatches += mediaBatch.toList()
                            mediaBatch = mutableListOf()
                        }
                    }
                    normalized.forEach { selection ->
                        val media = !selection.sendAsFile &&
                            (selection.item.mimeType.startsWith("image/") || selection.item.mimeType.startsWith("video/"))
                        if (!media) {
                            flushMedia()
                            selectionBatches += listOf(selection)
                        } else {
                            mediaBatch += selection
                            if (mediaBatch.size == MAX_MEDIA_PER_MESSAGE) flushMedia()
                        }
                    }
                    flushMedia()

                    var preparedItems = 0
                    var sentItems = 0
                    selectionBatches.forEachIndexed { index, batchSelections ->
                        ensureActive()
                        val preparedBatch = mutableListOf<com.fedmes.app.messaging.PreparedLocalAttachment>()
                        try {
                            batchSelections.forEach { selection ->
                                ensureActive()
                                preparedBatch += appContainer.deviceAttachmentRepository.prepare(selection)
                                preparedItems++
                                updateUploadProgress(taskId, preparedItems, UploadTaskPhase.PREPARING)
                            }
                            ensureActive()
                            val sentMessage = runInterruptible {
                                appContainer.messagingRepository.sendPreparedMediaMessage(
                                    chatId = chatId,
                                    attachments = preparedBatch,
                                    caption = if (index == 0) preparedBatch.firstOrNull()?.caption.orEmpty() else "",
                                    replyToId = if (index == 0) messenger.replyToId else null,
                                    captionEntities = if (index == 0) messenger.draftTextEntities else emptyList(),
                                )
                            }
                            completedMessages += sentMessage
                            sentItems += preparedBatch.size
                            updateUploadProgress(taskId, sentItems, UploadTaskPhase.UPLOADING)
                        } finally {
                            preparedBatch.forEach { item ->
                                item.bytes.fill(0)
                                item.previewBytes?.fill(0)
                            }
                        }
                    }
                    completedMessages
                }
                clearComposerAfterUpload(chatId, messenger.draft)
                sentMessages.forEach { commitSentMessage(chatId, it) }
                removeUploadTask(taskId)
                if (sentMessages.isNotEmpty()) appContainer.interfaceSoundPlayer.playSend()
            } catch (error: CancellationException) {
                removeUploadTask(taskId)
                throw error
            } catch (error: Exception) {
                removeUploadTask(taskId)
                showMessengerError(error)
            } finally {
                normalized.forEach { selection ->
                    appContainer.deviceAttachmentRepository.deleteTemporary(selection.item)
                }
                uploadJobs.remove(taskId)
            }
        }
        uploadJobs[taskId] = job
    }

    fun sendVoice(recorded: RecordedMedia) {
        sendRecorded(recorded, roundVideo = false)
    }

    fun sendRoundVideo(recorded: RecordedMedia) {
        if (recorded.bytes.isEmpty() || recorded.durationMillis < MIN_ROUND_VIDEO_DURATION_MILLIS) {
            recorded.bytes.fill(0)
            recorded.previewBytes?.fill(0)
            return
        }
        sendRecorded(recorded, roundVideo = true)
    }

    private fun sendRecorded(recorded: RecordedMedia, roundVideo: Boolean) {
        val messenger = mutableState.value.messenger
        val chatId = messenger.selectedChatId ?: run {
            recorded.bytes.fill(0)
            recorded.previewBytes?.fill(0)
            return
        }
        val taskId = UUID.randomUUID().toString()
        addUploadTask(
            UploadTaskUi(
                id = taskId,
                chatId = chatId,
                title = if (roundVideo) "Видеосообщение" else "Голосовое сообщение",
                completedItems = 0,
                totalItems = 1,
                phase = UploadTaskPhase.UPLOADING,
            ),
        )
        stopTyping(chatId)
        val job = viewModelScope.launch {
            try {
                val sentMessage = runInterruptible(Dispatchers.IO) {
                    if (roundVideo) {
                        appContainer.messagingRepository.sendRoundVideoMessage(chatId, recorded, messenger.replyToId)
                    } else {
                        appContainer.messagingRepository.sendVoiceMessage(chatId, recorded, messenger.replyToId)
                    }
                }
                updateUploadProgress(taskId, 1, UploadTaskPhase.UPLOADING)
                updateMessenger { current ->
                    if (current.selectedChatId == chatId) {
                        current.copy(replyToId = null, scrollToBottomToken = current.scrollToBottomToken + 1)
                    } else {
                        current
                    }
                }
                commitSentMessage(chatId, sentMessage)
                removeUploadTask(taskId)
                appContainer.interfaceSoundPlayer.playSend()
            } catch (error: CancellationException) {
                removeUploadTask(taskId)
                throw error
            } catch (error: Exception) {
                removeUploadTask(taskId)
                showMessengerError(error)
            } finally {
                recorded.bytes.fill(0)
                recorded.previewBytes?.fill(0)
                uploadJobs.remove(taskId)
            }
        }
        uploadJobs[taskId] = job
    }

    fun cancelUpload(taskId: String) {
        uploadJobs.remove(taskId)?.cancel()
        removeUploadTask(taskId)
    }

    private fun addUploadTask(task: UploadTaskUi) {
        updateMessenger { it.copy(uploads = it.uploads + (task.id to task), error = null) }
    }

    private fun updateUploadProgress(taskId: String, completed: Int, phase: UploadTaskPhase) {
        updateMessenger { current ->
            val task = current.uploads[taskId] ?: return@updateMessenger current
            current.copy(
                uploads = current.uploads + (
                    taskId to task.copy(
                        completedItems = completed.coerceIn(0, task.totalItems),
                        phase = phase,
                    )
                ),
            )
        }
    }

    private fun removeUploadTask(taskId: String) {
        updateMessenger { it.copy(uploads = it.uploads - taskId) }
    }

    private fun clearComposerAfterUpload(chatId: String, originalDraft: String) {
        draftBeforeEdit = null
        draftSpoilerBeforeEdit = null
        draftTextEntitiesBeforeEdit = null
        updateMessenger { current ->
            if (current.selectedChatId != chatId) return@updateMessenger current
            current.copy(
                draft = if (current.draft == originalDraft) "" else current.draft,
                draftSpoiler = if (current.draft == originalDraft) false else current.draftSpoiler,
                draftTextEntities = if (current.draft == originalDraft) emptyList() else current.draftTextEntities,
                replyToId = null,
                editingMessageId = null,
                scrollToBottomToken = current.scrollToBottomToken + 1,
            )
        }
    }

    suspend fun loadAttachmentPreview(message: DecryptedMessage, descriptor: MediaDescriptor): ByteArray? =
        withContext(Dispatchers.IO) {
            appContainer.messagingRepository.downloadPreview(message.chatId, message.id, descriptor)
                ?: if (descriptor.mimeType.startsWith("image/") && descriptor.originalSize <= INLINE_IMAGE_FALLBACK_BYTES) {
                    appContainer.messagingRepository.downloadAttachment(message.chatId, message.id, descriptor)
                } else {
                    null
                }
        }

    suspend fun loadAttachmentBytes(message: DecryptedMessage, descriptor: MediaDescriptor): ByteArray =
        withContext(Dispatchers.IO) {
            appContainer.messagingRepository.downloadAttachment(message.chatId, message.id, descriptor)
        }

    fun forwardMessage(message: DecryptedMessage, targetChatId: String) {
        if (mutableState.value.messenger.sending) return
        updateMessenger { it.copy(sending = true, error = null) }
        viewModelScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    appContainer.messagingRepository.forwardMessage(message, targetChatId)
                }
                val sourceChatId = message.chatId
                updateMessenger { it.copy(sending = false) }
                syncMessenger(showLoading = false)
                if (sourceChatId != targetChatId) {
                    forwardBackStack.addLast(sourceChatId)
                    openChatInternal(targetChatId)
                }
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                showMessengerError(error)
            }
        }
    }

    fun openAttachment(message: DecryptedMessage) {
        val descriptor = message.content.media ?: return
        openAttachment(message, descriptor)
    }

    fun openAttachment(message: DecryptedMessage, descriptor: MediaDescriptor) {
        if (mutableState.value.messenger.downloadingAttachmentId != null) return
        val resolvedKind = when {
            message.content.kind == MessageKind.MEDIA_GROUP && descriptor.mimeType.startsWith("image/") -> MessageKind.PHOTO
            message.content.kind == MessageKind.MEDIA_GROUP && descriptor.mimeType.startsWith("video/") -> MessageKind.VIDEO
            else -> message.content.kind
        }
        val isOrdinaryVideo = resolvedKind == MessageKind.VIDEO
        val cacheKey = VideoPlaybackCache.key(message.id, descriptor.id)
        val extension = VideoPlaybackCache.extension(descriptor.name)
        if (isOrdinaryVideo) {
            VideoPlaybackCache.find(appContainer.applicationContext, cacheKey, extension)?.let { cached ->
                updateMessenger {
                    it.copy(
                        downloadingAttachmentId = null,
                        error = null,
                        openedAttachment = OpenedAttachment(
                            messageId = message.id,
                            chatId = message.chatId,
                            kind = resolvedKind,
                            descriptor = descriptor,
                            plaintext = ByteArray(0),
                            localFilePath = cached.absolutePath,
                            caption = message.content.text,
                            allowSave = true,
                        ),
                    )
                }
                return
            }
        }

        if (isOrdinaryVideo) {
            updateMessenger {
                it.copy(
                    downloadingAttachmentId = message.id,
                    error = null,
                    openedAttachment = OpenedAttachment(
                        messageId = message.id,
                        chatId = message.chatId,
                        kind = resolvedKind,
                        descriptor = descriptor,
                        plaintext = ByteArray(0),
                        localFilePath = null,
                        caption = message.content.text,
                        allowSave = true,
                    ),
                )
            }
        } else {
            updateMessenger { it.copy(downloadingAttachmentId = message.id, error = null) }
        }
        viewModelScope.launch {
            try {
                val opened = if (isOrdinaryVideo) {
                    val cached = VideoPlaybackCache.load(
                        context = appContainer.applicationContext,
                        cacheKey = cacheKey,
                        extension = extension,
                    ) {
                        appContainer.messagingRepository.downloadAttachment(message.chatId, message.id, descriptor)
                    }
                    OpenedAttachment(
                        messageId = message.id,
                        chatId = message.chatId,
                        kind = resolvedKind,
                        descriptor = descriptor,
                        plaintext = ByteArray(0),
                        localFilePath = cached.absolutePath,
                        caption = message.content.text,
                        allowSave = true,
                    )
                } else {
                    val plaintext = withContext(Dispatchers.IO) {
                        appContainer.messagingRepository.downloadAttachment(message.chatId, message.id, descriptor)
                    }
                    OpenedAttachment(
                        messageId = message.id,
                        chatId = message.chatId,
                        kind = resolvedKind,
                        descriptor = descriptor,
                        plaintext = plaintext,
                        caption = message.content.text,
                        allowSave = message.content.kind != MessageKind.VOICE && message.content.kind != MessageKind.ROUND_VIDEO,
                    )
                }
                updateMessenger { current ->
                    val viewerStillOpen = current.openedAttachment?.let { active ->
                        active.messageId == message.id && active.descriptor.id == descriptor.id
                    } ?: !isOrdinaryVideo
                    current.copy(
                        downloadingAttachmentId = if (current.downloadingAttachmentId == message.id) {
                            null
                        } else {
                            current.downloadingAttachmentId
                        },
                        openedAttachment = if (viewerStillOpen) opened else current.openedAttachment,
                    )
                }
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                showMessengerError(error)
                updateMessenger { current ->
                    val activeViewer = current.openedAttachment
                    val closeVideoPlaceholder = isOrdinaryVideo &&
                        activeViewer != null &&
                        activeViewer.messageId == message.id &&
                        activeViewer.descriptor.id == descriptor.id
                    current.copy(
                        downloadingAttachmentId = if (current.downloadingAttachmentId == message.id) {
                            null
                        } else {
                            current.downloadingAttachmentId
                        },
                        openedAttachment = if (closeVideoPlaceholder) null else activeViewer,
                    )
                }
            }
        }
    }

    fun closeAttachment() {
        mutableState.value.messenger.openedAttachment?.plaintext?.fill(0)
        updateMessenger { it.copy(openedAttachment = null, downloadingAttachmentId = null) }
    }

    fun requestSpoilerReveal(message: DecryptedMessage) {
        val chatId = mutableState.value.messenger.selectedChatId ?: return
        viewModelScope.launch {
            runMessengerOperation {
                appContainer.messagingRepository.requestSpoilerReveal(chatId, message.id, message.senderUsername)
            }
        }
    }

    fun revealSpoiler(message: DecryptedMessage, username: String) {
        val chatId = mutableState.value.messenger.selectedChatId ?: return
        viewModelScope.launch {
            runMessengerOperation {
                appContainer.messagingRepository.revealSpoiler(chatId, message, username)
            }
        }
    }

    fun deleteMessages(messageIds: Set<String>, deleteForEveryone: Boolean) {
        val messenger = mutableState.value.messenger
        val chatId = messenger.selectedChatId ?: return
        val selected = messenger.messages.filter { it.id in messageIds }
        if (selected.isEmpty()) return
        val selectedIds = selected.mapTo(mutableSetOf(), DecryptedMessage::id)
        val scope = if (deleteForEveryone) MessageDeleteScope.EVERYONE else MessageDeleteScope.ME
        deletedIdsForChat(chatId).addAll(selectedIds)
        markMessageMutation(chatId)
        updateMessenger { current ->
            if (current.selectedChatId != chatId) return@updateMessenger current
            val remaining = current.messages.filterNot { it.id in selectedIds }
            messageCache[chatId] = CachedMessages(remaining, current.hasMoreOlder)
            current.copy(
                messages = remaining,
                selectedMessageIds = emptySet(),
            )
        }
        viewModelScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    appContainer.messagingRepository.deleteMessages(chatId, selected, scope)
                }
                syncMessenger(showLoading = false)
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                // Roll back only when the server rejected the deletion. Successful deletions keep
                // their tombstones so a delayed snapshot cannot make them flash back on screen.
                locallyDeletedMessageIds[chatId]?.removeAll(selectedIds)
                markMessageMutation(chatId)
                updateMessenger { current ->
                    if (current.selectedChatId != chatId) return@updateMessenger current
                    val restored = (current.messages + selected)
                        .distinctBy(DecryptedMessage::id)
                        .sortedWith(compareBy(DecryptedMessage::sequence, DecryptedMessage::createdAt))
                    messageCache[chatId] = CachedMessages(restored, current.hasMoreOlder)
                    current.copy(messages = restored)
                }
                showMessengerError(error)
            }
        }
    }

    fun pinMessage(messageId: String) {
        val chatId = mutableState.value.messenger.selectedChatId ?: return
        viewModelScope.launch {
            runMessengerOperation { appContainer.messagingRepository.pinMessage(chatId, messageId) }
        }
    }

    fun unpinMessage() {
        val chatId = mutableState.value.messenger.selectedChatId ?: return
        viewModelScope.launch {
            runMessengerOperation { appContainer.messagingRepository.unpinMessage(chatId) }
        }
    }

    fun toggleSelection(messageId: String) {
        updateMessenger { messenger ->
            val next = messenger.selectedMessageIds.toMutableSet()
            if (!next.add(messageId)) next.remove(messageId)
            messenger.copy(selectedMessageIds = next)
        }
    }

    fun clearSelection() {
        updateMessenger { it.copy(selectedMessageIds = emptySet()) }
    }

    fun updateRecoveryKeyInput(value: String) {
        mutableState.value = mutableState.value.copy(
            recoveryKeyInput = value.take(MAX_RECOVERY_KEY_INPUT),
            securityError = null,
            securityNotice = null,
        )
    }

    fun recoverAccount() {
        val candidate = appContainer.sessionStore.loadCandidateAccount()
            ?: appContainer.sessionStore.loadAccount()
            ?: return
        val recoveryKey = mutableState.value.recoveryKeyInput.trim()
        if (recoveryKey.isEmpty() || mutableState.value.securityBusy) return
        mutableState.value = mutableState.value.copy(securityBusy = true, securityError = null, securityNotice = null)
        viewModelScope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    appContainer.accountSecurityCoordinator.recoverWithRecoveryKey(candidate, recoveryKey)
                }
                val ready = appContainer.sessionStore.loadAccount()
                    ?: throw AccountSecurityException("session_commit_failed")
                mutableState.value = mutableState.value.copy(
                    screen = FedMesScreen.SIGNED_IN,
                    account = com.fedmes.app.provisioning.AccountSummary(
                        serverUrl = ready.serverUrl,
                        username = ready.username,
                        deviceId = ready.deviceId,
                        sessionExpiresAtEpochMillis = ready.sessionExpiresAtEpochMillis,
                        authenticationState = ready.authenticationState,
                    ),
                    recoveryKeyInput = "",
                    securityBusy = false,
                    securityError = null,
                    securityNotice = "Vault revision ${result.vaultRevision} проверен",
                )
                startMessenger()
            } catch (error: CancellationException) {
                throw error
            } catch (error: AccountSecurityException) {
                mutableState.value = mutableState.value.copy(
                    securityBusy = false,
                    securityError = securityErrorText(error.code),
                )
            } catch (_: Exception) {
                mutableState.value = mutableState.value.copy(
                    securityBusy = false,
                    securityError = "Не удалось безопасно восстановить ключи. Старые локальные данные не изменены.",
                )
            }
        }
    }

    fun cancelSecurityRecovery() {
        provisioningJob?.cancel()
        restoreJob?.cancel()
        val candidate = appContainer.sessionStore.loadCandidateAccount()
        viewModelScope.launch {
            withContext(Dispatchers.IO) {
                if (candidate != null) appContainer.accountSecurityCoordinator.cancelRecovery(candidate)
                appContainer.sessionStore.clearCandidate()
            }
            mutableState.value = mutableState.value.copy(
                screen = FedMesScreen.RESTORING,
                account = null,
                recoveryKeyInput = "",
                securityBusy = false,
                securityError = null,
                securityNotice = null,
            )
            restoreSession()
        }
    }

    private fun securityErrorText(code: String): String = when (code) {
        "recovery_key_invalid" -> "Recovery Key неверен. Текущий профиль и история не удалены."
        "recovery_package_invalid", "recovery_package_revision_mismatch" -> "Recovery package повреждён или не соответствует текущему vault."
        "vault_hash_mismatch", "vault_decryption_failed", "vault_test_record_invalid" -> "Encrypted vault не прошёл проверку целостности."
        "https_required" -> "Безопасное восстановление доступно только через HTTPS."
        "network_error" -> "Нет связи с сервером. Повтори попытку без повторного входа."
        "security_record_not_found" -> "Для аккаунта ещё не настроен Recovery Key. Подтверди устройство на старом устройстве."
        else -> "Безопасное восстановление не завершено: $code"
    }

    fun clearMessengerError() {
        updateMessenger { it.copy(error = null) }
    }

    private fun restoreSession() {
        restoreJob?.cancel()
        restoreJob = viewModelScope.launch {
            try {
                val account = withContext(Dispatchers.IO) {
                    appContainer.provisioningCoordinator.restoreSession()
                }
                if (account == null) {
                    applyAction(FedMesUiAction.RestoreWithoutAccount)
                    if (restoredOnboardingScreen == FedMesScreen.QR_SCANNER) {
                        applyAction(FedMesUiAction.OpenQrScanner)
                    }
                } else {
                    applyAction(FedMesUiAction.SessionRestored(account))
                    if (account.authenticationState == "READY") ensureSecurityReadyThenStart()
                }
            } catch (error: ProvisioningException) {
                applyAction(FedMesUiAction.SessionRestoreFailed(error.failure))
            } catch (error: CancellationException) {
                throw error
            } catch (_: Exception) {
                applyAction(FedMesUiAction.SessionRestoreFailed(ProvisioningFailure.SERVER))
            }
        }
    }

    private fun beginProvisioning(action: FedMesUiAction.QrDecoded) {
        val before = mutableState.value
        val next = FedMesUiReducer.reduce(before, action)
        if (next === before) return
        setState(next)
        provisioningJob?.cancel()
        restoreJob?.cancel()
        provisioningJob = viewModelScope.launch {
            try {
                val account = withContext(Dispatchers.IO) {
                    appContainer.provisioningCoordinator.redeem(action.rawPayload)
                }
                applyAction(FedMesUiAction.ProvisioningSucceeded(account))
                if (account.authenticationState == "READY") ensureSecurityReadyThenStart()
            } catch (error: ProvisioningException) {
                applyAction(FedMesUiAction.ProvisioningFailed(error.failure))
            } catch (error: CancellationException) {
                throw error
            } catch (_: Exception) {
                applyAction(FedMesUiAction.ProvisioningFailed(ProvisioningFailure.SERVER))
            }
        }
    }

    private suspend fun ensureSecurityReadyThenStart() {
        val account = appContainer.sessionStore.loadAccount() ?: return
        try {
            if (!appContainer.accountSecurityCoordinator.localVaultAvailable(account)) {
                val security = withContext(Dispatchers.IO) {
                    appContainer.accountSecurityCoordinator.getSecurityState(account)
                }
                if (security.vaultRevision == 0L && security.state == com.fedmes.app.accountsecurity.AccountSecurityProtocol.STATE_READY) {
                    // First trusted device: complete Account Root/Vault bootstrap before ratchet init.
                    // The generated Recovery Key remains encrypted locally until the user confirms
                    // it was saved, and is surfaced immediately in Security settings.
                    val recoveryKey = withContext(Dispatchers.IO) {
                        appContainer.accountSecurityCoordinator.enrollRecovery(account)
                    }
                    updateMessenger { current ->
                        current.copy(
                            settingsPage = SettingsPage.SECURITY,
                            recoveryConfigured = true,
                            generatedRecoveryKey = recoveryKey,
                            securitySettingsError = null,
                        )
                    }
                } else if (security.vaultRevision > 0L) {
                    mutableState.value = mutableState.value.copy(
                        screen = FedMesScreen.SECURITY_RECOVERY,
                        securityError = null,
                    )
                    return
                }
            }
            startMessenger()
        } catch (error: AccountSecurityException) {
            if (error.code == "recovery_required") {
                mutableState.value = mutableState.value.copy(
                    screen = FedMesScreen.SECURITY_RECOVERY,
                    securityError = null,
                )
            } else {
                showMessengerError(error)
            }
        } catch (error: Exception) {
            showMessengerError(error)
        }
    }

    private fun startMessenger() {
        messengerLoadJob?.cancel()
        messengerSyncJob?.cancel()
        messengerEphemeralSyncJob?.cancel()
        messengerLoadJob = viewModelScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    appContainer.messagingRepository.initialize(mutableState.value.messenger.showExactPresence)
                }
                syncMessenger(showLoading = true)
                appContainer.startBackgroundSync()
                messengerSyncJob = viewModelScope.launch {
                    // Event-driven foreground synchronization. The server keeps /events blocked
                    // until the event clock changes (or its 30s safety timeout expires), so new
                    // messages are fetched immediately instead of waiting for a 3s polling tick.
                    var eventCursor = withContext(Dispatchers.IO) {
                        appContainer.messagingRepository.waitForEvents(0L)
                    }
                    while (isActive && mutableState.value.screen == FedMesScreen.SIGNED_IN) {
                        try {
                            val nextCursor = withContext(Dispatchers.IO) {
                                appContainer.messagingRepository.waitForEvents(eventCursor)
                            }
                            if (nextCursor != eventCursor) {
                                // A lower cursor is an explicit server clock reset after restart/
                                // snapshot restore. Refresh once and continue from the new base.
                                eventCursor = nextCursor
                                syncMessenger(showLoading = false)
                            }
                        } catch (error: CancellationException) {
                            throw error
                        } catch (_: Exception) {
                            // A transient network change must not kill realtime sync. The next
                            // iteration reconnects using the same monotonic event cursor.
                            delay(FOREGROUND_RECONNECT_DELAY_MILLIS)
                        }
                    }
                }
                messengerEphemeralSyncJob = viewModelScope.launch {
                    // Typing has a short server TTL and presence changes independently from
                    // message traffic. Poll only these tiny ephemeral endpoints so a stale
                    // "печатает…" state disappears promptly without reloading chat history.
                    var heartbeatDueAt = android.os.SystemClock.elapsedRealtime()
                    while (isActive && mutableState.value.screen == FedMesScreen.SIGNED_IN) {
                        try {
                            val selectedChatId = mutableState.value.messenger.selectedChatId
                            val typingUsers = if (selectedChatId != null) {
                                withContext(Dispatchers.IO) {
                                    appContainer.messagingRepository.listTyping(selectedChatId)
                                        .map { it.username }
                                        .toSet()
                                }
                            } else {
                                emptySet()
                            }
                            val now = android.os.SystemClock.elapsedRealtime()
                            val presence = if (now >= heartbeatDueAt) {
                                withContext(Dispatchers.IO) {
                                    appContainer.messagingRepository.heartbeat(
                                        mutableState.value.messenger.showExactPresence,
                                    )
                                    appContainer.messagingRepository.listPresence()
                                }.also {
                                    heartbeatDueAt = now + FOREGROUND_HEARTBEAT_INTERVAL_MILLIS
                                }
                            } else {
                                null
                            }
                            updateMessenger { current ->
                                if (current.selectedChatId != selectedChatId) current else current.copy(
                                    typingUsers = typingUsers,
                                    presence = presence ?: current.presence,
                                )
                            }
                        } catch (error: CancellationException) {
                            throw error
                        } catch (_: Exception) {
                            // Ephemeral metadata is best-effort; the message event loop owns
                            // connection recovery and must never be blocked by this path.
                        }
                        delay(EPHEMERAL_REFRESH_MILLIS)
                    }
                }
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                showMessengerError(error)
            }
        }
    }

    private fun loadInitialChat(chatId: String) {
        messengerLoadJob?.cancel()
        val mutationGenerationAtStart = messageMutationGeneration[chatId] ?: 0L

        // Encryption/device prewarm is intentionally detached from the critical render path.
        // The old implementation serialized chats -> crypto prewarm -> presence -> messages -> typing,
        // which made a normal chat take multiple RTTs to open and made groups even slower.
        viewModelScope.launch(Dispatchers.IO) {
            runCatching { appContainer.messagingRepository.prewarmChat(chatId) }
        }

        messengerLoadJob = viewModelScope.launch {
            try {
                val critical = withContext(Dispatchers.IO) {
                    coroutineScope {
                        val chats = async { appContainer.messagingRepository.listChats() }
                        val page = async { appContainer.messagingRepository.loadLatestMessages(chatId) }
                        chats.await() to page.await()
                    }
                }
                val chats = critical.first
                val page = critical.second
                updateMessenger { current ->
                    if (current.selectedChatId != chatId) return@updateMessenger current
                    val chat = chats.firstOrNull { it.id == chatId }
                    val localMutationAfterRequest =
                        (messageMutationGeneration[chatId] ?: 0L) != mutationGenerationAtStart
                    val reconciled = mergeRecentMessages(
                        current.messages,
                        page.messages,
                        chat,
                        preserveExistingOnEmpty = localMutationAfterRequest,
                    )
                    messageCache[chatId] = CachedMessages(reconciled, page.hasMoreBefore)
                    current.copy(
                        initialized = true,
                        loading = false,
                        chats = chats,
                        messages = reconciled,
                        hasMoreOlder = page.hasMoreBefore,
                        loadingOlder = false,
                        previews = buildPreviews(chats, chatId, reconciled),
                        unreadCounts = calculateUnreadCounts(chats, chatId),
                        error = null,
                        scrollToBottomToken = current.scrollToBottomToken + 1,
                    )
                }

                observeCallSignals(chatId, page.messages, chats)
                scanCallSignalsBackground(chats, chatId)

                // Presence/typing are ephemeral decoration. They must never delay the chat itself.
                viewModelScope.launch(Dispatchers.IO) {
                    val presence = runCatching { appContainer.messagingRepository.listPresence() }.getOrNull()
                    val typing = runCatching { appContainer.messagingRepository.listTyping(chatId) }
                        .getOrDefault(emptyList())
                        .map { it.username }
                        .toSet()
                    withContext(Dispatchers.Main.immediate) {
                        updateMessenger { current ->
                            if (current.selectedChatId != chatId) current else current.copy(
                                presence = presence ?: current.presence,
                                typingUsers = typing,
                            )
                        }
                    }
                }
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                showMessengerError(error)
            }
        }
    }

    private suspend fun syncMessenger(showLoading: Boolean) {
        val previous = mutableState.value.messenger

        // Production fast path for foreground realtime events. A new message must not wait for
        // chat-list/presence metadata. Fetch the selected conversation window first (one RTT),
        // reconcile it immediately, then refresh chat metadata independently.
        if (!showLoading && previous.selectedChatId != null) {
            val selected = previous.selectedChatId
            val navigationGeneration = chatNavigationGeneration
            val mutationGenerationAtStart = messageMutationGeneration[selected] ?: 0L
            val page = withContext(Dispatchers.IO) {
                runCatching {
                    appContainer.messagingRepository.loadLatestMessages(
                        selected,
                        REALTIME_SYNC_PAGE_SIZE,
                    )
                }.getOrNull()
            }
            if (page != null) {
                updateMessenger { current ->
                    if (navigationGeneration != chatNavigationGeneration || current.selectedChatId != selected) {
                        current
                    } else {
                        val localMutationAfterRequest =
                            (messageMutationGeneration[selected] ?: 0L) != mutationGenerationAtStart
                        val chat = current.chats.firstOrNull { it.id == selected }
                        val reconciled = mergeRecentMessages(
                            current.messages,
                            page.messages,
                            chat,
                            preserveExistingOnEmpty = localMutationAfterRequest,
                        )
                        messageCache[selected] = CachedMessages(reconciled, page.hasMoreBefore)
                        current.copy(
                            initialized = true,
                            loading = false,
                            messages = reconciled,
                            hasMoreOlder = page.hasMoreBefore,
                            previews = buildPreviews(current.chats, selected, reconciled),
                            unreadCounts = calculateUnreadCounts(current.chats, selected),
                            error = null,
                        )
                    }
                }
                observeCallSignals(selected, page.messages, mutableState.value.messenger.chats)
            }
            refreshRealtimeMetadata(selected)
            return
        }
        val navigationGeneration = chatNavigationGeneration
        val selectedMutationGenerationAtStart = previous.selectedChatId
            ?.let { messageMutationGeneration[it] ?: 0L }
        if (showLoading) updateMessenger { it.copy(loading = true) }
        try {
            val result = withContext(Dispatchers.IO) {
                coroutineScope {
                    val candidateSelected = previous.selectedChatId ?: savedStateHandle.get<String>(CHAT_KEY)
                    val chatsDeferred = async { appContainer.messagingRepository.listChats() }
                    // Realtime message events must not wait on presence/typing. Those endpoints
                    // have their own lightweight loop. This cuts foreground event reconciliation
                    // to two parallel RTTs: chat metadata + selected message window.
                    val presenceDeferred = async {
                        if (showLoading) {
                            runCatching { appContainer.messagingRepository.listPresence() }.getOrDefault(previous.presence)
                        } else previous.presence
                    }
                    val pageDeferred = async {
                        candidateSelected?.let { selected ->
                            runCatching {
                                appContainer.messagingRepository.loadLatestMessages(
                                    selected,
                                    if (showLoading) RECENT_SYNC_PAGE_SIZE else REALTIME_SYNC_PAGE_SIZE,
                                )
                            }.getOrNull()
                        }
                    }
                    val typingDeferred = async {
                        if (!showLoading) previous.typingUsers.toList().map { TypingState(it) }
                        else candidateSelected?.let { selected ->
                            runCatching { appContainer.messagingRepository.listTyping(selected) }
                                .getOrDefault(emptyList())
                        }.orEmpty()
                    }

                    val chats = chatsDeferred.await()
                    val selected = candidateSelected?.takeIf { saved -> chats.any { it.id == saved } }
                    val recentPage = pageDeferred.await().takeIf { selected != null }
                    val messages = if (selected == null || recentPage == null) emptyList() else recentPage.messages
                    val typing = if (selected == null) emptySet() else typingDeferred.await().map { it.username }.toSet()
                    val presence = presenceDeferred.await()
                    val previews = buildPreviews(chats, selected, messages).toMutableMap()
                    // Never decrypt another chat only to build its one-line preview. Ratchet state is
                    // conversation ordered; speculative preview fetches caused duplicate decrypt work,
                    // UI stalls and could consume an inbound ratchet before the chat was opened.
                    for (chat in chats) {
                        if (chat.id != selected && chat.lastSequence > 0L && previews[chat.id].isNullOrBlank()) {
                            previews[chat.id] = if (chat.unreadCount > 0) "Новое сообщение" else "Сообщение"
                        }
                    }
                    SyncResult(
                        chats = chats,
                        presence = presence,
                        selectedChatId = selected,
                        messages = messages,
                        hasMoreOlder = recentPage?.hasMoreBefore ?: previous.hasMoreOlder,
                        typingUsers = typing,
                        previews = previews,
                        unreadCounts = calculateUnreadCounts(chats, selected),
                    )
                }
            }
            updateMessenger { current ->
                if (navigationGeneration != chatNavigationGeneration || current.selectedChatId != previous.selectedChatId) {
                    current.copy(
                        initialized = true,
                        loading = false,
                        chats = result.chats,
                        presence = result.presence,
                        previews = result.previews,
                        unreadCounts = calculateUnreadCounts(result.chats, current.selectedChatId),
                        error = null,
                    )
                } else {
                    val selected = result.selectedChatId
                    val chat = result.chats.firstOrNull { it.id == selected }
                    val localMutationAfterRequest = selected != null &&
                        (messageMutationGeneration[selected] ?: 0L) != selectedMutationGenerationAtStart
                    val reconciled = if (selected == null) {
                        emptyList()
                    } else {
                        mergeRecentMessages(
                            current.messages,
                            result.messages,
                            chat,
                            preserveExistingOnEmpty = localMutationAfterRequest,
                        )
                    }
                    if (selected != null) {
                        messageCache[selected] = CachedMessages(reconciled, result.hasMoreOlder)
                    }
                    current.copy(
                        initialized = true,
                        loading = false,
                        chats = result.chats,
                        presence = result.presence,
                        selectedChatId = selected,
                        messages = reconciled,
                        hasMoreOlder = result.hasMoreOlder,
                        typingUsers = result.typingUsers,
                        previews = buildPreviews(result.chats, selected, reconciled),
                        unreadCounts = result.unreadCounts,
                        error = null,
                    )
                }
            }
            result.selectedChatId?.let { selected -> observeCallSignals(selected, result.messages, result.chats) }
            scanCallSignalsBackground(result.chats, result.selectedChatId)
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            if (showLoading || !mutableState.value.messenger.initialized) showMessengerError(error)
        }
    }

    private fun refreshRealtimeMetadata(selectedChatId: String) {
        viewModelScope.launch(Dispatchers.IO) {
            val chats = runCatching { appContainer.messagingRepository.listChats() }.getOrNull() ?: return@launch
            // Refill ratchet sequence leases outside the send critical path. This keeps ordinary
            // and group sends from paying a sequence-reservation RTT after the initial warm-up.
            chats.forEach { chat ->
                launch {
                    runCatching { appContainer.messagingRepository.prewarmChat(chat.id) }
                }
            }
            withContext(Dispatchers.Main.immediate) {
                updateMessenger { current ->
                    val selected = current.selectedChatId
                    current.copy(
                        chats = chats,
                        previews = buildPreviews(chats, selected, current.messages),
                        unreadCounts = calculateUnreadCounts(chats, selected),
                    )
                }
                // Incoming call signalling in non-selected chats is best-effort and must not
                // block foreground message delivery. Scan only after metadata is committed.
                scanCallSignalsBackground(chats, mutableState.value.messenger.selectedChatId)
            }
        }
    }

    private suspend fun runMessengerOperation(operation: () -> Unit) {
        try {
            withContext(Dispatchers.IO) { operation() }
            syncMessenger(showLoading = false)
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            showMessengerError(error)
        }
    }

    private fun mergeRecentMessages(
        existing: List<DecryptedMessage>,
        recent: List<DecryptedMessage>,
        chat: ChatSummary?,
        preserveExistingOnEmpty: Boolean = false,
    ): List<DecryptedMessage> {
        val chatId = chat?.id ?: recent.firstOrNull()?.chatId ?: existing.firstOrNull()?.chatId
        val deleted = chatId?.let { locallyDeletedMessageIds[it].orEmpty() }.orEmpty()
        val visibleExisting = existing.filterNot { it.id in deleted }
        val visibleRecent = recent.filterNot { it.id in deleted }

        // A fetch that started before send/delete completed must never roll the UI backwards.
        // Keep pending local messages until an ACK with the same UUID arrives, and keep messages
        // newer than the newest row in a stale page when requests complete out of order.
        if (visibleRecent.isEmpty()) {
            return if (!preserveExistingOnEmpty && chat?.lastSequence == 0L) {
                visibleExisting.filter { it.deliveryState == MessageDeliveryState.PENDING }
            } else {
                visibleExisting
            }
        }
        val recentIds = visibleRecent.asSequence().map(DecryptedMessage::id).toHashSet()
        val cutoff = visibleRecent.minOf(DecryptedMessage::sequence)
        val latestRecentSequence = visibleRecent.maxOf(DecryptedMessage::sequence)
        val older = visibleExisting.filter { it.sequence < cutoff }
        val localAhead = visibleExisting.filter { message ->
            message.id !in recentIds &&
                (message.deliveryState == MessageDeliveryState.PENDING ||
                    message.sequence > latestRecentSequence)
        }
        return (older + visibleRecent + localAhead)
            .distinctBy(DecryptedMessage::id)
            .sortedWith(compareBy(DecryptedMessage::sequence, DecryptedMessage::createdAt))
    }

    private fun deletedIdsForChat(chatId: String): MutableSet<String> =
        locallyDeletedMessageIds.getOrPut(chatId) { mutableSetOf() }

    private fun isLocallyDeleted(chatId: String, messageId: String): Boolean =
        messageId in locallyDeletedMessageIds[chatId].orEmpty()

    private fun markMessageMutation(chatId: String): Long {
        val next = (messageMutationGeneration[chatId] ?: 0L) + 1L
        messageMutationGeneration[chatId] = next
        return next
    }

    private fun calculateUnreadCounts(
        chats: List<ChatSummary>,
        selectedChatId: String?,
    ): Map<String, Int> {
        return chats.associate { chat ->
            chat.id to if (chat.id == selectedChatId) 0 else chat.unreadCount.coerceIn(0, 99)
        }
    }

    private fun buildPreviews(
        chats: List<ChatSummary>,
        selectedChatId: String?,
        selectedMessages: List<DecryptedMessage>,
    ): Map<String, String> {
        val existing = mutableState.value.messenger.previews.toMutableMap()
        if (selectedChatId != null) {
            existing[selectedChatId] = selectedMessages.lastOrNull()?.previewText().orEmpty()
        }
        chats.filter { it.lastSequence == 0L }.forEach { chat -> existing[chat.id] = "Нет сообщений" }
        return existing
    }

    private fun commitSentMessage(chatId: String, message: DecryptedMessage) {
        markMessageMutation(chatId)
        updateMessenger { current ->
            val nextChats = current.chats.map { chat ->
                if (chat.id == chatId) chat.copy(
                    lastSequence = maxOf(chat.lastSequence, message.sequence),
                    lastMessageAt = message.createdAt,
                ) else chat
            }
            val nextMessages = if (current.selectedChatId == chatId) {
                (current.messages.filterNot { it.id == message.id } + message)
                    .sortedWith(compareBy(DecryptedMessage::sequence, DecryptedMessage::createdAt))
            } else current.messages
            current.copy(
                chats = nextChats,
                messages = nextMessages,
                previews = current.previews + (chatId to message.previewText()),
                scrollToBottomToken = if (current.selectedChatId == chatId) current.scrollToBottomToken + 1 else current.scrollToBottomToken,
            )
        }
        val cached = messageCache[chatId]
        messageCache[chatId] = CachedMessages(
            messages = ((cached?.messages).orEmpty().filterNot { it.id == message.id } + message)
                .sortedWith(compareBy(DecryptedMessage::sequence, DecryptedMessage::createdAt)),
            hasMoreOlder = cached?.hasMoreOlder ?: false,
        )
    }

    private fun DecryptedMessage.previewText(): String {
        if (content.spoiler) return "Спойлер"
        return when (content.kind) {
        MessageKind.TEXT -> content.text
        MessageKind.PHOTO -> "Фото${content.text.takeIf(String::isNotBlank)?.let { ": $it" }.orEmpty()}"
        MessageKind.VIDEO -> "Видео${content.text.takeIf(String::isNotBlank)?.let { ": $it" }.orEmpty()}"
        MessageKind.MEDIA_GROUP -> "Медиа: ${content.mediaItems.size}${content.text.takeIf(String::isNotBlank)?.let { ": $it" }.orEmpty()}"
        MessageKind.ROUND_VIDEO -> "Видеосообщение"
        MessageKind.SPOILER_REQUEST -> "Спойлер"
        MessageKind.AUDIO -> "Аудио${content.text.takeIf(String::isNotBlank)?.let { ": $it" }.orEmpty()}"
        MessageKind.VOICE -> "Голосовое сообщение"
        MessageKind.FILE -> "Файл: ${content.media?.name.orEmpty()}"
        MessageKind.CALL -> content.text.ifBlank { "Звонок" }
        MessageKind.SYSTEM -> content.text
        }
    }

    private fun observeCallSignals(
        chatId: String,
        messages: List<DecryptedMessage>,
        chats: List<ChatSummary> = mutableState.value.messenger.chats,
    ) {
        val username = mutableState.value.account?.username ?: return
        val chat = chats.firstOrNull { it.id == chatId } ?: return
        callScanHighWater[chatId] = maxOf(callScanHighWater[chatId] ?: 0L, messages.maxOfOrNull { it.sequence } ?: 0L)
        appContainer.callCoordinator.observeMessages(chatId, chat.title.ifBlank { "FedMes" }, username, messages)
    }

    private fun scanCallSignalsBackground(chats: List<ChatSummary>, selectedChatId: String?) {
        val username = mutableState.value.account?.username ?: return
        for (chat in chats) {
            if (chat.id == selectedChatId || chat.lastSequence <= (callScanHighWater[chat.id] ?: 0L)) continue
            viewModelScope.launch(Dispatchers.IO) {
                try {
                    val page = appContainer.messagingRepository.loadLatestMessages(chat.id, limit = 16, markRead = false)
                    callScanHighWater[chat.id] = maxOf(callScanHighWater[chat.id] ?: 0L, page.messages.maxOfOrNull { it.sequence } ?: chat.lastSequence)
                    appContainer.callCoordinator.observeMessages(chat.id, chat.title.ifBlank { "FedMes" }, username, page.messages)
                } catch (error: CancellationException) {
                    throw error
                } catch (_: Exception) {
                    // Call signalling scan is best-effort and never blocks normal messaging.
                }
            }
        }
    }

    private fun prefetchChatMessages() {
        prefetchJob?.cancel()
        val chats = mutableState.value.messenger.chats
        prefetchJob = viewModelScope.launch {
            for (chat in chats) {
                if (!isActive || chat.id in messageCache) continue
                try {
                    val page = withContext(Dispatchers.IO) {
                        appContainer.messagingRepository.loadLatestMessages(
                            chatId = chat.id,
                            limit = RECENT_SYNC_PAGE_SIZE,
                            markRead = false,
                        )
                    }
                    messageCache[chat.id] = CachedMessages(page.messages.filterNot { isLocallyDeleted(chat.id, it.id) }, page.hasMoreBefore)
                } catch (error: CancellationException) {
                    throw error
                } catch (_: Exception) {
                    // Prefetch is opportunistic; normal chat loading remains authoritative.
                }
            }
        }
    }

    private fun updateTypingLoop(typing: Boolean) {
        val chatId = mutableState.value.messenger.selectedChatId ?: return
        val chat = mutableState.value.messenger.chats.firstOrNull { it.id == chatId } ?: return
        if (chat.kind == "favorites") return
        if (!typing) {
            stopTyping(chatId)
            return
        }
        if (typingJob?.isActive == true) return
        typingJob = viewModelScope.launch {
            try {
                while (isActive && mutableState.value.messenger.selectedChatId == chatId &&
                    mutableState.value.messenger.draft.isNotBlank()
                ) {
                    withContext(Dispatchers.IO) {
                        appContainer.messagingRepository.setTyping(chatId, true)
                    }
                    delay(TYPING_REFRESH_MILLIS)
                }
            } catch (error: CancellationException) {
                throw error
            } catch (_: Exception) {
                // Typing is ephemeral metadata and must never block composing.
            } finally {
                withContext(NonCancellable + Dispatchers.IO) {
                    runCatching { appContainer.messagingRepository.setTyping(chatId, false) }
                }
            }
        }
    }

    private fun stopTyping(chatId: String) {
        typingJob?.cancel()
        typingJob = null
        viewModelScope.launch(Dispatchers.IO) {
            runCatching { appContainer.messagingRepository.setTyping(chatId, false) }
        }
    }

    private fun signOut() {
        draftBeforeEdit = null
        draftSpoilerBeforeEdit = null
        draftTextEntitiesBeforeEdit = null
        uploadJobs.values.forEach(Job::cancel)
        uploadJobs.clear()
        mutableState.value.messenger.openedAttachment?.plaintext?.fill(0)
        mutableState.value.messenger.selectedChatId?.let(::stopTyping)
        provisioningJob?.cancel()
        messengerLoadJob?.cancel()
        messengerSyncJob?.cancel()
        messengerEphemeralSyncJob?.cancel()
        typingJob?.cancel()
        prefetchJob?.cancel()
        deviceManagementJob?.cancel()
        deviceHistorySyncJob?.cancel()
        messageCache.clear()
        readCursorHighWater.clear()
        locallyDeletedMessageIds.clear()
        messageMutationGeneration.clear()
        appContainer.stopBackgroundSync()
        viewModelScope.launch {
            withContext(Dispatchers.IO) { appContainer.sessionStore.clear() }
            applyAction(FedMesUiAction.SignOut)
        }
    }

    private fun showMessengerError(error: Exception) {
        updateMessenger {
            it.copy(
                loading = false,
                loadingOlder = false,
                sending = false,
                error = error.message?.takeIf(String::isNotBlank) ?: "Ошибка связи с сервером",
            )
        }
    }

    private fun applyAction(action: FedMesUiAction) {
        setState(FedMesUiReducer.reduce(mutableState.value, action))
    }

    private fun updateMessenger(transform: (MessengerUiState) -> MessengerUiState) {
        mutableState.value = mutableState.value.copy(messenger = transform(mutableState.value.messenger))
    }

    private fun setState(next: FedMesUiState) {
        if (next.screen != FedMesScreen.RESTORING) {
            savedStateHandle[SCREEN_KEY] = next.screen.name
        }
        mutableState.value = next
    }

    private data class CachedMessages(
        val messages: List<DecryptedMessage>,
        val hasMoreOlder: Boolean,
    )

    private data class InitialChatResult(
        val chats: List<ChatSummary>,
        val presence: List<PresenceState>,
        val messages: List<DecryptedMessage>,
        val hasMoreOlder: Boolean,
        val typingUsers: Set<String>,
    )

    private data class SyncResult(
        val chats: List<ChatSummary>,
        val presence: List<PresenceState>,
        val selectedChatId: String?,
        val messages: List<DecryptedMessage>,
        val hasMoreOlder: Boolean,
        val typingUsers: Set<String>,
        val previews: Map<String, String>,
        val unreadCounts: Map<String, Int>,
    )

    companion object {
        private const val SCREEN_KEY = "fedmes.screen"
        private const val CHAT_KEY = "fedmes.chat"
        private const val MAX_DRAFT_LENGTH = 16_384
        private const val MAX_RECOVERY_KEY_INPUT = 256
        private const val FOREGROUND_HEARTBEAT_INTERVAL_MILLIS = 20_000L
        private const val FOREGROUND_RECONNECT_DELAY_MILLIS = 1_000L
        private const val EPHEMERAL_REFRESH_MILLIS = 2_000L
        private const val TYPING_REFRESH_MILLIS = 3_000L
        private const val RECENT_SYNC_PAGE_SIZE = 100
        private const val REALTIME_SYNC_PAGE_SIZE = 48
        private const val MAX_ATTACHMENT_SELECTION = 500
        private const val MAX_MEDIA_PER_MESSAGE = 10
        private const val INLINE_IMAGE_FALLBACK_BYTES = 4 * 1024 * 1024

        fun factory(appContainer: AppContainer): ViewModelProvider.Factory =
            object : ViewModelProvider.Factory {
                @Suppress("UNCHECKED_CAST")
                override fun <T : ViewModel> create(
                    modelClass: Class<T>,
                    extras: CreationExtras,
                ): T {
                    require(modelClass.isAssignableFrom(FedMesViewModel::class.java)) {
                        "Unsupported ViewModel: ${modelClass.name}"
                    }
                    return FedMesViewModel(
                        savedStateHandle = extras.createSavedStateHandle(),
                        appContainer = appContainer,
                    ) as T
                }
            }
    }
}
