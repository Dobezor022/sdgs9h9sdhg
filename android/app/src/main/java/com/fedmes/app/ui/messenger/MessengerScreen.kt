package com.fedmes.app.ui.messenger

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.pm.PackageManager
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.ime
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.contextmenu.provider.LocalTextContextMenuDropdownProvider
import androidx.compose.foundation.text.contextmenu.provider.LocalTextContextMenuToolbarProvider
import androidx.compose.foundation.text.contextmenu.provider.TextContextMenuDataProvider
import androidx.compose.foundation.text.contextmenu.provider.TextContextMenuProvider
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.CenterAlignedTopAppBar
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Alignment
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.platform.LocalTextToolbar
import androidx.compose.ui.platform.TextToolbar
import androidx.compose.ui.platform.TextToolbarStatus
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.input.OffsetMapping
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.input.TransformedText
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import com.fedmes.app.domain.family.AvatarTone
import com.fedmes.app.domain.family.FamilyUser
import com.fedmes.app.messaging.AttachmentSelection
import com.fedmes.app.messaging.ChatAudioRecorder
import com.fedmes.app.messaging.ChatSummary
import com.fedmes.app.messaging.DecryptedMessage
import com.fedmes.app.messaging.MediaDescriptor
import com.fedmes.app.messaging.MessageDeliveryState
import com.fedmes.app.messaging.MessageKind
import com.fedmes.app.messaging.RecordedMedia
import com.fedmes.app.messaging.RoundVideoShape
import com.fedmes.app.messaging.TextEntity
import com.fedmes.app.messaging.TextEntityType
import com.fedmes.app.messaging.clearTextEntities
import com.fedmes.app.messaging.expandToLineRange
import com.fedmes.app.messaging.remapTextEntitiesAfterEdit
import com.fedmes.app.messaging.sanitizeTextEntities
import com.fedmes.app.messaging.toggleTextEntity
import com.fedmes.app.messaging.PresenceState
import com.fedmes.app.provisioning.AccountSummary
import com.fedmes.app.calling.CallActions
import com.fedmes.app.calling.FedMesCallScreen
import com.fedmes.app.ui.components.AttachIcon
import com.fedmes.app.ui.components.BackIcon
import com.fedmes.app.ui.components.CloseIcon
import com.fedmes.app.ui.components.CopyIcon
import com.fedmes.app.ui.components.DeleteIcon
import com.fedmes.app.ui.components.DownArrowIcon
import com.fedmes.app.ui.components.EditIcon
import com.fedmes.app.ui.components.DeliveryChecksIcon
import com.fedmes.app.ui.components.FamilyAvatar
import com.fedmes.app.ui.components.SavedMessagesAvatar
import com.fedmes.app.ui.components.ForwardIcon
import com.fedmes.app.ui.components.PinIcon
import com.fedmes.app.ui.components.QuoteMarksIcon
import com.fedmes.app.ui.components.DownloadIcon
import com.fedmes.app.ui.components.MicIcon
import com.fedmes.app.ui.components.MoreIcon
import com.fedmes.app.ui.components.VideoMessageIcon
import com.fedmes.app.ui.components.ReplyIcon
import com.fedmes.app.ui.components.SendIcon
import com.fedmes.app.ui.components.SpoilerIcon
import com.fedmes.app.ui.components.ThemeToggleIcon
import com.fedmes.app.ui.model.MessengerUiState
import com.fedmes.app.ui.model.SettingsPage
import com.fedmes.app.ui.model.UploadTaskPhase
import com.fedmes.app.ui.model.UploadTaskUi
import com.fedmes.app.ui.fedui3.FedMes26BottomBar
import com.fedmes.app.ui.fedui3.FedMes26ChatRow
import com.fedmes.app.ui.fedui3.FedMes26Destination
import com.fedmes.app.ui.theme.FedMesThemeValues
import com.fedmes.app.ui.theme.ThemeMode
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.distinctUntilChanged
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.math.abs

class MessengerActions(
    val onOpenChat: (String) -> Unit,
    val onBack: () -> Unit,
    val onDraft: (String, List<TextEntity>) -> Unit,
    val onSend: () -> Unit,
    val onAttachments: (List<AttachmentSelection>) -> Unit,
    val onVoice: (RecordedMedia) -> Unit,
    val onRoundVideo: (RecordedMedia) -> Unit,
    val onCancelUpload: (String) -> Unit,
    val onOpenAttachment: (DecryptedMessage, MediaDescriptor) -> Unit,
    val onLoadAttachmentPreview: suspend (DecryptedMessage, MediaDescriptor) -> ByteArray?,
    val onLoadAttachmentBytes: suspend (DecryptedMessage, MediaDescriptor) -> ByteArray,
    val onCloseAttachment: () -> Unit,
    val onReply: (String) -> Unit,
    val onEdit: (DecryptedMessage) -> Unit,
    val onForward: (DecryptedMessage, String) -> Unit,
    val onDeleteMessages: (Set<String>, Boolean) -> Unit,
    val onPin: (String) -> Unit,
    val onUnpin: () -> Unit,
    val onRequestSpoilerReveal: (DecryptedMessage) -> Unit,
    val onRevealSpoiler: (DecryptedMessage, String) -> Unit,
    val onToggleSelection: (String) -> Unit,
    val onClearSelection: () -> Unit,
    val onLoadOlder: () -> Unit,
    val onJumpToMessage: (String) -> Unit,
    val onVisibleMessages: (Set<String>) -> Unit,
    val onCancelComposerMode: () -> Unit,
    val onClearError: () -> Unit,
    val onShowExactPresence: (Boolean) -> Unit,
    val onThemeMode: (ThemeMode) -> Unit,
    val onOpenSettings: () -> Unit,
    val onCloseSettings: () -> Unit,
    val onOpenDevices: () -> Unit,
    val onOpenNotifications: () -> Unit,
    val onOpenSecurity: () -> Unit,
    val onOpenProfile: () -> Unit,
    val onProfileMedia: (AttachmentSelection) -> Unit,
    val onClearProfileMedia: () -> Unit,
    val onProfileNameColor: (Long) -> Unit,
    val onNotificationsEnabled: (Boolean) -> Unit,
    val onNotificationSound: (Boolean) -> Unit,
    val onNotificationVibration: (Boolean) -> Unit,
    val onGroupNotifications: (Boolean) -> Unit,
    val onGenerateRecoveryKey: () -> Unit,
    val onConfirmRecoveryKeySaved: () -> Unit,
    val onConfigureOpaquePassword: (String) -> Unit,
    val onApprovePendingDevice: (String) -> Unit,
    val onRejectPendingDevice: (String) -> Unit,
    val onDevicesBack: () -> Unit,
    val onRefreshDevices: () -> Unit,
    val onStartDeviceLinkScan: () -> Unit,
    val onDeviceLinkQr: (String) -> Unit,
    val onRetryDeviceLinkScanner: () -> Unit,
    val onDeviceLinkCameraError: () -> Unit,
    val onCloseDeviceLinkFlow: () -> Unit,
    val onApproveDeviceLink: () -> Unit,
    val onRevokeDevice: (String) -> Unit,
    val onTerminateOtherDevices: () -> Unit,
    val onStartAudioCall: () -> Unit,
    val onStartVideoCall: () -> Unit,
    val onAcceptCall: () -> Unit,
    val onDeclineCall: () -> Unit,
    val onEndCall: () -> Unit,
    val onCallMuted: (Boolean) -> Unit,
    val onCallSpeaker: (Boolean) -> Unit,
    val onCallCamera: (Boolean) -> Unit,
    val onCallPermissionsGranted: () -> Unit,
    val onCallVideoFrame: (ByteArray) -> Unit,
    val onSignOut: () -> Unit,
)

@Composable
fun MessengerScreen(
    account: AccountSummary,
    familyMembers: List<FamilyUser>,
    state: MessengerUiState,
    themeMode: ThemeMode,
    actions: MessengerActions,
    modifier: Modifier = Modifier,
) {
    val currentUser = familyMembers.user(account.username)
    state.call?.let { call ->
        FedMesCallScreen(
            state = call,
            actions = CallActions(
                onAccept = actions.onAcceptCall,
                onDecline = actions.onDeclineCall,
                onEnd = actions.onEndCall,
                onMute = actions.onCallMuted,
                onSpeaker = actions.onCallSpeaker,
                onCamera = actions.onCallCamera,
                onPermissionsGranted = actions.onCallPermissionsGranted,
                onVideoFrame = actions.onCallVideoFrame,
            ),
            modifier = modifier,
        )
        return
    }
    when (state.settingsPage) {
        SettingsPage.ROOT -> {
            SettingsRootScreen(
                account = account,
                currentUser = currentUser,
                deviceCount = state.accountDevices.size,
                onBack = actions.onCloseSettings,
                onOpenDevices = actions.onOpenDevices,
                onOpenNotifications = actions.onOpenNotifications,
                onOpenSecurity = actions.onOpenSecurity,
                onOpenProfile = actions.onOpenProfile,
                profileAvatarUri = state.profileAvatarUri,
                profileAvatarMimeType = state.profileAvatarMimeType,
                profileNameColorArgb = state.profileNameColorArgb,
            )
            return
        }
        SettingsPage.PROFILE -> {
            var showProfilePicker by remember { mutableStateOf(false) }
            ProfileSettingsScreen(
                account = account,
                currentUser = currentUser,
                avatarUri = state.profileAvatarUri,
                avatarMimeType = state.profileAvatarMimeType,
                nameColorArgb = state.profileNameColorArgb,
                onBack = actions.onOpenSettings,
                onChooseMedia = { showProfilePicker = true },
                onClearMedia = actions.onClearProfileMedia,
                onColor = actions.onProfileNameColor,
            )
            if (showProfilePicker) {
                AttachmentPickerSheet(
                    initialCaption = "",
                    onDismiss = { showProfilePicker = false },
                    onSend = { selections ->
                        selections.firstOrNull()?.let(actions.onProfileMedia)
                        showProfilePicker = false
                    },
                )
            }
            return
        }
        SettingsPage.SECURITY -> {
            AccountSecuritySettingsScreen(
                loading = state.securityLoading,
                recoveryConfigured = state.recoveryConfigured,
                generatedRecoveryKey = state.generatedRecoveryKey,
                error = state.securitySettingsError,
                onBack = actions.onOpenSettings,
                onGenerateRecoveryKey = actions.onGenerateRecoveryKey,
                onConfirmRecoveryKeySaved = actions.onConfirmRecoveryKeySaved,
                opaqueEnrolled = state.opaqueEnrolled,
                pendingDevices = state.pendingDeviceRequests,
                onConfigureOpaquePassword = actions.onConfigureOpaquePassword,
                onApprovePendingDevice = actions.onApprovePendingDevice,
                onRejectPendingDevice = actions.onRejectPendingDevice,
            )
            return
        }
        SettingsPage.NOTIFICATIONS -> {
            NotificationSettingsScreen(
                enabled = state.notificationsEnabled,
                soundEnabled = state.notificationSoundEnabled,
                vibrationEnabled = state.notificationVibrationEnabled,
                groupEnabled = state.groupNotificationsEnabled,
                onBack = actions.onOpenSettings,
                onEnabled = actions.onNotificationsEnabled,
                onSound = actions.onNotificationSound,
                onVibration = actions.onNotificationVibration,
                onGroups = actions.onGroupNotifications,
            )
            return
        }
        SettingsPage.DEVICES -> {
            DevicesScreen(
                devices = state.accountDevices,
                loading = state.devicesLoading,
                historySyncing = state.deviceHistorySyncing,
                error = state.error,
                onBack = actions.onDevicesBack,
                onRefresh = actions.onRefreshDevices,
                onScanDesktopQr = actions.onStartDeviceLinkScan,
                onRevoke = actions.onRevokeDevice,
                onTerminateOthers = actions.onTerminateOtherDevices,
                onClearError = actions.onClearError,
            )
            return
        }
        SettingsPage.DEVICE_LINK_SCANNER -> {
            DeviceLinkScannerScreen(
                phase = state.deviceLinkScannerPhase,
                failure = state.deviceLinkFailure,
                onDecoded = actions.onDeviceLinkQr,
                onCameraError = actions.onDeviceLinkCameraError,
                onRetry = actions.onRetryDeviceLinkScanner,
                onClose = actions.onCloseDeviceLinkFlow,
            )
            return
        }
        SettingsPage.DEVICE_LINK_APPROVAL -> {
            val preview = state.deviceLinkPreview
            if (preview != null) {
                DeviceLinkApprovalScreen(
                    preview = preview,
                    approving = state.deviceLinkApproving,
                    error = state.error,
                    onBack = actions.onCloseDeviceLinkFlow,
                    onApprove = actions.onApproveDeviceLink,
                    onClearError = actions.onClearError,
                )
            }
            return
        }
        SettingsPage.NONE -> Unit
    }

    val selectedChat = state.chats.firstOrNull { it.id == state.selectedChatId }
    state.openedAttachment?.let { attachment ->
        AttachmentViewerDialog(attachment = attachment, onClose = actions.onCloseAttachment)
    }
    if (!state.initialized && state.loading) {
        Box(modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            CircularProgressIndicator()
        }
        return
    }
    if (selectedChat == null) {
        ChatListScreen(account, familyMembers, state, themeMode, actions, modifier)
    } else {
        key(selectedChat.id) {
            ChatScreen(account, familyMembers, selectedChat, state, actions, modifier)
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ChatListScreen(
    account: AccountSummary,
    familyMembers: List<FamilyUser>,
    state: MessengerUiState,
    themeMode: ThemeMode,
    actions: MessengerActions,
    modifier: Modifier,
) {
    var overflowMenu by remember { mutableStateOf(false) }
    var searchQuery by remember { mutableStateOf("") }
    var globalSearch by remember { mutableStateOf(false) }
    val snackbar = remember { SnackbarHostState() }
    val context = LocalContext.current
    val visibleChats = remember(state.chats) { state.chats.filter { it.lastSequence > 0L } }
    val searchResults = remember(state.chats, searchQuery) {
        val query = searchQuery.trim()
        if (query.isBlank()) emptyList() else state.chats.filter { chat ->
            chatDisplayName(chat, account.username).contains(query, ignoreCase = true) ||
                chat.title.contains(query, ignoreCase = true) ||
                chat.members.any { it.contains(query, ignoreCase = true) }
        }
    }

    LaunchedEffect(state.error) {
        state.error?.let {
            snackbar.showSnackbar(it)
            actions.onClearError()
        }
    }
    LaunchedEffect(state.generatedRecoveryKey, visibleChats.isEmpty()) {
        val recoveryKey = state.generatedRecoveryKey ?: return@LaunchedEffect
        if (visibleChats.isNotEmpty()) return@LaunchedEffect
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
        clipboard?.setPrimaryClip(ClipData.newPlainText("FedMes Recovery Key", recoveryKey))
    }

    Scaffold(
        modifier = modifier.fillMaxSize(),
        contentWindowInsets = WindowInsets.safeDrawing,
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("FedMes", fontWeight = FontWeight.SemiBold) },
                actions = {
                    Box {
                        IconButton(onClick = { overflowMenu = true }) {
                            MoreIcon(Modifier.size(25.dp), MaterialTheme.colorScheme.onSurface)
                        }
                        DropdownMenu(expanded = overflowMenu, onDismissRequest = { overflowMenu = false }) {
                            DropdownMenuItem(
                                text = { Text(if (FedMesThemeValues.extendedColors.isDark) "Светлая тема" else "Тёмная тема") },
                                onClick = {
                                    actions.onThemeMode(themeMode.next())
                                    overflowMenu = false
                                },
                            )
                            DropdownMenuItem(
                                text = { Text("Избранное") },
                                onClick = {
                                    state.chats.firstOrNull { it.kind == "favorites" }?.let { actions.onOpenChat(it.id) }
                                    overflowMenu = false
                                },
                            )
                            DropdownMenuItem(
                                text = { Text("Группа") },
                                onClick = {
                                    state.chats.firstOrNull { it.kind == "family" }?.let { actions.onOpenChat(it.id) }
                                    overflowMenu = false
                                },
                            )
                            DropdownMenuItem(
                                text = { Text("Выйти из аккаунта", color = MaterialTheme.colorScheme.error) },
                                onClick = {
                                    overflowMenu = false
                                    actions.onSignOut()
                                },
                            )
                        }
                    }
                },
            )
        },
        bottomBar = {
            Box(Modifier.fillMaxWidth().navigationBarsPadding().padding(horizontal = 6.dp, vertical = 2.dp)) {
                FedMes26BottomBar(
                    active = if (globalSearch) FedMes26Destination.SEARCH else FedMes26Destination.CHATS,
                    dark = FedMesThemeValues.extendedColors.isDark,
                    onDestination = { destination ->
                        when (destination) {
                            FedMes26Destination.CHATS -> globalSearch = false
                            FedMes26Destination.SEARCH -> globalSearch = true
                            FedMes26Destination.PROFILE -> actions.onOpenProfile()
                            FedMes26Destination.SETTINGS -> actions.onOpenSettings()
                        }
                    },
                )
            }
        },
    ) { padding ->
        if (globalSearch) {
            Column(
                modifier = Modifier.fillMaxSize().padding(padding).padding(horizontal = 16.dp, vertical = 10.dp),
            ) {
                Surface(
                    color = MaterialTheme.colorScheme.surface,
                    border = BorderStroke(1.dp, FedMesThemeValues.extendedColors.border),
                    shape = RoundedCornerShape(20.dp),
                ) {
                    BasicTextField(
                        value = searchQuery,
                        onValueChange = { searchQuery = it.take(80) },
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 12.dp),
                        singleLine = true,
                        textStyle = MaterialTheme.typography.bodyMedium.copy(color = MaterialTheme.colorScheme.onSurface),
                        cursorBrush = SolidColor(MaterialTheme.colorScheme.primary),
                        decorationBox = { inner ->
                            if (searchQuery.isBlank()) Text("Поиск", color = MaterialTheme.colorScheme.onSurfaceVariant)
                            inner()
                        },
                    )
                }
                Spacer(Modifier.height(8.dp))
                LazyColumn(Modifier.fillMaxSize()) {
                    items(searchResults, key = ChatSummary::id, contentType = { "search-chat" }) { chat ->
                        ChatRow(
                            chat = chat,
                            currentUsername = account.username,
                            familyMembers = familyMembers,
                            presence = state.presence,
                            preview = state.previews[chat.id].orEmpty(),
                            unreadCount = state.unreadCounts[chat.id] ?: 0,
                            onClick = { actions.onOpenChat(chat.id) },
                        )
                    }
                }
            }
        } else if (visibleChats.isEmpty()) {
            Column(
                modifier = Modifier.fillMaxSize().padding(padding).padding(horizontal = 24.dp),
                verticalArrangement = Arrangement.Center,
            ) {
                Text("Начать общение", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.height(6.dp))
                Text(
                    "Найдите пользователя или группу",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodyMedium,
                )
                Spacer(Modifier.height(14.dp))
                Surface(
                    color = MaterialTheme.colorScheme.surface,
                    border = BorderStroke(1.dp, FedMesThemeValues.extendedColors.border),
                    shape = RoundedCornerShape(5.dp),
                ) {
                    BasicTextField(
                        value = searchQuery,
                        onValueChange = { searchQuery = it.take(80) },
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 11.dp),
                        singleLine = true,
                        textStyle = MaterialTheme.typography.bodyMedium.copy(color = MaterialTheme.colorScheme.onSurface),
                        cursorBrush = SolidColor(MaterialTheme.colorScheme.primary),
                        decorationBox = { inner ->
                            if (searchQuery.isBlank()) Text("Поиск по имени", color = MaterialTheme.colorScheme.onSurfaceVariant)
                            inner()
                        },
                    )
                }
                searchResults.take(8).forEach { chat ->
                    Spacer(Modifier.height(4.dp))
                    Surface(
                        modifier = Modifier.fillMaxWidth().clickable { actions.onOpenChat(chat.id) },
                        color = MaterialTheme.colorScheme.surface,
                        shape = RoundedCornerShape(5.dp),
                    ) {
                        Column(Modifier.padding(horizontal = 12.dp, vertical = 10.dp)) {
                            Text(chatDisplayName(chat, account.username), fontWeight = FontWeight.SemiBold)
                            Text(if (chat.kind == "family") "Группа" else "Пользователь", color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.labelSmall)
                        }
                    }
                }
            }
        } else {
            LazyColumn(modifier = Modifier.fillMaxSize().padding(padding)) {
                items(visibleChats, key = ChatSummary::id, contentType = { "chat" }) { chat ->
                    ChatRow(
                        chat = chat,
                        currentUsername = account.username,
                        familyMembers = familyMembers,
                        presence = state.presence,
                        preview = state.previews[chat.id].orEmpty(),
                        unreadCount = state.unreadCounts[chat.id] ?: 0,
                        onClick = { actions.onOpenChat(chat.id) },
                    )
                }
            }
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun ChatRow(
    chat: ChatSummary,
    currentUsername: String,
    familyMembers: List<FamilyUser>,
    presence: List<PresenceState>,
    preview: String,
    unreadCount: Int,
    onClick: () -> Unit,
) {
    val peer = chat.members.firstOrNull { it != currentUsername } ?: currentUsername
    val avatarUser = when (chat.kind) {
        "favorites" -> familyMembers.user(currentUsername)
        "family" -> FamilyUser("family", "Семья", AvatarTone.GREEN)
        else -> familyMembers.user(peer)
    }
    val displayName = chatDisplayName(chat, currentUsername)
    val colors = FedMesThemeValues.extendedColors
    val peerPresence = presence.firstOrNull { it.username == peer }
    FedMes26ChatRow(
        title = displayName,
        preview = preview.ifBlank { if (chat.lastSequence > 0) "Зашифрованное сообщение" else "Нет сообщений" },
        time = chat.lastMessageAt?.let(::formatTime).orEmpty(),
        unreadCount = unreadCount,
        selected = false,
        online = peerPresence?.online == true && chat.kind == "direct",
        dark = colors.isDark,
        onClick = onClick,
        avatar = {
            if (chat.kind == "favorites") {
                SavedMessagesAvatar(size = 54.dp)
            } else {
                FamilyAvatar(
                    user = avatarUser,
                    size = 54.dp,
                    displayName = if (chat.kind == "family") "Семья" else familyDisplayName(peer, currentUsername),
                )
            }
        },
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ChatScreen(
    account: AccountSummary,
    familyMembers: List<FamilyUser>,
    chat: ChatSummary,
    state: MessengerUiState,
    actions: MessengerActions,
    modifier: Modifier,
) {
    val focusManager = LocalFocusManager.current
    val listState = rememberLazyListState()
    val snackbar = remember { SnackbarHostState() }
    var deleteRequest by remember { mutableStateOf<Set<String>?>(null) }
    var forwardingMessage by remember { mutableStateOf<DecryptedMessage?>(null) }
    var showAttachmentPicker by remember { mutableStateOf(false) }
    val context = LocalContext.current
    val audioRecorder = remember(context) { ChatAudioRecorder(context) }
    var recordMode by remember { mutableStateOf(ComposerRecordMode.AUDIO) }
    var audioRecording by remember { mutableStateOf(false) }
    var audioWaveform by remember { mutableStateOf<List<Int>>(emptyList()) }
    var audioElapsed by remember { mutableLongStateOf(0L) }
    var showRoundVideoRecorder by remember { mutableStateOf(false) }
    var pendingRecordMode by remember { mutableStateOf<ComposerRecordMode?>(null) }
    var recordingError by remember { mutableStateOf<String?>(null) }
    val messageById = remember(state.messages) { state.messages.associateBy(DecryptedMessage::id) }
    var highlightedMessageId by remember { mutableStateOf<String?>(null) }
    val scrollScope = rememberCoroutineScope()
    val colors = FedMesThemeValues.extendedColors
    val peerUsername = chat.members.firstOrNull { it != account.username } ?: account.username
    val headerDisplayName = chatDisplayName(chat, account.username)
    val headerUser = when (chat.kind) {
        "family" -> FamilyUser("family", "Семья", AvatarTone.GREEN)
        else -> familyMembers.user(peerUsername)
    }

    fun scrollToLatest() {
        scrollScope.launch {
            repeat(3) { pass ->
                if (pass > 0) delay(90)
                val target = state.messages.size + 1
                runCatching { listState.scrollToItem(target.coerceAtLeast(0)) }
            }
        }
    }

    fun startGrantedRecording(mode: ComposerRecordMode) {
        when (mode) {
            ComposerRecordMode.AUDIO -> runCatching {
                audioWaveform = emptyList()
                audioElapsed = 0L
                audioRecorder.start()
                audioRecording = true
            }.onFailure { recordingError = it.message ?: "Не удалось начать запись" }
            ComposerRecordMode.VIDEO -> showRoundVideoRecorder = true
        }
    }

    val recordingPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { result ->
        val mode = pendingRecordMode
        pendingRecordMode = null
        val granted = when (mode) {
            ComposerRecordMode.AUDIO -> result[Manifest.permission.RECORD_AUDIO] == true
            ComposerRecordMode.VIDEO -> result[Manifest.permission.CAMERA] == true && result[Manifest.permission.RECORD_AUDIO] == true
            null -> false
        }
        if (granted && mode != null) startGrantedRecording(mode) else if (mode != null) {
            recordingError = "Для записи нужны разрешения камеры и микрофона"
        }
    }

    fun requestRecording(mode: ComposerRecordMode) {
        val permissions = when (mode) {
            ComposerRecordMode.AUDIO -> arrayOf(Manifest.permission.RECORD_AUDIO)
            ComposerRecordMode.VIDEO -> arrayOf(Manifest.permission.CAMERA, Manifest.permission.RECORD_AUDIO)
        }
        if (permissions.all { ContextCompat.checkSelfPermission(context, it) == PackageManager.PERMISSION_GRANTED }) {
            startGrantedRecording(mode)
        } else {
            pendingRecordMode = mode
            recordingPermissionLauncher.launch(permissions)
        }
    }

    fun finishAudioRecording(send: Boolean) {
        val result = runCatching { audioRecorder.stop(send, audioWaveform) }
            .onFailure { recordingError = it.message ?: "Не удалось завершить запись" }
            .getOrNull()
        audioRecording = false
        audioWaveform = emptyList()
        audioElapsed = 0L
        if (result != null) actions.onVoice(result)
    }

    LaunchedEffect(audioRecording) {
        while (audioRecording) {
            audioElapsed = audioRecorder.elapsedMillis()
            val amplitude = audioRecorder.amplitudePercent()
            audioWaveform = (audioWaveform + amplitude).takeLast(64)
            delay(80)
        }
    }
    DisposableEffect(audioRecorder) {
        onDispose { audioRecorder.release() }
    }


    LaunchedEffect(state.jumpToMessageToken) {
        val targetId = state.jumpToMessageId ?: return@LaunchedEffect
        val index = state.messages.indexOfFirst { it.id == targetId }
        if (index >= 0) {
            listState.scrollToItem(index + 1)
            highlightedMessageId = targetId
            delay(1_250)
            if (highlightedMessageId == targetId) highlightedMessageId = null
        }
    }

    LaunchedEffect(state.scrollToBottomToken) {
        if (state.messages.isNotEmpty()) scrollToLatest()
    }
    LaunchedEffect(state.messages.lastOrNull()?.id) {
        if (state.messages.isEmpty()) return@LaunchedEffect
        val layout = listState.layoutInfo
        val lastVisible = layout.visibleItemsInfo.lastOrNull()?.index ?: 0
        val wasNearBottom = layout.totalItemsCount == 0 || lastVisible >= layout.totalItemsCount - 4
        if (wasNearBottom) scrollToLatest()
    }
    LaunchedEffect(listState, state.hasMoreOlder, state.loadingOlder) {
        snapshotFlow { listState.firstVisibleItemIndex }
            .distinctUntilChanged()
            .collect { firstVisible ->
                if (firstVisible <= 6 && state.hasMoreOlder && !state.loadingOlder) {
                    actions.onLoadOlder()
                }
            }
    }
    LaunchedEffect(listState, state.messages) {
        snapshotFlow {
            listState.layoutInfo.visibleItemsInfo
                .mapNotNull { item -> item.key as? String }
                .filterNot { it.startsWith(SPECIAL_ITEM_PREFIX) }
                .toSet()
        }.distinctUntilChanged().collect { visible -> actions.onVisibleMessages(visible) }
    }
    LaunchedEffect(state.error) {
        state.error?.let {
            snackbar.showSnackbar(it)
            actions.onClearError()
        }
    }
    LaunchedEffect(recordingError) {
        recordingError?.let {
            snackbar.showSnackbar(it)
            recordingError = null
        }
    }

    deleteRequest?.let { ids ->
        DeleteConfirmationDialog(
            chat = chat,
            currentUsername = account.username,
            messageCount = ids.size,
            onDismiss = { deleteRequest = null },
            onConfirm = { deleteForEveryone ->
                deleteRequest = null
                actions.onDeleteMessages(ids, deleteForEveryone)
            },
        )
    }
    forwardingMessage?.let { message ->
        ForwardMessageDialog(
            message = message,
            chats = state.chats,
            currentUsername = account.username,
            onDismiss = { forwardingMessage = null },
            onForward = { targetChatId ->
                forwardingMessage = null
                actions.onForward(message, targetChatId)
            },
        )
    }

    if (showRoundVideoRecorder) {
        RoundVideoRecorderDialog(
            initialShape = RoundVideoShape.CIRCLE,
            onDismiss = { showRoundVideoRecorder = false },
            onRecorded = { recorded ->
                showRoundVideoRecorder = false
                actions.onRoundVideo(recorded)
            },
        )
    }

    if (showAttachmentPicker) {
        AttachmentPickerSheet(
            initialCaption = state.draft,
            onDismiss = { showAttachmentPicker = false },
            onSend = { selections ->
                showAttachmentPicker = false
                actions.onAttachments(selections)
            },
        )
    }

    Scaffold(
        modifier = modifier
            .fillMaxSize()
            .imePadding(),
        contentWindowInsets = WindowInsets.safeDrawing.only(
            WindowInsetsSides.Horizontal + WindowInsetsSides.Top,
        ),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        if (chat.kind == "favorites") {
                            SavedMessagesAvatar(size = 40.dp)
                        } else {
                            FamilyAvatar(
                                user = headerUser,
                                size = 40.dp,
                                displayName = if (chat.kind == "family") "Семья" else familyDisplayName(peerUsername, account.username),
                            )
                        }
                        Spacer(Modifier.width(10.dp))
                        Column {
                            Text(
                                headerDisplayName,
                                color = if (chat.kind == "favorites") {
                                    MaterialTheme.colorScheme.primary
                                } else {
                                    colors.nameText
                                },
                                fontWeight = FontWeight.SemiBold,
                                maxLines = 1,
                            )
                            ChatStatusLine(
                                chat = chat,
                                currentUsername = account.username,
                                presence = state.presence,
                                typingUsers = state.typingUsers,
                            )
                        }
                    }
                },
                navigationIcon = {
                    IconButton(onClick = actions.onBack) {
                        BackIcon(Modifier.size(24.dp), MaterialTheme.colorScheme.onSurface)
                    }
                },
                actions = {
                    if (chat.kind != "favorites") {
                        IconButton(onClick = actions.onStartAudioCall) {
                            Text("☎", color = MaterialTheme.colorScheme.onSurface, fontSize = 20.sp)
                        }
                        IconButton(onClick = actions.onStartVideoCall) {
                            Text("▣", color = MaterialTheme.colorScheme.onSurface, fontSize = 19.sp)
                        }
                    }
                },
            )
        },
        bottomBar = {
            Column {
                val chatUploads = state.uploads.values
                    .filter { it.chatId == chat.id }
                    .sortedBy(UploadTaskUi::id)
                if (chatUploads.isNotEmpty()) {
                    UploadQueuePanel(
                        tasks = chatUploads,
                        onCancel = actions.onCancelUpload,
                    )
                }
                if (audioRecording) {
                    AudioRecordingBar(
                        elapsedMillis = audioElapsed,
                        waveform = audioWaveform,
                        onCancel = { finishAudioRecording(false) },
                        onSend = { finishAudioRecording(true) },
                    )
                } else {
                    Composer(
                        state = state,
                        recordMode = recordMode,
                        onDraft = actions.onDraft,
                        onSend = actions.onSend,
                        onFocused = { scrollToLatest() },
                        onAttachment = {
                            focusManager.clearFocus(force = true)
                            showAttachmentPicker = true
                        },
                        onToggleRecordMode = {
                            recordMode = if (recordMode == ComposerRecordMode.AUDIO) ComposerRecordMode.VIDEO else ComposerRecordMode.AUDIO
                        },
                        onRecordGesture = ::requestRecording,
                        onCancelMode = actions.onCancelComposerMode,
                    )
                }
            }
        },
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            if (state.selectedMessageIds.isNotEmpty()) {
                val selectedMessages = state.messages.filter { it.id in state.selectedMessageIds }
                val editable = selectedMessages.singleOrNull()?.takeIf { message ->
                    message.senderUsername == account.username &&
                        message.content.kind == MessageKind.TEXT &&
                        message.content.forwardedFromUsername == null
                }
                SelectionBar(
                    count = state.selectedMessageIds.size,
                    onCancel = actions.onClearSelection,
                    onEdit = editable?.let { message -> { actions.onEdit(message) } },
                    onDelete = { deleteRequest = state.selectedMessageIds },
                )
            }
            val pinned = state.messages.firstOrNull { it.id == chat.pinnedMessageId }
            if (chat.pinnedMessageId != null) {
                Surface(color = MaterialTheme.colorScheme.secondaryContainer) {
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 12.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        PinIcon(Modifier.size(20.dp), MaterialTheme.colorScheme.onSecondaryContainer)
                        Spacer(Modifier.width(8.dp))
                        Column(Modifier.weight(1f)) {
                            Text("Закреплённое сообщение", fontWeight = FontWeight.SemiBold)
                            Text(
                                pinned?.content?.text.orEmpty().ifBlank { "Зашифрованное сообщение" },
                                maxLines = 1,
                            )
                        }
                        TextButton(onClick = actions.onUnpin) { Text("Открепить") }
                    }
                }
            }
            Box(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth(),
            ) {
                val showScrollDown by remember(listState) {
                    derivedStateOf { listState.canScrollForward }
                }
                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f))
                        .padding(horizontal = 8.dp),
                    state = listState,
                    verticalArrangement = Arrangement.spacedBy(6.dp),
                ) {
                    item(key = "${SPECIAL_ITEM_PREFIX}top", contentType = "loader") {
                        Box(
                            Modifier
                                .fillMaxWidth()
                                .height(34.dp),
                            contentAlignment = Alignment.Center,
                        ) {
                            if (state.loadingOlder) {
                                CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
                            }
                        }
                    }
                    items(
                        items = state.messages,
                        key = DecryptedMessage::id,
                        contentType = { message ->
                            if (message.content.kind == MessageKind.ROUND_VIDEO) {
                                "${message.content.kind}:${message.content.roundVideoShape ?: RoundVideoShape.CIRCLE}"
                            } else {
                                message.content.kind
                            }
                        },
                    ) { message ->
                        MessageBubble(
                            message = message,
                            own = message.senderUsername == account.username,
                            selected = message.id in state.selectedMessageIds,
                            highlighted = message.id == highlightedMessageId,
                            selectionMode = state.selectedMessageIds.isNotEmpty(),
                            replyMessage = message.content.replyToId?.let(messageById::get),
                            onJumpToReply = { replyId -> actions.onJumpToMessage(replyId) },
                            onReply = { actions.onReply(message.id) },
                            onEdit = { actions.onEdit(message) },
                            onForward = { forwardingMessage = message },
                            onDelete = { deleteRequest = setOf(message.id) },
                            onPin = { actions.onPin(message.id) },
                            onSelect = { actions.onToggleSelection(message.id) },
                            currentUsername = account.username,
                            targetMessage = message.content.targetMessageId?.let(messageById::get),
                            onOpenAttachment = { descriptor -> actions.onOpenAttachment(message, descriptor) },
                            onLoadAttachmentPreview = actions.onLoadAttachmentPreview,
                            onLoadAttachmentBytes = actions.onLoadAttachmentBytes,
                            onRequestSpoilerReveal = { actions.onRequestSpoilerReveal(message) },
                            onRevealSpoiler = actions.onRevealSpoiler,
                            downloadingAttachment = state.downloadingAttachmentId == message.id,
                        )
                    }
                    item(key = "${SPECIAL_ITEM_PREFIX}bottom", contentType = "spacer") {
                        Spacer(Modifier.height(72.dp))
                    }
                }
                if (showScrollDown) {
                    Surface(
                        modifier = Modifier
                            .align(Alignment.BottomEnd)
                            .padding(16.dp)
                            .size(48.dp)
                            .clickable(onClick = ::scrollToLatest),
                        color = MaterialTheme.colorScheme.primary,
                        contentColor = Color.Black,
                        shape = CircleShape,
                        shadowElevation = 7.dp,
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            DownArrowIcon(Modifier.size(25.dp), Color.Black)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ChatStatusLine(
    chat: ChatSummary,
    currentUsername: String,
    presence: List<PresenceState>,
    typingUsers: Set<String>,
) {
    if (chat.kind == "favorites") return
    val dots = rememberTypingDots(typingUsers.isNotEmpty())
    val text = if (chat.kind == "family") {
        chat.members.joinToString(", ") { username ->
            if (username in typingUsers) {
                "${familyDisplayName(username, currentUsername)} - печатает$dots"
            } else {
                "${familyDisplayName(username, currentUsername)} - ${statusText(presence.firstOrNull { it.username == username })}"
            }
        }
    } else {
        val peer = chat.members.firstOrNull { it != currentUsername }.orEmpty()
        if (peer in typingUsers) {
            "печатает$dots"
        } else {
            statusText(presence.firstOrNull { it.username == peer })
        }
    }
    Text(
        text = text,
        style = MaterialTheme.typography.labelSmall,
        color = if (typingUsers.isNotEmpty()) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
        maxLines = if (chat.kind == "family") 2 else 1,
        overflow = TextOverflow.Ellipsis,
    )
}

@Composable
private fun rememberTypingDots(active: Boolean): String {
    var count by remember(active) { mutableIntStateOf(1) }
    LaunchedEffect(active) {
        while (active) {
            delay(420)
            count = count % 3 + 1
        }
    }
    return if (active) ".".repeat(count) else ""
}

@Composable
private fun SelectionBar(
    count: Int,
    onCancel: () -> Unit,
    onEdit: (() -> Unit)?,
    onDelete: () -> Unit,
) {
    Surface(color = MaterialTheme.colorScheme.surface) {
        Row(
            Modifier
                .fillMaxWidth()
                .height(58.dp)
                .padding(horizontal = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconButton(onClick = onCancel) {
                CloseIcon(Modifier.size(24.dp), MaterialTheme.colorScheme.onSurface)
            }
            Text(
                "$count выбрано",
                Modifier.weight(1f),
                color = MaterialTheme.colorScheme.onSurface,
                fontSize = 13.sp,
                fontWeight = FontWeight.SemiBold,
            )
            if (onEdit != null) {
                IconButton(onClick = onEdit) {
                    EditIcon(Modifier.size(22.dp), MaterialTheme.colorScheme.onSurface)
                }
            }
            IconButton(onClick = onDelete) {
                DeleteIcon(Modifier.size(24.dp), MaterialTheme.colorScheme.error)
            }
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun MessageBubble(
    message: DecryptedMessage,
    own: Boolean,
    selected: Boolean,
    highlighted: Boolean,
    selectionMode: Boolean,
    replyMessage: DecryptedMessage?,
    onJumpToReply: (String) -> Unit,
    onReply: () -> Unit,
    onEdit: () -> Unit,
    onForward: () -> Unit,
    onDelete: () -> Unit,
    onPin: () -> Unit,
    onSelect: () -> Unit,
    currentUsername: String,
    targetMessage: DecryptedMessage?,
    onOpenAttachment: (MediaDescriptor) -> Unit,
    onLoadAttachmentPreview: suspend (DecryptedMessage, MediaDescriptor) -> ByteArray?,
    onLoadAttachmentBytes: suspend (DecryptedMessage, MediaDescriptor) -> ByteArray,
    onRequestSpoilerReveal: () -> Unit,
    onRevealSpoiler: (DecryptedMessage, String) -> Unit,
    downloadingAttachment: Boolean,
) {
    val context = LocalContext.current
    var menu by remember(message.id) { mutableStateOf(false) }
    val extendedColors = FedMesThemeValues.extendedColors
    val roundVideo = message.content.kind == MessageKind.ROUND_VIDEO
    val cleanMedia = message.content.kind in setOf(MessageKind.PHOTO, MessageKind.VIDEO, MessageKind.MEDIA_GROUP) &&
        message.content.text.isBlank() &&
        message.content.replyToId.isNullOrBlank() &&
        message.content.forwardedFromUsername.isNullOrBlank()
    val transparentMedia = roundVideo || cleanMedia
    // Figma selection mode keeps the message's directional bubble color unchanged;
    // selection is represented by a dedicated 32dp control on the left.
    val bubbleColor = when {
        highlighted -> MaterialTheme.colorScheme.tertiaryContainer
        transparentMedia -> Color.Transparent
        own -> extendedColors.outgoingBubble
        else -> extendedColors.incomingBubble
    }
    val bubbleContentColor = when {
        highlighted -> MaterialTheme.colorScheme.onTertiaryContainer
        transparentMedia -> MaterialTheme.colorScheme.onSurface
        else -> extendedColors.messageText
    }

    val bubbleInteraction = remember(message.id) { MutableInteractionSource() }
    Box(
        modifier = Modifier.fillMaxWidth(),
        contentAlignment = if (own) Alignment.CenterEnd else Alignment.CenterStart,
    ) {
        // The transparent layer occupies only the empty row area in practice: the
        // visible bubble above it consumes its own taps, while blank space opens actions.
        Box(
            modifier = Modifier
                .matchParentSize()
                .combinedClickable(
                    onClick = { if (selectionMode) onSelect() else menu = true },
                    onLongClick = onSelect,
                ),
        ) {
            MessageActionsMenu(
                expanded = menu,
                onDismiss = { menu = false },
                message = message,
                own = own,
                onReply = onReply,
                onEdit = onEdit,
                onForward = onForward,
                onPin = onPin,
                onSelect = onSelect,
                onDelete = onDelete,
                onCopy = {
                    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                    clipboard.setPrimaryClip(ClipData.newPlainText("FedMes", message.content.text))
                },
                onDownload = { descriptor -> onOpenAttachment(descriptor) },
            )
        }

        if (selectionMode) {
            Surface(
                modifier = Modifier
                    .align(Alignment.CenterStart)
                    .padding(start = 4.dp)
                    .size(32.dp),
                shape = CircleShape,
                color = if (selected) MaterialTheme.colorScheme.primary.copy(alpha = 0.45f) else Color.Transparent,
                border = BorderStroke(2.dp, if (selected) MaterialTheme.colorScheme.primary else extendedColors.border),
            ) {
                Box(contentAlignment = Alignment.Center) {
                    if (selected) {
                        Text("✓", color = MaterialTheme.colorScheme.onPrimary, fontSize = 18.sp, fontWeight = FontWeight.Bold)
                    }
                }
            }
        }

        Surface(
            modifier = Modifier
                .padding(start = if (selectionMode) 44.dp else 0.dp)
                .then(if (roundVideo) Modifier else Modifier.fillMaxWidth(0.84f))
                .clickable(
                    interactionSource = bubbleInteraction,
                    indication = null,
                    onClick = { if (selectionMode) onSelect() },
                ),
                shape = RoundedCornerShape(16.dp),
                color = bubbleColor,
                contentColor = bubbleContentColor,
                tonalElevation = if (transparentMedia) 0.dp else 1.dp,
            ) {
                Column(
                    Modifier.padding(
                        horizontal = if (transparentMedia) 0.dp else 12.dp,
                        vertical = if (transparentMedia) 0.dp else 8.dp,
                    ),
                ) {
                    if (!own) {
                        Text(
                            familyDisplayName(message.senderUsername, currentUsername),
                            color = if (message.senderUsername == "grisha") {
                                MaterialTheme.colorScheme.primary
                            } else {
                                extendedColors.nameText
                            },
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.padding(horizontal = if (transparentMedia) 6.dp else 0.dp),
                        )
                    }
                    message.content.forwardedFromUsername?.let { username ->
                        Text(
                            "Переслано от ${familyDisplayName(username, currentUsername)}",
                            color = MaterialTheme.colorScheme.primary,
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.SemiBold,
                            modifier = Modifier.padding(
                                start = if (transparentMedia) 6.dp else 0.dp,
                                bottom = 4.dp,
                            ),
                        )
                    }
                    message.content.replyToId?.let { replyId ->
                        val replied = replyMessage
                        if (replied != null) {
                            ReplyPreview(
                                message = replied,
                                onJump = { onJumpToReply(replyId) },
                                onLoadPreview = onLoadAttachmentPreview,
                                compact = roundVideo,
                                currentUsername = currentUsername,
                            )
                        } else {
                            MissingReplyPreview(
                                onJump = { onJumpToReply(replyId) },
                                compact = roundVideo,
                            )
                        }
                        Spacer(Modifier.height(6.dp))
                    }
                    val messageBody: @Composable () -> Unit = {
                        MessageBody(
                            message = message,
                            currentUsername = currentUsername,
                            targetMessage = targetMessage,
                            onOpenAttachment = onOpenAttachment,
                            onLoadAttachmentPreview = onLoadAttachmentPreview,
                            onLoadAttachmentBytes = onLoadAttachmentBytes,
                            onRequestSpoilerReveal = onRequestSpoilerReveal,
                            onRevealSpoiler = onRevealSpoiler,
                            downloadingAttachment = downloadingAttachment,
                        )
                    }
                    if (transparentMedia) {
                        Box {
                            messageBody()
                            MessageMeta(
                                message = message,
                                own = own,
                                overlay = true,
                                modifier = Modifier
                                    .align(Alignment.BottomEnd)
                                    .padding(6.dp),
                            )
                        }
                    } else {
                        messageBody()
                        MessageMeta(
                            message = message,
                            own = own,
                            overlay = false,
                            modifier = Modifier.align(Alignment.End),
                        )
                    }
                }
        }
        if (selectionMode) {
            Box(
                modifier = Modifier
                    .matchParentSize()
                    .clickable(
                        interactionSource = remember(message.id, "selection") { MutableInteractionSource() },
                        indication = null,
                        onClick = onSelect,
                    ),
            )
        }
    }
}

@Composable
private fun MessageActionsMenu(
    expanded: Boolean,
    onDismiss: () -> Unit,
    message: DecryptedMessage,
    own: Boolean,
    onReply: () -> Unit,
    onEdit: () -> Unit,
    onForward: () -> Unit,
    onPin: () -> Unit,
    onSelect: () -> Unit,
    onDelete: () -> Unit,
    onCopy: () -> Unit,
    onDownload: (MediaDescriptor) -> Unit,
) {
    DropdownMenu(expanded = expanded, onDismissRequest = onDismiss) {
        DropdownMenuItem(
            text = { Text("Ответить") },
            leadingIcon = { ReplyIcon(Modifier.size(21.dp), MaterialTheme.colorScheme.onSurface) },
            onClick = { onDismiss(); onReply() },
        )
        if (own && message.content.kind == MessageKind.TEXT && message.content.forwardedFromUsername == null) {
            DropdownMenuItem(
                text = { Text("Изменить") },
                leadingIcon = { EditIcon(Modifier.size(21.dp), MaterialTheme.colorScheme.onSurface) },
                onClick = { onDismiss(); onEdit() },
            )
        }
        DropdownMenuItem(
            text = { Text("Копировать") },
            leadingIcon = { CopyIcon(Modifier.size(21.dp), MaterialTheme.colorScheme.onSurface) },
            enabled = message.content.text.isNotBlank(),
            onClick = { onDismiss(); onCopy() },
        )
        DropdownMenuItem(
            text = { Text("Переслать") },
            leadingIcon = { ForwardIcon(Modifier.size(21.dp), MaterialTheme.colorScheme.onSurface) },
            onClick = { onDismiss(); onForward() },
        )
        DropdownMenuItem(
            text = { Text("Закрепить") },
            leadingIcon = { PinIcon(Modifier.size(21.dp), MaterialTheme.colorScheme.onSurface) },
            onClick = { onDismiss(); onPin() },
        )
        if (message.content.kind == MessageKind.FILE || message.content.kind == MessageKind.AUDIO) {
            val descriptor = message.content.mediaItems.firstOrNull() ?: message.content.media
            if (descriptor != null) {
                DropdownMenuItem(
                    text = { Text("Скачать") },
                    leadingIcon = { DownloadIcon(Modifier.size(21.dp), MaterialTheme.colorScheme.onSurface) },
                    onClick = { onDismiss(); onDownload(descriptor) },
                )
            }
        }
        DropdownMenuItem(
            text = { Text("Выбрать") },
            onClick = { onDismiss(); onSelect() },
        )
        DropdownMenuItem(
            text = { Text("Удалить", color = MaterialTheme.colorScheme.error) },
            leadingIcon = { DeleteIcon(Modifier.size(21.dp), MaterialTheme.colorScheme.error) },
            onClick = { onDismiss(); onDelete() },
        )
    }
}

@Composable
private fun MessageMeta(
    message: DecryptedMessage,
    own: Boolean,
    overlay: Boolean,
    modifier: Modifier = Modifier,
) {
    val colors = FedMesThemeValues.extendedColors
    val metaColor = if (colors.isDark) Color.White else Color.Black
    val content: @Composable () -> Unit = {
        Row(verticalAlignment = Alignment.CenterVertically) {
            if (own && message.content.spoiler) {
                Text("скрыто ", color = metaColor, style = MaterialTheme.typography.labelSmall)
            }
            if (message.editedAt != null) {
                Text("изменено ", color = metaColor, style = MaterialTheme.typography.labelSmall)
            }
            Text(formatTime(message.createdAt), color = metaColor, style = MaterialTheme.typography.labelSmall)
            if (own) {
                Spacer(Modifier.width(4.dp))
                DeliveryChecksIcon(
                    state = message.deliveryState,
                    modifier = Modifier.size(width = 20.dp, height = 14.dp),
                    color = if (message.deliveryState == MessageDeliveryState.PENDING) {
                        Color(0xFF8E8E93)
                    } else {
                        Color(0xFF3B88C3)
                    },
                )
            }
        }
    }
    if (overlay) {
        Surface(
            modifier = modifier,
            color = if (colors.isDark) Color.Black.copy(alpha = 0.55f) else Color.White.copy(alpha = 0.78f),
            shape = RoundedCornerShape(7.dp),
            tonalElevation = 0.dp,
        ) {
            Box(Modifier.padding(horizontal = 6.dp, vertical = 2.dp)) { content() }
        }
    } else {
        Box(modifier = modifier.padding(top = 2.dp)) { content() }
    }
}

@Composable
private fun ReplyPreview(
    message: DecryptedMessage,
    onJump: () -> Unit,
    onLoadPreview: suspend (DecryptedMessage, MediaDescriptor) -> ByteArray?,
    compact: Boolean,
    currentUsername: String,
) {
    val descriptor = message.content.mediaItems.firstOrNull() ?: message.content.media
    val mediaKind = message.content.kind in setOf(
        MessageKind.PHOTO,
        MessageKind.VIDEO,
        MessageKind.MEDIA_GROUP,
        MessageKind.ROUND_VIDEO,
    )
    val colors = FedMesThemeValues.extendedColors
    Surface(
        modifier = Modifier
            .then(if (compact) Modifier.width(220.dp) else Modifier.fillMaxWidth())
            .clickable(onClick = onJump),
        color = colors.quoteBackground,
        contentColor = colors.messageText,
        shape = RoundedCornerShape(9.dp),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .height(IntrinsicSize.Min),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                Modifier
                    .width(4.dp)
                    .fillMaxHeight()
                    .background(colors.quoteBar),
            )
            Row(
                modifier = Modifier
                    .weight(1f)
                    .padding(horizontal = 7.dp, vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                if (descriptor != null && mediaKind) {
                    val previewShape = if (message.content.kind == MessageKind.ROUND_VIDEO) {
                        CircleShape
                    } else {
                        RoundedCornerShape(6.dp)
                    }
                    Box(
                        Modifier
                            .size(38.dp)
                            .clip(previewShape),
                    ) {
                        RemoteMediaPreview(
                            message = message,
                            descriptor = descriptor,
                            onLoadPreview = onLoadPreview,
                            modifier = Modifier.fillMaxSize(),
                        )
                    }
                    Spacer(Modifier.width(8.dp))
                }
                Column(Modifier.weight(1f)) {
                    Text(
                        familyDisplayName(message.senderUsername, currentUsername),
                        color = if (message.senderUsername == "grisha") {
                            MaterialTheme.colorScheme.primary
                        } else {
                            colors.nameText
                        },
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                    )
                    if (message.content.kind != MessageKind.ROUND_VIDEO) {
                        Text(
                            replyPreviewText(message),
                            color = colors.messageText,
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
                QuoteMarksIcon(
                    modifier = Modifier.size(22.dp),
                    color = colors.quoteMarks,
                )
            }
        }
    }
}

@Composable
private fun MissingReplyPreview(
    onJump: () -> Unit,
    compact: Boolean,
) {
    val colors = FedMesThemeValues.extendedColors
    Surface(
        modifier = Modifier
            .then(if (compact) Modifier.width(220.dp) else Modifier.fillMaxWidth())
            .clickable(onClick = onJump),
        color = colors.quoteBackground,
        shape = RoundedCornerShape(9.dp),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .height(IntrinsicSize.Min),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(Modifier.width(4.dp).fillMaxHeight().background(colors.quoteBar))
            Text(
                "Перейти к исходному сообщению",
                modifier = Modifier.weight(1f).padding(10.dp),
                color = colors.messageText,
                style = MaterialTheme.typography.bodySmall,
            )
            QuoteMarksIcon(Modifier.padding(end = 8.dp).size(22.dp), colors.quoteMarks)
        }
    }
}

private fun replyPreviewText(message: DecryptedMessage): String = when (message.content.kind) {
    MessageKind.TEXT, MessageKind.SYSTEM, MessageKind.SPOILER_REQUEST, MessageKind.CALL ->
        message.content.text.ifBlank { "Сообщение" }
    MessageKind.PHOTO -> message.content.text.ifBlank { "Фото" }
    MessageKind.VIDEO -> message.content.text.ifBlank { "Видео" }
    MessageKind.MEDIA_GROUP -> message.content.text.ifBlank { "Медиагруппа" }
    MessageKind.AUDIO -> message.content.text.ifBlank { "Аудио" }
    MessageKind.VOICE -> "Голосовое сообщение"
    MessageKind.ROUND_VIDEO -> ""
    MessageKind.FILE -> message.content.media?.name ?: "Файл"
}

@Composable
private fun DeleteConfirmationDialog(
    chat: ChatSummary,
    currentUsername: String,
    messageCount: Int,
    onDismiss: () -> Unit,
    onConfirm: (Boolean) -> Unit,
) {
    val forceEveryone = chat.kind == "favorites"
    var deleteForEveryone by remember(chat.id, messageCount) { mutableStateOf(forceEveryone) }
    val peer = chat.members.firstOrNull { it != currentUsername }.orEmpty()
    val checkboxLabel = when (chat.kind) {
        "direct" -> "Также удалить для ${familyDisplayName(peer, currentUsername)}"
        "family" -> "Также удалить для всех участников"
        else -> "Удалить навсегда"
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (messageCount == 1) "Удалить сообщение?" else "Удалить сообщения?") },
        text = {
            Column {
                Text(
                    if (messageCount == 1) {
                        "Вы точно хотите удалить это сообщение?"
                    } else {
                        "Вы точно хотите удалить выбранные сообщения: $messageCount?"
                    },
                )
                if (!forceEveryone) {
                    Spacer(Modifier.height(12.dp))
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { deleteForEveryone = !deleteForEveryone },
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Checkbox(
                            checked = deleteForEveryone,
                            onCheckedChange = { deleteForEveryone = it },
                        )
                        Text(checkboxLabel)
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { onConfirm(deleteForEveryone || forceEveryone) }) {
                Text("Удалить", color = MaterialTheme.colorScheme.error)
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Отмена") } },
    )
}

@Composable
private fun ForwardMessageDialog(
    message: DecryptedMessage,
    chats: List<ChatSummary>,
    currentUsername: String,
    onDismiss: () -> Unit,
    onForward: (String) -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Переслать сообщение") },
        text = {
            LazyColumn(Modifier.heightIn(max = 360.dp)) {
                items(
                    chats.filterNot { it.id == message.chatId }.sortedWith(compareBy<ChatSummary> { it.kind != "favorites" }.thenBy { chatDisplayName(it, currentUsername) }),
                    key = ChatSummary::id,
                ) { chat ->
                    Text(
                        text = chatDisplayName(chat, currentUsername),
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onForward(chat.id) }
                            .padding(vertical = 14.dp, horizontal = 6.dp),
                        fontWeight = FontWeight.Medium,
                    )
                }
            }
        },
        confirmButton = {},
        dismissButton = { TextButton(onClick = onDismiss) { Text("Отмена") } },
    )
}

@Composable
private fun MessageBody(
    message: DecryptedMessage,
    currentUsername: String,
    targetMessage: DecryptedMessage?,
    onOpenAttachment: (MediaDescriptor) -> Unit,
    onLoadAttachmentPreview: suspend (DecryptedMessage, MediaDescriptor) -> ByteArray?,
    onLoadAttachmentBytes: suspend (DecryptedMessage, MediaDescriptor) -> ByteArray,
    onRequestSpoilerReveal: () -> Unit,
    onRevealSpoiler: (DecryptedMessage, String) -> Unit,
    downloadingAttachment: Boolean,
) {
    val content = message.content
    when (content.kind) {
        MessageKind.TEXT -> TextSpoilerMessageBody(message)
        MessageKind.CALL -> {
            val call = content.call
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(content.text.ifBlank { "Звонок" }, fontWeight = FontWeight.SemiBold)
                call?.let {
                    Text(
                        when (it.event) {
                            com.fedmes.app.messaging.CallEvent.INVITE -> if (it.mode == com.fedmes.app.messaging.CallMode.AUDIO) "Аудиозвонок" else "Видеозвонок"
                            com.fedmes.app.messaging.CallEvent.ENDED -> "Завершён"
                            com.fedmes.app.messaging.CallEvent.DECLINED -> "Отклонён"
                            com.fedmes.app.messaging.CallEvent.NO_ANSWER -> "Нет ответа"
                            com.fedmes.app.messaging.CallEvent.FAILED -> "Ошибка"
                        },
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        }
        MessageKind.SYSTEM -> Text(content.text)
        MessageKind.PHOTO, MessageKind.VIDEO, MessageKind.MEDIA_GROUP -> MediaGroupMessageBody(
            message = message,
            currentUsername = currentUsername,
            onOpen = onOpenAttachment,
            onLoadPreview = onLoadAttachmentPreview,
            onLoadBytes = onLoadAttachmentBytes,
        )
        MessageKind.AUDIO, MessageKind.VOICE -> {
            val descriptor = content.mediaItems.firstOrNull() ?: content.media
            if (descriptor == null) {
                Text("Аудио недоступно")
            } else {
                AudioWaveformMessageBody(message, descriptor, onLoadAttachmentBytes)
            }
        }
        MessageKind.ROUND_VIDEO -> {
            val descriptor = content.mediaItems.firstOrNull() ?: content.media
            if (descriptor == null) {
                Text("Видеосообщение недоступно")
            } else {
                RoundVideoMessageBody(
                    message = message,
                    descriptor = descriptor,
                    onLoadPreview = onLoadAttachmentPreview,
                    onLoadBytes = onLoadAttachmentBytes,
                )
            }
        }
        MessageKind.SPOILER_REQUEST -> SpoilerRequestMessageBody(
            message = message,
            currentUsername = currentUsername,
            targetMessage = targetMessage,
            onReveal = onRevealSpoiler,
        )
        MessageKind.FILE -> AttachmentBody(
            kind = "Файл",
            name = content.media?.name,
            caption = content.text,
            captionEntities = content.textEntities,
            onOpen = { content.media?.let(onOpenAttachment) },
            downloading = downloadingAttachment,
        )
    }
}

@Composable
private fun AttachmentBody(
    kind: String,
    name: String?,
    caption: String,
    captionEntities: List<TextEntity>,
    onOpen: () -> Unit,
    downloading: Boolean,
) {
    Surface(
        modifier = Modifier.clickable(enabled = !downloading, onClick = onOpen),
        color = MaterialTheme.colorScheme.secondaryContainer,
        shape = RoundedCornerShape(10.dp),
    ) {
        Row(
            modifier = Modifier.padding(10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text(kind, fontWeight = FontWeight.SemiBold)
                name?.let { Text(it, maxLines = 2, overflow = TextOverflow.Ellipsis) }
            }
            if (downloading) {
                CircularProgressIndicator(Modifier.size(22.dp), strokeWidth = 2.dp)
            } else {
                DownloadIcon(Modifier.size(22.dp), MaterialTheme.colorScheme.onSecondaryContainer)
            }
        }
    }
    if (caption.isNotBlank()) {
        Spacer(Modifier.height(6.dp))
        RichMessageText(caption, captionEntities)
    }
}

private object FedMesDisabledTextContextMenuProvider : TextContextMenuProvider {
    override suspend fun showTextContextMenu(dataProvider: TextContextMenuDataProvider) = Unit
}

private object FedMesDisabledTextToolbar : TextToolbar {
    override val status: TextToolbarStatus = TextToolbarStatus.Hidden

    override fun hide() = Unit

    override fun showMenu(
        rect: Rect,
        onCopyRequested: (() -> Unit)?,
        onPasteRequested: (() -> Unit)?,
        onCutRequested: (() -> Unit)?,
        onSelectAllRequested: (() -> Unit)?,
    ) = Unit
}

@OptIn(androidx.compose.ui.ExperimentalComposeUiApi::class)
@Composable
private fun Composer(
    state: MessengerUiState,
    recordMode: ComposerRecordMode,
    onDraft: (String, List<TextEntity>) -> Unit,
    onSend: () -> Unit,
    onFocused: () -> Unit,
    onAttachment: () -> Unit,
    onToggleRecordMode: () -> Unit,
    onRecordGesture: (ComposerRecordMode) -> Unit,
    onCancelMode: () -> Unit,
) {
    val density = LocalDensity.current
    val imeVisible = WindowInsets.ime.getBottom(density) > 0
    val recordDragThreshold = with(density) { 36.dp.toPx() }
    val focusRequester = remember { FocusRequester() }
    val keyboardController = LocalSoftwareKeyboardController.current
    val context = LocalContext.current
    var formattingMenu by remember { mutableStateOf(false) }
    var fieldValue by remember {
        mutableStateOf(TextFieldValue(state.draft, selection = androidx.compose.ui.text.TextRange(state.draft.length)))
    }

    LaunchedEffect(state.draft, state.editingMessageId) {
        if (fieldValue.text != state.draft) {
            fieldValue = TextFieldValue(
                text = state.draft,
                selection = androidx.compose.ui.text.TextRange(state.draft.length),
            )
        }
    }
    LaunchedEffect(state.editingMessageId, state.replyToId) {
        if (state.editingMessageId != null || state.replyToId != null) {
            focusRequester.requestFocus()
            keyboardController?.show()
            onFocused()
        }
    }
    LaunchedEffect(imeVisible) {
        if (imeVisible) onFocused()
    }

    val selectionStart = minOf(fieldValue.selection.start, fieldValue.selection.end)
    val selectionEnd = maxOf(fieldValue.selection.start, fieldValue.selection.end)
    val hasSelection = selectionEnd > selectionStart
    val colors = FedMesThemeValues.extendedColors
    val quoteBackground = colors.quoteBackground
    val visualTransformation = remember(state.draftTextEntities, quoteBackground) {
        RichTextVisualTransformation(state.draftTextEntities, quoteBackground)
    }

    fun commit(value: TextFieldValue, entities: List<TextEntity>) {
        fieldValue = value
        onDraft(value.text, sanitizeTextEntities(value.text, entities))
    }

    fun copySelection() {
        if (!hasSelection) return
        val selected = fieldValue.text.substring(selectionStart, selectionEnd)
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("FedMes", selected))
    }

    fun cutSelection() {
        if (!hasSelection) return
        copySelection()
        val newText = fieldValue.text.removeRange(selectionStart, selectionEnd)
        val entities = remapTextEntitiesAfterEdit(fieldValue.text, newText, state.draftTextEntities)
        commit(
            TextFieldValue(newText, selection = androidx.compose.ui.text.TextRange(selectionStart)),
            entities,
        )
    }

    fun toggleFormat(type: TextEntityType, lineBased: Boolean = false) {
        if (!hasSelection) return
        val range = if (lineBased) {
            expandToLineRange(fieldValue.text, selectionStart, selectionEnd)
        } else {
            selectionStart..selectionEnd
        }
        val entities = toggleTextEntity(
            fieldValue.text,
            state.draftTextEntities,
            type,
            range.first,
            range.last,
        )
        commit(fieldValue, entities)
    }

    Surface(tonalElevation = 3.dp) {
        Column(
            Modifier
                .fillMaxWidth()
                .then(if (imeVisible) Modifier else Modifier.navigationBarsPadding())
                .padding(horizontal = 8.dp, vertical = 5.dp),
        ) {
            if (hasSelection) {
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    color = colors.formattingSurface,
                    contentColor = colors.formattingText,
                    border = BorderStroke(2.dp, colors.formattingBorder),
                    tonalElevation = 6.dp,
                ) {
                    Row(
                        modifier = Modifier.padding(horizontal = 4.dp, vertical = 2.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        TextButton(onClick = ::cutSelection) { Text("Вырезать", color = colors.formattingText) }
                        TextButton(onClick = ::copySelection) { Text("Копировать", color = colors.formattingText) }
                        TextButton(onClick = { toggleFormat(TextEntityType.QUOTE, lineBased = true) }) {
                            Text("Цитировать", color = colors.formattingText)
                        }
                        Box {
                            IconButton(onClick = { formattingMenu = true }) {
                                MoreIcon(Modifier.size(22.dp), colors.formattingText)
                            }
                            DropdownMenu(
                                expanded = formattingMenu,
                                onDismissRequest = { formattingMenu = false },
                                containerColor = colors.formattingSurface,
                            ) {
                                DropdownMenuItem(
                                    text = { Text("Жирный", color = colors.formattingText, fontWeight = FontWeight.Bold) },
                                    onClick = { formattingMenu = false; toggleFormat(TextEntityType.BOLD) },
                                )
                                DropdownMenuItem(
                                    text = { Text("Курсив", color = colors.formattingText, fontStyle = androidx.compose.ui.text.font.FontStyle.Italic) },
                                    onClick = { formattingMenu = false; toggleFormat(TextEntityType.ITALIC) },
                                )
                                DropdownMenuItem(
                                    text = { Text("Моно", color = colors.formattingText, fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace) },
                                    onClick = { formattingMenu = false; toggleFormat(TextEntityType.MONOSPACE) },
                                )
                                DropdownMenuItem(
                                    text = { Text("Зачёркнутый", color = colors.formattingText, textDecoration = androidx.compose.ui.text.style.TextDecoration.LineThrough) },
                                    onClick = { formattingMenu = false; toggleFormat(TextEntityType.STRIKETHROUGH) },
                                )
                                DropdownMenuItem(
                                    text = { Text("Подчёркнутый", color = colors.formattingText, textDecoration = androidx.compose.ui.text.style.TextDecoration.Underline) },
                                    onClick = { formattingMenu = false; toggleFormat(TextEntityType.UNDERLINE) },
                                )
                                DropdownMenuItem(
                                    text = { Text("Скрытый текст", color = colors.formattingText) },
                                    leadingIcon = { SpoilerIcon(Modifier.size(20.dp), colors.formattingText) },
                                    onClick = { formattingMenu = false; toggleFormat(TextEntityType.SPOILER) },
                                )
                                HorizontalDivider()
                                DropdownMenuItem(
                                    text = { Text("Обычный", color = colors.formattingText) },
                                    onClick = {
                                        formattingMenu = false
                                        commit(
                                            fieldValue,
                                            clearTextEntities(
                                                fieldValue.text,
                                                state.draftTextEntities,
                                                selectionStart,
                                                selectionEnd,
                                            ),
                                        )
                                    },
                                )
                            }
                        }
                    }
                }
                Spacer(Modifier.height(4.dp))
            }
            if (state.replyToId != null || state.editingMessageId != null) {
                Row(
                    Modifier
                        .fillMaxWidth()
                        .padding(start = 48.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        if (state.editingMessageId != null) "Редактирование сообщения" else "Ответ на сообщение",
                        modifier = Modifier.weight(1f),
                        color = MaterialTheme.colorScheme.primary,
                        style = MaterialTheme.typography.labelMedium,
                    )
                    IconButton(onClick = onCancelMode, modifier = Modifier.size(36.dp)) {
                        CloseIcon(Modifier.size(18.dp), MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
            Row(verticalAlignment = Alignment.Bottom) {
                IconButton(
                    onClick = onAttachment,
                    enabled = !state.sending && state.editingMessageId == null,
                ) {
                    AttachIcon(Modifier.size(25.dp), MaterialTheme.colorScheme.onSurfaceVariant)
                }
                Surface(
                    modifier = Modifier
                        .weight(1f)
                        .heightIn(min = 44.dp, max = 120.dp),
                    shape = RoundedCornerShape(22.dp),
                    color = colors.formattingSurface,
                    border = BorderStroke(1.dp, colors.formattingBorder),
                ) {
                    CompositionLocalProvider(
                        LocalTextContextMenuToolbarProvider provides FedMesDisabledTextContextMenuProvider,
                        LocalTextContextMenuDropdownProvider provides FedMesDisabledTextContextMenuProvider,
                        LocalTextToolbar provides FedMesDisabledTextToolbar,
                    ) {
                        BasicTextField(
                            value = fieldValue,
                        onValueChange = { next ->
                            val limitedText = next.text.take(MAX_COMPOSER_TEXT_LENGTH)
                            val limited = if (limitedText == next.text) next else TextFieldValue(
                                text = limitedText,
                                selection = androidx.compose.ui.text.TextRange(limitedText.length),
                            )
                            val entities = remapTextEntitiesAfterEdit(
                                fieldValue.text,
                                limited.text,
                                state.draftTextEntities,
                            )
                            commit(limited, entities)
                        },
                        modifier = Modifier
                            .fillMaxWidth()
                            .focusRequester(focusRequester)
                            .onFocusChanged { if (it.isFocused) onFocused() }
                            .padding(horizontal = 14.dp, vertical = 11.dp),
                        textStyle = MaterialTheme.typography.bodyLarge.copy(
                            color = colors.formattingText,
                        ),
                        cursorBrush = SolidColor(MaterialTheme.colorScheme.primary),
                        visualTransformation = visualTransformation,
                        maxLines = 5,
                        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Default),
                        decorationBox = { innerTextField ->
                            Box(contentAlignment = Alignment.CenterStart) {
                                if (state.draft.isEmpty()) {
                                    Text(
                                        "Сообщение",
                                        color = colors.formattingText.copy(alpha = 0.65f),
                                    )
                                }
                                innerTextField()
                            }
                            },
                        )
                    }
                }
                Spacer(Modifier.width(6.dp))
                if (state.draft.isNotBlank() || state.sending) {
                    IconButton(
                        onClick = onSend,
                        enabled = state.draft.isNotBlank() && !state.sending,
                        modifier = Modifier
                            .size(46.dp)
                            .background(
                                color = if (state.draft.isNotBlank() && !state.sending) {
                                    MaterialTheme.colorScheme.primary
                                } else {
                                    MaterialTheme.colorScheme.surfaceVariant
                                },
                                shape = CircleShape,
                            ),
                    ) {
                        if (state.sending) {
                            CircularProgressIndicator(Modifier.size(19.dp), strokeWidth = 2.dp)
                        } else {
                            SendIcon(Modifier.size(22.dp), MaterialTheme.colorScheme.onPrimary)
                        }
                    }
                } else {
                    Box(
                        modifier = Modifier
                            .size(46.dp)
                            .clip(CircleShape)
                            .background(MaterialTheme.colorScheme.primary)
                            .pointerInput(recordMode, recordDragThreshold) {
                                awaitEachGesture {
                                    val down = awaitFirstDown(requireUnconsumed = false)
                                    val pointerId = down.id
                                    var verticalDrag = 0f
                                    var moved = false
                                    while (true) {
                                        val event = awaitPointerEvent()
                                        val change = event.changes.firstOrNull { it.id == pointerId } ?: break
                                        verticalDrag += change.position.y - change.previousPosition.y
                                        if (abs(verticalDrag) > viewConfiguration.touchSlop) moved = true
                                        if (!change.pressed) {
                                            change.consume()
                                            if (verticalDrag <= -recordDragThreshold) {
                                                onRecordGesture(recordMode)
                                            } else if (!moved) {
                                                onToggleRecordMode()
                                            }
                                            break
                                        }
                                        if (moved) change.consume()
                                    }
                                }
                            },
                        contentAlignment = Alignment.Center,
                    ) {
                        if (recordMode == ComposerRecordMode.AUDIO) {
                            MicIcon(Modifier.size(24.dp), MaterialTheme.colorScheme.onPrimary)
                        } else {
                            VideoMessageIcon(Modifier.size(24.dp), MaterialTheme.colorScheme.onPrimary)
                        }
                    }
                }
            }
        }
    }
}

private class RichTextVisualTransformation(
    private val entities: List<TextEntity>,
    private val quoteBackground: Color,
) : VisualTransformation {
    override fun filter(text: AnnotatedString): TransformedText = TransformedText(
        text = buildRichAnnotatedString(text.text, entities, quoteBackground),
        offsetMapping = OffsetMapping.Identity,
    )
}

private const val MAX_COMPOSER_TEXT_LENGTH = 16_384

@Composable
private fun UploadQueuePanel(
    tasks: List<UploadTaskUi>,
    onCancel: (String) -> Unit,
) {
    Surface(tonalElevation = 4.dp) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 7.dp),
            verticalArrangement = Arrangement.spacedBy(7.dp),
        ) {
            tasks.forEach { task ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(
                            text = task.title,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            style = MaterialTheme.typography.labelLarge,
                        )
                        Spacer(Modifier.height(4.dp))
                        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                        Spacer(Modifier.height(3.dp))
                        Text(
                            text = when (task.phase) {
                                UploadTaskPhase.PREPARING -> "Подготовка ${task.completedItems}/${task.totalItems}"
                                UploadTaskPhase.UPLOADING -> "Отправка ${task.completedItems}/${task.totalItems}"
                            },
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            style = MaterialTheme.typography.labelSmall,
                        )
                    }
                    Spacer(Modifier.width(8.dp))
                    TextButton(onClick = { onCancel(task.id) }) {
                        Text("Отмена")
                    }
                }
            }
        }
    }
}

@Composable
private fun AudioRecordingBar(
    elapsedMillis: Long,
    waveform: List<Int>,
    onCancel: () -> Unit,
    onSend: () -> Unit,
) {
    val primary = MaterialTheme.colorScheme.primary
    val muted = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.42f)
    Surface(tonalElevation = 3.dp) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .navigationBarsPadding()
                .padding(horizontal = 10.dp, vertical = 7.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(formatMediaDuration(elapsedMillis), style = MaterialTheme.typography.labelLarge)
            Spacer(Modifier.width(10.dp))
            androidx.compose.foundation.Canvas(
                modifier = Modifier
                    .weight(1f)
                    .height(34.dp),
            ) {
                val values = waveform.takeLast(48)
                if (values.isEmpty()) return@Canvas
                val barWidth = size.width / (values.size * 1.7f)
                val gap = barWidth * 0.7f
                values.forEachIndexed { index, value ->
                    val normalized = (value.coerceIn(3, 100) / 100f)
                    val height = (size.height * normalized).coerceAtLeast(4f)
                    val left = index * (barWidth + gap)
                    drawRoundRect(
                        color = if (index >= values.lastIndex - 4) primary else muted,
                        topLeft = androidx.compose.ui.geometry.Offset(left, (size.height - height) / 2f),
                        size = androidx.compose.ui.geometry.Size(barWidth, height),
                        cornerRadius = androidx.compose.ui.geometry.CornerRadius(barWidth / 2f),
                    )
                }
            }
            TextButton(onClick = onCancel) { Text("Отмена") }
            IconButton(
                onClick = onSend,
                modifier = Modifier
                    .size(46.dp)
                    .background(primary, CircleShape),
            ) {
                SendIcon(Modifier.size(22.dp), MaterialTheme.colorScheme.onPrimary)
            }
        }
    }
}

private enum class ComposerRecordMode { AUDIO, VIDEO }

private fun List<FamilyUser>.user(id: String): FamilyUser =
    firstOrNull { it.id == id } ?: FamilyUser(id, familyDisplayName(id, id), AvatarTone.GRAY)

private fun familyDisplayName(username: String, currentUsername: String): String = when (username.lowercase(Locale.ROOT)) {
    "papa" -> if (currentUsername.equals("mama", ignoreCase = true)) "Муж" else "Папа"
    "mama" -> if (currentUsername.equals("papa", ignoreCase = true)) "Жена" else "Мама"
    "yura" -> "Юра"
    "vasya" -> "Вася"
    "grisha" -> "Гриша"
    else -> username
}

private fun chatDisplayName(chat: ChatSummary, currentUsername: String): String = when (chat.kind) {
    "favorites" -> "Избранное"
    "family" -> "Семья"
    else -> {
        val peer = chat.members.firstOrNull { it != currentUsername }.orEmpty()
        familyDisplayName(peer.ifBlank { chat.title }, currentUsername)
    }
}

private fun statusText(presence: PresenceState?): String {
    if (presence == null) return "статус неизвестен"
    if (presence.online) return "в сети"
    val last = presence.lastSeenAt
    if (presence.showExact && last != null) {
        val now = System.currentTimeMillis()
        val age = now - last
        return when {
            age < DAY_MILLIS && sameDay(now, last) -> "был(а) в ${formatTime(last)}"
            age < 2 * DAY_MILLIS -> "был(а) вчера в ${formatTime(last)}"
            age < 7 * DAY_MILLIS -> "был(а) на этой неделе"
            age < 31 * DAY_MILLIS -> "был(а) в этом месяце"
            else -> "был(а) давно"
        }
    }
    return when (presence.lastSeenCategory) {
        "today" -> "был(а) сегодня"
        "yesterday" -> "был(а) вчера"
        "week" -> "был(а) на этой неделе"
        "month" -> "был(а) в этом месяце"
        else -> "был(а) давно"
    }
}

private fun sameDay(first: Long, second: Long): Boolean {
    val format = SimpleDateFormat("yyyyMMdd", Locale.US)
    return format.format(Date(first)) == format.format(Date(second))
}

private fun formatTime(epochMillis: Long): String =
    SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date(epochMillis))

private fun ThemeMode.next(): ThemeMode = when (this) {
    ThemeMode.SYSTEM -> ThemeMode.LIGHT
    ThemeMode.LIGHT -> ThemeMode.DARK
    ThemeMode.DARK -> ThemeMode.SYSTEM
}

private fun themeName(themeMode: ThemeMode): String = when (themeMode) {
    ThemeMode.SYSTEM -> "системная"
    ThemeMode.LIGHT -> "светлая"
    ThemeMode.DARK -> "тёмная"
}

private const val SPECIAL_ITEM_PREFIX = "__fedmes_"
private const val DAY_MILLIS = 24L * 60L * 60L * 1000L
private val ONLINE_COLOR = Color(0xFF2FBA72)
