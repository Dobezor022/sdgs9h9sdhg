package com.fedmes.app.ui.messenger

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.graphics.Bitmap
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.produceState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.draw.clip
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.fedmes.app.devices.AccountDevice
import com.fedmes.app.accountsecurity.PendingDeviceRequest
import com.fedmes.app.devices.DeviceLinkPreview
import com.fedmes.app.messaging.DeviceAttachmentItem
import com.fedmes.app.messaging.DeviceAttachmentKind
import com.fedmes.app.messaging.DeviceAttachmentRepository
import com.fedmes.app.domain.family.FamilyUser
import com.fedmes.app.provisioning.AccountSummary
import com.fedmes.app.provisioning.ProvisioningFailure
import com.fedmes.app.ui.components.BackIcon
import com.fedmes.app.ui.components.FamilyAvatar
import com.fedmes.app.ui.model.ScannerPhase
import com.fedmes.app.ui.provisioning.QrScannerScaffold
import java.text.SimpleDateFormat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsRootScreen(
    account: AccountSummary,
    currentUser: FamilyUser,
    deviceCount: Int,
    onBack: () -> Unit,
    onOpenDevices: () -> Unit,
    onOpenNotifications: () -> Unit,
    onOpenSecurity: () -> Unit,
    onOpenProfile: () -> Unit,
    profileAvatarUri: String?,
    profileAvatarMimeType: String?,
    profileNameColorArgb: Long,
) {
    BackHandler(onBack = onBack)
    Scaffold(
        contentWindowInsets = WindowInsets.safeDrawing,
        topBar = {
            TopAppBar(
                title = { Text("Настройки", fontWeight = FontWeight.Bold) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        BackIcon(Modifier.size(24.dp), MaterialTheme.colorScheme.onSurface)
                    }
                },
            )
        },
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp),
        ) {
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(24.dp),
                color = MaterialTheme.colorScheme.surfaceContainer,
            ) {
                Row(
                    modifier = Modifier.padding(20.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    ProfileAvatarPreview(
                        user = currentUser,
                        uri = profileAvatarUri,
                        mimeType = profileAvatarMimeType,
                        size = 64.dp,
                    )
                    Spacer(Modifier.size(16.dp))
                    Column {
                        Text(
                            account.username,
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold,
                            color = profileArgbColor(profileNameColorArgb, MaterialTheme.colorScheme.onSurface),
                        )
                        Text(
                            "FedMes ID: ${account.deviceId.take(8)}",
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            }
            Spacer(Modifier.height(16.dp))
            SettingsRow(
                title = "Профиль: ${account.username}",
                subtitle = "Аватар, видео профиля и цвет имени",
                onClick = onOpenProfile,
            ) {
                ProfilePersonIcon(Modifier.size(28.dp), MaterialTheme.colorScheme.primary)
            }
            Spacer(Modifier.height(10.dp))
            SettingsRow(
                title = "Безопасность и восстановление",
                subtitle = "Recovery Key, vault и доверенные устройства",
                onClick = onOpenSecurity,
            ) {
                SecurityShieldIcon(Modifier.size(28.dp), MaterialTheme.colorScheme.primary)
            }
            Spacer(Modifier.height(10.dp))
            SettingsRow(
                title = "Уведомления",
                subtitle = "Сообщения, звук, вибрация и группы",
                onClick = onOpenNotifications,
            ) {
                NotificationBellIcon(Modifier.size(28.dp), MaterialTheme.colorScheme.primary)
            }
            Spacer(Modifier.height(10.dp))
            SettingsRow(
                title = "Устройства",
                subtitle = if (deviceCount > 0) "$deviceCount активных" else "Активные сеансы и вход Desktop",
                onClick = onOpenDevices,
            ) {
                DevicesIcon(Modifier.size(28.dp), MaterialTheme.colorScheme.primary)
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ProfileSettingsScreen(
    account: AccountSummary,
    currentUser: FamilyUser,
    avatarUri: String?,
    avatarMimeType: String?,
    nameColorArgb: Long,
    onBack: () -> Unit,
    onChooseMedia: () -> Unit,
    onClearMedia: () -> Unit,
    onColor: (Long) -> Unit,
) {
    BackHandler(onBack = onBack)
    val colors = listOf(
        0L, 0xFF111111L, 0xFFFFFFFFL, 0xFF2AABEE, 0xFF39B982, 0xFFFF9F43,
        0xFF8854D0, 0xFFEE5253, 0xFF22A6B3, 0xFFEAB43C,
    )
    Scaffold(
        contentWindowInsets = WindowInsets.safeDrawing,
        topBar = {
            TopAppBar(
                title = { Text("Профиль", fontWeight = FontWeight.Bold) },
                navigationIcon = { IconButton(onClick = onBack) { BackIcon(Modifier.size(24.dp), MaterialTheme.colorScheme.onSurface) } },
            )
        },
    ) { padding ->
        Column(
            Modifier.fillMaxSize().padding(padding).padding(horizontal = 18.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Spacer(Modifier.height(18.dp))
            Box {
                ProfileAvatarPreview(currentUser, avatarUri, avatarMimeType, 116.dp)
                Surface(
                    modifier = Modifier.align(Alignment.BottomEnd).size(38.dp).clickable(onClick = onChooseMedia),
                    shape = CircleShape,
                    color = MaterialTheme.colorScheme.primary,
                ) { Box(contentAlignment = Alignment.Center) { ProfileCameraIcon(Modifier.size(22.dp), MaterialTheme.colorScheme.onPrimary) } }
            }
            Spacer(Modifier.height(14.dp))
            Text(
                account.username,
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold,
                color = profileArgbColor(nameColorArgb, MaterialTheme.colorScheme.onSurface),
            )
            Text(
                if (avatarMimeType?.startsWith("video/") == true) "Видео профиля" else if (avatarUri != null) "Фото профиля" else "Буквенный аватар",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Row(Modifier.padding(top = 10.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = onChooseMedia) { Text("Изменить") }
                if (avatarUri != null) OutlinedButton(onClick = onClearMedia) { Text("Удалить") }
            }
            Spacer(Modifier.height(24.dp))
            Text("Цвет имени", modifier = Modifier.fillMaxWidth(), fontWeight = FontWeight.SemiBold)
            Row(
                Modifier.fillMaxWidth().padding(top = 12.dp),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                colors.forEach { argb ->
                    Surface(
                        modifier = Modifier.size(if (argb == nameColorArgb) 42.dp else 36.dp).clickable { onColor(argb) },
                        shape = CircleShape,
                        color = profileArgbColor(argb, MaterialTheme.colorScheme.surfaceVariant),
                        border = if (argb == nameColorArgb) androidx.compose.foundation.BorderStroke(3.dp, MaterialTheme.colorScheme.primary) else null,
                    ) {}
                }
            }
            Spacer(Modifier.height(22.dp))
            Text(
                "Профиль хранится локально на этом устройстве. Серверная синхронизация аватаров будет добавлена отдельной миграцией.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

private fun profileArgbColor(argb: Long, fallback: Color): Color {
    if (argb == 0L) return fallback
    // Compose Color(ULong) expects Compose's internal 64-bit color encoding,
    // not a regular Android ARGB value. Convert the persisted ARGB to Int so
    // the public ARGB constructor is used and the profile screen cannot crash.
    return Color((argb and 0xFFFFFFFFL).toInt())
}

@Composable
private fun ProfileAvatarPreview(
    user: FamilyUser,
    uri: String?,
    mimeType: String?,
    size: androidx.compose.ui.unit.Dp,
) {
    val context = LocalContext.current
    val repository = remember(context) { DeviceAttachmentRepository(context) }
    val item = remember(uri, mimeType) {
        uri?.let {
            DeviceAttachmentItem(
                stableId = "profile:$it",
                uri = it,
                name = "profile",
                mimeType = mimeType.orEmpty(),
                size = 0,
                modifiedAtSeconds = 0,
                durationMillis = null,
                kind = if (mimeType?.startsWith("video/") == true) DeviceAttachmentKind.VIDEO else DeviceAttachmentKind.PHOTO,
            )
        }
    }
    val bitmap by produceState<Bitmap?>(initialValue = null, item?.uri) {
        value = item?.let { withContext(Dispatchers.IO) { repository.loadThumbnail(it, 480) } }
    }
    val image = bitmap
    if (image == null) {
        FamilyAvatar(user, size = size)
    } else {
        Image(
            bitmap = image.asImageBitmap(),
            contentDescription = "Аватар ${user.displayName}",
            modifier = Modifier.size(size).clip(CircleShape).background(MaterialTheme.colorScheme.surfaceVariant),
            contentScale = ContentScale.Crop,
        )
    }
}

@Composable
private fun ProfilePersonIcon(modifier: Modifier, color: Color) {
    Canvas(modifier) {
        drawCircle(color, radius = size.minDimension * .18f, center = Offset(size.width * .5f, size.height * .32f))
        drawArc(color, 200f, 140f, false, topLeft = Offset(size.width * .18f, size.height * .44f), size = androidx.compose.ui.geometry.Size(size.width * .64f, size.height * .48f), style = Stroke(2.dp.toPx(), cap = StrokeCap.Round))
    }
}

@Composable
private fun ProfileCameraIcon(modifier: Modifier, color: Color) {
    val lensColor = MaterialTheme.colorScheme.primary
    Canvas(modifier) {
        drawRoundRect(color, cornerRadius = androidx.compose.ui.geometry.CornerRadius(3.dp.toPx()), topLeft = Offset(size.width * .1f, size.height * .25f), size = androidx.compose.ui.geometry.Size(size.width * .8f, size.height * .58f))
        drawCircle(lensColor, radius = size.minDimension * .16f, center = center)
        drawCircle(color, radius = size.minDimension * .1f, center = center)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NotificationSettingsScreen(
    enabled: Boolean,
    soundEnabled: Boolean,
    vibrationEnabled: Boolean,
    groupEnabled: Boolean,
    onBack: () -> Unit,
    onEnabled: (Boolean) -> Unit,
    onSound: (Boolean) -> Unit,
    onVibration: (Boolean) -> Unit,
    onGroups: (Boolean) -> Unit,
) {
    BackHandler(onBack = onBack)
    Scaffold(
        contentWindowInsets = WindowInsets.safeDrawing,
        topBar = {
            TopAppBar(
                title = { Text("Уведомления", fontWeight = FontWeight.Bold) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        BackIcon(Modifier.size(24.dp), MaterialTheme.colorScheme.onSurface)
                    }
                },
            )
        },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding).padding(horizontal = 16.dp)) {
            NotificationToggleRow("Уведомления", "Разрешить уведомления о новых сообщениях", enabled, onEnabled)
            NotificationToggleRow("Звук", "Проигрывать звук нового сообщения", soundEnabled, onSound, enabled)
            NotificationToggleRow("Вибрация", "Вибрация при новом сообщении", vibrationEnabled, onVibration, enabled)
            NotificationToggleRow("Группа «Семья»", "Уведомлять о сообщениях семейной группы", groupEnabled, onGroups, enabled)
            Spacer(Modifier.height(12.dp))
            Text(
                "Текст сообщений на экране блокировки не показывается.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

@Composable
private fun NotificationToggleRow(
    title: String,
    subtitle: String,
    checked: Boolean,
    onChecked: (Boolean) -> Unit,
    enabled: Boolean = true,
) {
    Row(
        Modifier.fillMaxWidth().clickable(enabled = enabled) { onChecked(!checked) }.padding(vertical = 13.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(title, fontWeight = FontWeight.SemiBold)
            Text(subtitle, color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
        }
        Switch(checked = checked, onCheckedChange = onChecked, enabled = enabled)
    }
    HorizontalDivider()
}

@Composable
private fun NotificationBellIcon(modifier: Modifier, color: Color) {
    Canvas(modifier) {
        val stroke = 2.dp.toPx()
        drawArc(color, 205f, 130f, false, style = Stroke(stroke, cap = StrokeCap.Round))
        drawLine(color, Offset(size.width * .24f, size.height * .68f), Offset(size.width * .76f, size.height * .68f), stroke, StrokeCap.Round)
        drawCircle(color, radius = stroke * .72f, center = Offset(size.width * .5f, size.height * .82f))
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AccountSecuritySettingsScreen(
    loading: Boolean,
    recoveryConfigured: Boolean,
    generatedRecoveryKey: String?,
    error: String?,
    opaqueEnrolled: Boolean,
    pendingDevices: List<PendingDeviceRequest>,
    onBack: () -> Unit,
    onGenerateRecoveryKey: () -> Unit,
    onConfirmRecoveryKeySaved: () -> Unit,
    onConfigureOpaquePassword: (String) -> Unit,
    onApprovePendingDevice: (String) -> Unit,
    onRejectPendingDevice: (String) -> Unit,
) {
    BackHandler(enabled = generatedRecoveryKey == null && !loading, onBack = onBack)
    var showPasswordDialog by remember { mutableStateOf(false) }
    var password by remember { mutableStateOf("") }
    var passwordRepeat by remember { mutableStateOf("") }

    if (showPasswordDialog) {
        AlertDialog(
            onDismissRequest = { if (!loading) { password = ""; passwordRepeat = ""; showPasswordDialog = false } },
            title = { Text(if (opaqueEnrolled) "Сменить парольную фразу" else "Настроить парольную фразу") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text("OPAQUE проверяет пароль без передачи пароля серверу. Пароль не заменяет Recovery Key.")
                    OutlinedTextField(
                        value = password,
                        onValueChange = { password = it.take(256) },
                        label = { Text("Парольная фраза") },
                        visualTransformation = PasswordVisualTransformation(),
                        singleLine = true,
                    )
                    OutlinedTextField(
                        value = passwordRepeat,
                        onValueChange = { passwordRepeat = it.take(256) },
                        label = { Text("Повтори парольную фразу") },
                        visualTransformation = PasswordVisualTransformation(),
                        singleLine = true,
                    )
                    if (password.isNotEmpty() && (password.length < 12 || password != passwordRepeat)) {
                        Text(
                            if (password.length < 12) "Минимум 12 символов" else "Парольные фразы не совпадают",
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            },
            confirmButton = {
                TextButton(
                    enabled = !loading && password.length >= 12 && password == passwordRepeat,
                    onClick = {
                        val value = password
                        password = ""
                        passwordRepeat = ""
                        showPasswordDialog = false
                        onConfigureOpaquePassword(value)
                    },
                ) { Text(if (opaqueEnrolled) "Сменить" else "Настроить") }
            },
            dismissButton = {
                TextButton(enabled = !loading, onClick = { password = ""; passwordRepeat = ""; showPasswordDialog = false }) {
                    Text("Отмена")
                }
            },
        )
    }

    Scaffold(
        contentWindowInsets = WindowInsets.safeDrawing,
        topBar = {
            TopAppBar(
                title = { Text("Безопасность", fontWeight = FontWeight.Bold) },
                navigationIcon = {
                    IconButton(onClick = onBack, enabled = generatedRecoveryKey == null && !loading) {
                        BackIcon(Modifier.size(24.dp), MaterialTheme.colorScheme.onSurface)
                    }
                },
            )
        },
    ) { padding ->
        LazyColumn(
            Modifier.fillMaxSize().padding(padding).padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item { Spacer(Modifier.height(4.dp)) }
            item {
                Text(
                    "Вход на сервер и доступ к истории разделены. Новое устройство получает ключи только через Recovery Key или подтверждение доверенным устройством.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (loading) {
                item { Box(Modifier.fillMaxWidth().padding(24.dp), contentAlignment = Alignment.Center) { CircularProgressIndicator() } }
            }
            if (generatedRecoveryKey != null) {
                item {
                    Surface(Modifier.fillMaxWidth(), RoundedCornerShape(18.dp), color = MaterialTheme.colorScheme.surfaceContainer) {
                        Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                            Text("Сохрани ключ вне телефона", fontWeight = FontWeight.Bold)
                            Text(generatedRecoveryKey, style = MaterialTheme.typography.bodyLarge)
                            Text("Ключ показывается один раз. Не отправляй его в чат.", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                            Button(onClick = onConfirmRecoveryKeySaved, enabled = !loading, modifier = Modifier.fillMaxWidth()) { Text("Я сохранил Recovery Key") }
                        }
                    }
                }
            } else {
                item {
                    Surface(Modifier.fillMaxWidth(), RoundedCornerShape(18.dp), color = MaterialTheme.colorScheme.surfaceContainer) {
                        Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text("Recovery Key", fontWeight = FontWeight.Bold)
                            Text(
                                if (recoveryConfigured) "Настроен. Он восстанавливает Account Root Key после переустановки."
                                else "Не настроен. Без него и доверенного устройства восстановить историю невозможно.",
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                            if (!recoveryConfigured) Button(onClick = onGenerateRecoveryKey, enabled = !loading, modifier = Modifier.fillMaxWidth()) { Text("Создать Recovery Key") }
                        }
                    }
                }
            }
            item { Text("ЗАПРОСЫ НОВЫХ УСТРОЙСТВ", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary) }
            if (pendingDevices.isEmpty()) {
                item { Text("Новых запросов нет", color = MaterialTheme.colorScheme.onSurfaceVariant) }
            } else {
                items(pendingDevices, key = PendingDeviceRequest::id) { request ->
                    Surface(Modifier.fillMaxWidth(), RoundedCornerShape(18.dp), color = MaterialTheme.colorScheme.surfaceContainer) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            Text(request.displayName, fontWeight = FontWeight.Bold)
                            Text("${platformName(request.platform)} · ${request.networkHint}", color = MaterialTheme.colorScheme.onSurfaceVariant)
                            Text("Signing: ${request.signingFingerprintHex.chunked(4).take(4).joinToString(" ")}…", style = MaterialTheme.typography.bodySmall)
                            Text("Agreement: ${request.keyAgreementFingerprintHex.chunked(4).take(4).joinToString(" ")}…", style = MaterialTheme.typography.bodySmall)
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                Button(enabled = !loading, onClick = { onApprovePendingDevice(request.id) }) { Text("Подтвердить") }
                                OutlinedButton(enabled = !loading, onClick = { onRejectPendingDevice(request.id) }) { Text("Отклонить") }
                            }
                        }
                    }
                }
            }
            if (!error.isNullOrBlank()) item { Text(error, color = MaterialTheme.colorScheme.error) }
            item {
                Text(
                    "Выход из сессии не удаляет encrypted vault. Удаление локальных данных, отзыв устройства и удаление аккаунта — разные действия.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            item { Spacer(Modifier.height(16.dp)) }
        }
    }
}

@Composable
private fun SecurityShieldIcon(modifier: Modifier, color: Color) {
    Canvas(modifier) {
        val path = androidx.compose.ui.graphics.Path().apply {
            moveTo(size.width * .5f, size.height * .08f)
            lineTo(size.width * .84f, size.height * .22f)
            lineTo(size.width * .78f, size.height * .66f)
            quadraticTo(size.width * .67f, size.height * .86f, size.width * .5f, size.height * .94f)
            quadraticTo(size.width * .33f, size.height * .86f, size.width * .22f, size.height * .66f)
            lineTo(size.width * .16f, size.height * .22f)
            close()
        }
        drawPath(path, color = color, style = Stroke(2.dp.toPx(), cap = StrokeCap.Round))
        drawLine(color, Offset(size.width * .36f, size.height * .52f), Offset(size.width * .47f, size.height * .64f), 2.dp.toPx(), StrokeCap.Round)
        drawLine(color, Offset(size.width * .47f, size.height * .64f), Offset(size.width * .68f, size.height * .39f), 2.dp.toPx(), StrokeCap.Round)
    }
}

@Composable
private fun SettingsRow(
    title: String,
    subtitle: String,
    onClick: () -> Unit,
    icon: @Composable () -> Unit,
) {
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        shape = RoundedCornerShape(18.dp),
        color = MaterialTheme.colorScheme.surfaceContainer,
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 18.dp, vertical = 16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            icon()
            Spacer(Modifier.size(16.dp))
            Column(Modifier.weight(1f)) {
                Text(title, fontWeight = FontWeight.SemiBold)
                Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Text("›", style = MaterialTheme.typography.headlineSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DevicesScreen(
    devices: List<AccountDevice>,
    loading: Boolean,
    historySyncing: Boolean,
    error: String?,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onScanDesktopQr: () -> Unit,
    onRevoke: (String) -> Unit,
    onTerminateOthers: () -> Unit,
    onClearError: () -> Unit,
) {
    BackHandler(onBack = onBack)
    var revokeTarget by remember { mutableStateOf<AccountDevice?>(null) }
    var confirmTerminate by remember { mutableStateOf(false) }

    revokeTarget?.let { target ->
        AlertDialog(
            onDismissRequest = { revokeTarget = null },
            title = { Text("Отключить устройство?") },
            text = { Text("${target.displayName} потеряет доступ к FedMes. Для повторного входа потребуется новый QR с телефона.") },
            confirmButton = {
                TextButton(onClick = { onRevoke(target.id); revokeTarget = null }) { Text("Отключить") }
            },
            dismissButton = { TextButton(onClick = { revokeTarget = null }) { Text("Отмена") } },
        )
    }
    if (confirmTerminate) {
        AlertDialog(
            onDismissRequest = { confirmTerminate = false },
            title = { Text("Завершить остальные сеансы?") },
            text = { Text("Все устройства, кроме этого телефона, будут немедленно отключены.") },
            confirmButton = {
                TextButton(onClick = { onTerminateOthers(); confirmTerminate = false }) { Text("Завершить") }
            },
            dismissButton = { TextButton(onClick = { confirmTerminate = false }) { Text("Отмена") } },
        )
    }

    Scaffold(
        contentWindowInsets = WindowInsets.safeDrawing,
        topBar = {
            TopAppBar(
                title = { Text("Устройства", fontWeight = FontWeight.Bold) },
                navigationIcon = {
                    IconButton(onClick = onBack) { BackIcon(Modifier.size(24.dp), MaterialTheme.colorScheme.onSurface) }
                },
                actions = {
                    TextButton(onClick = onRefresh, enabled = !loading) { Text("Обновить") }
                },
            )
        },
    ) { padding ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(padding),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            error?.let { message ->
                item { DeviceErrorBanner(message = message, onDismiss = onClearError) }
            }
            item {
                Button(
                    modifier = Modifier.fillMaxWidth().height(52.dp),
                    onClick = onScanDesktopQr,
                ) {
                    QrLinkIcon(Modifier.size(24.dp), MaterialTheme.colorScheme.onPrimary)
                    Spacer(Modifier.size(10.dp))
                    Text("Подключить Desktop")
                }
            }
            if (historySyncing) {
                item {
                    Surface(shape = RoundedCornerShape(16.dp), color = MaterialTheme.colorScheme.secondaryContainer) {
                        Row(Modifier.fillMaxWidth().padding(14.dp), verticalAlignment = Alignment.CenterVertically) {
                            CircularProgressIndicator(Modifier.size(22.dp), strokeWidth = 2.dp)
                            Spacer(Modifier.size(12.dp))
                            Text("Передача ключей истории на новое устройство…", style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }
            item {
                Text(
                    "АКТИВНЫЕ СЕАНСЫ",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.padding(top = 8.dp, bottom = 2.dp),
                )
            }
            if (loading && devices.isEmpty()) {
                item { Box(Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) { CircularProgressIndicator() } }
            }
            items(devices, key = AccountDevice::id) { device ->
                DeviceCard(device, onRevoke = { revokeTarget = device })
            }
            if (devices.count { !it.current } > 0) {
                item {
                    OutlinedButton(
                        modifier = Modifier.fillMaxWidth(),
                        onClick = { confirmTerminate = true },
                    ) { Text("Завершить все другие сеансы") }
                }
            }
            item {
                Text(
                    "Новый компьютер получает доступ только после сканирования QR этим телефоном и подтверждения системной блокировкой устройства. QR одноразовый и действует 2 минуты.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(6.dp),
                )
            }
        }
    }
}

@Composable
private fun DeviceCard(device: AccountDevice, onRevoke: () -> Unit) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(18.dp),
        color = if (device.current) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceContainer,
    ) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier.size(46.dp).background(MaterialTheme.colorScheme.surface, CircleShape),
                contentAlignment = Alignment.Center,
            ) {
                DevicesIcon(Modifier.size(27.dp), MaterialTheme.colorScheme.primary)
            }
            Spacer(Modifier.size(14.dp))
            Column(Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(device.displayName, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    if (device.current) {
                        Spacer(Modifier.size(8.dp))
                        Text("это устройство", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.primary)
                    }
                }
                Text(
                    "${platformName(device.platform)} · ${device.lastSeenAtEpochMillis?.let(::formatDeviceTime) ?: "неактивно"}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    "Ключ ${device.identityFingerprint.take(12)}…",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (!device.current) {
                TextButton(onClick = onRevoke) { Text("Отключить") }
            }
        }
    }
}

@Composable
fun DeviceLinkScannerScreen(
    phase: ScannerPhase,
    failure: ProvisioningFailure?,
    onDecoded: (String) -> Unit,
    onCameraError: () -> Unit,
    onRetry: () -> Unit,
    onClose: () -> Unit,
) {
    QrScannerScaffold(
        phase = phase,
        failure = failure,
        onQrDecoded = onDecoded,
        onCameraError = onCameraError,
        onRetry = onRetry,
        onClose = onClose,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DeviceLinkApprovalScreen(
    preview: DeviceLinkPreview,
    approving: Boolean,
    error: String?,
    onBack: () -> Unit,
    onApprove: () -> Unit,
    onClearError: () -> Unit,
) {
    BackHandler(enabled = !approving, onBack = onBack)
    val context = LocalContext.current
    var deviceLockError by remember { mutableStateOf<String?>(null) }
    val credentialLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == Activity.RESULT_OK) onApprove()
    }
    @Suppress("DEPRECATION")
    fun confirmWithDeviceLock() {
        val keyguard = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        val intent = keyguard.createConfirmDeviceCredentialIntent(
            "Подтвердите вход FedMes",
            "Разблокируйте телефон, чтобы разрешить вход на ${preview.displayName}",
        )
        if (intent == null) {
            deviceLockError = "Для подключения нового устройства настройте PIN, пароль или биометрию блокировки экрана."
        } else {
            credentialLauncher.launch(intent)
        }
    }

    Scaffold(
        contentWindowInsets = WindowInsets.safeDrawing,
        topBar = {
            TopAppBar(
                title = { Text("Подтверждение входа") },
                navigationIcon = {
                    IconButton(onClick = onBack, enabled = !approving) { BackIcon(Modifier.size(24.dp), MaterialTheme.colorScheme.onSurface) }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding).padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            Surface(shape = CircleShape, color = MaterialTheme.colorScheme.primaryContainer) {
                DevicesIcon(Modifier.padding(28.dp).size(72.dp), MaterialTheme.colorScheme.primary)
            }
            Spacer(Modifier.height(24.dp))
            Text(preview.displayName, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
            Text(platformName(preview.platform), color = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.height(22.dp))
            Surface(shape = RoundedCornerShape(18.dp), color = MaterialTheme.colorScheme.surfaceContainer) {
                Column(Modifier.fillMaxWidth().padding(16.dp)) {
                    Text("Проверьте, что QR открыт на вашем компьютере.", fontWeight = FontWeight.SemiBold)
                    Spacer(Modifier.height(10.dp))
                    Text("Ключ устройства: ${preview.identityFingerprint.chunked(4).take(4).joinToString(" ")}…", style = MaterialTheme.typography.bodySmall)
                    Text("Ключ сообщений: ${preview.encryptionFingerprint.chunked(4).take(4).joinToString(" ")}…", style = MaterialTheme.typography.bodySmall)
                }
            }
            error?.let { message ->
                DeviceErrorBanner(message = message, onDismiss = onClearError)
                Spacer(Modifier.height(12.dp))
            }
            deviceLockError?.let { message ->
                Text(
                    text = message,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                )
                Spacer(Modifier.height(12.dp))
            }
            Spacer(Modifier.height(24.dp))
            Button(
                modifier = Modifier.fillMaxWidth().height(54.dp),
                enabled = !approving,
                onClick = ::confirmWithDeviceLock,
            ) {
                if (approving) {
                    CircularProgressIndicator(Modifier.size(22.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                } else {
                    Text("Разрешить вход")
                }
            }
            Spacer(Modifier.height(10.dp))
            TextButton(onClick = onBack, enabled = !approving) { Text("Это не мой компьютер") }
        }
    }
}

@Composable
private fun DeviceErrorBanner(message: String, onDismiss: () -> Unit) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        color = MaterialTheme.colorScheme.errorContainer,
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = message,
                modifier = Modifier.weight(1f),
                color = MaterialTheme.colorScheme.onErrorContainer,
                style = MaterialTheme.typography.bodySmall,
            )
            TextButton(onClick = onDismiss) { Text("Закрыть") }
        }
    }
}

@Composable
fun SettingsIcon(modifier: Modifier = Modifier, color: Color) {
    Canvas(modifier) {
        val stroke = size.minDimension * 0.08f
        drawCircle(color, radius = size.minDimension * 0.18f, center = center, style = Stroke(stroke))
        repeat(8) { index ->
            val angle = Math.toRadians(index * 45.0)
            val inner = size.minDimension * 0.31f
            val outer = size.minDimension * 0.43f
            drawLine(
                color,
                Offset(center.x + kotlin.math.cos(angle).toFloat() * inner, center.y + kotlin.math.sin(angle).toFloat() * inner),
                Offset(center.x + kotlin.math.cos(angle).toFloat() * outer, center.y + kotlin.math.sin(angle).toFloat() * outer),
                stroke,
                StrokeCap.Round,
            )
        }
    }
}

@Composable
private fun DevicesIcon(modifier: Modifier = Modifier, color: Color) {
    Canvas(modifier) {
        val stroke = size.minDimension * 0.07f
        drawRoundRect(color, Offset(size.width * .08f, size.height * .16f), androidx.compose.ui.geometry.Size(size.width * .60f, size.height * .62f), androidx.compose.ui.geometry.CornerRadius(size.width * .08f), style = Stroke(stroke))
        drawRoundRect(color, Offset(size.width * .62f, size.height * .32f), androidx.compose.ui.geometry.Size(size.width * .30f, size.height * .54f), androidx.compose.ui.geometry.CornerRadius(size.width * .06f), style = Stroke(stroke))
        drawLine(color, Offset(size.width * .26f, size.height * .88f), Offset(size.width * .52f, size.height * .88f), stroke, StrokeCap.Round)
    }
}

@Composable
private fun QrLinkIcon(modifier: Modifier = Modifier, color: Color) {
    Canvas(modifier) {
        val stroke = size.minDimension * .075f
        fun corner(x: Float, y: Float, dx: Float, dy: Float) {
            drawLine(color, Offset(x, y), Offset(x + dx, y), stroke, StrokeCap.Square)
            drawLine(color, Offset(x, y), Offset(x, y + dy), stroke, StrokeCap.Square)
        }
        corner(size.width * .15f, size.height * .15f, size.width * .24f, size.height * .24f)
        corner(size.width * .85f, size.height * .15f, -size.width * .24f, size.height * .24f)
        corner(size.width * .15f, size.height * .85f, size.width * .24f, -size.height * .24f)
        corner(size.width * .85f, size.height * .85f, -size.width * .24f, -size.height * .24f)
        drawCircle(color, size.minDimension * .07f, center)
    }
}

private fun platformName(value: String): String = when (value) {
    "windows" -> "Windows Desktop"
    "linux" -> "Linux Desktop"
    "macos" -> "macOS Desktop"
    "android" -> "Android"
    else -> value
}

private fun formatDeviceTime(epochMillis: Long): String =
    SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.getDefault()).format(Date(epochMillis))
