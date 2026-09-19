package com.fedmes.app.ui.messenger

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.net.Uri
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.gestures.rememberTransformableState
import androidx.compose.foundation.gestures.transformable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items as gridItems
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.core.content.ContextCompat
import androidx.media3.common.MediaItem
import androidx.media3.common.util.UnstableApi
import androidx.media3.exoplayer.ExoPlayer
import androidx.media3.ui.AspectRatioFrameLayout
import androidx.media3.ui.PlayerView
import com.fedmes.app.messaging.AttachmentQuality
import com.fedmes.app.messaging.AttachmentSelection
import com.fedmes.app.messaging.DeviceAttachmentItem
import com.fedmes.app.messaging.DeviceAttachmentKind
import com.fedmes.app.messaging.DeviceAttachmentRepository
import com.fedmes.app.messaging.DrawingPoint
import com.fedmes.app.messaging.DrawingStroke
import com.fedmes.app.ui.components.BackIcon
import com.fedmes.app.ui.components.BrushIcon
import com.fedmes.app.ui.components.CameraIcon
import com.fedmes.app.ui.components.FileIcon
import com.fedmes.app.ui.components.GalleryIcon
import com.fedmes.app.ui.components.MoreIcon
import com.fedmes.app.ui.components.RotateIcon
import com.fedmes.app.ui.components.SendIcon
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.DecimalFormat

private enum class AttachmentTab {
    GALLERY,
    FILES,
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AttachmentPickerSheet(
    initialCaption: String,
    onDismiss: () -> Unit,
    onSend: (List<AttachmentSelection>) -> Unit,
) {
    val context = LocalContext.current
    val repository = remember(context) { DeviceAttachmentRepository(context) }
    val scope = rememberCoroutineScope()
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = false)
    var tab by remember { mutableStateOf(AttachmentTab.GALLERY) }
    var gallery by remember { mutableStateOf<List<DeviceAttachmentItem>>(emptyList()) }
    var files by remember { mutableStateOf<List<DeviceAttachmentItem>>(emptyList()) }
    var selected by remember { mutableStateOf<List<String>>(emptyList()) }
    var previewItem by remember { mutableStateOf<DeviceAttachmentItem?>(null) }
    var caption by remember(initialCaption) { mutableStateOf(initialCaption) }
    var quality by remember { mutableStateOf(AttachmentQuality.SD) }
    var spoiler by remember { mutableStateOf(false) }
    var rotations by remember { mutableStateOf<Map<String, Int>>(emptyMap()) }
    var drawings by remember { mutableStateOf<Map<String, List<DrawingStroke>>>(emptyMap()) }
    var loadingGallery by remember { mutableStateOf(true) }
    var loadingFiles by remember { mutableStateOf(true) }
    var galleryPermissionGranted by remember { mutableStateOf(hasGalleryPermission(context)) }
    var error by remember { mutableStateOf<String?>(null) }
    var showCustomCamera by remember { mutableStateOf(false) }

    fun loadGallery() {
        if (!galleryPermissionGranted) {
            loadingGallery = false
            return
        }
        loadingGallery = true
        scope.launch {
            runCatching { withContext(Dispatchers.IO) { repository.listGallery() } }
                .onSuccess { gallery = it }
                .onFailure { error = it.message ?: "Не удалось открыть галерею" }
            loadingGallery = false
        }
    }

    fun loadFiles() {
        loadingFiles = true
        scope.launch {
            runCatching { withContext(Dispatchers.IO) { repository.listFiles() } }
                .onSuccess { files = it }
                .onFailure { error = it.message ?: "Не удалось прочитать файлы" }
            loadingFiles = false
        }
    }

    val galleryPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { result ->
        galleryPermissionGranted = galleryPermissions().any { permission -> result[permission] == true }
        if (galleryPermissionGranted) {
            loadGallery()
            loadFiles()
        }
    }
    val cameraPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (granted) showCustomCamera = true
        else error = "Для камеры требуется разрешение"
    }
    LaunchedEffect(Unit) {
        if (galleryPermissionGranted) {
            loadGallery()
        } else {
            loadingGallery = false
        }
        if (galleryPermissionGranted || Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            loadFiles()
        } else {
            loadingFiles = false
        }
    }

    fun toggleSelection(item: DeviceAttachmentItem) {
        selected = if (item.stableId in selected) {
            selected - item.stableId
        } else if (selected.size >= MAX_SELECTION) {
            error = "Можно выбрать не больше $MAX_SELECTION файлов"
            selected
        } else {
            selected + item.stableId
        }
    }

    fun selectedItems(): List<DeviceAttachmentItem> {
        val all = (gallery + files).associateBy(DeviceAttachmentItem::stableId)
        return selected.mapNotNull(all::get)
    }

    fun sendItems(items: List<DeviceAttachmentItem>, activeItem: DeviceAttachmentItem? = null) {
        val ordered = when {
            items.isNotEmpty() -> items
            activeItem != null -> listOf(activeItem)
            else -> emptyList()
        }
        if (ordered.isEmpty()) return
        val selections = ordered.mapIndexed { index, item ->
            AttachmentSelection(
                item = item,
                caption = if (index == 0) caption else "",
                rotationDegrees = rotations[item.stableId] ?: 0,
                quality = quality,
                spoiler = spoiler,
                drawingStrokes = drawings[item.stableId].orEmpty(),
            )
        }
        onSend(selections)
    }

    if (showCustomCamera) {
        FedMesCameraDialog(
            repository = repository,
            latestGalleryItem = gallery.firstOrNull(),
            onDismiss = { showCustomCamera = false },
            onOpenGallery = { showCustomCamera = false },
            onCaptured = { captured ->
                showCustomCamera = false
                gallery = listOf(captured) + gallery.filterNot { it.stableId == captured.stableId }
                selected = listOf(captured.stableId)
                previewItem = captured
            },
            onError = { message -> error = message },
        )
    }

    previewItem?.let { item ->
        AttachmentPreviewDialog(
            item = item,
            repository = repository,
            selectedNumber = selected.indexOf(item.stableId).takeIf { it >= 0 }?.plus(1),
            caption = caption,
            quality = quality,
            spoiler = spoiler,
            rotationDegrees = rotations[item.stableId] ?: 0,
            drawingStrokes = drawings[item.stableId].orEmpty(),
            onDrawingStrokes = { strokes -> drawings = drawings + (item.stableId to strokes) },
            onBack = { previewItem = null },
            onToggleSelected = { toggleSelection(item) },
            onCaption = { caption = it.take(MAX_CAPTION_LENGTH) },
            onQuality = { quality = it },
            onToggleSpoiler = { spoiler = !spoiler },
            onRotate = {
                rotations = rotations + (item.stableId to (((rotations[item.stableId] ?: 0) + 90) % 360))
            },
            onSend = {
                val chosen = selectedItems()
                sendItems(chosen, item)
                previewItem = null
            },
        )
    }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        containerColor = MaterialTheme.colorScheme.surface,
        dragHandle = null,
    ) {
        Column(
            Modifier
                .fillMaxWidth()
                .fillMaxHeight(0.88f),
        ) {
            AttachmentSheetHeader(
                tab = tab,
                selectedCount = selected.size,
                onDismiss = onDismiss,
            )
            error?.let { message ->
                Surface(color = MaterialTheme.colorScheme.errorContainer) {
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 12.dp, vertical = 6.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            message,
                            modifier = Modifier.weight(1f),
                            color = MaterialTheme.colorScheme.onErrorContainer,
                            maxLines = 2,
                        )
                        TextButton(onClick = { error = null }) { Text("Закрыть") }
                    }
                }
            }
            Box(Modifier.weight(1f)) {
                when (tab) {
                    AttachmentTab.GALLERY -> GalleryTab(
                        items = gallery,
                        selected = selected,
                        loading = loadingGallery,
                        permissionGranted = galleryPermissionGranted,
                        repository = repository,
                        onPermission = { galleryPermissionLauncher.launch(galleryPermissions()) },
                        liveCameraEnabled = !showCustomCamera,
                        onCamera = {
                            if (ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
                                showCustomCamera = true
                            } else {
                                cameraPermissionLauncher.launch(Manifest.permission.CAMERA)
                            }
                        },
                        onOpen = { previewItem = it },
                        onToggle = ::toggleSelection,
                    )
                    AttachmentTab.FILES -> FilesTab(
                        items = files,
                        selected = selected,
                        loading = loadingFiles,
                        permissionGranted = galleryPermissionGranted || Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU,
                        onPermission = { galleryPermissionLauncher.launch(galleryPermissions()) },
                        onToggle = ::toggleSelection,
                    )
                }
            }
            if (selected.isNotEmpty()) {
                AttachmentSelectionFooter(
                    count = selected.size,
                    caption = caption,
                    quality = quality,
                    spoiler = spoiler,
                    onCaption = { caption = it.take(MAX_CAPTION_LENGTH) },
                    onQuality = { quality = it },
                    onToggleSpoiler = { spoiler = !spoiler },
                    onPreview = { selectedItems().firstOrNull()?.let { previewItem = it } },
                    onSend = { sendItems(selectedItems()) },
                )
            }
            AttachmentTabs(tab = tab, onTab = { tab = it })
        }
    }
}

@Composable
private fun AttachmentSheetHeader(
    tab: AttachmentTab,
    selectedCount: Int,
    onDismiss: () -> Unit,
) {
    Column(Modifier.fillMaxWidth()) {
        Box(
            Modifier
                .align(Alignment.CenterHorizontally)
                .padding(top = 2.dp, bottom = 8.dp)
                .width(36.dp)
                .height(4.dp)
                .background(
                    MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.34f),
                    RoundedCornerShape(99.dp),
                ),
        )
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text(
                    text = if (tab == AttachmentTab.GALLERY) "Недавние" else "Файлы",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                )
                Text(
                    text = if (selectedCount > 0) "Выбрано: $selectedCount" else "Выберите фото, видео или файл",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            TextButton(onClick = onDismiss) {
                Text("Закрыть")
            }
        }
    }
}

@Composable
private fun AttachmentTabs(tab: AttachmentTab, onTab: (AttachmentTab) -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 4.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        AttachmentTabButton(
            selected = tab == AttachmentTab.GALLERY,
            label = "Галерея",
            icon = { color -> GalleryIcon(Modifier.size(22.dp), color) },
            onClick = { onTab(AttachmentTab.GALLERY) },
            modifier = Modifier.weight(1f),
        )
        AttachmentTabButton(
            selected = tab == AttachmentTab.FILES,
            label = "Файл",
            icon = { color -> FileIcon(Modifier.size(22.dp), color) },
            onClick = { onTab(AttachmentTab.FILES) },
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun AttachmentTabButton(
    selected: Boolean,
    label: String,
    icon: @Composable (Color) -> Unit,
    onClick: () -> Unit,
    modifier: Modifier,
) {
    val background = if (selected) MaterialTheme.colorScheme.primaryContainer else Color.Transparent
    val content = if (selected) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.onSurfaceVariant
    Surface(
        modifier = modifier.clickable(onClick = onClick),
        color = background,
        contentColor = content,
        shape = RoundedCornerShape(18.dp),
    ) {
        Row(
            Modifier.padding(horizontal = 12.dp, vertical = 9.dp),
            horizontalArrangement = Arrangement.Center,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            icon(content)
            Spacer(Modifier.width(7.dp))
            Text(label, fontWeight = FontWeight.SemiBold)
        }
    }
}

@Composable
private fun GalleryTab(
    items: List<DeviceAttachmentItem>,
    selected: List<String>,
    loading: Boolean,
    permissionGranted: Boolean,
    repository: DeviceAttachmentRepository,
    onPermission: () -> Unit,
    liveCameraEnabled: Boolean,
    onCamera: () -> Unit,
    onOpen: (DeviceAttachmentItem) -> Unit,
    onToggle: (DeviceAttachmentItem) -> Unit,
) {
    when {
        !permissionGranted -> PermissionPanel(
            title = "Разрешите доступ к фото и видео",
            detail = "FedMes покажет галерею внутри приложения и не откроет Google Files.",
            onGrant = onPermission,
        )
        loading -> LoadingPanel()
        else -> LazyVerticalGrid(
            columns = GridCells.Fixed(3),
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(1.dp),
            horizontalArrangement = Arrangement.spacedBy(1.dp),
            verticalArrangement = Arrangement.spacedBy(1.dp),
        ) {
            item(key = "camera") {
                LiveCameraTile(enabled = liveCameraEnabled, onClick = onCamera)
            }
            gridItems(items, key = DeviceAttachmentItem::stableId) { item ->
                GalleryTile(
                    item = item,
                    selectionNumber = selected.indexOf(item.stableId).takeIf { it >= 0 }?.plus(1),
                    repository = repository,
                    onOpen = { onOpen(item) },
                    onToggle = { onToggle(item) },
                )
            }
        }
    }
}

@Composable
private fun FilesTab(
    items: List<DeviceAttachmentItem>,
    selected: List<String>,
    loading: Boolean,
    permissionGranted: Boolean,
    onPermission: () -> Unit,
    onToggle: (DeviceAttachmentItem) -> Unit,
) {
    if (!permissionGranted) {
        PermissionPanel(
            title = "Разрешите доступ к памяти",
            detail = "FedMes покажет доступные файлы собственным интерфейсом.",
            onGrant = onPermission,
        )
        return
    }
    if (loading) {
        LoadingPanel()
        return
    }
    if (items.isEmpty()) {
        PermissionPanel(
            title = "В папке загрузок нет доступных файлов",
            detail = "FedMes показывает доступные файлы собственным интерфейсом. На новых Android система может скрывать документы других приложений.",
            onGrant = {},
            buttonVisible = false,
        )
        return
    }
    LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(vertical = 4.dp)) {
        item(key = "file-sources") {
            Column(Modifier.padding(horizontal = 12.dp, vertical = 6.dp)) {
                FileSourceCard("Внутреннее хранилище", "Недавние файлы устройства", Color(0xFF54B6F2))
                FileSourceCard("FedMes", "Файлы приложения", MaterialTheme.colorScheme.primary)
                FileSourceCard("Галерея", "Фото и видео без системного Google-проводника", Color(0xFFEAB43C))
                Text(
                    "Недавние файлы",
                    modifier = Modifier.padding(start = 4.dp, top = 12.dp, bottom = 4.dp),
                    color = MaterialTheme.colorScheme.primary,
                    fontWeight = FontWeight.SemiBold,
                )
            }
        }
        items(items, key = DeviceAttachmentItem::stableId) { item ->
            val number = selected.indexOf(item.stableId).takeIf { it >= 0 }?.plus(1)
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { onToggle(item) }
                    .padding(horizontal = 14.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Surface(
                    modifier = Modifier.size(44.dp),
                    shape = RoundedCornerShape(12.dp),
                    color = MaterialTheme.colorScheme.secondaryContainer,
                    contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        FileIcon(Modifier.size(25.dp), MaterialTheme.colorScheme.onSecondaryContainer)
                    }
                }
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Text(item.name, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text(
                        "${formatBytes(item.size)} · ${item.mimeType}",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
                SelectionBadge(number = number, selected = number != null, onClick = { onToggle(item) })
            }
        }
    }
}

@Composable
private fun FileSourceCard(title: String, subtitle: String, color: Color) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 7.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Surface(modifier = Modifier.size(48.dp), shape = CircleShape, color = color) {
            Box(contentAlignment = Alignment.Center) { FileIcon(Modifier.size(27.dp), Color.White) }
        }
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.titleMedium)
            Text(subtitle, color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun GalleryTile(
    item: DeviceAttachmentItem,
    selectionNumber: Int?,
    repository: DeviceAttachmentRepository,
    onOpen: () -> Unit,
    onToggle: () -> Unit,
) {
    Box(
        Modifier
            .fillMaxWidth()
            .aspectRatio(1f)
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .clickable(onClick = onOpen),
    ) {
        AttachmentImage(item, repository, Modifier.fillMaxSize())
        if (item.kind == DeviceAttachmentKind.VIDEO) {
            Surface(
                modifier = Modifier
                    .align(Alignment.BottomStart)
                    .padding(5.dp),
                color = Color.Black.copy(alpha = 0.64f),
                contentColor = Color.White,
                shape = RoundedCornerShape(5.dp),
            ) {
                Text(
                    formatDuration(item.durationMillis),
                    modifier = Modifier.padding(horizontal = 5.dp, vertical = 2.dp),
                    style = MaterialTheme.typography.labelSmall,
                )
            }
        }
        SelectionBadge(
            number = selectionNumber,
            selected = selectionNumber != null,
            onClick = onToggle,
            modifier = Modifier
                .align(Alignment.TopEnd)
                .padding(6.dp),
        )
    }
}

@Composable
private fun LiveCameraTile(enabled: Boolean, onClick: () -> Unit) {
    val context = LocalContext.current
    val lifecycleOwner = androidx.lifecycle.compose.LocalLifecycleOwner.current
    var previewView by remember { mutableStateOf<androidx.camera.view.PreviewView?>(null) }
    var provider by remember { mutableStateOf<androidx.camera.lifecycle.ProcessCameraProvider?>(null) }
    LaunchedEffect(previewView, enabled) {
        val view = previewView ?: return@LaunchedEffect
        if (!enabled) {
            provider?.unbindAll()
            return@LaunchedEffect
        }
        val future = androidx.camera.lifecycle.ProcessCameraProvider.getInstance(context)
        future.addListener(
            {
                runCatching {
                    val cameraProvider = future.get()
                    provider = cameraProvider
                    val preview = androidx.camera.core.Preview.Builder().build().also {
                        it.surfaceProvider = view.surfaceProvider
                    }
                    cameraProvider.unbindAll()
                    cameraProvider.bindToLifecycle(
                        lifecycleOwner,
                        androidx.camera.core.CameraSelector.DEFAULT_BACK_CAMERA,
                        preview,
                    )
                }
            },
            ContextCompat.getMainExecutor(context),
        )
    }
    DisposableEffect(Unit) {
        onDispose { provider?.unbindAll() }
    }
    Surface(
        modifier = Modifier.fillMaxWidth().aspectRatio(1f).clickable(onClick = onClick),
        color = MaterialTheme.colorScheme.surfaceVariant,
    ) {
        Box(contentAlignment = Alignment.Center) {
            AndroidView(
                factory = {
                    androidx.camera.view.PreviewView(it).apply {
                        implementationMode = androidx.camera.view.PreviewView.ImplementationMode.PERFORMANCE
                        scaleType = androidx.camera.view.PreviewView.ScaleType.FILL_CENTER
                        previewView = this
                    }
                },
                modifier = Modifier.fillMaxSize(),
            )
            Surface(
                modifier = Modifier.size(48.dp),
                color = Color.Black.copy(alpha = 0.44f),
                shape = CircleShape,
            ) {
                Box(contentAlignment = Alignment.Center) {
                    CameraIcon(Modifier.size(28.dp), Color.White)
                }
            }
        }
    }
}

@Composable
private fun AttachmentImage(
    item: DeviceAttachmentItem,
    repository: DeviceAttachmentRepository,
    modifier: Modifier,
    preview: Boolean = false,
    rotationDegrees: Int = 0,
) {
    val bitmap by produceState<Bitmap?>(initialValue = null, item.uri, preview) {
        value = withContext(Dispatchers.IO) {
            if (preview) repository.loadPreview(item) else repository.loadThumbnail(item, THUMBNAIL_EDGE)
        }
    }
    val image = bitmap
    if (image == null) {
        Box(modifier.background(MaterialTheme.colorScheme.surfaceVariant), contentAlignment = Alignment.Center) {
            CircularProgressIndicator(Modifier.size(24.dp), strokeWidth = 2.dp)
        }
    } else {
        Image(
            bitmap = image.asImageBitmap(),
            contentDescription = item.name,
            modifier = modifier.graphicsLayer(rotationZ = rotationDegrees.toFloat()),
            contentScale = if (preview) ContentScale.Fit else ContentScale.Crop,
        )
    }
}

@Composable
private fun ZoomableGalleryPhoto(
    item: DeviceAttachmentItem,
    repository: DeviceAttachmentRepository,
    rotationDegrees: Int,
    modifier: Modifier,
) {
    val bitmap by produceState<Bitmap?>(initialValue = null, item.uri) {
        value = withContext(Dispatchers.IO) { repository.loadPreview(item) }
    }
    val image = bitmap
    if (image == null) {
        Box(modifier.background(Color.Black), contentAlignment = Alignment.Center) {
            CircularProgressIndicator(Modifier.size(28.dp), strokeWidth = 2.dp, color = Color.White)
        }
        return
    }
    var scale by remember(image) { mutableFloatStateOf(1f) }
    var offset by remember(image) { mutableStateOf(Offset.Zero) }
    val transformState = rememberTransformableState { zoomChange, panChange, _ ->
        val nextScale = (scale * zoomChange).coerceIn(1f, 8f)
        scale = nextScale
        offset = if (nextScale <= 1.01f) Offset.Zero else offset + panChange
    }
    Box(modifier.background(Color.Black), contentAlignment = Alignment.Center) {
        Image(
            bitmap = image.asImageBitmap(),
            contentDescription = "Фото",
            contentScale = ContentScale.Fit,
            modifier = Modifier
                .fillMaxSize()
                .graphicsLayer {
                    rotationZ = rotationDegrees.toFloat()
                    scaleX = scale
                    scaleY = scale
                    translationX = offset.x
                    translationY = offset.y
                }
                .transformable(transformState)
                .pointerInput(image) {
                    detectTapGestures(
                        onDoubleTap = {
                            if (scale > 1.05f) {
                                scale = 1f
                                offset = Offset.Zero
                            } else {
                                scale = 2.75f
                            }
                        },
                    )
                },
        )
    }
}

@androidx.annotation.OptIn(UnstableApi::class)
@Composable
private fun GalleryVideoPreview(
    item: DeviceAttachmentItem,
    modifier: Modifier,
) {
    val context = LocalContext.current
    val player = remember(item.uri) {
        ExoPlayer.Builder(context).build().apply {
            setMediaItem(MediaItem.fromUri(Uri.parse(item.uri)))
            prepare()
            playWhenReady = false
        }
    }
    DisposableEffect(player) {
        onDispose { player.release() }
    }
    Box(modifier.background(Color.Black), contentAlignment = Alignment.Center) {
        AndroidView(
            factory = { ctx ->
                PlayerView(ctx).apply {
                    this.player = player
                    useController = true
                    resizeMode = AspectRatioFrameLayout.RESIZE_MODE_FIT
                    setShowBuffering(PlayerView.SHOW_BUFFERING_ALWAYS)
                    setShutterBackgroundColor(android.graphics.Color.BLACK)
                }
            },
            update = { it.player = player },
            modifier = Modifier.fillMaxSize(),
        )
    }
}

@Composable
private fun SelectionBadge(
    number: Int?,
    selected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Surface(
        modifier = modifier
            .size(30.dp)
            .clickable(onClick = onClick),
        color = if (selected) MaterialTheme.colorScheme.primary else Color.Black.copy(alpha = 0.34f),
        contentColor = Color.White,
        shape = CircleShape,
        border = androidx.compose.foundation.BorderStroke(2.dp, Color.White),
    ) {
        Box(contentAlignment = Alignment.Center) {
            if (number != null) {
                Text(number.toString(), fontWeight = FontWeight.Bold, style = MaterialTheme.typography.labelMedium)
            }
        }
    }
}

@Composable
private fun AttachmentSelectionFooter(
    count: Int,
    caption: String,
    quality: AttachmentQuality,
    spoiler: Boolean,
    onCaption: (String) -> Unit,
    onQuality: (AttachmentQuality) -> Unit,
    onToggleSpoiler: () -> Unit,
    onPreview: () -> Unit,
    onSend: () -> Unit,
) {
    var menu by remember { mutableStateOf(false) }
    Surface(tonalElevation = 6.dp) {
        Column(
            Modifier
                .fillMaxWidth()
                .imePadding()
                .padding(horizontal = 12.dp, vertical = 8.dp),
        ) {
            Surface(
                color = MaterialTheme.colorScheme.surfaceVariant,
                shape = RoundedCornerShape(24.dp),
            ) {
                BasicTextField(
                    value = caption,
                    onValueChange = onCaption,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 12.dp),
                    textStyle = MaterialTheme.typography.bodyLarge.copy(
                        color = MaterialTheme.colorScheme.onSurface,
                    ),
                    cursorBrush = SolidColor(MaterialTheme.colorScheme.primary),
                    maxLines = 4,
                    decorationBox = { field ->
                        Box(contentAlignment = Alignment.CenterStart) {
                            if (caption.isEmpty()) {
                                Text(
                                    "Добавить подпись…",
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                            field()
                        }
                    },
                )
            }
            Row(
                Modifier
                    .fillMaxWidth()
                    .padding(top = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                TextButton(onClick = onPreview) {
                    Text("Выбрано: $count", fontWeight = FontWeight.SemiBold)
                }
                Box {
                    IconButton(onClick = { menu = true }) {
                        MoreIcon(Modifier.size(24.dp), MaterialTheme.colorScheme.onSurface)
                    }
                    AttachmentOptionsMenu(
                        expanded = menu,
                        quality = quality,
                        spoiler = spoiler,
                        onDismiss = { menu = false },
                        onQuality = { menu = false; onQuality(it) },
                        onToggleSpoiler = { menu = false; onToggleSpoiler() },
                    )
                }
                if (spoiler) {
                    Surface(
                        color = MaterialTheme.colorScheme.secondaryContainer,
                        shape = RoundedCornerShape(10.dp),
                    ) {
                        Text(
                            "Спойлер",
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSecondaryContainer,
                        )
                    }
                    Spacer(Modifier.width(6.dp))
                }
                Surface(
                    modifier = Modifier.clickable {
                        onQuality(if (quality == AttachmentQuality.HD) AttachmentQuality.SD else AttachmentQuality.HD)
                    },
                    color = if (quality == AttachmentQuality.HD) {
                        MaterialTheme.colorScheme.primary
                    } else {
                        MaterialTheme.colorScheme.surfaceVariant
                    },
                    shape = RoundedCornerShape(10.dp),
                ) {
                    Text(
                        if (quality == AttachmentQuality.ORIGINAL) "FILE" else quality.name,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold,
                        color = if (quality == AttachmentQuality.HD) {
                            MaterialTheme.colorScheme.onPrimary
                        } else {
                            MaterialTheme.colorScheme.onSurfaceVariant
                        },
                    )
                }
                Spacer(Modifier.weight(1f))
                Surface(
                    modifier = Modifier.size(52.dp).clickable(onClick = onSend),
                    shape = CircleShape,
                    color = MaterialTheme.colorScheme.primary,
                    contentColor = MaterialTheme.colorScheme.onPrimary,
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        SendIcon(Modifier.size(24.dp), MaterialTheme.colorScheme.onPrimary)
                    }
                }
            }
        }
    }
}

@Composable
private fun AttachmentOptionsMenu(
    expanded: Boolean,
    quality: AttachmentQuality,
    spoiler: Boolean,
    onDismiss: () -> Unit,
    onQuality: (AttachmentQuality) -> Unit,
    onToggleSpoiler: () -> Unit,
) {
    DropdownMenu(expanded = expanded, onDismissRequest = onDismiss) {
        DropdownMenuItem(
            text = { Text("Отправить без сжатия") },
            onClick = { onQuality(AttachmentQuality.ORIGINAL) },
        )
        DropdownMenuItem(
            text = { Text(if (spoiler) "Убрать спойлер" else "Скрыть под спойлер") },
            onClick = onToggleSpoiler,
        )
        DropdownMenuItem(
            text = { Text(if (quality == AttachmentQuality.HD) "Отправить в SD-качестве" else "Отправить в HD-качестве") },
            onClick = {
                onQuality(if (quality == AttachmentQuality.HD) AttachmentQuality.SD else AttachmentQuality.HD)
            },
        )
    }
}

@Composable
private fun AttachmentPreviewDialog(
    item: DeviceAttachmentItem,
    repository: DeviceAttachmentRepository,
    selectedNumber: Int?,
    caption: String,
    quality: AttachmentQuality,
    spoiler: Boolean,
    rotationDegrees: Int,
    drawingStrokes: List<DrawingStroke>,
    onDrawingStrokes: (List<DrawingStroke>) -> Unit,
    onBack: () -> Unit,
    onToggleSelected: () -> Unit,
    onCaption: (String) -> Unit,
    onQuality: (AttachmentQuality) -> Unit,
    onToggleSpoiler: () -> Unit,
    onRotate: () -> Unit,
    onSend: () -> Unit,
) {
    var optionsMenu by remember { mutableStateOf(false) }
    var brushMode by remember(item.stableId) { mutableStateOf(false) }
    var brushColor by remember(item.stableId) { mutableStateOf(Color.White.toArgb()) }
    Dialog(
        onDismissRequest = onBack,
        properties = DialogProperties(usePlatformDefaultWidth = false),
    ) {
        Surface(color = Color.Black, contentColor = Color.White) {
            Column(Modifier.fillMaxSize().imePadding()) {
                Row(
                    Modifier
                        .fillMaxWidth()
                        .padding(top = 24.dp, start = 8.dp, end = 8.dp, bottom = 6.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    IconButton(onClick = onBack) {
                        BackIcon(Modifier.size(26.dp), Color.White)
                    }
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = when (item.kind) {
                                DeviceAttachmentKind.PHOTO -> "Фото"
                                DeviceAttachmentKind.VIDEO -> "Видео"
                                DeviceAttachmentKind.FILE -> item.name
                            },
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            fontWeight = FontWeight.SemiBold,
                        )
                        if (item.kind != DeviceAttachmentKind.FILE && caption.isNotBlank()) {
                            Text(
                                text = caption.trim(),
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                                color = Color.White.copy(alpha = 0.68f),
                                style = MaterialTheme.typography.labelMedium,
                            )
                        }
                    }
                    if (selectedNumber != null) {
                        Box {
                            IconButton(onClick = { optionsMenu = true }) {
                                MoreIcon(Modifier.size(25.dp), Color.White)
                            }
                            AttachmentOptionsMenu(
                                expanded = optionsMenu,
                                quality = quality,
                                spoiler = spoiler,
                                onDismiss = { optionsMenu = false },
                                onQuality = { optionsMenu = false; onQuality(it) },
                                onToggleSpoiler = { optionsMenu = false; onToggleSpoiler() },
                            )
                        }
                    }
                    SelectionBadge(
                        number = selectedNumber,
                        selected = selectedNumber != null,
                        onClick = onToggleSelected,
                    )
                }
                Box(Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) {
                    if (item.kind == DeviceAttachmentKind.FILE) {
                        Column(
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.Center,
                            modifier = Modifier.padding(28.dp),
                        ) {
                            Surface(
                                modifier = Modifier.size(96.dp),
                                shape = RoundedCornerShape(24.dp),
                                color = Color(0xFF2B2B2B),
                            ) {
                                Box(contentAlignment = Alignment.Center) {
                                    FileIcon(Modifier.size(54.dp), Color.White)
                                }
                            }
                            Spacer(Modifier.height(18.dp))
                            Text(
                                item.name,
                                style = MaterialTheme.typography.titleMedium,
                                maxLines = 3,
                                overflow = TextOverflow.Ellipsis,
                            )
                            Spacer(Modifier.height(6.dp))
                            Text(
                                "${formatBytes(item.size)} · ${item.mimeType}",
                                color = Color.White.copy(alpha = 0.62f),
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                    } else {
                        when (item.kind) {
                            DeviceAttachmentKind.PHOTO -> ZoomableGalleryPhoto(
                                item = item,
                                repository = repository,
                                rotationDegrees = rotationDegrees,
                                modifier = Modifier.fillMaxSize().padding(8.dp),
                            )
                            DeviceAttachmentKind.VIDEO -> GalleryVideoPreview(
                                item = item,
                                modifier = Modifier.fillMaxSize().padding(8.dp),
                            )
                            DeviceAttachmentKind.FILE -> Unit
                        }
                        if (item.kind == DeviceAttachmentKind.PHOTO) {
                            DrawingOverlay(
                                strokes = drawingStrokes,
                                enabled = brushMode,
                                colorArgb = brushColor,
                                onStroke = { stroke -> onDrawingStrokes(drawingStrokes + stroke) },
                                modifier = Modifier.fillMaxSize().padding(8.dp),
                            )
                        }
                    }
                }
                if (brushMode && item.kind == DeviceAttachmentKind.PHOTO) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 18.dp, vertical = 6.dp),
                        horizontalArrangement = Arrangement.spacedBy(12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        listOf(Color.White, Color.Red, Color(0xFF42A5F5), Color(0xFF66BB6A), Color.Yellow).forEach { color ->
                            Surface(
                                modifier = Modifier
                                    .size(if (brushColor == color.toArgb()) 30.dp else 24.dp)
                                    .clickable { brushColor = color.toArgb() },
                                shape = CircleShape,
                                color = color,
                                border = androidx.compose.foundation.BorderStroke(2.dp, Color.White.copy(alpha = 0.8f)),
                            ) {}
                        }
                        Spacer(Modifier.weight(1f))
                        TextButton(
                            enabled = drawingStrokes.isNotEmpty(),
                            onClick = { onDrawingStrokes(drawingStrokes.dropLast(1)) },
                        ) { Text("Отменить штрих", color = Color.White) }
                        TextButton(
                            enabled = drawingStrokes.isNotEmpty(),
                            onClick = { onDrawingStrokes(emptyList()) },
                        ) { Text("Очистить", color = Color.White) }
                    }
                }
                Surface(
                    modifier = Modifier.padding(horizontal = 12.dp),
                    color = Color(0xFF242424),
                    shape = RoundedCornerShape(24.dp),
                ) {
                    BasicTextField(
                        value = caption,
                        onValueChange = onCaption,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp, vertical = 13.dp),
                        textStyle = MaterialTheme.typography.bodyLarge.copy(color = Color.White),
                        cursorBrush = SolidColor(MaterialTheme.colorScheme.primary),
                        maxLines = 4,
                        decorationBox = { field ->
                            Box(contentAlignment = Alignment.CenterStart) {
                                if (caption.isEmpty()) {
                                    Text("Добавить подпись…", color = Color.White.copy(alpha = 0.56f))
                                }
                                field()
                            }
                        },
                    )
                }
                Row(
                    Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 14.dp, vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    if (item.kind == DeviceAttachmentKind.PHOTO) {
                        IconButton(onClick = onRotate) {
                            RotateIcon(Modifier.size(27.dp), Color.White)
                        }
                        IconButton(onClick = { brushMode = !brushMode }) {
                            BrushIcon(
                                Modifier.size(27.dp),
                                if (brushMode) MaterialTheme.colorScheme.primary else Color.White,
                            )
                        }
                    }
                    if (item.kind == DeviceAttachmentKind.PHOTO || item.kind == DeviceAttachmentKind.VIDEO) {
                        Surface(
                            modifier = Modifier.clickable {
                                onQuality(if (quality == AttachmentQuality.HD) AttachmentQuality.SD else AttachmentQuality.HD)
                            },
                            color = if (quality == AttachmentQuality.HD) MaterialTheme.colorScheme.primary else Color(0xFF303030),
                            shape = RoundedCornerShape(10.dp),
                        ) {
                            Text(
                                if (quality == AttachmentQuality.HD) "HD" else "SD",
                                modifier = Modifier.padding(horizontal = 12.dp, vertical = 7.dp),
                                color = Color.White,
                                fontWeight = FontWeight.Bold,
                            )
                        }
                    }
                    Spacer(Modifier.weight(1f))
                    Surface(
                        modifier = Modifier
                            .size(54.dp)
                            .clickable(onClick = onSend),
                        shape = CircleShape,
                        color = MaterialTheme.colorScheme.primary,
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            SendIcon(Modifier.size(25.dp), MaterialTheme.colorScheme.onPrimary)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun DrawingOverlay(
    strokes: List<DrawingStroke>,
    enabled: Boolean,
    colorArgb: Int,
    onStroke: (DrawingStroke) -> Unit,
    modifier: Modifier = Modifier,
) {
    var currentPoints by remember(enabled, colorArgb) { mutableStateOf<List<DrawingPoint>>(emptyList()) }
    Canvas(
        modifier = modifier.pointerInput(enabled, colorArgb) {
            if (!enabled) return@pointerInput
            detectDragGestures(
                onDragStart = { offset ->
                    currentPoints = listOf(
                        DrawingPoint(
                            xFraction = (offset.x / size.width.coerceAtLeast(1).toFloat()).coerceIn(0f, 1f),
                            yFraction = (offset.y / size.height.coerceAtLeast(1).toFloat()).coerceIn(0f, 1f),
                        ),
                    )
                },
                onDrag = { change, _ ->
                    currentPoints = currentPoints + DrawingPoint(
                        xFraction = (change.position.x / size.width.coerceAtLeast(1).toFloat()).coerceIn(0f, 1f),
                        yFraction = (change.position.y / size.height.coerceAtLeast(1).toFloat()).coerceIn(0f, 1f),
                    )
                    change.consume()
                },
                onDragEnd = {
                    if (currentPoints.size >= 2) {
                        onStroke(
                            DrawingStroke(
                                points = currentPoints,
                                colorArgb = colorArgb,
                            ),
                        )
                    }
                    currentPoints = emptyList()
                },
                onDragCancel = { currentPoints = emptyList() },
            )
        },
    ) {
        fun drawStroke(stroke: DrawingStroke) {
            if (stroke.points.isEmpty()) return
            val path = Path()
            val first = stroke.points.first()
            path.moveTo(first.xFraction * size.width, first.yFraction * size.height)
            stroke.points.drop(1).forEach { point ->
                path.lineTo(point.xFraction * size.width, point.yFraction * size.height)
            }
            drawPath(
                path = path,
                color = Color(stroke.colorArgb),
                style = androidx.compose.ui.graphics.drawscope.Stroke(
                    width = (stroke.widthFraction * size.minDimension).coerceAtLeast(2f),
                    cap = androidx.compose.ui.graphics.StrokeCap.Round,
                    join = androidx.compose.ui.graphics.StrokeJoin.Round,
                ),
            )
        }
        strokes.forEach(::drawStroke)
        if (currentPoints.isNotEmpty()) {
            drawStroke(DrawingStroke(currentPoints, colorArgb))
        }
    }
}

@Composable
private fun PermissionPanel(
    title: String,
    detail: String,
    onGrant: () -> Unit,
    buttonVisible: Boolean = true,
) {
    Column(
        Modifier
            .fillMaxSize()
            .padding(28.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        GalleryIcon(Modifier.size(52.dp), MaterialTheme.colorScheme.primary)
        Spacer(Modifier.height(12.dp))
        Text(title, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(6.dp))
        Text(detail, color = MaterialTheme.colorScheme.onSurfaceVariant)
        if (buttonVisible) {
            Spacer(Modifier.height(14.dp))
            TextButton(onClick = onGrant) { Text("Разрешить") }
        }
    }
}

@Composable
private fun LoadingPanel() {
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        CircularProgressIndicator()
    }
}

private fun hasGalleryPermission(context: Context): Boolean =
    galleryPermissions().any { permission ->
        ContextCompat.checkSelfPermission(context, permission) == PackageManager.PERMISSION_GRANTED
    }

private fun galleryPermissions(): Array<String> = if (Build.VERSION.SDK_INT >= 34) {
    arrayOf(
        Manifest.permission.READ_MEDIA_IMAGES,
        Manifest.permission.READ_MEDIA_VIDEO,
        Manifest.permission.READ_MEDIA_VISUAL_USER_SELECTED,
    )
} else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
    arrayOf(Manifest.permission.READ_MEDIA_IMAGES, Manifest.permission.READ_MEDIA_VIDEO)
} else {
    arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE)
}

private fun formatDuration(durationMillis: Long?): String {
    val totalSeconds = (durationMillis ?: 0L) / 1000L
    val minutes = totalSeconds / 60L
    val seconds = totalSeconds % 60L
    return "%d:%02d".format(LocaleHolder.locale, minutes, seconds)
}

private fun formatBytes(bytes: Long): String {
    if (bytes < 1024L) return "$bytes Б"
    val units = arrayOf("КБ", "МБ", "ГБ")
    var value = bytes.toDouble() / 1024.0
    var unit = 0
    while (value >= 1024.0 && unit < units.lastIndex) {
        value /= 1024.0
        unit++
    }
    return "${DecimalFormat("0.#").format(value)} ${units[unit]}"
}

private object LocaleHolder {
    val locale: java.util.Locale = java.util.Locale.getDefault()
}

private const val MAX_SELECTION = 500
private const val MAX_CAPTION_LENGTH = 4096
private const val THUMBNAIL_EDGE = 384
