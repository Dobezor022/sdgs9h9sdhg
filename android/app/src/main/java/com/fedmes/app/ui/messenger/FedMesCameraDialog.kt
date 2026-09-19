package com.fedmes.app.ui.messenger

import android.Manifest
import android.annotation.SuppressLint
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.media.MediaMetadataRetriever
import androidx.camera.core.Camera
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageCapture
import androidx.camera.core.ImageCaptureException
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.video.FallbackStrategy
import androidx.camera.video.FileOutputOptions
import androidx.camera.video.Quality
import androidx.camera.video.QualitySelector
import androidx.camera.video.Recorder
import androidx.camera.video.Recording
import androidx.camera.video.VideoCapture
import androidx.camera.video.VideoRecordEvent
import androidx.camera.view.PreviewView
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.gestures.waitForUpOrCancellation
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.draw.clip
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.fedmes.app.messaging.DeviceAttachmentItem
import com.fedmes.app.messaging.DeviceAttachmentKind
import com.fedmes.app.messaging.DeviceAttachmentRepository
import com.fedmes.app.ui.components.CloseIcon
import com.fedmes.app.ui.components.GalleryIcon
import com.fedmes.app.ui.components.SwitchCameraIcon
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.io.File

/** FedMes-owned CameraX UI. No system camera or Google picker is launched. */
@SuppressLint("MissingPermission")
@Composable
fun FedMesCameraDialog(
    repository: DeviceAttachmentRepository,
    latestGalleryItem: DeviceAttachmentItem?,
    onDismiss: () -> Unit,
    onOpenGallery: () -> Unit,
    onCaptured: (DeviceAttachmentItem) -> Unit,
    onError: (String) -> Unit,
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val mainExecutor = remember(context) { ContextCompat.getMainExecutor(context) }
    val recorder = remember {
        Recorder.Builder()
            .setQualitySelector(
                QualitySelector.from(
                    Quality.SD,
                    FallbackStrategy.higherQualityOrLowerThan(Quality.SD),
                ),
            )
            .build()
    }
    val videoCapture = remember(recorder) { VideoCapture.withOutput(recorder) }
    val imageCapture = remember {
        ImageCapture.Builder()
            .setCaptureMode(ImageCapture.CAPTURE_MODE_MINIMIZE_LATENCY)
            .build()
    }
    var previewView by remember { mutableStateOf<PreviewView?>(null) }
    var provider by remember { mutableStateOf<ProcessCameraProvider?>(null) }
    var boundCamera by remember { mutableStateOf<Camera?>(null) }
    var lensFacing by remember { mutableIntStateOf(CameraSelector.LENS_FACING_BACK) }
    var ready by remember { mutableStateOf(false) }
    var torch by remember { mutableStateOf(false) }
    var recording by remember { mutableStateOf<Recording?>(null) }
    var recordingFile by remember { mutableStateOf<File?>(null) }
    var finalizing by remember { mutableStateOf(false) }
    val latestGalleryThumbnail by produceState<Bitmap?>(initialValue = null, latestGalleryItem?.uri) {
        value = latestGalleryItem?.let { item ->
            withContext(Dispatchers.IO) { repository.loadThumbnail(item, 160) }
        }
    }

    fun capturePhoto() {
        if (!ready || recording != null || finalizing) return
        val file = repository.createCameraOutputFile("jpg")
        finalizing = true
        imageCapture.takePicture(
            ImageCapture.OutputFileOptions.Builder(file).build(),
            mainExecutor,
            object : ImageCapture.OnImageSavedCallback {
                override fun onImageSaved(outputFileResults: ImageCapture.OutputFileResults) {
                    finalizing = false
                    runCatching {
                        repository.createTemporaryMediaItem(file, "image/jpeg", DeviceAttachmentKind.PHOTO)
                    }.onSuccess(onCaptured).onFailure {
                        file.delete()
                        onError(it.message ?: "Не удалось сохранить фотографию")
                    }
                }

                override fun onError(exception: ImageCaptureException) {
                    finalizing = false
                    file.delete()
                    onError(exception.message ?: "Не удалось сделать фотографию")
                }
            },
        )
    }

    fun startVideo() {
        if (!ready || recording != null || finalizing) return
        val file = repository.createCameraOutputFile("mp4")
        recordingFile = file
        var pending = videoCapture.output.prepareRecording(
            context,
            FileOutputOptions.Builder(file).build(),
        )
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED) {
            pending = pending.withAudioEnabled()
        }
        recording = pending.start(mainExecutor) { event ->
            when (event) {
                is VideoRecordEvent.Finalize -> {
                    recording = null
                    val completed = recordingFile
                    recordingFile = null
                    finalizing = false
                    if (!event.hasError() && completed != null && completed.isFile && completed.length() > 0L) {
                        val duration = runCatching {
                            MediaMetadataRetriever().let { retriever ->
                                try {
                                    retriever.setDataSource(completed.absolutePath)
                                    retriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_DURATION)?.toLongOrNull()
                                } finally {
                                    retriever.release()
                                }
                            }
                        }.getOrNull()
                        runCatching {
                            repository.createTemporaryMediaItem(completed, "video/mp4", DeviceAttachmentKind.VIDEO, duration)
                        }.onSuccess(onCaptured).onFailure {
                            completed.delete()
                            onError(it.message ?: "Не удалось сохранить видео")
                        }
                    } else {
                        completed?.delete()
                        onError("Не удалось записать видео")
                    }
                }
                else -> Unit
            }
        }
    }

    fun stopVideo() {
        val active = recording ?: return
        finalizing = true
        active.stop()
    }

    LaunchedEffect(previewView, lensFacing) {
        val view = previewView ?: return@LaunchedEffect
        ready = false
        val future = ProcessCameraProvider.getInstance(context)
        future.addListener(
            {
                runCatching {
                    val cameraProvider = future.get()
                    provider = cameraProvider
                    val requested = CameraSelector.Builder().requireLensFacing(lensFacing).build()
                    val selector = if (cameraProvider.hasCamera(requested)) requested else CameraSelector.DEFAULT_BACK_CAMERA
                    val preview = Preview.Builder().build().also { it.surfaceProvider = view.surfaceProvider }
                    cameraProvider.unbindAll()
                    boundCamera = cameraProvider.bindToLifecycle(
                        lifecycleOwner,
                        selector,
                        preview,
                        imageCapture,
                        videoCapture,
                    )
                    boundCamera?.cameraControl?.enableTorch(torch)
                    ready = true
                }.onFailure {
                    ready = false
                    onError(it.message ?: "Не удалось открыть камеру")
                }
            },
            mainExecutor,
        )
    }

    LaunchedEffect(torch, boundCamera) {
        boundCamera?.cameraControl?.enableTorch(torch)
    }

    DisposableEffect(Unit) {
        onDispose {
            recording?.stop()
            provider?.unbindAll()
            recordingFile?.delete()
        }
    }

    Dialog(
        onDismissRequest = { if (recording == null && !finalizing) onDismiss() },
        properties = DialogProperties(usePlatformDefaultWidth = false, dismissOnClickOutside = false),
    ) {
        Box(Modifier.fillMaxSize().background(Color.Black)) {
            AndroidView(
                factory = {
                    PreviewView(it).apply {
                        implementationMode = PreviewView.ImplementationMode.PERFORMANCE
                        scaleType = PreviewView.ScaleType.FILL_CENTER
                        previewView = this
                    }
                },
                modifier = Modifier.fillMaxSize(),
            )
            Row(
                Modifier.align(Alignment.TopCenter).padding(top = 26.dp, start = 18.dp, end = 18.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                CameraControlButton(onClick = onDismiss) { CloseIcon(Modifier.size(24.dp), Color.White) }
                Spacer(Modifier.weight(1f))
                CameraControlButton(onClick = { torch = !torch }) {
                    Text(if (torch) "⚡" else "⚡̸", color = Color.White, style = MaterialTheme.typography.titleLarge)
                }
            }
            Column(
                Modifier.align(Alignment.BottomCenter).padding(bottom = 30.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                if (recording != null) {
                    Text("Запись… отпустите кнопку", color = Color.White, modifier = Modifier.padding(bottom = 12.dp))
                } else {
                    Text("Нажмите для фото · удерживайте для видео", color = Color.White, modifier = Modifier.padding(bottom = 12.dp))
                }
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(28.dp)) {
                    Surface(
                        modifier = Modifier.size(52.dp).clickable(onClick = onOpenGallery),
                        shape = CircleShape,
                        color = Color.Black.copy(alpha = 0.45f),
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            val thumbnail = latestGalleryThumbnail
                            if (thumbnail == null) {
                                GalleryIcon(Modifier.size(26.dp), Color.White)
                            } else {
                                Image(
                                    bitmap = thumbnail.asImageBitmap(),
                                    contentDescription = "Последнее медиа",
                                    modifier = Modifier.fillMaxSize().clip(CircleShape),
                                    contentScale = ContentScale.Crop,
                                )
                            }
                        }
                    }
                    Surface(
                        modifier = Modifier
                            .size(84.dp)
                            .pointerInput(ready, recording, finalizing) {
                                awaitEachGesture {
                                    awaitFirstDown(requireUnconsumed = false)
                                    val quickRelease = withTimeoutOrNull(340L) { waitForUpOrCancellation() }
                                    if (quickRelease != null) {
                                        capturePhoto()
                                    } else {
                                        startVideo()
                                        waitForUpOrCancellation()
                                        stopVideo()
                                    }
                                }
                            },
                        shape = CircleShape,
                        color = if (recording == null) Color.White else Color(0xFFE5484D),
                    ) {
                        Box(Modifier.padding(7.dp).background(Color.Transparent, CircleShape))
                    }
                    CameraControlButton(
                        onClick = {
                            if (recording == null && !finalizing) {
                                lensFacing = if (lensFacing == CameraSelector.LENS_FACING_BACK) {
                                    CameraSelector.LENS_FACING_FRONT
                                } else {
                                    CameraSelector.LENS_FACING_BACK
                                }
                            }
                        },
                    ) { SwitchCameraIcon(Modifier.size(28.dp), Color.White) }
                }
            }
            if (!ready || finalizing) {
                CircularProgressIndicator(Modifier.align(Alignment.Center), color = Color.White)
            }
        }
    }
}

@Composable
private fun CameraControlButton(onClick: () -> Unit, content: @Composable () -> Unit) {
    Surface(
        modifier = Modifier.size(48.dp).clickable(onClick = onClick),
        shape = CircleShape,
        color = Color.Black.copy(alpha = 0.45f),
    ) { Box(contentAlignment = Alignment.Center) { content() } }
}
