package com.fedmes.app.ui.provisioning

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.fedmes.app.R
import com.fedmes.app.provisioning.ProvisioningFailure
import com.fedmes.app.ui.model.ScannerPhase
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

@Composable
fun QrScannerScaffold(
    phase: ScannerPhase,
    failure: ProvisioningFailure?,
    onQrDecoded: (String) -> Unit,
    onCameraError: () -> Unit,
    onRetry: () -> Unit,
    onClose: () -> Unit,
    modifier: Modifier = Modifier,
) {
    BackHandler {
        if (phase != ScannerPhase.PROCESSING) onClose()
    }
    Column(
        modifier = modifier
            .fillMaxSize()
            .windowInsetsPadding(WindowInsets.safeDrawing)
            .padding(16.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text(
                text = stringResource(R.string.scanner_title),
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
            )
            TextButton(
                onClick = onClose,
                enabled = phase != ScannerPhase.PROCESSING,
            ) {
                Text(stringResource(R.string.close_scanner))
            }
        }
        Spacer(Modifier.height(20.dp))
        Box(
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .background(Color.Black, RoundedCornerShape(22.dp))
                .border(
                    width = 3.dp,
                    color = MaterialTheme.colorScheme.primary,
                    shape = RoundedCornerShape(22.dp),
                ),
            contentAlignment = Alignment.Center,
        ) {
            when (phase) {
                ScannerPhase.SCANNING -> CameraPermissionContent(
                    onQrDecoded = onQrDecoded,
                    onCameraError = onCameraError,
                )
                ScannerPhase.PROCESSING -> ProcessingContent()
                ScannerPhase.ERROR -> ErrorContent(
                    failure = failure ?: ProvisioningFailure.INVALID_RESPONSE,
                    onRetry = onRetry,
                )
            }
        }
        Spacer(Modifier.height(16.dp))
        Text(
            text = stringResource(R.string.scanner_hint),
            textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.fillMaxWidth(),
        )
    }
}

@Composable
private fun CameraPermissionContent(
    onQrDecoded: (String) -> Unit,
    onCameraError: () -> Unit,
) {
    val context = LocalContext.current
    var permissionGranted by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
                PackageManager.PERMISSION_GRANTED,
        )
    }
    var permissionRequested by rememberSaveable { mutableStateOf(false) }
    val permissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission(),
    ) { granted ->
        permissionGranted = granted
        permissionRequested = true
    }
    LaunchedEffect(permissionGranted, permissionRequested) {
        if (!permissionGranted && !permissionRequested) {
            permissionRequested = true
            permissionLauncher.launch(Manifest.permission.CAMERA)
        }
    }

    if (permissionGranted) {
        NativeCameraPreview(
            onQrDecoded = onQrDecoded,
            onCameraError = onCameraError,
        )
    } else {
        Column(
            modifier = Modifier.padding(28.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(
                text = stringResource(R.string.camera_permission_title),
                style = MaterialTheme.typography.titleMedium,
                color = Color.White,
                fontWeight = FontWeight.Bold,
                textAlign = TextAlign.Center,
            )
            Spacer(Modifier.height(10.dp))
            Text(
                text = stringResource(R.string.camera_permission_description),
                color = Color.White.copy(alpha = 0.8f),
                textAlign = TextAlign.Center,
            )
            Spacer(Modifier.height(18.dp))
            Button(
                onClick = {
                    permissionRequested = true
                    permissionLauncher.launch(Manifest.permission.CAMERA)
                },
            ) {
                Text(stringResource(R.string.grant_camera_permission))
            }
        }
    }
}

@Composable
private fun NativeCameraPreview(
    onQrDecoded: (String) -> Unit,
    onCameraError: () -> Unit,
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val currentOnQrDecoded by rememberUpdatedState(onQrDecoded)
    val currentOnCameraError by rememberUpdatedState(onCameraError)
    val previewView = remember {
        PreviewView(context).apply {
            implementationMode = PreviewView.ImplementationMode.COMPATIBLE
            scaleType = PreviewView.ScaleType.FILL_CENTER
        }
    }

    AndroidView(
        factory = { previewView },
        modifier = Modifier.fillMaxSize(),
    )
    Box(
        modifier = Modifier
            .size(250.dp)
            .border(
                width = 2.dp,
                color = Color.White.copy(alpha = 0.78f),
                shape = RoundedCornerShape(18.dp),
            ),
    )

    DisposableEffect(lifecycleOwner, previewView) {
        val disposed = AtomicBoolean(false)
        val analysisExecutor = Executors.newSingleThreadExecutor()
        val mainExecutor = ContextCompat.getMainExecutor(context)
        val providerFuture = ProcessCameraProvider.getInstance(context)
        var provider: ProcessCameraProvider? = null
        var analysis: ImageAnalysis? = null
        providerFuture.addListener(
            {
                if (disposed.get()) return@addListener
                try {
                    provider = providerFuture.get()
                    val preview = Preview.Builder().build().also { useCase ->
                        useCase.surfaceProvider = previewView.surfaceProvider
                    }
                    analysis = ImageAnalysis.Builder()
                        .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                        .build()
                        .also { useCase ->
                            useCase.setAnalyzer(
                                analysisExecutor,
                                QrCodeAnalyzer(
                                    callbackExecutor = mainExecutor,
                                    onQrDecoded = { currentOnQrDecoded(it) },
                                    onAnalyzerError = { currentOnCameraError() },
                                ),
                            )
                        }
                    provider?.unbindAll()
                    provider?.bindToLifecycle(
                        lifecycleOwner,
                        CameraSelector.DEFAULT_BACK_CAMERA,
                        preview,
                        analysis,
                    )
                } catch (_: Exception) {
                    currentOnCameraError()
                }
            },
            mainExecutor,
        )
        onDispose {
            disposed.set(true)
            analysis?.clearAnalyzer()
            provider?.unbindAll()
            analysisExecutor.shutdownNow()
        }
    }
}

@Composable
private fun ProcessingContent() {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        CircularProgressIndicator(color = Color.White)
        Spacer(Modifier.height(18.dp))
        Text(
            text = stringResource(R.string.scanner_processing),
            modifier = Modifier.padding(horizontal = 28.dp),
            color = Color.White,
            textAlign = TextAlign.Center,
        )
    }
}

@Composable
private fun ErrorContent(
    failure: ProvisioningFailure,
    onRetry: () -> Unit,
) {
    Column(
        modifier = Modifier.padding(28.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            text = stringResource(failure.messageResource()),
            color = Color.White,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(18.dp))
        Button(onClick = onRetry) {
            Text(stringResource(R.string.retry))
        }
    }
}

internal fun ProvisioningFailure.messageResource(): Int = when (this) {
    ProvisioningFailure.INVALID_QR -> R.string.error_invalid_qr
    ProvisioningFailure.UNSUPPORTED_QR -> R.string.error_unsupported_qr
    ProvisioningFailure.EXPIRED_QR -> R.string.error_expired_qr
    ProvisioningFailure.INSECURE_SERVER -> R.string.error_insecure_server
    ProvisioningFailure.INVALID_USER -> R.string.error_invalid_user
    ProvisioningFailure.INVITATION_USED -> R.string.error_invitation_used
    ProvisioningFailure.INVITATION_REJECTED -> R.string.error_invitation_rejected
    ProvisioningFailure.NETWORK -> R.string.error_network
    ProvisioningFailure.SERVER -> R.string.error_server
    ProvisioningFailure.INVALID_RESPONSE -> R.string.error_invalid_response
    ProvisioningFailure.DEVICE_SECURITY -> R.string.error_device_security
    ProvisioningFailure.SESSION_RECOVERY -> R.string.error_session_recovery
    ProvisioningFailure.SECURE_STORAGE -> R.string.error_secure_storage
    ProvisioningFailure.CAMERA -> R.string.error_camera
}
