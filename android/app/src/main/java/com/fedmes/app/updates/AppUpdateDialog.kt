package com.fedmes.app.updates

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
fun AppUpdateDialog(
    state: AppUpdateUiState,
    onUpdate: () -> Unit,
    onDismiss: () -> Unit,
) {
    val release = state.release ?: return
    AlertDialog(
        onDismissRequest = { if (!state.required && !state.downloading) onDismiss() },
        title = { Text(if (state.required) "Требуется обновление FedMes" else "Доступно обновление") },
        text = {
            Column {
                Text("Новая версия: ${release.versionName}")
                if (release.notes.isNotBlank()) {
                    Spacer(Modifier.height(8.dp))
                    Text(release.notes)
                }
                if (state.downloading) {
                    Spacer(Modifier.height(14.dp))
                    LinearProgressIndicator(
                        progress = { state.progressPercent / 100f },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Spacer(Modifier.height(6.dp))
                    Text("Загрузка: ${state.progressPercent}%")
                }
                state.error?.let {
                    Spacer(Modifier.height(10.dp))
                    Text(it)
                }
            }
        },
        confirmButton = {
            Button(onClick = onUpdate, enabled = !state.downloading) {
                Text(if (state.downloading) "Загрузка…" else "Обновить")
            }
        },
        dismissButton = if (!state.required && !state.downloading) {
            { TextButton(onClick = onDismiss) { Text("Позже") } }
        } else {
            null
        },
    )
}
