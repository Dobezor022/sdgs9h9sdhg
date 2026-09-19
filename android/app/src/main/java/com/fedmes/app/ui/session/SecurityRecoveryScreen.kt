package com.fedmes.app.ui.session

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.fedmes.app.provisioning.AccountSummary

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecurityRecoveryScreen(
    account: AccountSummary,
    recoveryKey: String,
    busy: Boolean,
    error: String?,
    notice: String?,
    onRecoveryKeyChanged: (String) -> Unit,
    onRecover: () -> Unit,
    onCancel: () -> Unit,
) {
    Scaffold(
        topBar = { TopAppBar(title = { Text("Безопасное восстановление") }) },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(24.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(
                text = "Серверная сессия для ${account.username} создана, но ключи истории ещё не восстановлены.",
                style = MaterialTheme.typography.titleMedium,
            )
            Spacer(Modifier.height(12.dp))
            Text(
                text = "Введите Recovery Key. Старый локальный профиль не удаляется, пока vault не будет расшифрован и проверен.",
                style = MaterialTheme.typography.bodyMedium,
            )
            Spacer(Modifier.height(20.dp))
            OutlinedTextField(
                value = recoveryKey,
                onValueChange = onRecoveryKeyChanged,
                modifier = Modifier.fillMaxWidth(),
                enabled = !busy,
                singleLine = false,
                minLines = 2,
                label = { Text("Recovery Key") },
                visualTransformation = PasswordVisualTransformation(),
                supportingText = { Text("Ключ обрабатывается только на устройстве и не отправляется серверу.") },
            )
            if (!error.isNullOrBlank()) {
                Spacer(Modifier.height(12.dp))
                Text(error, color = MaterialTheme.colorScheme.error)
            }
            if (!notice.isNullOrBlank()) {
                Spacer(Modifier.height(12.dp))
                Text(notice, color = MaterialTheme.colorScheme.primary)
            }
            Spacer(Modifier.height(20.dp))
            Button(
                onClick = onRecover,
                enabled = !busy && recoveryKey.isNotBlank(),
                modifier = Modifier.fillMaxWidth(),
            ) {
                if (busy) {
                    CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                } else {
                    Text("Восстановить ключи и историю")
                }
            }
            Spacer(Modifier.height(10.dp))
            OutlinedButton(
                onClick = onCancel,
                enabled = !busy,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Отменить вход")
            }
        }
    }
}
