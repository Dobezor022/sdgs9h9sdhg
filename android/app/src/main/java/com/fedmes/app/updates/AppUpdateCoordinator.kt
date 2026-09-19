package com.fedmes.app.updates

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.core.content.FileProvider
import com.fedmes.app.BuildConfig
import com.fedmes.app.provisioning.ProvisionedAccount
import com.fedmes.app.security.SessionStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.File
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.security.MessageDigest


data class AppUpdateRelease(
    val versionName: String,
    val versionCode: Long,
    val minimumSupportedCode: Long,
    val serverUrl: String,
    val downloadPath: String,
    val downloadTicket: String,
    val sha256: String,
    val sizeBytes: Long,
    val notes: String,
)

data class AppUpdateUiState(
    val checking: Boolean = false,
    val release: AppUpdateRelease? = null,
    val required: Boolean = false,
    val downloading: Boolean = false,
    val progressPercent: Int = 0,
    val error: String? = null,
    val dismissedVersionCode: Long? = null,
)

class AppUpdateCoordinator(
    private val context: Context,
    private val sessionStore: SessionStore,
) {
    private val mutex = Mutex()
    private val mutableState = MutableStateFlow(AppUpdateUiState())
    val state: StateFlow<AppUpdateUiState> = mutableState.asStateFlow()

    suspend fun checkNow(): AppUpdateRelease? = mutex.withLock {
        val account = sessionStore.loadAccount()
        if (account == null) {
            mutableState.value = mutableState.value.copy(checking = false, release = null, error = null)
            return@withLock null
        }
        mutableState.value = mutableState.value.copy(checking = true, error = null)
        try {
            val result = withContext(Dispatchers.IO) { fetchRelease(account) }
            val previous = mutableState.value
            mutableState.value = previous.copy(
                checking = false,
                release = if (result.release?.versionCode == previous.dismissedVersionCode && !result.required) null else result.release,
                required = result.required,
                error = null,
            )
            result.release
        } catch (error: Exception) {
            mutableState.value = mutableState.value.copy(
                checking = false,
                error = if (mutableState.value.release == null) null else error.message,
            )
            null
        }
    }

    fun dismiss() {
        val release = mutableState.value.release ?: return
        if (mutableState.value.required) return
        mutableState.value = mutableState.value.copy(
            release = null,
            dismissedVersionCode = release.versionCode,
            error = null,
        )
    }

    suspend fun downloadAndInstall(activity: Activity): Unit = mutex.withLock {
        var release = mutableState.value.release ?: return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && !context.packageManager.canRequestPackageInstalls()) {
            mutableState.value = mutableState.value.copy(
                error = "Разрешите FedMes устанавливать обновления, затем нажмите «Обновить» ещё раз.",
            )
            activity.startActivity(
                Intent(
                    Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                    Uri.parse("package:${context.packageName}"),
                ),
            )
            return
        }

        mutableState.value = mutableState.value.copy(downloading = true, progressPercent = 0, error = null)
        try {
            var account = sessionStore.loadAccount() ?: throw IllegalStateException("Сессия FedMes недоступна.")
            val file = withContext(Dispatchers.IO) {
                var firstFailure: Exception? = null
                repeat(2) { attempt ->
                    try {
                        return@withContext downloadVerified(release, account.sessionToken)
                    } catch (error: Exception) {
                        firstFailure = firstFailure ?: error
                        if (attempt == 1) throw IllegalStateException(
                            error.message ?: "Не удалось загрузить проверенное обновление.",
                            firstFailure,
                        )
                        account = sessionStore.loadAccount()
                            ?: throw IllegalStateException("Сессия FedMes недоступна.")
                        val refreshed = fetchRelease(account).release
                            ?: throw IllegalStateException("Обновление больше не доступно.")
                        release = refreshed
                        mutableState.value = mutableState.value.copy(progressPercent = 0)
                    }
                }
                throw IllegalStateException("Не удалось загрузить обновление.", firstFailure)
            }
            mutableState.value = mutableState.value.copy(
                downloading = false,
                progressPercent = 100,
                release = release,
                error = null,
            )
            val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
            val installIntent = Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(uri, APK_MIME)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            activity.startActivity(installIntent)
        } catch (error: Exception) {
            mutableState.value = mutableState.value.copy(
                downloading = false,
                error = error.message ?: "Не удалось загрузить обновление.",
            )
        }
    }

    private data class CheckResult(val release: AppUpdateRelease?, val required: Boolean)

    private fun fetchRelease(account: ProvisionedAccount): CheckResult {
        val platform = if (BuildConfig.DISTRIBUTION_CHANNEL == "huawei") {
            "android-huawei"
        } else {
            "android-normal"
        }
        val endpoint = URI(account.serverUrl).resolve(
            "/api/v1/updates/check?platform=$platform&version_name=${Uri.encode(BuildConfig.VERSION_NAME)}" +
                "&version_code=${BuildConfig.VERSION_CODE}&client_nonce=${System.currentTimeMillis()}",
        ).toURL()
        val response = requestJson(endpoint, account.sessionToken)
        require(response.getInt("version") == UPDATE_PROTOCOL_VERSION) { "Версия протокола обновления не поддерживается." }
        val available = response.getBoolean("update_available")
        val required = response.getBoolean("required")
        val latest = response.getJSONObject("latest")
        return CheckResult(
            release = if (available) latest.toRelease(account.serverUrl) else null,
            required = required,
        )
    }

    private fun requestJson(url: URL, sessionToken: String): JSONObject {
        val connection = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = CONNECT_TIMEOUT_MILLIS
            readTimeout = READ_TIMEOUT_MILLIS
            setRequestProperty("Accept", "application/json")
            setRequestProperty("Authorization", "Bearer $sessionToken")
            setRequestProperty("Cache-Control", "no-store")
            setRequestProperty("User-Agent", "FedMes-Android/${BuildConfig.VERSION_NAME}")
            useCaches = false
        }
        return try {
            when (connection.responseCode) {
                HttpURLConnection.HTTP_OK -> Unit
                HttpURLConnection.HTTP_UNAUTHORIZED,
                HttpURLConnection.HTTP_FORBIDDEN,
                -> throw IllegalStateException("Сессия FedMes не разрешает получить обновление.")
                else -> throw IllegalStateException("Сервер обновлений временно недоступен.")
            }
            val bytes = connection.inputStream.use { input ->
                val output = ByteArrayOutputStream()
                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                var total = 0
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    total += read
                    if (total > MAX_JSON_BYTES) {
                        throw IllegalStateException("Ответ сервера обновлений слишком большой.")
                    }
                    output.write(buffer, 0, read)
                }
                output.toByteArray()
            }
            JSONObject(bytes.toString(Charsets.UTF_8))
        } finally {
            connection.disconnect()
        }
    }

    private fun JSONObject.toRelease(serverUrl: String): AppUpdateRelease {
        require(getString("download_method") == "POST") { "Сервер вернул небезопасный способ загрузки." }
        val path = getString("download_path")
        require(path == UPDATE_DOWNLOAD_PATH) { "Сервер вернул неправильный путь обновления." }
        val server = URI(serverUrl)
        require(server.scheme == "https") { "Обновления разрешены только через HTTPS." }
        val ticket = getString("download_ticket")
        require(ticket.length in 64..4096) { "Сервер вернул неправильный билет загрузки." }
        val hash = getString("sha256").lowercase()
        require(hash.matches(Regex("[a-f0-9]{64}"))) { "Сервер вернул неверную контрольную сумму." }
        val sizeBytes = getLong("size_bytes")
        require(sizeBytes > 0L && sizeBytes <= MAX_APK_BYTES) { "Сервер вернул неверный размер APK." }
        return AppUpdateRelease(
            versionName = getString("version_name"),
            versionCode = getLong("version_code"),
            minimumSupportedCode = getLong("minimum_supported_code"),
            serverUrl = serverUrl,
            downloadPath = path,
            downloadTicket = ticket,
            sha256 = hash,
            sizeBytes = sizeBytes,
            notes = optString("notes"),
        )
    }

    private fun downloadVerified(release: AppUpdateRelease, sessionToken: String): File {
        val directory = File(context.filesDir, "updates").apply { mkdirs() }
        val target = File(
            directory,
            "FedMes-${release.versionName}-${release.versionCode}-${release.sha256.take(12)}.apk",
        )
        directory.listFiles()?.forEach { existing ->
            if (existing != target) runCatching { existing.delete() }
        }
        val temporary = File(directory, target.name + ".part")
        temporary.delete()
        val endpoint = URI(release.serverUrl).resolve(release.downloadPath).toURL()
        val body = JSONObject()
            .put("version", 1)
            .put("ticket", release.downloadTicket)
            .toString()
            .toByteArray(Charsets.UTF_8)
        val connection = (endpoint.openConnection() as HttpURLConnection).apply {
            connectTimeout = CONNECT_TIMEOUT_MILLIS
            readTimeout = DOWNLOAD_TIMEOUT_MILLIS
            requestMethod = "POST"
            doOutput = true
            setFixedLengthStreamingMode(body.size)
            setRequestProperty("Authorization", "Bearer $sessionToken")
            setRequestProperty("Content-Type", "application/json; charset=utf-8")
            setRequestProperty("Accept", APK_MIME)
            setRequestProperty("Accept-Encoding", "identity")
            setRequestProperty("Cache-Control", "no-store")
            setRequestProperty("User-Agent", "FedMes-Android/${BuildConfig.VERSION_NAME}")
            useCaches = false
        }
        try {
            connection.outputStream.use { it.write(body) }
            when (connection.responseCode) {
                HttpURLConnection.HTTP_OK -> Unit
                HttpURLConnection.HTTP_GONE -> throw DownloadTicketExpiredException()
                HttpURLConnection.HTTP_UNAUTHORIZED,
                HttpURLConnection.HTTP_FORBIDDEN,
                -> throw IllegalStateException("Сервер отклонил авторизацию обновления.")
                else -> throw IllegalStateException("Не удалось скачать APK: HTTP ${connection.responseCode}.")
            }
            val headerHash = connection.getHeaderField("X-FedMes-SHA256")?.lowercase()
            val headerSize = connection.getHeaderField("X-FedMes-Size")?.toLongOrNull()
            require(headerHash == release.sha256 && headerSize == release.sizeBytes) {
                "Метаданные APK не совпадают с подписанным билетом."
            }

            val digest = MessageDigest.getInstance("SHA-256")
            var total = 0L
            connection.inputStream.use { input ->
                temporary.outputStream().buffered().use { output ->
                    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                    while (true) {
                        val read = input.read(buffer)
                        if (read < 0) break
                        total += read
                        if (total > release.sizeBytes || total > MAX_APK_BYTES) {
                            throw IllegalStateException("Размер APK не совпадает с манифестом.")
                        }
                        output.write(buffer, 0, read)
                        digest.update(buffer, 0, read)
                        val progress = ((total * 100L) / release.sizeBytes.coerceAtLeast(1L)).toInt().coerceIn(0, 99)
                        mutableState.value = mutableState.value.copy(progressPercent = progress)
                    }
                }
            }
            if (total != release.sizeBytes) {
                throw IllegalStateException("APK загружен не полностью: $total из ${release.sizeBytes} байт.")
            }
            val actual = digest.digest()
            val expected = release.sha256.hexBytes()
            try {
                if (!MessageDigest.isEqual(actual, expected)) {
                    throw IllegalStateException("SHA-256 APK не совпал с серверным манифестом.")
                }
            } finally {
                actual.fill(0)
                expected.fill(0)
            }
            if (target.exists() && !target.delete()) throw IllegalStateException("Не удалось заменить старое обновление.")
            if (!temporary.renameTo(target)) throw IllegalStateException("Не удалось подготовить APK к установке.")
            return target
        } finally {
            body.fill(0)
            connection.disconnect()
            if (temporary.exists()) temporary.delete()
        }
    }

    private fun String.hexBytes(): ByteArray = chunked(2)
        .map { it.toInt(16).toByte() }
        .toByteArray()

    private class DownloadTicketExpiredException : Exception("Билет загрузки истёк.")

    private companion object {
        const val UPDATE_PROTOCOL_VERSION = 2
        const val UPDATE_DOWNLOAD_PATH = "/api/v1/updates/download"
        const val APK_MIME = "application/vnd.android.package-archive"
        const val CONNECT_TIMEOUT_MILLIS = 10_000
        const val READ_TIMEOUT_MILLIS = 20_000
        const val DOWNLOAD_TIMEOUT_MILLIS = 45 * 60_000
        const val MAX_JSON_BYTES = 128 * 1024
        const val MAX_APK_BYTES = 512L * 1024L * 1024L
    }
}
