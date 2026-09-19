package com.fedmes.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.content.edit
import com.fedmes.app.settings.UserPreferences
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

class FedMesSyncService : Service() {
    private val serviceJob: Job = SupervisorJob()
    private val scope = CoroutineScope(serviceJob + Dispatchers.IO)
    private var syncJob: Job? = null
    private var updateJob: Job? = null
    private val preferences by lazy {
        getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)
    }
    private val userPreferences by lazy { UserPreferences(applicationContext) }

    override fun onCreate() {
        super.onCreate()
        createChannels()
        startForeground(FOREGROUND_NOTIFICATION_ID, foregroundNotification())
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (!scope.isActive) return START_NOT_STICKY
        if (syncJob?.isActive != true) {
            syncJob = scope.launch { synchronizationLoop() }
        }
        if (updateJob?.isActive != true) {
            updateJob = scope.launch { updateLoop() }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        serviceJob.cancel()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private suspend fun synchronizationLoop() {
        val container = (application as FedMesApplication).appContainer
        val account = container.sessionStore.loadAccount() ?: run {
            stopSelf()
            return
        }
        var eventCursor = preferences.getLong(EVENT_CURSOR_KEY, -1L)
        try {
            val chats = container.messagingRepository.listChats()
            chats.forEach { chat ->
                val cursorKey = chatCursorKey(chat.id)
                val rosterKey = chatRosterKey(chat.id)
                val fingerprint = container.messagingRepository
                    .encryptionReadyDeviceFingerprint(chat.id)
                if (fingerprint != preferences.getString(rosterKey, null)) {
                    container.messagingRepository.repairEnvelopeHistory(chat.id)
                    preferences.edit { putString(rosterKey, fingerprint) }
                }
                if (!preferences.contains(cursorKey)) {
                    val page = container.messagingRepository.loadLatestMessages(
                        chatId = chat.id,
                        limit = BACKGROUND_PAGE_SIZE,
                        markRead = false,
                    )
                    val highestDecryptableSequence = page.messages.maxOfOrNull { it.sequence } ?: 0L
                    preferences.edit { putLong(cursorKey, highestDecryptableSequence) }
                }
            }
            if (eventCursor < 0L) {
                eventCursor = container.messagingRepository.waitForEvents(0L)
                preferences.edit { putLong(EVENT_CURSOR_KEY, eventCursor) }
            }
        } catch (error: CancellationException) {
            throw error
        } catch (_: Exception) {
            delay(RETRY_DELAY_MILLIS)
        }

        while (scope.isActive) {
            try {
                val nextEventCursor = container.messagingRepository.waitForEvents(eventCursor)
                if (nextEventCursor == eventCursor) continue
                // A lower sequence means the server explicitly reset its in-memory clock.
                // Persist the new base and run one reconciliation pass instead of stalling.

                var hasIncoming = false
                val chats = container.messagingRepository.listChats()
                chats.forEach { chat ->
                    val key = chatCursorKey(chat.id)
                    val rosterKey = chatRosterKey(chat.id)
                    val previousDecryptableSequence = preferences.getLong(key, 0L)
                    val fingerprint = container.messagingRepository
                        .encryptionReadyDeviceFingerprint(chat.id)
                    val rosterChanged = fingerprint != preferences.getString(rosterKey, null)
                    if (rosterChanged) {
                        container.messagingRepository.repairEnvelopeHistory(chat.id)
                        preferences.edit { putString(rosterKey, fingerprint) }
                    }
                    if (!rosterChanged && chat.lastSequence <= previousDecryptableSequence) {
                        return@forEach
                    }
                    val page = if (previousDecryptableSequence > 0L) {
                        container.messagingRepository.loadMessagesAfter(
                            chatId = chat.id,
                            after = previousDecryptableSequence,
                            limit = BACKGROUND_PAGE_SIZE,
                            markRead = false,
                        )
                    } else {
                        container.messagingRepository.loadLatestMessages(
                            chatId = chat.id,
                            limit = BACKGROUND_PAGE_SIZE,
                            markRead = false,
                        )
                    }
                    val latestDecryptableSequence = page.messages.maxOfOrNull { it.sequence }
                        ?: previousDecryptableSequence
                    if (
                        page.messages.any { message ->
                            message.sequence > previousDecryptableSequence &&
                                message.senderUsername != account.username
                        } && (chat.kind != "family" || userPreferences.groupNotificationsEnabled())
                    ) {
                        hasIncoming = true
                    }
                    preferences.edit { putLong(key, latestDecryptableSequence) }
                }
                eventCursor = nextEventCursor
                preferences.edit { putLong(EVENT_CURSOR_KEY, eventCursor) }
                if (hasIncoming) notifyIncomingMessage()
            } catch (error: CancellationException) {
                throw error
            } catch (_: Exception) {
                delay(RETRY_DELAY_MILLIS)
            }
        }
    }


    private suspend fun updateLoop() {
        val container = (application as FedMesApplication).appContainer
        while (scope.isActive) {
            try {
                val release = container.updateCoordinator.checkNow()
                if (release != null && preferences.getLong(LAST_UPDATE_NOTIFICATION_CODE, -1L) != release.versionCode) {
                    notifyAvailableUpdate(release.versionName)
                    preferences.edit { putLong(LAST_UPDATE_NOTIFICATION_CODE, release.versionCode) }
                }
            } catch (error: CancellationException) {
                throw error
            } catch (_: Exception) {
                // Update failures never interrupt encrypted message synchronization.
            }
            delay(UPDATE_CHECK_INTERVAL_MILLIS)
        }
    }

    private fun chatCursorKey(chatId: String): String =
        "$CHAT_CURSOR_PREFIX${chatId.hashCode()}"

    private fun chatRosterKey(chatId: String): String =
        "$CHAT_ROSTER_PREFIX${chatId.hashCode()}"

    private fun foregroundNotification(): Notification = notificationBuilder(SYNC_CHANNEL_ID)
        .setSmallIcon(R.drawable.ic_fedmes)
        .setContentTitle("FedMes")
        .setContentText("Защищённая синхронизация включена")
        .setOngoing(true)
        .setContentIntent(openAppIntent())
        .build()

    private fun notifyIncomingMessage() {
        if (!userPreferences.notificationsEnabled()) return
        val manager = getSystemService(NotificationManager::class.java)
        val notification = notificationBuilder(MESSAGE_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_fedmes)
            .setContentTitle("FedMes")
            .setContentText("Новое зашифрованное сообщение")
            .setAutoCancel(true)
            .setContentIntent(openAppIntent())
            .build()
        manager.notify(MESSAGE_NOTIFICATION_ID, notification)
    }


    private fun notifyAvailableUpdate(versionName: String) {
        val manager = getSystemService(NotificationManager::class.java)
        val notification = notificationBuilder(UPDATE_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_fedmes)
            .setContentTitle("Доступно обновление FedMes")
            .setContentText("Версия $versionName готова к установке")
            .setAutoCancel(true)
            .setContentIntent(openAppIntent())
            .build()
        manager.notify(UPDATE_NOTIFICATION_ID, notification)
    }

    @Suppress("DEPRECATION")
    private fun notificationBuilder(channelId: String): Notification.Builder =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, channelId)
        } else {
            Notification.Builder(this)
        }

    private fun openAppIntent(): PendingIntent {
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        return PendingIntent.getActivity(
            this,
            0,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
    }

    private fun createChannels() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(
                SYNC_CHANNEL_ID,
                "Синхронизация FedMes",
                NotificationManager.IMPORTANCE_LOW,
            ),
        )
        manager.createNotificationChannel(
            NotificationChannel(
                MESSAGE_CHANNEL_ID,
                "Новые сообщения",
                NotificationManager.IMPORTANCE_DEFAULT,
            ).apply {
                description = "Уведомления без открытого текста сообщений"
                lockscreenVisibility = Notification.VISIBILITY_PRIVATE
            },
        )
        manager.createNotificationChannel(
            NotificationChannel(
                UPDATE_CHANNEL_ID,
                "Обновления FedMes",
                NotificationManager.IMPORTANCE_DEFAULT,
            ),
        )
    }

    companion object {
        private const val SYNC_CHANNEL_ID = "fedmes_sync"
        private const val MESSAGE_CHANNEL_ID = "fedmes_messages"
        private const val UPDATE_CHANNEL_ID = "fedmes_updates"
        private const val FOREGROUND_NOTIFICATION_ID = 1001
        private const val MESSAGE_NOTIFICATION_ID = 1002
        private const val UPDATE_NOTIFICATION_ID = 1003
        private const val PREFERENCES_NAME = "fedmes.sync.v1"
        private const val EVENT_CURSOR_KEY = "event_cursor"
        private const val LAST_UPDATE_NOTIFICATION_CODE = "last_update_notification_code"
        private const val CHAT_CURSOR_PREFIX = "chat_cursor:"
        private const val CHAT_ROSTER_PREFIX = "chat_roster:"
        private const val RETRY_DELAY_MILLIS = 10_000L
        private const val UPDATE_CHECK_INTERVAL_MILLIS = 10L * 60L * 1000L
        private const val BACKGROUND_PAGE_SIZE = 200

        fun start(context: Context) {
            val intent = Intent(context, FedMesSyncService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, FedMesSyncService::class.java))
        }
    }
}
