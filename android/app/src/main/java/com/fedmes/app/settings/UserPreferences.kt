package com.fedmes.app.settings

import android.content.Context
import androidx.core.content.edit
import com.fedmes.app.ui.theme.ThemeMode

class UserPreferences(context: Context) {
    private val preferences = context.getSharedPreferences(FILE_NAME, Context.MODE_PRIVATE)

    fun themeMode(): ThemeMode = runCatching {
        ThemeMode.valueOf(preferences.getString(KEY_THEME, ThemeMode.SYSTEM.name).orEmpty())
    }.getOrDefault(ThemeMode.SYSTEM)

    fun setThemeMode(value: ThemeMode) {
        preferences.edit { putString(KEY_THEME, value.name) }
    }

    fun showExactPresence(): Boolean = preferences.getBoolean(KEY_EXACT_PRESENCE, true)

    fun setShowExactPresence(value: Boolean) {
        preferences.edit { putBoolean(KEY_EXACT_PRESENCE, value) }
    }


    fun profileAvatarUri(username: String): String? = preferences.getString(profileKey(username, "avatar"), null)

    fun profileAvatarMimeType(username: String): String? = preferences.getString(profileKey(username, "avatar.mime"), null)

    fun setProfileAvatar(username: String, uri: String?, mimeType: String?) {
        preferences.edit {
            if (uri.isNullOrBlank()) {
                remove(profileKey(username, "avatar"))
                remove(profileKey(username, "avatar.mime"))
            } else {
                putString(profileKey(username, "avatar"), uri)
                putString(profileKey(username, "avatar.mime"), mimeType.orEmpty())
            }
        }
    }

    fun profileNameColorArgb(username: String): Long =
        preferences.getLong(profileKey(username, "name.color"), DEFAULT_PROFILE_NAME_COLOR)

    fun setProfileNameColorArgb(username: String, value: Long) {
        preferences.edit { putLong(profileKey(username, "name.color"), value) }
    }

    private fun profileKey(username: String, suffix: String): String =
        "profile:${username.lowercase().hashCode()}:$suffix"

    fun notificationsEnabled(): Boolean = preferences.getBoolean(KEY_NOTIFICATIONS_ENABLED, true)

    fun setNotificationsEnabled(value: Boolean) {
        preferences.edit { putBoolean(KEY_NOTIFICATIONS_ENABLED, value) }
    }

    fun notificationSoundEnabled(): Boolean = preferences.getBoolean(KEY_NOTIFICATION_SOUND, true)

    fun setNotificationSoundEnabled(value: Boolean) {
        preferences.edit { putBoolean(KEY_NOTIFICATION_SOUND, value) }
    }

    fun notificationVibrationEnabled(): Boolean = preferences.getBoolean(KEY_NOTIFICATION_VIBRATION, true)

    fun setNotificationVibrationEnabled(value: Boolean) {
        preferences.edit { putBoolean(KEY_NOTIFICATION_VIBRATION, value) }
    }

    fun groupNotificationsEnabled(): Boolean = preferences.getBoolean(KEY_GROUP_NOTIFICATIONS, true)

    fun setGroupNotificationsEnabled(value: Boolean) {
        preferences.edit { putBoolean(KEY_GROUP_NOTIFICATIONS, value) }
    }

    fun lastReadSequence(account: String, chatId: String): Long =
        preferences.getLong(readKey(account, chatId), 0L)

    fun setLastReadSequence(account: String, chatId: String, sequence: Long) {
        val key = readKey(account, chatId)
        if (sequence > preferences.getLong(key, 0L)) {
            preferences.edit { putLong(key, sequence) }
        }
    }

    private fun readKey(account: String, chatId: String): String =
        "$KEY_READ_PREFIX${account.hashCode()}:${chatId.hashCode()}"

    private companion object {
        const val FILE_NAME = "fedmes_user_preferences"
        const val KEY_THEME = "theme"
        const val KEY_EXACT_PRESENCE = "presence.exact"
        const val KEY_NOTIFICATIONS_ENABLED = "notifications.enabled"
        const val KEY_NOTIFICATION_SOUND = "notifications.sound"
        const val KEY_NOTIFICATION_VIBRATION = "notifications.vibration"
        const val KEY_GROUP_NOTIFICATIONS = "notifications.groups"
        const val KEY_READ_PREFIX = "read:"
        const val DEFAULT_PROFILE_NAME_COLOR = 0L
    }
}
