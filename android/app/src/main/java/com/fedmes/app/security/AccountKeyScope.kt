package com.fedmes.app.security

import java.net.URI
import java.security.MessageDigest
import java.util.Locale

/** Stable, non-secret scope used to separate Android Keystore keys by server and account. */
internal object AccountKeyScope {
    fun value(serverUrl: String, username: String): String {
        val canonicalServer = runCatching {
            val uri = URI(serverUrl.trim())
            val scheme = uri.scheme?.lowercase(Locale.US).orEmpty()
            val authority = uri.rawAuthority?.lowercase(Locale.US).orEmpty()
            "$scheme://$authority"
        }.getOrElse { serverUrl.trim().trimEnd('/').lowercase(Locale.US) }
        return "$canonicalServer\n${username.trim().lowercase(Locale.US)}"
    }

    fun hashHex(serverUrl: String, username: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(value(serverUrl, username).toByteArray(Charsets.UTF_8))
        return try {
            digest.joinToString(separator = "") { byte -> "%02x".format(byte.toInt() and 0xff) }
        } finally {
            digest.fill(0)
        }
    }

    fun aliasSuffix(serverUrl: String, username: String): String =
        hashHex(serverUrl, username).take(32)
}
