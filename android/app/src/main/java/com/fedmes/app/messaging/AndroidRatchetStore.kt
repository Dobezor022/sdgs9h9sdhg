package com.fedmes.app.messaging

import android.content.Context
import android.util.AtomicFile
import android.util.Base64
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

internal data class LocalOlmState(
    var accountPickle: String,
    var curve25519IdentityKey: String,
    var ed25519IdentityKey: String,
    var selfOneTimeKeyId: String?,
    var selfOneTimeKey: String?,
    var bundleVersion: Int,
    val sessions: MutableMap<String, String>,
    val outboundGroups: MutableMap<String, LocalMegolmOutbound>,
    val inboundGroups: MutableMap<String, String>,
    val ownMessageKeys: MutableMap<String, String>,
    val seenGroupIndexes: MutableMap<String, String>,
)

internal data class LocalMegolmOutbound(
    var roomKeyVersion: Long,
    var sessionId: String,
    var sessionKey: String,
    var pickle: String,
)

class AndroidRatchetStore(context: Context) {
    private val root = File(context.noBackupFilesDir, "ratchet-v2").apply {
        if (!exists() && !mkdirs()) error("Ratchet state directory could not be created")
    }

    @Synchronized
    internal fun load(serverUrl: String, username: String, accountRootKey: ByteArray): LocalOlmState? {
        val file = file(serverUrl, username)
        if (!file.exists()) return null
        val encoded = file.readBytes()
        return try { decrypt(serverUrl, username, accountRootKey, encoded) } finally { encoded.fill(0) }
    }

    @Synchronized
    internal fun save(serverUrl: String, username: String, accountRootKey: ByteArray, state: LocalOlmState) {
        val encoded = encrypt(serverUrl, username, accountRootKey, state)
        try {
            val atomic = AtomicFile(file(serverUrl, username))
            val output = atomic.startWrite()
            try {
                output.write(encoded)
                output.fd.sync()
                atomic.finishWrite(output)
            } catch (error: Throwable) {
                atomic.failWrite(output)
                throw error
            }
        } finally { encoded.fill(0) }
    }

    @Synchronized
    fun delete(serverUrl: String, username: String) { file(serverUrl, username).delete() }

    private fun encrypt(serverUrl: String, username: String, rootKey: ByteArray, state: LocalOlmState): ByteArray {
        val plaintext = stateToJson(state).toString().toByteArray(Charsets.UTF_8)
        val key = deriveKey(rootKey, serverUrl, username)
        val aad = aad(serverUrl, username)
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
            cipher.updateAAD(aad)
            val ciphertext = cipher.doFinal(plaintext)
            try {
                JSONObject().put("version", 1)
                    .put("iv", Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
                    .put("ciphertext", Base64.encodeToString(ciphertext, Base64.NO_WRAP))
                    .toString().toByteArray(Charsets.UTF_8)
            } finally { ciphertext.fill(0) }
        } finally { plaintext.fill(0); key.fill(0); aad.fill(0) }
    }

    private fun decrypt(serverUrl: String, username: String, rootKey: ByteArray, encoded: ByteArray): LocalOlmState {
        val envelope = JSONObject(encoded.toString(Charsets.UTF_8))
        if (envelope.optInt("version") != 1) error("Unsupported ratchet state")
        val iv = Base64.decode(envelope.getString("iv"), Base64.NO_WRAP)
        val ciphertext = Base64.decode(envelope.getString("ciphertext"), Base64.NO_WRAP)
        val key = deriveKey(rootKey, serverUrl, username)
        val aad = aad(serverUrl, username)
        val plaintext = try {
            Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
                updateAAD(aad)
                doFinal(ciphertext)
            }
        } finally { iv.fill(0); ciphertext.fill(0); key.fill(0); aad.fill(0) }
        return try { stateFromJson(JSONObject(plaintext.toString(Charsets.UTF_8))) } finally { plaintext.fill(0) }
    }

    private fun stateToJson(state: LocalOlmState): JSONObject = JSONObject()
        .put("version", 1)
        .put("account_pickle", state.accountPickle)
        .put("curve25519", state.curve25519IdentityKey)
        .put("ed25519", state.ed25519IdentityKey)
        .put("self_otk_id", state.selfOneTimeKeyId ?: JSONObject.NULL)
        .put("self_otk", state.selfOneTimeKey ?: JSONObject.NULL)
        .put("bundle_version", state.bundleVersion)
        .put("sessions", JSONObject(state.sessions as Map<*, *>))
        .put("outbound_groups", JSONObject().apply {
            state.outboundGroups.forEach { (chat, group) ->
                put(chat, JSONObject().put("room_key_version", group.roomKeyVersion)
                    .put("session_id", group.sessionId).put("session_key", group.sessionKey).put("pickle", group.pickle))
            }
        })
        .put("inbound_groups", JSONObject(state.inboundGroups as Map<*, *>))
        .put("own_message_keys", JSONObject(state.ownMessageKeys as Map<*, *>))
        .put("seen_group_indexes", JSONObject(state.seenGroupIndexes as Map<*, *>))

    private fun stateFromJson(root: JSONObject): LocalOlmState {
        if (root.optInt("version") != 1) error("Unsupported ratchet state")
        fun nullableString(name: String): String? {
            if (!root.has(name) || root.isNull(name)) return null
            return root.optString(name).takeIf { it.isNotBlank() && it != "null" }
        }
        fun stringMap(name: String): MutableMap<String, String> {
            val objectValue = root.optJSONObject(name) ?: JSONObject()
            return buildMap { objectValue.keys().forEach { key -> put(key, objectValue.getString(key)) } }.toMutableMap()
        }
        val groups = mutableMapOf<String, LocalMegolmOutbound>()
        val groupRoot = root.optJSONObject("outbound_groups") ?: JSONObject()
        groupRoot.keys().forEach { chat ->
            val value = groupRoot.getJSONObject(chat)
            groups[chat] = LocalMegolmOutbound(value.getLong("room_key_version"), value.getString("session_id"), value.getString("session_key"), value.getString("pickle"))
        }
        return LocalOlmState(
            accountPickle = root.getString("account_pickle"),
            curve25519IdentityKey = root.getString("curve25519"),
            ed25519IdentityKey = root.getString("ed25519"),
            selfOneTimeKeyId = nullableString("self_otk_id"),
            selfOneTimeKey = nullableString("self_otk"),
            bundleVersion = root.optInt("bundle_version", 0),
            sessions = stringMap("sessions"),
            outboundGroups = groups,
            inboundGroups = stringMap("inbound_groups"),
            ownMessageKeys = stringMap("own_message_keys"),
            seenGroupIndexes = stringMap("seen_group_indexes"),
        )
    }

    private fun deriveKey(rootKey: ByteArray, serverUrl: String, username: String): ByteArray {
        require(rootKey.size == 32)
        val context = "fedmes-ratchet-local-state-v1\n$serverUrl\n$username".toByteArray(Charsets.UTF_8)
        return try {
            Mac.getInstance("HmacSHA256").run { init(SecretKeySpec(rootKey, "HmacSHA256")); doFinal(context) }
        } finally { context.fill(0) }
    }
    private fun aad(serverUrl: String, username: String): ByteArray =
        "fedmes-ratchet-state-envelope-v1\n$serverUrl\n$username".toByteArray(Charsets.UTF_8)
    private fun file(serverUrl: String, username: String): File {
        val digest = MessageDigest.getInstance("SHA-256").digest("$serverUrl\n$username".toByteArray(Charsets.UTF_8))
        val name = digest.joinToString("") { "%02x".format(it.toInt() and 0xff) }
        digest.fill(0)
        return File(root, "$name.bin")
    }
}
