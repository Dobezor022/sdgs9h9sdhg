package com.fedmes.app.messaging

import android.net.Uri
import com.fedmes.app.provisioning.ProtocolTime
import com.fedmes.app.provisioning.ProvisionedAccount
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.ConnectException
import java.net.HttpURLConnection
import java.net.NoRouteToHostException
import java.net.SocketTimeoutException
import java.net.URL
import java.net.UnknownHostException

class MessagingHttpApi {
    data class SequenceLeaseItem(
        val requestId: String,
        val messageId: String,
        val cryptoSequence: Long,
    )

    fun registerEncryptionKey(
        account: ProvisionedAccount,
        algorithm: String,
        publicKeySpkiBase64: String,
    ) {
        val body = JSONObject()
            .put("version", 1)
            .put("algorithm", algorithm)
            .put("public_key_spki", publicKeySpkiBase64)
        execute(account, "PUT", "/api/v1/devices/encryption-key", body.toString().toByteArray())
    }

    fun listChats(account: ProvisionedAccount): List<ChatSummary> {
        val root = executeJson(account, "GET", "/api/v1/chats")
        return root.arrayOrEmpty("chats").mapObjects { value ->
            ChatSummary(
                id = value.getString("id"),
                kind = value.getString("kind"),
                title = value.getString("title"),
                members = value.arrayOrEmpty("members").mapStrings(),
                lastSequence = value.getLong("last_sequence"),
                lastMessageAt = value.optionalTimestamp("last_message_at"),
                pinnedMessageId = value.optString("pinned_message_id").takeIf(String::isNotBlank),
                unreadCount = value.optInt("unread_count", 0),
            )
        }
    }

    fun listDevices(account: ProvisionedAccount, chatId: String): List<ChatDevice> {
        val root = executeJson(account, "GET", "/api/v1/chats/${segment(chatId)}/devices")
        return root.arrayOrEmpty("devices").mapObjects { value ->
            ChatDevice(
                id = value.getString("id"),
                username = value.getString("username"),
                identityAlgorithm = value.optString("identity_algorithm"),
                identityPublicKeySpkiBase64 = value.optString("identity_public_key_spki"),
                encryptionAlgorithm = value.optString("encryption_algorithm").takeIf(String::isNotBlank),
                encryptionPublicKeySpkiBase64 = value.optString("encryption_public_key_spki")
                    .takeIf(String::isNotBlank),
                ratchetBundleVersion = value.optInt("ratchet_bundle_version", 0),
            )
        }
    }

    fun listMessages(
        account: ProvisionedAccount,
        chatId: String,
        after: Long = 0,
        before: Long = 0,
        limit: Int = 100,
    ): MessagePage {
        require(after == 0L || before == 0L) { "Only one message cursor may be used" }
        val query = buildString {
            append("?limit=").append(limit.coerceIn(1, 200))
            if (after > 0) append("&after=").append(after)
            if (before > 0) append("&before=").append(before)
        }
        val root = executeJson(
            account,
            "GET",
            "/api/v1/chats/${segment(chatId)}/messages$query",
        )
        return MessagePage(
            messages = root.arrayOrEmpty("messages").mapObjects(::parseWireMessage),
            hasMoreBefore = root.optBoolean("has_more_before", false),
        )
    }

    fun listEnvelopeRepairMessages(
        account: ProvisionedAccount,
        chatId: String,
        before: Long = 0,
        limit: Int = 200,
    ): MessagePage {
        val query = buildString {
            append("?limit=").append(limit.coerceIn(1, 200))
            if (before > 0) append("&before=").append(before)
        }
        val root = executeJson(
            account,
            "GET",
            "/api/v1/chats/${segment(chatId)}/envelope-repair$query",
        )
        return MessagePage(
            messages = root.arrayOrEmpty("messages").mapObjects(::parseWireMessage),
            hasMoreBefore = root.optBoolean("has_more_before", false),
        )
    }

    fun reserveCryptoSequence(
        account: ProvisionedAccount,
        chatId: String,
        requestId: String,
        messageId: String,
    ): Long {
        val root = executeJson(
            account,
            "POST",
            "/api/v3/chats/${segment(chatId)}/crypto-sequence",
            JSONObject().put("version", 2).put("request_id", requestId).put("message_id", messageId)
                .toString().toByteArray(),
        )
        if (root.optInt("version") != 2 || root.optString("message_id") != messageId) {
            throw IOException("Invalid crypto sequence response")
        }
        return root.getLong("crypto_sequence").also { require(it > 0) }
    }

    fun reserveCryptoSequenceLease(
        account: ProvisionedAccount,
        chatId: String,
        identifiers: List<Pair<String, String>>,
    ): List<SequenceLeaseItem> {
        require(identifiers.isNotEmpty() && identifiers.size <= 16)
        val items = JSONArray()
        identifiers.forEach { (requestId, messageId) ->
            items.put(JSONObject().put("request_id", requestId).put("message_id", messageId))
        }
        val root = executeJson(
            account,
            "POST",
            "/api/v3/chats/${segment(chatId)}/crypto-sequence/lease",
            JSONObject().put("version", 1).put("items", items).toString().toByteArray(),
        )
        if (root.optInt("version") != 1) throw IOException("Invalid crypto sequence lease response")
        val result = root.arrayOrEmpty("items").mapObjects { value ->
            SequenceLeaseItem(
                requestId = value.getString("request_id"),
                messageId = value.getString("message_id"),
                cryptoSequence = value.getLong("crypto_sequence").also { require(it > 0L) },
            )
        }
        if (result.size != identifiers.size || result.map { it.messageId }.toSet().size != result.size) {
            throw IOException("Invalid crypto sequence lease response")
        }
        return result
    }

    fun createMessage(
        account: ProvisionedAccount,
        chatId: String,
        prepared: PreparedMessage,
    ): CreatedMessageReceipt {
        val message = executeJson(
            account,
            "POST",
            "/api/v1/chats/${segment(chatId)}/messages",
            prepared.toJson().toString().toByteArray(),
        ).getJSONObject("message")
        return CreatedMessageReceipt(
            sequence = message.getLong("sequence"),
            id = message.getString("id"),
            createdAt = message.requireTimestamp("created_at"),
            envelopeDeviceIds = message.arrayOrEmpty("envelope_device_ids").mapStrings().toSet(),
        )
    }

    fun updateMessage(account: ProvisionedAccount, chatId: String, prepared: PreparedMessage) {
        execute(
            account,
            "PUT",
            "/api/v1/chats/${segment(chatId)}/messages/${segment(prepared.id)}",
            prepared.toJson().toString().toByteArray(),
        )
    }

    fun deleteMessage(
        account: ProvisionedAccount,
        chatId: String,
        messageId: String,
        scope: MessageDeleteScope,
    ) {
        execute(
            account,
            "DELETE",
            "/api/v1/chats/${segment(chatId)}/messages/${segment(messageId)}?scope=${scope.name.lowercase()}",
        )
    }

    fun addMessageEnvelopes(
        account: ProvisionedAccount,
        chatId: String,
        messageId: String,
        envelopes: List<MessageEnvelope>,
    ) {
        if (envelopes.isEmpty()) return
        val body = JSONObject()
            .put("version", 1)
            .put("envelopes", envelopes.toJson())
        execute(
            account,
            "PUT",
            "/api/v1/chats/${segment(chatId)}/messages/${segment(messageId)}/envelopes",
            body.toString().toByteArray(),
        )
    }

    fun markReceipts(
        account: ProvisionedAccount,
        chatId: String,
        deliveredMessageIds: List<String>,
        readMessageIds: List<String>,
    ) {
        if (deliveredMessageIds.isEmpty() && readMessageIds.isEmpty()) return
        val body = JSONObject()
            .put("version", 1)
            .put("delivered_message_ids", JSONArray(deliveredMessageIds))
            .put("read_message_ids", JSONArray(readMessageIds))
        execute(
            account,
            "POST",
            "/api/v1/chats/${segment(chatId)}/receipts",
            body.toString().toByteArray(),
        )
    }

    fun markReadCursor(
        account: ProvisionedAccount,
        chatId: String,
        maxReadSequence: Long,
    ) {
        if (maxReadSequence <= 0L) return
        val body = JSONObject()
            .put("version", 1)
            .put("max_read_sequence", maxReadSequence)
        execute(
            account,
            "PUT",
            "/api/v1/chats/${segment(chatId)}/read-cursor",
            body.toString().toByteArray(),
        )
    }

    fun setTyping(account: ProvisionedAccount, chatId: String, typing: Boolean) {
        val body = JSONObject().put("version", 1).put("typing", typing)
        execute(
            account,
            "PUT",
            "/api/v1/chats/${segment(chatId)}/typing",
            body.toString().toByteArray(),
        )
    }

    fun listTyping(account: ProvisionedAccount, chatId: String): List<TypingState> {
        val root = executeJson(account, "GET", "/api/v1/chats/${segment(chatId)}/typing")
        return root.arrayOrEmpty("typing").mapObjects { item ->
            TypingState(username = item.getString("username"))
        }
    }

    fun pinMessage(account: ProvisionedAccount, chatId: String, messageId: String) {
        execute(
            account,
            "PUT",
            "/api/v1/chats/${segment(chatId)}/pin/${segment(messageId)}",
        )
    }

    fun unpinMessage(account: ProvisionedAccount, chatId: String) {
        execute(account, "DELETE", "/api/v1/chats/${segment(chatId)}/pin")
    }

    fun heartbeat(account: ProvisionedAccount, showExact: Boolean) {
        val body = JSONObject().put("version", 1).put("show_exact", showExact)
        execute(account, "POST", "/api/v1/presence/heartbeat", body.toString().toByteArray())
    }

    fun listPresence(account: ProvisionedAccount): List<PresenceState> {
        val root = executeJson(account, "GET", "/api/v1/presence")
        return root.arrayOrEmpty("presence").mapObjects { value ->
            PresenceState(
                username = value.getString("username"),
                online = value.getBoolean("online"),
                lastSeenAt = value.optionalTimestamp("last_seen_at"),
                showExact = value.getBoolean("show_exact"),
                lastSeenCategory = value.optString("last_seen_category", "long_ago"),
            )
        }
    }

    fun waitForEvents(account: ProvisionedAccount, after: Long): Long =
        executeJson(account, "GET", "/api/v1/events?after=$after", readTimeoutMillis = 35_000)
            .getLong("sequence")

    fun uploadMedia(account: ProvisionedAccount, chatId: String, mediaId: String, ciphertext: ByteArray) {
        execute(
            account = account,
            method = "PUT",
            path = "/api/v1/chats/${segment(chatId)}/media/${segment(mediaId)}",
            body = ciphertext,
            contentType = "application/octet-stream",
            readTimeoutMillis = MEDIA_TRANSFER_TIMEOUT,
        )
    }

    fun downloadMedia(account: ProvisionedAccount, chatId: String, mediaId: String): ByteArray =
        execute(
            account = account,
            method = "GET",
            path = "/api/v1/chats/${segment(chatId)}/media/${segment(mediaId)}",
            readTimeoutMillis = MEDIA_TRANSFER_TIMEOUT,
            maximumResponseBytes = null,
        )

    fun deleteMedia(account: ProvisionedAccount, chatId: String, mediaId: String) {
        execute(
            account = account,
            method = "DELETE",
            path = "/api/v1/chats/${segment(chatId)}/media/${segment(mediaId)}",
            readTimeoutMillis = 60_000,
        )
    }

    private fun parseWireMessage(value: JSONObject): WireMessage {
        val envelope = value.optJSONObject("envelope")?.let { item ->
            MessageEnvelope(
                deviceId = item.getString("device_id"),
                algorithm = item.getString("algorithm"),
                ciphertextBase64 = item.getString("ciphertext"),
            )
        }
        val ratchetEnvelope = value.optJSONObject("ratchet_envelope")?.let { item ->
            RatchetMessageEnvelope(
                recipientDeviceId = item.getString("recipient_device_id"),
                senderCurve25519Key = item.getString("sender_curve25519_key"),
                sessionId = item.getString("session_id"),
                messageType = item.getInt("message_type"),
                ciphertextBase64Url = item.getString("ciphertext"),
                ciphertextSha256Hex = item.getString("ciphertext_sha256"),
            )
        }
        return WireMessage(
            sequence = value.getLong("sequence"),
            id = value.getString("id"),
            chatId = value.getString("chat_id"),
            senderUsername = value.getString("sender_username"),
            senderDeviceId = value.getString("sender_device_id"),
            ciphertextBase64 = value.getString("ciphertext"),
            nonceBase64 = value.getString("nonce"),
            aad = value.getString("aad"),
            createdAt = value.requireTimestamp("created_at"),
            editedAt = value.optionalTimestamp("edited_at"),
            envelope = envelope,
            envelopeDeviceIds = value.arrayOrEmpty("envelope_device_ids").mapStrings().toSet(),
            recipientCount = value.optInt("recipient_count", 0),
            deliveredCount = value.optInt("delivered_count", 0),
            readCount = value.optInt("read_count", 0),
            cryptoVersion = value.optInt("crypto_version", 1),
            roomKeyVersion = value.optLong("room_key_version", 1),
            aadVersion = value.optInt("aad_version", 1),
            cryptoSequence = value.optLong("crypto_sequence", 0),
            encryptionAlgorithm = value.optString("encryption_algorithm", "fedmes-aes256gcm-rsa-oaep-v1"),
            messageType = value.optString("message_type", "legacy"),
            ratchetEnvelope = ratchetEnvelope,
        )
    }

    private fun PreparedMessage.toJson(): JSONObject = JSONObject()
        .put("version", protocolVersion)
        .put("id", id)
        .put("ciphertext", ciphertextBase64)
        .put("nonce", nonceBase64)
        .put("aad", aad)
        .apply {
            if (protocolVersion == 1) {
                put("envelopes", envelopes.toJson())
            } else {
                put("crypto_version", cryptoVersion)
                put("room_key_version", roomKeyVersion)
                put("aad_version", aadVersion)
                put("crypto_sequence", cryptoSequence)
                put("encryption_algorithm", encryptionAlgorithm)
                put("message_type", messageType)
                put("sequence_request_id", sequenceRequestId)
                put("envelopes", JSONArray())
                put("ratchet_envelopes", ratchetEnvelopes.toRatchetJson())
            }
        }

    private fun List<RatchetMessageEnvelope>.toRatchetJson(): JSONArray = JSONArray().apply {
        forEach { envelope ->
            put(JSONObject()
                .put("recipient_device_id", envelope.recipientDeviceId)
                .put("sender_curve25519_key", envelope.senderCurve25519Key)
                .put("session_id", envelope.sessionId)
                .put("message_type", envelope.messageType)
                .put("ciphertext", envelope.ciphertextBase64Url)
                .put("ciphertext_sha256", envelope.ciphertextSha256Hex))
        }
    }

    private fun List<MessageEnvelope>.toJson(): JSONArray = JSONArray().apply {
        forEach { envelope ->
            put(
                JSONObject()
                    .put("device_id", envelope.deviceId)
                    .put("algorithm", envelope.algorithm)
                    .put("ciphertext", envelope.ciphertextBase64),
            )
        }
    }

    private fun executeJson(
        account: ProvisionedAccount,
        method: String,
        path: String,
        body: ByteArray? = null,
        readTimeoutMillis: Int = DEFAULT_READ_TIMEOUT,
    ): JSONObject = JSONObject(
        execute(account, method, path, body, readTimeoutMillis = readTimeoutMillis)
            .toString(Charsets.UTF_8),
    )

    private fun execute(
        account: ProvisionedAccount,
        method: String,
        path: String,
        body: ByteArray? = null,
        contentType: String = "application/json; charset=utf-8",
        readTimeoutMillis: Int = DEFAULT_READ_TIMEOUT,
        maximumResponseBytes: Long? = MAX_RESPONSE_BYTES.toLong(),
    ): ByteArray {
        val endpoint = account.serverUrl.trimEnd('/') + path
        val connection = URL(endpoint).openConnection() as HttpURLConnection
        var responseConsumed = false
        try {
            connection.requestMethod = method
            connection.connectTimeout = CONNECT_TIMEOUT
            connection.readTimeout = readTimeoutMillis
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.setRequestProperty("Accept", "application/json")
            connection.setRequestProperty("Authorization", "Bearer ${account.sessionToken}")
            if (body != null) {
                connection.doOutput = true
                connection.setFixedLengthStreamingMode(body.size)
                connection.setRequestProperty("Content-Type", contentType)
                connection.outputStream.use { stream -> stream.write(body) }
            }
            val status = connection.responseCode
            val response = readResponse(connection, status, maximumResponseBytes)
            // Fully consuming and closing the response stream lets Android's HTTP stack keep
            // the underlying TLS connection in its pool for the next FedMes request.
            responseConsumed = true
            if (status !in 200..299) {
                val code = runCatching {
                    JSONObject(response.toString(Charsets.UTF_8))
                        .optJSONObject("error")
                        ?.optString("code")
                }.getOrNull().orEmpty()
                throw MessagingApiException(status, code.ifBlank { "http_$status" })
            }
            return response
        } catch (error: SocketTimeoutException) {
            throw MessagingNetworkException(
                "Сервер FedMes не ответил вовремя. Проверьте, что fedmes-server.exe запущен на ${account.serverUrl}.",
                error,
            )
        } catch (error: UnknownHostException) {
            throw MessagingNetworkException("Адрес сервера FedMes не найден: ${account.serverUrl}", error)
        } catch (error: NoRouteToHostException) {
            throw MessagingNetworkException("Нет маршрута до сервера FedMes: ${account.serverUrl}", error)
        } catch (error: ConnectException) {
            throw MessagingNetworkException(
                "Не удалось подключиться к FedMes. Проверьте сервер, Wi-Fi и порт 8008.",
                error,
            )
        } finally {
            // disconnect() on a successful request tells HttpURLConnection that this socket is
            // unlikely to be reused. Only tear it down when the response was not consumed.
            if (!responseConsumed) connection.disconnect()
        }
    }

    private fun readResponse(
        connection: HttpURLConnection,
        status: Int,
        maximumResponseBytes: Long?,
    ): ByteArray {
        val source = if (status in 200..299) connection.inputStream else connection.errorStream
        if (source == null) return ByteArray(0)
        return source.use { input ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(16 * 1024)
            var total = 0L
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                total += count.toLong()
                if (maximumResponseBytes != null && total > maximumResponseBytes) {
                    throw IOException("FedMes response is too large")
                }
                output.write(buffer, 0, count)
            }
            buffer.fill(0)
            output.toByteArray()
        }
    }


    private fun JSONObject.arrayOrEmpty(name: String): JSONArray =
        when (val value = opt(name)) {
            is JSONArray -> value
            null, JSONObject.NULL -> JSONArray()
            else -> throw IOException("FedMes field '$name' must be a JSON array")
        }

    private fun JSONObject.requireTimestamp(name: String): Long =
        ProtocolTime.parseRfc3339(getString(name)) ?: error("Invalid timestamp: $name")

    private fun JSONObject.optionalTimestamp(name: String): Long? =
        optString(name).takeIf(String::isNotBlank)?.let(ProtocolTime::parseRfc3339)

    private fun JSONArray.mapStrings(): List<String> =
        List(length()) { index -> getString(index) }

    private fun <T> JSONArray.mapObjects(transform: (JSONObject) -> T): List<T> =
        List(length()) { index -> transform(getJSONObject(index)) }

    private fun segment(value: String): String = Uri.encode(value)

    private companion object {
        const val CONNECT_TIMEOUT = 15_000
        const val DEFAULT_READ_TIMEOUT = 30_000
        const val MEDIA_TRANSFER_TIMEOUT = 30 * 60_000
        const val MAX_RESPONSE_BYTES = 64 * 1024 * 1024
    }
}

class MessagingApiException(
    val statusCode: Int,
    val code: String,
) : IOException("FedMes API rejected request: $code")

class MessagingNetworkException(
    message: String,
    cause: IOException,
) : IOException(message, cause)
