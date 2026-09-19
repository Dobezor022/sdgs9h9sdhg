package com.fedmes.app.messaging

import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.SecureRandom
import java.security.spec.X509EncodedKeySpec
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class MessageCrypto(
    private val messageKeyStore: AndroidMessageKeyStore,
    private val random: SecureRandom = SecureRandom(),
) {
    fun prepare(
        chatId: String,
        senderUsername: String,
        senderDeviceId: String,
        content: MessageContent,
        devices: List<ChatDevice>,
        messageId: String = UUID.randomUUID().toString(),
    ): PreparedMessage {
        require(devices.isNotEmpty()) { "No trusted devices are registered in this chat" }
        val messageKey = randomBytes(AES_KEY_BYTES)
        val nonce = randomBytes(GCM_NONCE_BYTES)
        val aad = canonicalAad(chatId, senderUsername, senderDeviceId, messageId)
        val plaintext = encodeContent(content)
        val padded = pad(plaintext)
        plaintext.fill(0)
        val ciphertext = try {
            aesGcm(Cipher.ENCRYPT_MODE, messageKey, nonce, aad.toByteArray(Charsets.UTF_8), padded)
        } finally {
            padded.fill(0)
        }
        val envelopes = try {
            wrapMessageKey(messageKey, devices)
        } finally {
            messageKey.fill(0)
        }
        return try {
            PreparedMessage(
                id = messageId,
                ciphertextBase64 = Base64.encodeToString(ciphertext, Base64.NO_WRAP),
                nonceBase64 = Base64.encodeToString(nonce, Base64.NO_WRAP),
                aad = aad,
                envelopes = envelopes,
            )
        } finally {
            ciphertext.fill(0)
            nonce.fill(0)
        }
    }

    fun decrypt(message: WireMessage): DecryptedMessage {
        require(
            message.aad == canonicalAad(
                message.chatId,
                message.senderUsername,
                message.senderDeviceId,
                message.id,
            ),
        ) { "Message AAD does not match wire metadata" }
        val envelope = requireNotNull(message.envelope) { "Message key envelope is not available" }
        require(envelope.algorithm == AndroidMessageKeyStore.ALGORITHM) {
            "Unsupported message envelope algorithm"
        }
        val wrapped = Base64.decode(envelope.ciphertextBase64, Base64.NO_WRAP)
        val messageKey = try {
            messageKeyStore.unwrapMessageKey(wrapped)
        } finally {
            wrapped.fill(0)
        }
        val nonce = Base64.decode(message.nonceBase64, Base64.NO_WRAP)
        val ciphertext = Base64.decode(message.ciphertextBase64, Base64.NO_WRAP)
        val padded = try {
            aesGcm(
                Cipher.DECRYPT_MODE,
                messageKey,
                nonce,
                message.aad.toByteArray(Charsets.UTF_8),
                ciphertext,
            )
        } finally {
            messageKey.fill(0)
            nonce.fill(0)
            ciphertext.fill(0)
        }
        val plaintext = try {
            unpad(padded)
        } finally {
            padded.fill(0)
        }
        return try {
            message.toDecrypted(decodeContent(plaintext), true)
        } finally {
            plaintext.fill(0)
        }
    }

    fun createAdditionalEnvelopes(
        message: WireMessage,
        devices: List<ChatDevice>,
    ): List<MessageEnvelope> {
        if (devices.isEmpty()) return emptyList()
        val currentEnvelope = requireNotNull(message.envelope) {
            "Current device cannot access this message key"
        }
        val wrapped = Base64.decode(currentEnvelope.ciphertextBase64, Base64.NO_WRAP)
        val messageKey = try {
            messageKeyStore.unwrapMessageKey(wrapped)
        } finally {
            wrapped.fill(0)
        }
        return try {
            wrapMessageKey(messageKey, devices)
        } finally {
            messageKey.fill(0)
        }
    }

    fun encryptMedia(
        chatId: String,
        messageId: String,
        mediaId: String,
        plaintext: ByteArray,
    ): EncryptedMedia {
        val key = randomBytes(AES_KEY_BYTES)
        val nonce = randomBytes(GCM_NONCE_BYTES)
        val aad = canonicalMediaAad(chatId, messageId, mediaId).toByteArray(Charsets.UTF_8)
        val ciphertext = aesGcm(Cipher.ENCRYPT_MODE, key, nonce, aad, plaintext)
        return EncryptedMedia(key, nonce, ciphertext)
    }

    fun decryptMedia(
        chatId: String,
        messageId: String,
        descriptor: MediaDescriptor,
        ciphertext: ByteArray,
    ): ByteArray {
        val key = Base64.decode(descriptor.keyBase64, Base64.NO_WRAP)
        val nonce = Base64.decode(descriptor.nonceBase64, Base64.NO_WRAP)
        return try {
            aesGcm(
                Cipher.DECRYPT_MODE,
                key,
                nonce,
                canonicalMediaAad(chatId, messageId, descriptor.id).toByteArray(Charsets.UTF_8),
                ciphertext,
            )
        } finally {
            key.fill(0)
            nonce.fill(0)
        }
    }

    private fun wrapMessageKey(
        messageKey: ByteArray,
        devices: List<ChatDevice>,
    ): List<MessageEnvelope> = devices.map { device ->
        val publicKeyValue = requireNotNull(device.encryptionPublicKeySpkiBase64) {
            "Устройство ${device.username} не зарегистрировало ключ шифрования"
        }
        require(device.encryptionAlgorithm == AndroidMessageKeyStore.ALGORITHM)
        val spki = Base64.decode(publicKeyValue, Base64.NO_WRAP)
        val publicKey = try {
            KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(spki))
        } finally {
            spki.fill(0)
        }
        val wrapped = Cipher.getInstance(RSA_TRANSFORMATION).run {
            init(Cipher.ENCRYPT_MODE, publicKey, AndroidMessageKeyStore.oaepParameters())
            doFinal(messageKey)
        }
        try {
            MessageEnvelope(
                deviceId = device.id,
                algorithm = AndroidMessageKeyStore.ALGORITHM,
                ciphertextBase64 = Base64.encodeToString(wrapped, Base64.NO_WRAP),
            )
        } finally {
            wrapped.fill(0)
        }
    }

    internal fun encodeContent(content: MessageContent): ByteArray {
        val version = when {
            content.call != null || content.kind == MessageKind.CALL -> 3
            content.textEntities.isNotEmpty() || content.requiresProtocolV2() -> 2
            else -> 1
        }
        val root = JSONObject()
            .put("version", version)
            .put("kind", content.kind.name.lowercase())
            .put("text", content.text)
        content.replyToId?.let { root.put("reply_to_id", it) }
        content.media?.let { root.put("media", mediaToJson(it)) }
        if (content.mediaItems.isNotEmpty()) {
            root.put("media_items", JSONArray().apply { content.mediaItems.forEach { put(mediaToJson(it)) } })
        }
        if (content.spoiler) root.put("spoiler", true)
        if (content.revealedFor.isNotEmpty()) root.put("revealed_for", JSONArray(content.revealedFor.toList()))
        if (content.waveform.isNotEmpty()) root.put("waveform", JSONArray(content.waveform))
        content.durationMillis?.let { root.put("duration_ms", it) }
        content.roundVideoShape?.let { root.put("round_shape", it.name.lowercase()) }
        content.targetMessageId?.let { root.put("target_message_id", it) }
        content.targetUsername?.let { root.put("target_username", it) }
        content.forwardedFromUsername?.let { root.put("forwarded_from", it) }
        content.call?.let { call ->
            root.put(
                "call",
                JSONObject()
                    .put("call_id", call.callId)
                    .put("mode", call.mode.name.lowercase())
                    .put("event", call.event.name.lowercase())
                    .put("capability", call.capabilityBase64Url)
                    .put("shared_secret", call.sharedSecretBase64Url)
                    .put("route", call.routeBase64Url)
                    .put("generation", call.generation)
                    .put("created_at_ms", call.createdAtEpochMillis)
                    .put("expires_at_ms", call.expiresAtEpochMillis)
                    .put("initiator", call.initiatorUsername),
            )
        }
        if (content.textEntities.isNotEmpty()) {
            root.put(
                "entities",
                JSONArray().apply {
                    sanitizeTextEntities(content.text, content.textEntities).forEach { entity ->
                        put(
                            JSONObject()
                                .put("type", entity.type.name.lowercase())
                                .put("offset", entity.offset)
                                .put("length", entity.length),
                        )
                    }
                },
            )
        }
        return root.toString().toByteArray(Charsets.UTF_8)
    }

    /**
     * Protocol v1 is retained for ordinary text and single legacy attachments so
     * devices running FedMes 0.4.x can still decrypt those messages. Version 2
     * is used only when the encrypted body contains semantics that older clients
     * cannot represent safely.
     */
    private fun MessageContent.requiresProtocolV2(): Boolean =
        kind == MessageKind.MEDIA_GROUP ||
            kind == MessageKind.ROUND_VIDEO ||
            kind == MessageKind.SPOILER_REQUEST ||
            mediaItems.size > 1 ||
            spoiler ||
            revealedFor.isNotEmpty() ||
            roundVideoShape != null ||
            targetMessageId != null ||
            targetUsername != null ||
            forwardedFromUsername != null ||
            call != null

    internal fun decodeContent(bytes: ByteArray): MessageContent {
        val root = JSONObject(bytes.toString(Charsets.UTF_8))
        val version = root.getInt("version")
        require(version in 1..3)
        val kind = runCatching { MessageKind.valueOf(root.getString("kind").uppercase()) }
            .getOrDefault(MessageKind.SYSTEM)
        val media = root.optJSONObject("media")?.let(::mediaFromJson)
        val mediaItems = root.optJSONArray("media_items")?.let { array ->
            List(array.length()) { index -> mediaFromJson(array.getJSONObject(index)) }
        }.orEmpty().ifEmpty { media?.let(::listOf).orEmpty() }
        val revealedFor = root.optJSONArray("revealed_for")?.let { array ->
            buildSet { for (index in 0 until array.length()) add(array.getString(index)) }
        }.orEmpty()
        val waveform = root.optJSONArray("waveform")?.let { array ->
            List(array.length()) { index -> array.optInt(index).coerceIn(0, 100) }
        }.orEmpty()
        val text = root.optString("text")
        val textEntities = root.optJSONArray("entities")?.let { array ->
            List(array.length()) { index ->
                val item = array.getJSONObject(index)
                val type = runCatching {
                    TextEntityType.valueOf(item.getString("type").uppercase())
                }.getOrNull()
                type?.let {
                    TextEntity(
                        type = it,
                        offset = item.optInt("offset", -1),
                        length = item.optInt("length", 0),
                    )
                }
            }.filterNotNull()
        }.orEmpty()
        val call = root.optJSONObject("call")?.let { value ->
            runCatching {
                CallDescriptor(
                    callId = value.getString("call_id"),
                    mode = CallMode.valueOf(value.getString("mode").uppercase()),
                    event = CallEvent.valueOf(value.getString("event").uppercase()),
                    capabilityBase64Url = value.getString("capability"),
                    sharedSecretBase64Url = value.getString("shared_secret"),
                    routeBase64Url = value.getString("route"),
                    generation = value.getLong("generation"),
                    createdAtEpochMillis = value.getLong("created_at_ms"),
                    expiresAtEpochMillis = value.getLong("expires_at_ms"),
                    initiatorUsername = value.getString("initiator"),
                )
            }.getOrNull()
        }
        return MessageContent(
            kind = kind,
            text = text,
            replyToId = root.optString("reply_to_id").takeIf(String::isNotBlank),
            media = media ?: mediaItems.firstOrNull(),
            mediaItems = mediaItems,
            spoiler = root.optBoolean("spoiler", false),
            revealedFor = revealedFor,
            waveform = waveform,
            durationMillis = if (root.has("duration_ms")) root.optLong("duration_ms") else media?.durationMillis,
            roundVideoShape = root.optString("round_shape").takeIf(String::isNotBlank)?.let { raw ->
                runCatching { RoundVideoShape.valueOf(raw.uppercase()) }.getOrNull()
            },
            targetMessageId = root.optString("target_message_id").takeIf(String::isNotBlank),
            targetUsername = root.optString("target_username").takeIf(String::isNotBlank),
            forwardedFromUsername = root.optString("forwarded_from").takeIf(String::isNotBlank),
            textEntities = sanitizeTextEntities(text, textEntities),
            call = call,
        )
    }

    private fun mediaToJson(media: MediaDescriptor): JSONObject = JSONObject()
        .put("id", media.id)
        .put("name", media.name)
        .put("mime_type", media.mimeType)
        .put("original_size", media.originalSize)
        .put("encrypted_size", media.encryptedSize)
        .put("key", media.keyBase64)
        .put("nonce", media.nonceBase64)
        .apply {
            media.width?.let { put("width", it) }
            media.height?.let { put("height", it) }
            media.durationMillis?.let { put("duration_ms", it) }
            media.preview?.let { preview ->
                put(
                    "preview",
                    JSONObject()
                        .put("id", preview.id)
                        .put("original_size", preview.originalSize)
                        .put("encrypted_size", preview.encryptedSize)
                        .put("key", preview.keyBase64)
                        .put("nonce", preview.nonceBase64),
                )
            }
        }

    private fun mediaFromJson(value: JSONObject): MediaDescriptor {
        val preview = value.optJSONObject("preview")?.let { item ->
            MediaPreviewDescriptor(
                id = item.getString("id"),
                originalSize = item.getLong("original_size"),
                encryptedSize = item.getLong("encrypted_size"),
                keyBase64 = item.getString("key"),
                nonceBase64 = item.getString("nonce"),
            )
        }
        return MediaDescriptor(
            id = value.getString("id"),
            name = value.getString("name"),
            mimeType = value.getString("mime_type"),
            originalSize = value.getLong("original_size"),
            encryptedSize = value.getLong("encrypted_size"),
            keyBase64 = value.getString("key"),
            nonceBase64 = value.getString("nonce"),
            width = if (value.has("width")) value.optInt("width") else null,
            height = if (value.has("height")) value.optInt("height") else null,
            durationMillis = if (value.has("duration_ms")) value.optLong("duration_ms") else null,
            preview = preview,
        )
    }

    internal fun pad(plaintext: ByteArray): ByteArray {
        val rawSize = Int.SIZE_BYTES + plaintext.size
        val paddedSize = ((rawSize + PADDING_BLOCK_BYTES - 1) / PADDING_BLOCK_BYTES) * PADDING_BLOCK_BYTES
        return ByteBuffer.allocate(paddedSize).putInt(plaintext.size).put(plaintext).array()
    }

    internal fun unpad(padded: ByteArray): ByteArray {
        require(padded.size >= Int.SIZE_BYTES && padded.size % PADDING_BLOCK_BYTES == 0)
        val buffer = ByteBuffer.wrap(padded)
        val size = buffer.int
        require(size >= 0 && size <= padded.size - Int.SIZE_BYTES)
        val plaintext = ByteArray(size).also(buffer::get)
        while (buffer.hasRemaining()) {
            require(buffer.get() == 0.toByte()) { "Invalid message padding" }
        }
        return plaintext
    }

    internal fun aesGcm(
        mode: Int,
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        input: ByteArray,
    ): ByteArray = Cipher.getInstance(AES_TRANSFORMATION).run {
        init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, nonce))
        updateAAD(aad)
        doFinal(input)
    }

    private fun randomBytes(size: Int): ByteArray = ByteArray(size).also(random::nextBytes)

    private fun canonicalAad(chatId: String, username: String, deviceId: String, messageId: String): String =
        listOf("fedmes-message-v1", chatId, username, deviceId, messageId).joinToString("\n")

    private fun canonicalMediaAad(chatId: String, messageId: String, mediaId: String): String =
        listOf("fedmes-media-v1", chatId, messageId, mediaId).joinToString("\n")

    internal fun toDecryptedMessage(message: WireMessage, content: MessageContent, decryptable: Boolean): DecryptedMessage =
        message.toDecrypted(content, decryptable)

    internal fun WireMessage.toDecrypted(content: MessageContent, decryptable: Boolean): DecryptedMessage =
        DecryptedMessage(
            sequence = sequence,
            id = id,
            chatId = chatId,
            senderUsername = senderUsername,
            senderDeviceId = senderDeviceId,
            content = content,
            createdAt = createdAt,
            editedAt = editedAt,
            decryptable = decryptable,
            envelopeDeviceIds = envelopeDeviceIds,
            deliveryState = when {
                readCount > 0 -> MessageDeliveryState.READ
                else -> MessageDeliveryState.SENT
            },
        )

    data class EncryptedMedia(
        val key: ByteArray,
        val nonce: ByteArray,
        val ciphertext: ByteArray,
    )

    private companion object {
        const val AES_KEY_BYTES = 32
        const val GCM_NONCE_BYTES = 12
        const val GCM_TAG_BITS = 128
        const val PADDING_BLOCK_BYTES = 256
        const val AES_TRANSFORMATION = "AES/GCM/NoPadding"
        const val RSA_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
    }
}
