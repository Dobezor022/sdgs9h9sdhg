package com.fedmes.app.messaging

import android.os.SystemClock
import android.util.Base64
import com.fedmes.app.provisioning.ProvisionedAccount
import com.fedmes.app.provisioning.ProvisioningCoordinator
import com.fedmes.app.security.SessionStore
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

class MessagingRepository(
    private val sessionStore: SessionStore,
    private val provisioningCoordinator: ProvisioningCoordinator,
    private val api: MessagingHttpApi,
    private val keyStore: AndroidMessageKeyStore,
    private val crypto: MessageCrypto,
    private val ratchetCrypto: RatchetMessageCrypto,
) {
    @Volatile
    private var registeredEncryptionIdentity: String? = null
    private val deviceCache = ConcurrentHashMap<String, CachedDevices>()
    private val chatCache = ConcurrentHashMap<String, ChatSummary>()
    private val outboundLocks = ConcurrentHashMap<String, ReentrantLock>()
    private val sequencePools = ConcurrentHashMap<String, ConcurrentLinkedQueue<ReservedSequence>>()
    private val allocatedSequences = ConcurrentHashMap<String, ReservedSequence>()
    private val decryptedMessageCache = ConcurrentHashMap<String, CachedDecryptedMessage>()

    fun initialize(showExactPresence: Boolean): ProvisionedAccount {
        val account = activeAccount()
        ensureCurrentEncryptionKeyRegistered(account, force = true)
        ratchetCrypto.initialize(account)
        deviceCache.clear()
        sequencePools.clear()
        allocatedSequences.clear()
        api.heartbeat(account, showExact = false)
        return account
    }

    fun listChats(): List<ChatSummary> = api.listChats(activeAccount()).also { chats ->
        chats.forEach { chatCache[it.id] = it }
    }
    fun prewarmChat(chatId: String) {
        val account = activeAccount()
        val devices = allReadyDevices(account, chatId, forceRefresh = false)
        if (devices.isNotEmpty() && devices.all(::isRatchetReady)) {
            topUpSequencePool(account, chatId)
        }
    }

    fun allocateOutgoingMessageId(chatId: String): String {
        val now = SystemClock.elapsedRealtime()
        val queue = sequencePools[chatId]
        while (queue != null) {
            val reserved = queue.poll() ?: break
            if (reserved.expiresAtElapsedRealtime > now) {
                allocatedSequences[reserved.messageId] = reserved
                return reserved.messageId
            }
        }
        return UUID.randomUUID().toString()
    }

    fun listPresence(): List<PresenceState> = api.listPresence(activeAccount())
    fun listTyping(chatId: String): List<TypingState> = api.listTyping(activeAccount(), chatId)
    fun setTyping(chatId: String, typing: Boolean) = api.setTyping(activeAccount(), chatId, typing)

    fun encryptionReadyDeviceFingerprint(chatId: String): String {
        val account = activeAccount()
        return encryptionReadyDevices(account, chatId)
            .asSequence()
            .map(ChatDevice::id)
            .sorted()
            .joinToString("|")
    }

    fun invalidateEncryptionDeviceCache() {
        deviceCache.clear()
        sequencePools.clear()
        allocatedSequences.clear()
    }

    fun repairEnvelopeHistory(chatId: String) {
        val account = activeAccount()
        val readyDevices = encryptionReadyDevices(account, chatId, forceRefresh = true)
        if (readyDevices.none { it.id == account.deviceId }) return
        var before = 0L
        do {
            val page = api.listEnvelopeRepairMessages(account, chatId, before, ENVELOPE_REPAIR_PAGE_SIZE)
            repairPendingEnvelopes(account, chatId, page.messages, readyDevices)
            before = page.messages.firstOrNull()?.sequence ?: 0L
        } while (page.hasMoreBefore && before > 0L)
    }

    fun repairAllChatsForCurrentUserDevices() {
        listChats().forEach { chat -> repairEnvelopeHistory(chat.id) }
    }

    fun heartbeat(showExact: Boolean = true) = api.heartbeat(activeAccount(), showExact)

    fun loadLatestMessages(chatId: String, limit: Int = PAGE_SIZE, markRead: Boolean = false): DecryptedMessagePage =
        loadPage(chatId, after = 0, before = 0, limit = limit, markRead = markRead)

    fun loadOlderMessages(chatId: String, before: Long, limit: Int = PAGE_SIZE): DecryptedMessagePage =
        loadPage(chatId, after = 0, before = before, limit = limit, markRead = false)

    fun loadMessagesAfter(chatId: String, after: Long, limit: Int = 200, markRead: Boolean = false): DecryptedMessagePage =
        loadPage(chatId, after = after, before = 0, limit = limit, markRead = markRead)

    fun sendText(chatId: String, text: String, replyToId: String?, spoiler: Boolean = false): String =
        sendTextMessage(chatId, text, replyToId, spoiler).id

    fun sendTextMessage(
        chatId: String,
        text: String,
        replyToId: String?,
        spoiler: Boolean = false,
        textEntities: List<TextEntity> = emptyList(),
        messageId: String = UUID.randomUUID().toString(),
    ): DecryptedMessage {
        val normalized = normalizeFormattedText(text, textEntities)
        require(normalized.text.isNotEmpty()) { "Сообщение пустое" }
        require(normalized.text.length <= MAX_TEXT_LENGTH) { "Сообщение слишком длинное" }
        return sendContentMessage(
            chatId,
            MessageContent(
                kind = MessageKind.TEXT,
                text = normalized.text,
                replyToId = replyToId,
                media = null,
                spoiler = spoiler,
                textEntities = normalized.entities,
            ),
            messageId,
        )
    }

    fun sendCallSignal(
        chatId: String,
        call: CallDescriptor,
        messageId: String = allocateOutgoingMessageId(chatId),
    ): DecryptedMessage = sendContentMessage(
        chatId,
        MessageContent(
            kind = MessageKind.CALL,
            text = when (call.event) {
                CallEvent.INVITE -> if (call.mode == CallMode.AUDIO) "Аудиозвонок" else "Видеозвонок"
                CallEvent.ENDED -> "Звонок завершён"
                CallEvent.DECLINED -> "Звонок отклонён"
                CallEvent.NO_ANSWER -> "Нет ответа"
                CallEvent.FAILED -> "Звонок не состоялся"
            },
            replyToId = null,
            media = null,
            call = call,
        ),
        messageId,
    )

    fun editText(
        chatId: String,
        messageId: String,
        text: String,
        replyToId: String?,
        spoiler: Boolean = false,
        textEntities: List<TextEntity> = emptyList(),
    ) {
        val normalized = normalizeFormattedText(text, textEntities)
        require(normalized.text.isNotEmpty()) { "Сообщение пустое" }
        require(normalized.text.length <= MAX_TEXT_LENGTH) { "Сообщение слишком длинное" }
        updateContent(
            chatId,
            messageId,
            MessageContent(
                kind = MessageKind.TEXT,
                text = normalized.text,
                replyToId = replyToId,
                media = null,
                spoiler = spoiler,
                textEntities = normalized.entities,
            ),
        )
    }

    fun sendAttachment(
        chatId: String,
        fileName: String,
        mimeType: String,
        plaintext: ByteArray,
        caption: String,
        replyToId: String?,
        captionEntities: List<TextEntity> = emptyList(),
    ): String = sendAttachmentMessage(chatId, fileName, mimeType, plaintext, caption, replyToId, captionEntities).id

    fun sendAttachmentMessage(
        chatId: String,
        fileName: String,
        mimeType: String,
        plaintext: ByteArray,
        caption: String,
        replyToId: String?,
        captionEntities: List<TextEntity> = emptyList(),
    ): DecryptedMessage = sendPreparedMediaMessage(
        chatId = chatId,
        attachments = listOf(
            PreparedLocalAttachment(
                name = fileName,
                mimeType = mimeType,
                bytes = plaintext,
                caption = caption,
                waveform = if (mimeType.startsWith("audio/")) approximateWaveform(plaintext) else emptyList(),
                sendAsFile = !mimeType.startsWith("image/") && !mimeType.startsWith("video/") && !mimeType.startsWith("audio/"),
            ),
        ),
        caption = caption,
        replyToId = replyToId,
        captionEntities = captionEntities,
    )

    fun sendPreparedMedia(
        chatId: String,
        attachments: List<PreparedLocalAttachment>,
        caption: String,
        replyToId: String?,
        captionEntities: List<TextEntity> = emptyList(),
        forcedKind: MessageKind? = null,
        roundVideoShape: RoundVideoShape? = null,
        forwardedFromUsername: String? = null,
    ): String = sendPreparedMediaMessage(
        chatId, attachments, caption, replyToId, captionEntities, forcedKind, roundVideoShape, forwardedFromUsername,
    ).id

    fun sendPreparedMediaMessage(
        chatId: String,
        attachments: List<PreparedLocalAttachment>,
        caption: String,
        replyToId: String?,
        captionEntities: List<TextEntity> = emptyList(),
        forcedKind: MessageKind? = null,
        roundVideoShape: RoundVideoShape? = null,
        forwardedFromUsername: String? = null,
    ): DecryptedMessage {
        require(attachments.isNotEmpty()) { "Нет вложений" }
        require(attachments.size <= MAX_MEDIA_GROUP_ITEMS) { "В одном сообщении может быть не больше 10 медиа" }
        attachments.forEach { item ->
            require(item.bytes.isNotEmpty()) { "Файл пустой" }
        }
        val account = activeAccount()
        val messageId = UUID.randomUUID().toString()
        val uploadedIDs = mutableListOf<String>()
        try {
            val descriptors = attachments.map { item ->
                uploadPreparedAttachment(account, chatId, messageId, item, uploadedIDs)
            }
            val kind = forcedKind ?: when {
                attachments.all(PreparedLocalAttachment::sendAsFile) -> if (descriptors.size == 1) MessageKind.FILE else MessageKind.MEDIA_GROUP
                descriptors.size > 1 -> MessageKind.MEDIA_GROUP
                else -> kindForMime(descriptors.single().mimeType)
            }
            val first = attachments.first()
            val normalizedCaption = normalizeFormattedText(caption, captionEntities)
            val content = MessageContent(
                kind = kind,
                text = normalizedCaption.text,
                replyToId = replyToId,
                media = descriptors.firstOrNull(),
                mediaItems = descriptors,
                spoiler = attachments.any(PreparedLocalAttachment::spoiler),
                waveform = first.waveform,
                durationMillis = first.durationMillis,
                roundVideoShape = roundVideoShape,
                forwardedFromUsername = forwardedFromUsername,
                textEntities = normalizedCaption.entities,
            )
            return sendContentMessage(chatId, content, messageId)
        } catch (error: Exception) {
            uploadedIDs.forEach { id -> runCatching { api.deleteMedia(account, chatId, id) } }
            throw error
        }
    }

    fun sendVoice(chatId: String, recorded: RecordedMedia, replyToId: String?): String =
        sendVoiceMessage(chatId, recorded, replyToId).id

    fun sendVoiceMessage(chatId: String, recorded: RecordedMedia, replyToId: String?): DecryptedMessage =
        try {
            sendPreparedMediaMessage(
                chatId = chatId,
                attachments = listOf(
                    PreparedLocalAttachment(
                        name = recorded.name,
                        mimeType = recorded.mimeType,
                        bytes = recorded.bytes,
                        caption = "",
                        durationMillis = recorded.durationMillis,
                        waveform = recorded.waveform,
                    ),
                ),
                caption = "",
                replyToId = replyToId,
                forcedKind = MessageKind.VOICE,
            )
        } finally {
            recorded.bytes.fill(0)
            recorded.previewBytes?.fill(0)
        }

    fun sendRoundVideo(chatId: String, recorded: RecordedMedia, replyToId: String?): String =
        sendRoundVideoMessage(chatId, recorded, replyToId).id

    fun sendRoundVideoMessage(chatId: String, recorded: RecordedMedia, replyToId: String?): DecryptedMessage =
        try {
            require(recorded.bytes.isNotEmpty()) { "Пустое видеосообщение" }
            require(recorded.durationMillis >= MIN_ROUND_VIDEO_DURATION_MILLIS) {
                "Слишком короткое видеосообщение"
            }
            sendPreparedMediaMessage(
                chatId = chatId,
                attachments = listOf(
                    PreparedLocalAttachment(
                        name = recorded.name,
                        mimeType = recorded.mimeType,
                        bytes = recorded.bytes,
                        caption = "",
                        durationMillis = recorded.durationMillis,
                        previewBytes = recorded.previewBytes,
                    ),
                ),
                caption = "",
                replyToId = replyToId,
                forcedKind = MessageKind.ROUND_VIDEO,
                roundVideoShape = recorded.roundVideoShape ?: RoundVideoShape.CIRCLE,
            )
        } finally {
            recorded.bytes.fill(0)
            recorded.previewBytes?.fill(0)
        }

    fun requestSpoilerReveal(chatId: String, targetMessageId: String, ownerUsername: String): String =
        sendContent(
            chatId,
            MessageContent(
                kind = MessageKind.SPOILER_REQUEST,
                text = "Спойлер",
                replyToId = targetMessageId,
                media = null,
                targetMessageId = targetMessageId,
                targetUsername = ownerUsername,
            ),
        )

    fun revealSpoiler(chatId: String, message: DecryptedMessage, username: String) {
        val account = activeAccount()
        require(message.senderUsername == account.username) { "Раскрыть спойлер может только отправитель" }
        updateContent(
            chatId = chatId,
            messageId = message.id,
            content = message.content.copy(revealedFor = message.content.revealedFor + username),
        )
    }

    fun forwardMessage(message: DecryptedMessage, targetChatId: String): String {
        require(message.decryptable) { "Сообщение недоступно для пересылки" }
        val descriptors = message.content.mediaItems.ifEmpty { message.content.media?.let(::listOf).orEmpty() }
        val forwardedFrom = message.content.forwardedFromUsername ?: message.senderUsername
        if (descriptors.isEmpty()) {
            return sendContent(
                targetChatId,
                message.content.copy(replyToId = null, forwardedFromUsername = forwardedFrom),
            )
        }
        val prepared = descriptors.map { descriptor ->
            val plaintext = downloadAttachment(message.chatId, message.id, descriptor)
            val previewBytes = runCatching {
                downloadPreview(message.chatId, message.id, descriptor)
            }.getOrNull()
            PreparedLocalAttachment(
                name = descriptor.name,
                mimeType = descriptor.mimeType,
                bytes = plaintext,
                caption = "",
                width = descriptor.width,
                height = descriptor.height,
                durationMillis = descriptor.durationMillis,
                previewBytes = previewBytes,
                waveform = if (descriptors.size == 1) message.content.waveform else emptyList(),
                sendAsFile = message.content.kind == MessageKind.FILE,
                spoiler = message.content.spoiler,
            )
        }
        return try {
            sendPreparedMedia(
                targetChatId,
                prepared,
                message.content.text,
                replyToId = null,
                captionEntities = message.content.textEntities,
                forcedKind = message.content.kind.takeIf { it in setOf(MessageKind.VOICE, MessageKind.ROUND_VIDEO) },
                roundVideoShape = message.content.roundVideoShape,
                forwardedFromUsername = forwardedFrom,
            )
        } finally {
            prepared.forEach {
                it.bytes.fill(0)
                it.previewBytes?.fill(0)
            }
        }
    }

    fun downloadAttachment(chatId: String, messageId: String, descriptor: MediaDescriptor): ByteArray {
        val ciphertext = api.downloadMedia(activeAccount(), chatId, descriptor.id)
        return try {
            crypto.decryptMedia(chatId, messageId, descriptor, ciphertext)
        } finally {
            ciphertext.fill(0)
        }
    }

    fun downloadPreview(chatId: String, messageId: String, descriptor: MediaDescriptor): ByteArray? {
        val preview = descriptor.preview ?: return null
        val previewDescriptor = MediaDescriptor(
            id = preview.id,
            name = "preview.jpg",
            mimeType = "image/jpeg",
            originalSize = preview.originalSize,
            encryptedSize = preview.encryptedSize,
            keyBase64 = preview.keyBase64,
            nonceBase64 = preview.nonceBase64,
        )
        return downloadAttachment(chatId, messageId, previewDescriptor)
    }

    fun deleteMessages(chatId: String, messages: List<DecryptedMessage>, scope: MessageDeleteScope) {
        val account = activeAccount()
        for (message in messages.distinctBy(DecryptedMessage::id)) {
            api.deleteMessage(account, chatId, message.id, scope)
            if (scope == MessageDeleteScope.EVERYONE) {
                message.content.mediaItems.ifEmpty { message.content.media?.let(::listOf).orEmpty() }
                    .flatMap { descriptor -> listOfNotNull(descriptor.id, descriptor.preview?.id) }
                    .distinct()
                    .forEach { id -> runCatching { api.deleteMedia(account, chatId, id) } }
            }
        }
    }

    fun markMessagesRead(chatId: String, messages: List<DecryptedMessage>) {
        val account = activeAccount()
        val maxReadSequence = messages.asSequence()
            .filter { it.senderUsername != account.username && it.decryptable }
            .maxOfOrNull(DecryptedMessage::sequence)
            ?: return
        api.markReadCursor(account, chatId, maxReadSequence)
    }

    fun pinMessage(chatId: String, messageId: String) = api.pinMessage(activeAccount(), chatId, messageId)
    fun unpinMessage(chatId: String) = api.unpinMessage(activeAccount(), chatId)
    fun waitForEvents(after: Long): Long = api.waitForEvents(activeAccount(), after)

    private fun uploadPreparedAttachment(
        account: ProvisionedAccount,
        chatId: String,
        messageId: String,
        item: PreparedLocalAttachment,
        uploadedIDs: MutableList<String>,
    ): MediaDescriptor {
        val mediaId = UUID.randomUUID().toString()
        val encrypted = crypto.encryptMedia(chatId, messageId, mediaId, item.bytes)
        val previewDescriptor: MediaPreviewDescriptor?
        try {
            api.uploadMedia(account, chatId, mediaId, encrypted.ciphertext)
            uploadedIDs += mediaId
            previewDescriptor = item.previewBytes?.let { previewBytes ->
                val previewId = UUID.randomUUID().toString()
                val encryptedPreview = crypto.encryptMedia(chatId, messageId, previewId, previewBytes)
                try {
                    api.uploadMedia(account, chatId, previewId, encryptedPreview.ciphertext)
                    uploadedIDs += previewId
                    MediaPreviewDescriptor(
                        id = previewId,
                        originalSize = previewBytes.size.toLong(),
                        encryptedSize = encryptedPreview.ciphertext.size.toLong(),
                        keyBase64 = Base64.encodeToString(encryptedPreview.key, Base64.NO_WRAP),
                        nonceBase64 = Base64.encodeToString(encryptedPreview.nonce, Base64.NO_WRAP),
                    )
                } finally {
                    encryptedPreview.key.fill(0)
                    encryptedPreview.nonce.fill(0)
                    encryptedPreview.ciphertext.fill(0)
                    previewBytes.fill(0)
                }
            }
            return MediaDescriptor(
                id = mediaId,
                name = item.name.take(MAX_FILE_NAME_LENGTH),
                mimeType = item.mimeType.take(MAX_MIME_LENGTH),
                originalSize = item.bytes.size.toLong(),
                encryptedSize = encrypted.ciphertext.size.toLong(),
                keyBase64 = Base64.encodeToString(encrypted.key, Base64.NO_WRAP),
                nonceBase64 = Base64.encodeToString(encrypted.nonce, Base64.NO_WRAP),
                width = item.width,
                height = item.height,
                durationMillis = item.durationMillis,
                preview = previewDescriptor,
            )
        } finally {
            encrypted.key.fill(0)
            encrypted.nonce.fill(0)
            encrypted.ciphertext.fill(0)
        }
    }

    private fun updateContent(chatId: String, messageId: String, content: MessageContent) {
        outboundLock(chatId).withLock {
            val account = activeAccount()
            val prepared = prepareForWrite(account, chatId, content, messageId)
            api.updateMessage(account, chatId, prepared)
        }
    }

    private fun loadPage(chatId: String, after: Long, before: Long, limit: Int, markRead: Boolean): DecryptedMessagePage {
        val account = activeAccount()
        val page = api.listMessages(account, chatId, after, before, limit)
        repairPendingEnvelopes(account, chatId, page.messages.filter { it.cryptoVersion <= 1 })
        val decrypted = page.messages.mapNotNull { wire ->
            val fingerprint = wireFingerprint(wire)
            decryptedMessageCache[wire.id]
                ?.takeIf { it.fingerprint == fingerprint }
                ?.message
                ?.copy(
                    deliveryState = if (wire.readCount > 0) MessageDeliveryState.READ else MessageDeliveryState.SENT,
                    envelopeDeviceIds = wire.envelopeDeviceIds,
                )
                ?: runCatching {
                    if (wire.cryptoVersion >= 2) ratchetCrypto.decrypt(account, wire)
                    else {
                        if (wire.envelope == null) return@mapNotNull null
                        crypto.decrypt(wire)
                    }
                }.getOrNull()?.also { message ->
                    decryptedMessageCache[wire.id] = CachedDecryptedMessage(fingerprint, message)
                }
        }
        if (markRead) {
            decrypted.asSequence()
                .filter { it.senderUsername != account.username && it.decryptable }
                .maxOfOrNull(DecryptedMessage::sequence)
                ?.let { api.markReadCursor(account, chatId, it) }
        }
        return DecryptedMessagePage(decrypted, page.hasMoreBefore)
    }

    private fun repairPendingEnvelopes(
        account: ProvisionedAccount,
        chatId: String,
        wireMessages: List<WireMessage>,
        knownReadyDevices: List<ChatDevice>? = null,
    ) {
        val repairable = wireMessages.filter { it.envelope != null }
        if (repairable.isEmpty()) return
        val allReadyDevices = knownReadyDevices ?: encryptionReadyDevices(account, chatId)
        for (message in repairable) {
            // The original sender is authorized to add envelopes for every active member device.
            // A recipient may only repair envelopes for their own newly linked devices.
            val eligibleDevices = if (message.senderUsername == account.username) {
                allReadyDevices
            } else {
                allReadyDevices.filter { it.username == account.username }
            }
            val missing = eligibleDevices.filterNot { it.id in message.envelopeDeviceIds }
            if (missing.isEmpty()) continue
            api.addMessageEnvelopes(account, chatId, message.id, crypto.createAdditionalEnvelopes(message, missing))
        }
    }

    private fun sendContent(
        chatId: String,
        content: MessageContent,
        messageId: String = UUID.randomUUID().toString(),
    ): String = sendContentMessage(chatId, content, messageId).id

    private fun sendContentMessage(
        chatId: String,
        content: MessageContent,
        messageId: String = UUID.randomUUID().toString(),
    ): DecryptedMessage = outboundLock(chatId).withLock {
        // Ratchet state is ordered per conversation. UI callers are free to enqueue multiple
        // messages immediately; only the cryptographic/network commit is serialized per chat.
        val account = activeAccount()
        val prepared = prepareForWrite(account, chatId, content, messageId)
        val receipt = api.createMessage(account, chatId, prepared)
        DecryptedMessage(
            sequence = receipt.sequence,
            id = receipt.id,
            chatId = chatId,
            senderUsername = account.username,
            senderDeviceId = account.deviceId,
            content = content,
            createdAt = receipt.createdAt,
            editedAt = null,
            decryptable = true,
            envelopeDeviceIds = receipt.envelopeDeviceIds.ifEmpty {
                prepared.envelopes.map(MessageEnvelope::deviceId).toSet()
            },
            deliveryState = MessageDeliveryState.SENT,
        )
    }

    private fun prepareForWrite(
        account: ProvisionedAccount,
        chatId: String,
        content: MessageContent,
        messageId: String,
    ): PreparedMessage {
        // Device membership is cached and explicitly invalidated by trust/device changes.
        // Do not add a full network RTT to every message send.
        val allDevices = allReadyDevices(account, chatId, forceRefresh = false)
        val chat = chatCache[chatId] ?: listChats().firstOrNull { it.id == chatId }
            ?: error("Чат не найден")
        if (allDevices.isNotEmpty() && allDevices.all(::isRatchetReady)) {
            val reserved = allocatedSequences.remove(messageId)
            val requestId: String
            val sequence: Long
            if (reserved != null && reserved.expiresAtElapsedRealtime > SystemClock.elapsedRealtime()) {
                requestId = reserved.requestId
                sequence = reserved.cryptoSequence
            } else {
                requestId = UUID.randomUUID().toString()
                sequence = api.reserveCryptoSequence(account, chatId, requestId, messageId)
            }
            return ratchetCrypto.prepare(
                account = account,
                chat = chat,
                content = content,
                devices = allDevices,
                messageId = messageId,
                cryptoSequence = sequence,
                sequenceRequestId = requestId,
            )
        }
        val legacy = allDevices.filter(::isEncryptionReady)
        require(legacy.size == allDevices.size && legacy.isNotEmpty()) {
            "Не все устройства готовы к безопасной отправке. Обновите и откройте FedMes на каждом устройстве."
        }
        return crypto.prepare(chatId, account.username, account.deviceId, content, legacy, messageId)
    }

    private fun topUpSequencePool(account: ProvisionedAccount, chatId: String) {
        val queue = sequencePools.computeIfAbsent(chatId) { ConcurrentLinkedQueue() }
        val now = SystemClock.elapsedRealtime()
        while (queue.peek()?.expiresAtElapsedRealtime?.let { it <= now } == true) queue.poll()
        val missing = (SEQUENCE_POOL_TARGET - queue.size).coerceAtLeast(0)
        if (missing == 0) return
        val identifiers = List(missing) { UUID.randomUUID().toString() to UUID.randomUUID().toString() }
        val leased = api.reserveCryptoSequenceLease(account, chatId, identifiers)
        val expiry = SystemClock.elapsedRealtime() + SEQUENCE_POOL_LOCAL_TTL_MILLIS
        leased.forEach { item ->
            queue.offer(ReservedSequence(item.requestId, item.messageId, item.cryptoSequence, expiry))
        }
    }

    private fun activeAccount(): ProvisionedAccount {
        val stored = sessionStore.loadAccount() ?: error("Аккаунт не найден")
        if (stored.sessionExpiresAtEpochMillis > System.currentTimeMillis() + SESSION_REFRESH_SKEW) return stored
        provisioningCoordinator.restoreSession()
        return sessionStore.loadAccount() ?: error("Сессия не восстановлена")
    }

    private fun ensureCurrentEncryptionKeyRegistered(
        account: ProvisionedAccount,
        force: Boolean = false,
    ) {
        val publicKey = keyStore.getOrCreatePublicKeySpkiBase64()
        val identity = listOf(account.username, account.deviceId, publicKey).joinToString("|")
        if (!force && registeredEncryptionIdentity == identity) return
        synchronized(this) {
            if (!force && registeredEncryptionIdentity == identity) return
            api.registerEncryptionKey(account, AndroidMessageKeyStore.ALGORITHM, publicKey)
            registeredEncryptionIdentity = identity
            deviceCache.clear()
        }
    }

    private fun encryptionReadyDevices(
        account: ProvisionedAccount,
        chatId: String,
        forceRefresh: Boolean = false,
    ): List<ChatDevice> {
        val all = allReadyDevices(account, chatId, forceRefresh)
        val ready = all.filter(::isEncryptionReady)
        require(ready.size == all.size && ready.any { it.id == account.deviceId }) {
            "Ключи не всех устройств зарегистрированы"
        }
        return ready
    }

    private fun allReadyDevices(
        account: ProvisionedAccount,
        chatId: String,
        forceRefresh: Boolean = false,
    ): List<ChatDevice> {
        ensureCurrentEncryptionKeyRegistered(account)
        val now = SystemClock.elapsedRealtime()
        if (!forceRefresh) {
            deviceCache[chatId]?.takeIf { now - it.loadedAtElapsedMillis < DEVICE_CACHE_TTL_MILLIS }?.let {
                return it.devices
            }
        }
        val devices = api.listDevices(account, chatId)
        require(devices.any { it.id == account.deviceId }) { "Текущее устройство не готово" }
        deviceCache[chatId] = CachedDevices(devices, now)
        return devices
    }

    private fun isEncryptionReady(device: ChatDevice): Boolean =
        device.encryptionAlgorithm == AndroidMessageKeyStore.ALGORITHM && !device.encryptionPublicKeySpkiBase64.isNullOrBlank()

    private fun isRatchetReady(device: ChatDevice): Boolean =
        device.ratchetBundleVersion > 0 && device.identityAlgorithm.isNotBlank() && device.identityPublicKeySpkiBase64.isNotBlank()

    private fun outboundLock(chatId: String): ReentrantLock =
        outboundLocks.computeIfAbsent(chatId) { ReentrantLock(true) }

    private fun kindForMime(mimeType: String): MessageKind = when {
        mimeType.startsWith("image/") -> MessageKind.PHOTO
        mimeType.startsWith("video/") -> MessageKind.VIDEO
        mimeType.startsWith("audio/") -> MessageKind.AUDIO
        else -> MessageKind.FILE
    }

    private fun approximateWaveform(bytes: ByteArray, bars: Int = 56): List<Int> {
        if (bytes.isEmpty()) return emptyList()
        val step = (bytes.size / bars).coerceAtLeast(1)
        return List(bars) { index ->
            val from = (index * step).coerceAtMost(bytes.lastIndex)
            val to = ((index + 1) * step).coerceAtMost(bytes.size)
            var total = 0L
            var count = 0
            var cursor = from
            while (cursor < to) {
                total += kotlin.math.abs(bytes[cursor].toInt())
                count++
                cursor += 8
            }
            ((total / count.coerceAtLeast(1)).toInt() * 100 / 128).coerceIn(5, 100)
        }
    }

    private data class CachedDecryptedMessage(
        val fingerprint: Int,
        val message: DecryptedMessage,
    )

    private fun wireFingerprint(wire: WireMessage): Int {
        var result = wire.ciphertextBase64.hashCode()
        result = 31 * result + wire.nonceBase64.hashCode()
        result = 31 * result + wire.aad.hashCode()
        result = 31 * result + (wire.editedAt?.hashCode() ?: 0)
        return result
    }

    private data class CachedDevices(
        val devices: List<ChatDevice>,
        val loadedAtElapsedMillis: Long,
    )

    private data class ReservedSequence(
        val requestId: String,
        val messageId: String,
        val cryptoSequence: Long,
        val expiresAtElapsedRealtime: Long,
    )

    private companion object {
        const val SEQUENCE_POOL_TARGET = 32
        const val SEQUENCE_POOL_LOCAL_TTL_MILLIS = 8 * 60 * 1000L
        const val PAGE_SIZE = 100
        const val ENVELOPE_REPAIR_PAGE_SIZE = 200
        const val MAX_MEDIA_GROUP_ITEMS = 10
        const val MAX_TEXT_LENGTH = 16_384
        const val MAX_FILE_NAME_LENGTH = 255
        const val MAX_MIME_LENGTH = 127
        const val SESSION_REFRESH_SKEW = 30_000L
        const val DEVICE_CACHE_TTL_MILLIS = 60_000L
    }
}
