package com.fedmes.app.messaging

const val MIN_ROUND_VIDEO_DURATION_MILLIS = 1_000L

data class ChatSummary(
    val id: String,
    val kind: String,
    val title: String,
    val members: List<String>,
    val lastSequence: Long,
    val lastMessageAt: Long?,
    val pinnedMessageId: String?,
    val unreadCount: Int,
)

data class ChatDevice(
    val id: String,
    val username: String,
    val identityAlgorithm: String = "",
    val identityPublicKeySpkiBase64: String = "",
    val encryptionAlgorithm: String?,
    val encryptionPublicKeySpkiBase64: String?,
    val ratchetBundleVersion: Int = 0,
)

data class MessageEnvelope(
    val deviceId: String,
    val algorithm: String,
    val ciphertextBase64: String,
)

data class RatchetMessageEnvelope(
    val recipientDeviceId: String,
    val senderCurve25519Key: String,
    val sessionId: String,
    val messageType: Int,
    val ciphertextBase64Url: String,
    val ciphertextSha256Hex: String,
)

data class WireMessage(
    val sequence: Long,
    val id: String,
    val chatId: String,
    val senderUsername: String,
    val senderDeviceId: String,
    val ciphertextBase64: String,
    val nonceBase64: String,
    val aad: String,
    val createdAt: Long,
    val editedAt: Long?,
    val envelope: MessageEnvelope?,
    val envelopeDeviceIds: Set<String>,
    val recipientCount: Int,
    val deliveredCount: Int,
    val readCount: Int,
    val cryptoVersion: Int = 1,
    val roomKeyVersion: Long = 1,
    val aadVersion: Int = 1,
    val cryptoSequence: Long = 0,
    val encryptionAlgorithm: String = "fedmes-aes256gcm-rsa-oaep-v1",
    val messageType: String = "legacy",
    val ratchetEnvelope: RatchetMessageEnvelope? = null,
)

data class MessagePage(
    val messages: List<WireMessage>,
    val hasMoreBefore: Boolean,
)

data class CreatedMessageReceipt(
    val sequence: Long,
    val id: String,
    val createdAt: Long,
    val envelopeDeviceIds: Set<String>,
)

data class DecryptedMessagePage(
    val messages: List<DecryptedMessage>,
    val hasMoreBefore: Boolean,
)

enum class MessageKind {
    TEXT,
    FILE,
    PHOTO,
    VIDEO,
    MEDIA_GROUP,
    AUDIO,
    VOICE,
    ROUND_VIDEO,
    SPOILER_REQUEST,
    CALL,
    SYSTEM,
}

enum class TextEntityType {
    BOLD,
    ITALIC,
    MONOSPACE,
    STRIKETHROUGH,
    UNDERLINE,
    QUOTE,
    SPOILER,
}

data class TextEntity(
    val type: TextEntityType,
    val offset: Int,
    val length: Int,
) {
    val endExclusive: Int get() = offset + length
}

enum class MessageDeliveryState {
    PENDING,
    SENT,
    DELIVERED,
    READ,
}

enum class MessageDeleteScope {
    ME,
    EVERYONE,
}

enum class RoundVideoShape {
    CIRCLE,
    SQUARE,
    // Legacy wire value. New clients do not create it and render it as CIRCLE.
    HEART,
}

enum class CallMode { AUDIO, VIDEO, GROUP }

enum class CallEvent { INVITE, ENDED, DECLINED, NO_ANSWER, FAILED }

data class CallDescriptor(
    val callId: String,
    val mode: CallMode,
    val event: CallEvent,
    val capabilityBase64Url: String,
    val sharedSecretBase64Url: String,
    val routeBase64Url: String,
    val generation: Long,
    val createdAtEpochMillis: Long,
    val expiresAtEpochMillis: Long,
    val initiatorUsername: String,
)

data class MediaPreviewDescriptor(
    val id: String,
    val originalSize: Long,
    val encryptedSize: Long,
    val keyBase64: String,
    val nonceBase64: String,
)

data class MediaDescriptor(
    val id: String,
    val name: String,
    val mimeType: String,
    val originalSize: Long,
    val encryptedSize: Long,
    val keyBase64: String,
    val nonceBase64: String,
    val width: Int? = null,
    val height: Int? = null,
    val durationMillis: Long? = null,
    val preview: MediaPreviewDescriptor? = null,
)

data class MessageContent(
    val kind: MessageKind,
    val text: String,
    val replyToId: String?,
    val media: MediaDescriptor?,
    val mediaItems: List<MediaDescriptor> = media?.let(::listOf).orEmpty(),
    val spoiler: Boolean = false,
    val revealedFor: Set<String> = emptySet(),
    val waveform: List<Int> = emptyList(),
    val durationMillis: Long? = null,
    val roundVideoShape: RoundVideoShape? = null,
    val targetMessageId: String? = null,
    val targetUsername: String? = null,
    val forwardedFromUsername: String? = null,
    val textEntities: List<TextEntity> = emptyList(),
    val call: CallDescriptor? = null,
)

data class DecryptedMessage(
    val sequence: Long,
    val id: String,
    val chatId: String,
    val senderUsername: String,
    val senderDeviceId: String,
    val content: MessageContent,
    val createdAt: Long,
    val editedAt: Long?,
    val decryptable: Boolean,
    val envelopeDeviceIds: Set<String>,
    val deliveryState: MessageDeliveryState,
)

data class PresenceState(
    val username: String,
    val online: Boolean,
    val lastSeenAt: Long?,
    val showExact: Boolean,
    val lastSeenCategory: String,
)

data class TypingState(
    val username: String,
)

data class PreparedMessage(
    val id: String,
    val ciphertextBase64: String,
    val nonceBase64: String,
    val aad: String,
    val envelopes: List<MessageEnvelope> = emptyList(),
    val protocolVersion: Int = 1,
    val cryptoVersion: Int = 1,
    val roomKeyVersion: Long = 1,
    val aadVersion: Int = 1,
    val cryptoSequence: Long = 0,
    val encryptionAlgorithm: String = "fedmes-aes256gcm-rsa-oaep-v1",
    val messageType: String = "legacy",
    val sequenceRequestId: String = "",
    val ratchetEnvelopes: List<RatchetMessageEnvelope> = emptyList(),
)

data class OpenedAttachment(
    val messageId: String,
    val chatId: String,
    val kind: MessageKind,
    val descriptor: MediaDescriptor,
    val plaintext: ByteArray,
    val localFilePath: String? = null,
    val caption: String = "",
    val allowSave: Boolean = true,
)

data class RecordedMedia(
    val name: String,
    val mimeType: String,
    val bytes: ByteArray,
    val durationMillis: Long,
    val waveform: List<Int> = emptyList(),
    val roundVideoShape: RoundVideoShape? = null,
    val previewBytes: ByteArray? = null,
)
