using System.Text.Json.Serialization;

namespace FedMes.Desktop.Core.Messaging;

public enum MessageKind
{
    Text,
    File,
    Photo,
    Video,
    MediaGroup,
    Audio,
    Voice,
    RoundVideo,
    SpoilerRequest,
    Call,
    System,
}

public enum TextEntityType
{
    Bold,
    Italic,
    Monospace,
    Strikethrough,
    Underline,
    Quote,
    Spoiler,
}

public sealed record TextEntity(TextEntityType Type, int Offset, int Length)
{
    public int EndExclusive => checked(Offset + Length);
}

public enum MessageDeliveryState
{
    Pending,
    Sent,
    Delivered,
    Read,
}

public enum MessageDeleteScope
{
    Me,
    Everyone,
}

public enum RoundVideoShape
{
    Circle,
    Square,
    Heart,
}

public enum CallMode { Audio, Video, Group }
public enum CallEvent { Invite, Ended, Declined, NoAnswer, Failed }

public sealed record CallDescriptor(
    string CallId,
    CallMode Mode,
    CallEvent Event,
    string CapabilityBase64Url,
    string SharedSecretBase64Url,
    string RouteBase64Url,
    long Generation,
    DateTimeOffset CreatedAt,
    DateTimeOffset ExpiresAt,
    string InitiatorUsername);

public sealed record ChatSummary(
    string Id,
    string Kind,
    string Title,
    IReadOnlyList<string> Members,
    long LastSequence,
    DateTimeOffset? LastMessageAt,
    string? PinnedMessageId,
    int UnreadCount);

public sealed record ChatDevice(
    string Id,
    string Username,
    string? EncryptionAlgorithm,
    string? EncryptionPublicKeySpkiBase64,
    string IdentityAlgorithm = "",
    string IdentityPublicKeySpkiBase64 = "",
    int RatchetBundleVersion = 0);

public sealed record MessageEnvelope(
    string DeviceId,
    string Algorithm,
    string CiphertextBase64);

public sealed record RatchetMessageEnvelope(
    string RecipientDeviceId,
    string SenderCurve25519Key,
    string SessionId,
    int MessageType,
    string CiphertextBase64Url,
    string CiphertextSha256Hex);

public sealed record WireMessage(
    long Sequence,
    string Id,
    string ChatId,
    string SenderUsername,
    string SenderDeviceId,
    string CiphertextBase64,
    string NonceBase64,
    string Aad,
    DateTimeOffset CreatedAt,
    DateTimeOffset? EditedAt,
    MessageEnvelope? Envelope,
    IReadOnlySet<string> EnvelopeDeviceIds,
    int RecipientCount,
    int DeliveredCount,
    int ReadCount,
    int CryptoVersion = 1,
    long RoomKeyVersion = 1,
    int AadVersion = 1,
    long CryptoSequence = 0,
    string EncryptionAlgorithm = "fedmes-aes256gcm-rsa-oaep-v1",
    string MessageType = "legacy",
    RatchetMessageEnvelope? RatchetEnvelope = null);

public sealed record MessagePage(
    IReadOnlyList<WireMessage> Messages,
    bool HasMoreBefore);

public sealed record CreatedMessageReceipt(
    long Sequence,
    string Id,
    DateTimeOffset CreatedAt,
    IReadOnlySet<string> EnvelopeDeviceIds);

public sealed record DecryptedMessagePage(
    IReadOnlyList<DecryptedMessage> Messages,
    bool HasMoreBefore);

public sealed record MediaPreviewDescriptor(
    string Id,
    long OriginalSize,
    long EncryptedSize,
    string KeyBase64,
    string NonceBase64);

public sealed record MediaDescriptor(
    string Id,
    string Name,
    string MimeType,
    long OriginalSize,
    long EncryptedSize,
    string KeyBase64,
    string NonceBase64,
    int? Width = null,
    int? Height = null,
    long? DurationMilliseconds = null,
    MediaPreviewDescriptor? Preview = null);

public sealed record MessageContent(
    MessageKind Kind,
    string Text,
    string? ReplyToId,
    MediaDescriptor? Media,
    IReadOnlyList<MediaDescriptor> MediaItems,
    bool Spoiler = false,
    IReadOnlySet<string>? RevealedFor = null,
    IReadOnlyList<int>? Waveform = null,
    long? DurationMilliseconds = null,
    RoundVideoShape? RoundVideoShape = null,
    string? TargetMessageId = null,
    string? TargetUsername = null,
    string? ForwardedFromUsername = null,
    IReadOnlyList<TextEntity>? TextEntities = null,
    CallDescriptor? Call = null)
{
    public IReadOnlySet<string> EffectiveRevealedFor =>
        RevealedFor ?? EmptyValues.RevealedFor;

    public IReadOnlyList<int> EffectiveWaveform =>
        Waveform ?? [];

    public IReadOnlyList<MediaDescriptor> EffectiveMediaItems =>
        MediaItems.Count > 0 ? MediaItems : Media is null ? [] : [Media];

    public IReadOnlyList<TextEntity> EffectiveTextEntities =>
        TextEntities ?? [];
}

public sealed record DecryptedMessage(
    long Sequence,
    string Id,
    string ChatId,
    string SenderUsername,
    string SenderDeviceId,
    MessageContent Content,
    DateTimeOffset CreatedAt,
    DateTimeOffset? EditedAt,
    bool Decryptable,
    IReadOnlySet<string> EnvelopeDeviceIds,
    MessageDeliveryState DeliveryState);

public sealed record PresenceState(
    string Username,
    bool Online,
    DateTimeOffset? LastSeenAt,
    bool ShowExact,
    string LastSeenCategory);

public sealed record TypingState(string Username);

public sealed record PreparedMessage(
    string Id,
    string CiphertextBase64,
    string NonceBase64,
    string Aad,
    IReadOnlyList<MessageEnvelope> Envelopes,
    int ProtocolVersion = 1,
    int CryptoVersion = 1,
    long RoomKeyVersion = 1,
    int AadVersion = 1,
    long CryptoSequence = 0,
    string EncryptionAlgorithm = "fedmes-aes256gcm-rsa-oaep-v1",
    string MessageType = "legacy",
    string SequenceRequestId = "",
    IReadOnlyList<RatchetMessageEnvelope>? RatchetEnvelopes = null)
{
    public IReadOnlyList<RatchetMessageEnvelope> EffectiveRatchetEnvelopes => RatchetEnvelopes ?? [];
}

public sealed record PreparedDesktopAttachment(
    string Name,
    string MimeType,
    byte[] Bytes,
    byte[]? PreviewBytes = null,
    int? Width = null,
    int? Height = null,
    long? DurationMilliseconds = null,
    IReadOnlyList<int>? Waveform = null,
    bool SendAsFile = false,
    bool Spoiler = false);

public sealed record AccountDevice(
    string Id,
    string DisplayName,
    string Platform,
    DateTimeOffset CreatedAt,
    DateTimeOffset? LastSeenAt,
    bool Current);

internal static class EmptyValues
{
    public static IReadOnlySet<string> RevealedFor { get; } = new HashSet<string>(StringComparer.Ordinal);
}

internal sealed record ChatListResponse(
    [property: JsonPropertyName("chats")] IReadOnlyList<ChatWireModel>? Chats);

internal sealed record ChatWireModel(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("title")] string Title,
    [property: JsonPropertyName("members")] IReadOnlyList<string>? Members,
    [property: JsonPropertyName("last_sequence")] long LastSequence,
    [property: JsonPropertyName("last_message_at")] DateTimeOffset? LastMessageAt,
    [property: JsonPropertyName("pinned_message_id")] string? PinnedMessageId,
    [property: JsonPropertyName("unread_count")] int UnreadCount);

internal sealed record DeviceListResponse(
    [property: JsonPropertyName("devices")] IReadOnlyList<DeviceWireModel>? Devices);

internal sealed record DeviceWireModel(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("username")] string Username,
    [property: JsonPropertyName("encryption_algorithm")] string? EncryptionAlgorithm,
    [property: JsonPropertyName("encryption_public_key_spki")] string? EncryptionPublicKeySpkiBase64,
    [property: JsonPropertyName("identity_algorithm")] string? IdentityAlgorithm,
    [property: JsonPropertyName("identity_public_key_spki")] string? IdentityPublicKeySpkiBase64,
    [property: JsonPropertyName("ratchet_bundle_version")] int RatchetBundleVersion);

internal sealed record MessageListResponse(
    [property: JsonPropertyName("messages")] IReadOnlyList<MessageWireModel>? Messages,
    [property: JsonPropertyName("has_more_before")] bool HasMoreBefore);

internal sealed record CreateMessageResponse(
    [property: JsonPropertyName("message")] MessageWireModel Message);

internal sealed record MessageWireModel(
    [property: JsonPropertyName("sequence")] long Sequence,
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("chat_id")] string ChatId,
    [property: JsonPropertyName("sender_username")] string SenderUsername,
    [property: JsonPropertyName("sender_device_id")] string SenderDeviceId,
    [property: JsonPropertyName("ciphertext")] string CiphertextBase64,
    [property: JsonPropertyName("nonce")] string NonceBase64,
    [property: JsonPropertyName("aad")] string Aad,
    [property: JsonPropertyName("created_at")] DateTimeOffset CreatedAt,
    [property: JsonPropertyName("edited_at")] DateTimeOffset? EditedAt,
    [property: JsonPropertyName("envelope")] EnvelopeWireModel? Envelope,
    [property: JsonPropertyName("envelope_device_ids")] IReadOnlyList<string>? EnvelopeDeviceIds,
    [property: JsonPropertyName("recipient_count")] int RecipientCount,
    [property: JsonPropertyName("delivered_count")] int DeliveredCount,
    [property: JsonPropertyName("read_count")] int ReadCount,
    [property: JsonPropertyName("crypto_version")] int CryptoVersion,
    [property: JsonPropertyName("room_key_version")] long RoomKeyVersion,
    [property: JsonPropertyName("aad_version")] int AadVersion,
    [property: JsonPropertyName("crypto_sequence")] long CryptoSequence,
    [property: JsonPropertyName("encryption_algorithm")] string? EncryptionAlgorithm,
    [property: JsonPropertyName("message_type")] string? MessageType,
    [property: JsonPropertyName("ratchet_envelope")] RatchetEnvelopeWireModel? RatchetEnvelope);

internal sealed record EnvelopeWireModel(
    [property: JsonPropertyName("device_id")] string DeviceId,
    [property: JsonPropertyName("algorithm")] string Algorithm,
    [property: JsonPropertyName("ciphertext")] string CiphertextBase64);

internal sealed record RatchetEnvelopeWireModel(
    [property: JsonPropertyName("recipient_device_id")] string RecipientDeviceId,
    [property: JsonPropertyName("sender_curve25519_key")] string SenderCurve25519Key,
    [property: JsonPropertyName("session_id")] string SessionId,
    [property: JsonPropertyName("message_type")] int MessageType,
    [property: JsonPropertyName("ciphertext")] string CiphertextBase64Url,
    [property: JsonPropertyName("ciphertext_sha256")] string CiphertextSha256Hex);

internal sealed record PresenceListResponse(
    [property: JsonPropertyName("presence")] IReadOnlyList<PresenceWireModel>? Presence);

internal sealed record PresenceWireModel(
    [property: JsonPropertyName("username")] string Username,
    [property: JsonPropertyName("online")] bool Online,
    [property: JsonPropertyName("last_seen_at")] DateTimeOffset? LastSeenAt,
    [property: JsonPropertyName("show_exact")] bool ShowExact,
    [property: JsonPropertyName("last_seen_category")] string LastSeenCategory);

internal sealed record TypingListResponse(
    [property: JsonPropertyName("typing")] IReadOnlyList<TypingWireModel>? Typing);

internal sealed record TypingWireModel(
    [property: JsonPropertyName("username")] string Username);

internal sealed record EventSequenceResponse(
    [property: JsonPropertyName("sequence")] long Sequence);

internal sealed record AccountDeviceListResponse(
    [property: JsonPropertyName("devices")] IReadOnlyList<AccountDeviceWireModel>? Devices);

internal sealed record AccountDeviceWireModel(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("display_name")] string DisplayName,
    [property: JsonPropertyName("platform")] string Platform,
    [property: JsonPropertyName("bound_at")] DateTimeOffset CreatedAt,
    [property: JsonPropertyName("last_seen_at")] DateTimeOffset? LastSeenAt,
    [property: JsonPropertyName("current")] bool Current);

internal sealed record CryptoSequenceResponse(
    [property: JsonPropertyName("version")] int Version,
    [property: JsonPropertyName("message_id")] string MessageId,
    [property: JsonPropertyName("crypto_sequence")] long CryptoSequence,
    [property: JsonPropertyName("replayed")] bool Replayed);

internal sealed record CryptoSequenceLeaseResponse(
    [property: JsonPropertyName("version")] int Version,
    [property: JsonPropertyName("items")] IReadOnlyList<CryptoSequenceLeaseItem>? Items);

internal sealed record CryptoSequenceLeaseItem(
    [property: JsonPropertyName("request_id")] string RequestId,
    [property: JsonPropertyName("message_id")] string MessageId,
    [property: JsonPropertyName("crypto_sequence")] long CryptoSequence);
