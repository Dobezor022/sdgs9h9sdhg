using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using FedMes.Desktop.Core.Devices;

namespace FedMes.Desktop.Core.Messaging;

public sealed class MessageCryptoService : IDisposable
{
    public const string MessageEnvelopeAlgorithm = "rsa-oaep-sha256";
    private const int AesKeySize = 32;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int PaddingBlockSize = 256;
    private readonly DesktopDeviceIdentity _identity;
    private readonly RandomNumberGenerator _random;
    private readonly bool _ownsRandom;
    private bool _disposed;

    public MessageCryptoService(DesktopDeviceIdentity identity, RandomNumberGenerator? random = null)
    {
        _identity = identity ?? throw new ArgumentNullException(nameof(identity));
        _random = random ?? RandomNumberGenerator.Create();
        _ownsRandom = random is null;
    }

    public PreparedMessage Prepare(
        string chatId,
        string senderUsername,
        string senderDeviceId,
        MessageContent content,
        IReadOnlyList<ChatDevice> devices,
        string? messageId = null)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(chatId);
        ArgumentException.ThrowIfNullOrWhiteSpace(senderUsername);
        ArgumentException.ThrowIfNullOrWhiteSpace(senderDeviceId);
        ArgumentNullException.ThrowIfNull(content);
        ArgumentNullException.ThrowIfNull(devices);
        if (devices.Count == 0)
        {
            throw new InvalidOperationException("В чате нет устройств с зарегистрированными ключами шифрования.");
        }

        string id = messageId ?? Guid.NewGuid().ToString();
        string aad = CanonicalMessageAad(chatId, senderUsername, senderDeviceId, id);
        byte[] messageKey = RandomBytes(AesKeySize);
        byte[] nonce = RandomBytes(NonceSize);
        byte[] plaintext = EncodeContent(content);
        byte[] padded = Pad(plaintext);
        byte[] ciphertext = [];
        try
        {
            ciphertext = EncryptAesGcm(messageKey, nonce, Encoding.UTF8.GetBytes(aad), padded);
            IReadOnlyList<MessageEnvelope> envelopes = WrapMessageKey(messageKey, devices);
            return new PreparedMessage(
                id,
                Convert.ToBase64String(ciphertext),
                Convert.ToBase64String(nonce),
                aad,
                envelopes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(messageKey);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(padded);
            CryptographicOperations.ZeroMemory(ciphertext);
        }
    }

    public DecryptedMessage Decrypt(WireMessage message)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(message);
        string expectedAad = CanonicalMessageAad(
            message.ChatId,
            message.SenderUsername,
            message.SenderDeviceId,
            message.Id);
        if (!string.Equals(message.Aad, expectedAad, StringComparison.Ordinal))
        {
            throw new CryptographicException("AAD сообщения не совпадает с метаданными.");
        }

        MessageEnvelope envelope = message.Envelope
            ?? throw new CryptographicException("Для этого устройства отсутствует конверт ключа сообщения.");
        if (!string.Equals(envelope.Algorithm, MessageEnvelopeAlgorithm, StringComparison.Ordinal))
        {
            throw new CryptographicException("Алгоритм конверта сообщения не поддерживается.");
        }

        byte[] wrapped = Convert.FromBase64String(envelope.CiphertextBase64);
        byte[] messageKey = [];
        byte[] nonce = [];
        byte[] ciphertext = [];
        byte[] padded = [];
        byte[] plaintext = [];
        try
        {
            messageKey = _identity.UnwrapMessageKey(wrapped);
            if (messageKey.Length != AesKeySize)
            {
                throw new CryptographicException("Ключ сообщения имеет неверную длину.");
            }

            nonce = Convert.FromBase64String(message.NonceBase64);
            ciphertext = Convert.FromBase64String(message.CiphertextBase64);
            padded = DecryptAesGcm(messageKey, nonce, Encoding.UTF8.GetBytes(message.Aad), ciphertext);
            plaintext = Unpad(padded);
            MessageContent content = DecodeContent(plaintext);
            return new DecryptedMessage(
                message.Sequence,
                message.Id,
                message.ChatId,
                message.SenderUsername,
                message.SenderDeviceId,
                content,
                message.CreatedAt,
                message.EditedAt,
                true,
                message.EnvelopeDeviceIds,
                GetDeliveryState(message));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrapped);
            CryptographicOperations.ZeroMemory(messageKey);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(padded);
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public IReadOnlyList<MessageEnvelope> CreateAdditionalEnvelopes(
        WireMessage message,
        IReadOnlyList<ChatDevice> devices)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(message);
        ArgumentNullException.ThrowIfNull(devices);
        if (devices.Count == 0)
        {
            return [];
        }

        MessageEnvelope envelope = message.Envelope
            ?? throw new CryptographicException("Текущее устройство не может получить ключ сообщения.");
        byte[] wrapped = Convert.FromBase64String(envelope.CiphertextBase64);
        byte[] messageKey = [];
        try
        {
            messageKey = _identity.UnwrapMessageKey(wrapped);
            return WrapMessageKey(messageKey, devices);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrapped);
            CryptographicOperations.ZeroMemory(messageKey);
        }
    }

    public EncryptedMedia EncryptMedia(
        string chatId,
        string messageId,
        string mediaId,
        ReadOnlySpan<byte> plaintext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        byte[] key = RandomBytes(AesKeySize);
        byte[] nonce = RandomBytes(NonceSize);
        byte[] aad = Encoding.UTF8.GetBytes(CanonicalMediaAad(chatId, messageId, mediaId));
        try
        {
            byte[] ciphertext = EncryptAesGcm(key, nonce, aad, plaintext);
            return new EncryptedMedia(key, nonce, ciphertext);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(nonce);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(aad);
        }
    }

    public byte[] DecryptMedia(
        string chatId,
        string messageId,
        MediaDescriptor descriptor,
        ReadOnlySpan<byte> ciphertext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        byte[] key = Convert.FromBase64String(descriptor.KeyBase64);
        byte[] nonce = Convert.FromBase64String(descriptor.NonceBase64);
        byte[] aad = Encoding.UTF8.GetBytes(CanonicalMediaAad(chatId, messageId, descriptor.Id));
        try
        {
            return DecryptAesGcm(key, nonce, aad, ciphertext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(aad);
        }
    }

    public static string CanonicalMessageAad(
        string chatId,
        string username,
        string deviceId,
        string messageId) =>
        string.Join("\n", "fedmes-message-v1", chatId, username, deviceId, messageId);

    public static string CanonicalMediaAad(string chatId, string messageId, string mediaId) =>
        string.Join("\n", "fedmes-media-v1", chatId, messageId, mediaId);

    private List<MessageEnvelope> WrapMessageKey(
        ReadOnlySpan<byte> messageKey,
        IReadOnlyList<ChatDevice> devices)
    {
        var result = new List<MessageEnvelope>(devices.Count);
        foreach (ChatDevice device in devices)
        {
            if (!string.Equals(device.EncryptionAlgorithm, MessageEnvelopeAlgorithm, StringComparison.Ordinal) ||
                string.IsNullOrWhiteSpace(device.EncryptionPublicKeySpkiBase64))
            {
                throw new CryptographicException($"Устройство {device.Username} не зарегистрировало совместимый ключ шифрования.");
            }

            byte[] spki = Convert.FromBase64String(device.EncryptionPublicKeySpkiBase64);
            using RSA publicKey = RSA.Create();
            try
            {
                publicKey.ImportSubjectPublicKeyInfo(spki, out int bytesRead);
                if (bytesRead != spki.Length || publicKey.KeySize < 3072)
                {
                    throw new CryptographicException("Открытый RSA-ключ устройства повреждён.");
                }

                byte[] wrapped = RsaOaepSha256Mgf1Sha1.Encrypt(publicKey, messageKey, _random);
                try
                {
                    result.Add(new MessageEnvelope(
                        device.Id,
                        MessageEnvelopeAlgorithm,
                        Convert.ToBase64String(wrapped)));
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(wrapped);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(spki);
            }
        }

        return result;
    }

    internal static byte[] EncodeContent(MessageContent content)
    {
        int version = content.Call is not null || content.Kind == MessageKind.Call
            ? 3
            : content.EffectiveTextEntities.Count > 0 || RequiresProtocolV2(content) ? 2 : 1;
        var root = new JsonObject
        {
            ["version"] = version,
            ["kind"] = ToWireKind(content.Kind),
            ["text"] = content.Text,
        };
        if (!string.IsNullOrWhiteSpace(content.ReplyToId)) root["reply_to_id"] = content.ReplyToId;
        if (content.Media is not null) root["media"] = MediaToJson(content.Media);
        if (content.EffectiveMediaItems.Count > 0)
        {
            var items = new JsonArray();
            foreach (MediaDescriptor media in content.EffectiveMediaItems) items.Add(MediaToJson(media));
            root["media_items"] = items;
        }

        if (content.Spoiler) root["spoiler"] = true;
        if (content.EffectiveRevealedFor.Count > 0)
        {
            var revealed = new JsonArray();
            foreach (string username in content.EffectiveRevealedFor) revealed.Add(username);
            root["revealed_for"] = revealed;
        }

        if (content.EffectiveWaveform.Count > 0)
        {
            var waveform = new JsonArray();
            foreach (int value in content.EffectiveWaveform) waveform.Add(Math.Clamp(value, 0, 100));
            root["waveform"] = waveform;
        }

        if (content.DurationMilliseconds is not null) root["duration_ms"] = content.DurationMilliseconds.Value;
        if (content.RoundVideoShape is not null) root["round_shape"] = ToWireShape(content.RoundVideoShape.Value);
        if (!string.IsNullOrWhiteSpace(content.TargetMessageId)) root["target_message_id"] = content.TargetMessageId;
        if (!string.IsNullOrWhiteSpace(content.TargetUsername)) root["target_username"] = content.TargetUsername;
        if (!string.IsNullOrWhiteSpace(content.ForwardedFromUsername)) root["forwarded_from"] = content.ForwardedFromUsername;
        if (content.Call is not null)
        {
            root["call"] = new JsonObject
            {
                ["call_id"] = content.Call.CallId,
                ["mode"] = content.Call.Mode.ToString().ToLowerInvariant(),
                ["event"] = content.Call.Event switch
                {
                    CallEvent.NoAnswer => "no_answer",
                    _ => content.Call.Event.ToString().ToLowerInvariant(),
                },
                ["capability"] = content.Call.CapabilityBase64Url,
                ["shared_secret"] = content.Call.SharedSecretBase64Url,
                ["route"] = content.Call.RouteBase64Url,
                ["generation"] = content.Call.Generation,
                ["created_at_ms"] = content.Call.CreatedAt.ToUnixTimeMilliseconds(),
                ["expires_at_ms"] = content.Call.ExpiresAt.ToUnixTimeMilliseconds(),
                ["initiator"] = content.Call.InitiatorUsername,
            };
        }
        if (content.EffectiveTextEntities.Count > 0)
        {
            var entities = new JsonArray();
            foreach (TextEntity entity in TextFormatting.Sanitize(content.Text, content.EffectiveTextEntities))
            {
                entities.Add(new JsonObject
                {
                    ["type"] = ToWireTextEntityType(entity.Type),
                    ["offset"] = entity.Offset,
                    ["length"] = entity.Length,
                });
            }
            root["entities"] = entities;
        }
        return Encoding.UTF8.GetBytes(root.ToJsonString());
    }

    internal static MessageContent DecodeContent(ReadOnlySpan<byte> bytes)
    {
        using JsonDocument document = JsonDocument.Parse(bytes.ToArray());
        JsonElement root = document.RootElement;
        int version = root.GetProperty("version").GetInt32();
        if (version is not (1 or 2 or 3))
        {
            throw new CryptographicException("Версия зашифрованного сообщения не поддерживается.");
        }

        MessageKind kind = ParseKind(root.GetProperty("kind").GetString());
        string text = root.TryGetProperty("text", out JsonElement textElement) ? textElement.GetString() ?? string.Empty : string.Empty;
        string? replyToId = GetOptionalString(root, "reply_to_id");
        MediaDescriptor? media = root.TryGetProperty("media", out JsonElement mediaElement)
            ? MediaFromJson(mediaElement)
            : null;
        var mediaItems = new List<MediaDescriptor>();
        if (root.TryGetProperty("media_items", out JsonElement itemsElement) && itemsElement.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement item in itemsElement.EnumerateArray()) mediaItems.Add(MediaFromJson(item));
        }

        if (mediaItems.Count == 0 && media is not null) mediaItems.Add(media);
        var revealedFor = new HashSet<string>(StringComparer.Ordinal);
        if (root.TryGetProperty("revealed_for", out JsonElement revealedElement) && revealedElement.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement item in revealedElement.EnumerateArray())
            {
                string? value = item.GetString();
                if (!string.IsNullOrWhiteSpace(value)) revealedFor.Add(value);
            }
        }

        var waveform = new List<int>();
        if (root.TryGetProperty("waveform", out JsonElement waveformElement) && waveformElement.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement item in waveformElement.EnumerateArray()) waveform.Add(Math.Clamp(item.GetInt32(), 0, 100));
        }

        var textEntities = new List<TextEntity>();
        if (root.TryGetProperty("entities", out JsonElement entitiesElement) && entitiesElement.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement item in entitiesElement.EnumerateArray())
            {
                TextEntityType? type = ParseTextEntityType(GetOptionalString(item, "type"));
                if (type is null) continue;
                int offset = item.TryGetProperty("offset", out JsonElement offsetElement) ? offsetElement.GetInt32() : -1;
                int length = item.TryGetProperty("length", out JsonElement lengthElement) ? lengthElement.GetInt32() : 0;
                textEntities.Add(new TextEntity(type.Value, offset, length));
            }
        }

        long? duration = root.TryGetProperty("duration_ms", out JsonElement durationElement)
            ? durationElement.GetInt64()
            : media?.DurationMilliseconds;
        RoundVideoShape? shape = ParseShape(GetOptionalString(root, "round_shape"));
        CallDescriptor? call = null;
        if (root.TryGetProperty("call", out JsonElement callElement) && callElement.ValueKind == JsonValueKind.Object)
        {
            string? modeText = GetOptionalString(callElement, "mode");
            string? eventText = GetOptionalString(callElement, "event");
            if (Enum.TryParse<CallMode>(modeText, true, out CallMode callMode))
            {
                CallEvent callEvent = eventText?.ToLowerInvariant() switch
                {
                    "invite" => CallEvent.Invite,
                    "ended" => CallEvent.Ended,
                    "declined" => CallEvent.Declined,
                    "no_answer" => CallEvent.NoAnswer,
                    "failed" => CallEvent.Failed,
                    _ => CallEvent.Failed,
                };
                call = new CallDescriptor(
                    callElement.GetProperty("call_id").GetString() ?? string.Empty,
                    callMode,
                    callEvent,
                    callElement.GetProperty("capability").GetString() ?? string.Empty,
                    callElement.GetProperty("shared_secret").GetString() ?? string.Empty,
                    callElement.GetProperty("route").GetString() ?? string.Empty,
                    callElement.GetProperty("generation").GetInt64(),
                    DateTimeOffset.FromUnixTimeMilliseconds(callElement.GetProperty("created_at_ms").GetInt64()),
                    DateTimeOffset.FromUnixTimeMilliseconds(callElement.GetProperty("expires_at_ms").GetInt64()),
                    callElement.GetProperty("initiator").GetString() ?? string.Empty);
            }
        }
        return new MessageContent(
            kind,
            text,
            replyToId,
            media ?? mediaItems.FirstOrDefault(),
            mediaItems,
            root.TryGetProperty("spoiler", out JsonElement spoilerElement) && spoilerElement.GetBoolean(),
            revealedFor,
            waveform,
            duration,
            shape,
            GetOptionalString(root, "target_message_id"),
            GetOptionalString(root, "target_username"),
            GetOptionalString(root, "forwarded_from"),
            TextFormatting.Sanitize(text, textEntities),
            call);
    }

    private static JsonObject MediaToJson(MediaDescriptor media)
    {
        var value = new JsonObject
        {
            ["id"] = media.Id,
            ["name"] = media.Name,
            ["mime_type"] = media.MimeType,
            ["original_size"] = media.OriginalSize,
            ["encrypted_size"] = media.EncryptedSize,
            ["key"] = media.KeyBase64,
            ["nonce"] = media.NonceBase64,
        };
        if (media.Width is not null) value["width"] = media.Width.Value;
        if (media.Height is not null) value["height"] = media.Height.Value;
        if (media.DurationMilliseconds is not null) value["duration_ms"] = media.DurationMilliseconds.Value;
        if (media.Preview is not null)
        {
            value["preview"] = new JsonObject
            {
                ["id"] = media.Preview.Id,
                ["original_size"] = media.Preview.OriginalSize,
                ["encrypted_size"] = media.Preview.EncryptedSize,
                ["key"] = media.Preview.KeyBase64,
                ["nonce"] = media.Preview.NonceBase64,
            };
        }

        return value;
    }

    private static MediaDescriptor MediaFromJson(JsonElement value)
    {
        MediaPreviewDescriptor? preview = null;
        if (value.TryGetProperty("preview", out JsonElement previewElement))
        {
            preview = new MediaPreviewDescriptor(
                previewElement.GetProperty("id").GetString() ?? throw new JsonException("Preview id is missing."),
                previewElement.GetProperty("original_size").GetInt64(),
                previewElement.GetProperty("encrypted_size").GetInt64(),
                previewElement.GetProperty("key").GetString() ?? throw new JsonException("Preview key is missing."),
                previewElement.GetProperty("nonce").GetString() ?? throw new JsonException("Preview nonce is missing."));
        }

        return new MediaDescriptor(
            value.GetProperty("id").GetString() ?? throw new JsonException("Media id is missing."),
            value.GetProperty("name").GetString() ?? "file",
            value.GetProperty("mime_type").GetString() ?? "application/octet-stream",
            value.GetProperty("original_size").GetInt64(),
            value.GetProperty("encrypted_size").GetInt64(),
            value.GetProperty("key").GetString() ?? throw new JsonException("Media key is missing."),
            value.GetProperty("nonce").GetString() ?? throw new JsonException("Media nonce is missing."),
            value.TryGetProperty("width", out JsonElement width) ? width.GetInt32() : null,
            value.TryGetProperty("height", out JsonElement height) ? height.GetInt32() : null,
            value.TryGetProperty("duration_ms", out JsonElement duration) ? duration.GetInt64() : null,
            preview);
    }

    private static string ToWireTextEntityType(TextEntityType type) => type switch
    {
        TextEntityType.Bold => "bold",
        TextEntityType.Italic => "italic",
        TextEntityType.Monospace => "monospace",
        TextEntityType.Strikethrough => "strikethrough",
        TextEntityType.Underline => "underline",
        TextEntityType.Quote => "quote",
        TextEntityType.Spoiler => "spoiler",
        _ => throw new ArgumentOutOfRangeException(nameof(type)),
    };

    private static TextEntityType? ParseTextEntityType(string? value) => value?.ToLowerInvariant() switch
    {
        "bold" => TextEntityType.Bold,
        "italic" => TextEntityType.Italic,
        "monospace" => TextEntityType.Monospace,
        "strikethrough" => TextEntityType.Strikethrough,
        "underline" => TextEntityType.Underline,
        "quote" => TextEntityType.Quote,
        "spoiler" => TextEntityType.Spoiler,
        _ => null,
    };

    private static bool RequiresProtocolV2(MessageContent content) =>
        content.Kind is MessageKind.MediaGroup or MessageKind.RoundVideo or MessageKind.SpoilerRequest ||
        content.EffectiveMediaItems.Count > 1 ||
        content.Spoiler ||
        content.EffectiveRevealedFor.Count > 0 ||
        content.RoundVideoShape is not null ||
        content.TargetMessageId is not null ||
        content.TargetUsername is not null ||
        content.ForwardedFromUsername is not null ||
        content.Call is not null;

    internal static MessageDeliveryState GetDeliveryState(WireMessage message)
    {
        return message.ReadCount > 0 ? MessageDeliveryState.Read : MessageDeliveryState.Sent;
    }

    internal static byte[] Pad(ReadOnlySpan<byte> plaintext)
    {
        int rawSize = sizeof(int) + plaintext.Length;
        int paddedSize = ((rawSize + PaddingBlockSize - 1) / PaddingBlockSize) * PaddingBlockSize;
        byte[] padded = new byte[paddedSize];
        BinaryPrimitives.WriteInt32BigEndian(padded, plaintext.Length);
        plaintext.CopyTo(padded.AsSpan(sizeof(int)));
        return padded;
    }

    internal static byte[] Unpad(ReadOnlySpan<byte> padded)
    {
        if (padded.Length < sizeof(int) || padded.Length % PaddingBlockSize != 0)
        {
            throw new CryptographicException("Padding сообщения повреждён.");
        }

        int length = BinaryPrimitives.ReadInt32BigEndian(padded);
        if (length < 0 || length > padded.Length - sizeof(int))
        {
            throw new CryptographicException("Размер сообщения в padding неверен.");
        }

        ReadOnlySpan<byte> tail = padded[(sizeof(int) + length)..];
        foreach (byte value in tail)
        {
            if (value != 0) throw new CryptographicException("Padding сообщения содержит посторонние данные.");
        }

        return padded.Slice(sizeof(int), length).ToArray();
    }

    internal static byte[] EncryptAesGcm(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> aad,
        ReadOnlySpan<byte> plaintext)
    {
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[TagSize];
        try
        {
            using var aes = new AesGcm(key, TagSize);
            aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);
            byte[] combined = new byte[ciphertext.Length + tag.Length];
            ciphertext.CopyTo(combined, 0);
            tag.CopyTo(combined, ciphertext.Length);
            return combined;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
        }
    }

    internal static byte[] DecryptAesGcm(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> aad,
        ReadOnlySpan<byte> combined)
    {
        if (nonce.Length != NonceSize || combined.Length < TagSize)
        {
            throw new CryptographicException("AES-GCM payload повреждён.");
        }

        int ciphertextLength = combined.Length - TagSize;
        byte[] plaintext = new byte[ciphertextLength];
        using var aes = new AesGcm(key, TagSize);
        aes.Decrypt(
            nonce,
            combined[..ciphertextLength],
            combined[ciphertextLength..],
            plaintext,
            aad);
        return plaintext;
    }

    private byte[] RandomBytes(int size)
    {
        byte[] value = new byte[size];
        _random.GetBytes(value);
        return value;
    }

    private static string? GetOptionalString(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out JsonElement value) || value.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
        {
            return null;
        }

        string? text = value.GetString();
        return string.IsNullOrWhiteSpace(text) ? null : text;
    }

    private static string ToWireKind(MessageKind kind) => kind switch
    {
        MessageKind.MediaGroup => "media_group",
        MessageKind.RoundVideo => "round_video",
        MessageKind.SpoilerRequest => "spoiler_request",
        _ => kind.ToString().ToLowerInvariant(),
    };

    private static MessageKind ParseKind(string? value) => value?.ToLowerInvariant() switch
    {
        "text" => MessageKind.Text,
        "file" => MessageKind.File,
        "photo" => MessageKind.Photo,
        "video" => MessageKind.Video,
        "media_group" => MessageKind.MediaGroup,
        "audio" => MessageKind.Audio,
        "voice" => MessageKind.Voice,
        "round_video" => MessageKind.RoundVideo,
        "spoiler_request" => MessageKind.SpoilerRequest,
        "call" => MessageKind.Call,
        _ => MessageKind.System,
    };

    private static string ToWireShape(RoundVideoShape shape) => shape.ToString().ToLowerInvariant();

    private static RoundVideoShape? ParseShape(string? value) => value?.ToLowerInvariant() switch
    {
        "circle" => RoundVideoShape.Circle,
        "square" => RoundVideoShape.Square,
        "heart" => RoundVideoShape.Heart,
        _ => null,
    };

    public void Dispose()
    {
        if (_disposed) return;
        if (_ownsRandom) _random.Dispose();
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    public sealed record EncryptedMedia(byte[] Key, byte[] Nonce, byte[] Ciphertext) : IDisposable
    {
        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(Key);
            CryptographicOperations.ZeroMemory(Nonce);
            CryptographicOperations.ZeroMemory(Ciphertext);
        }
    }
}
