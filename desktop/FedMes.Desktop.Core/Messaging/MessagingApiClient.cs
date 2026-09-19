using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using FedMes.Desktop.Core.Storage;
using FedMes.Desktop.Core.Transport;

namespace FedMes.Desktop.Core.Messaging;

public sealed class MessagingApiClient : IDisposable
{
    private const int MaximumJsonResponseBytes = 64 * 1024 * 1024;
    private const int MaximumInitialMediaBufferBytes = 8 * 1024 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly ServerEndpointMode _endpointMode;

    public MessagingApiClient(
        HttpClient? httpClient = null,
        ServerEndpointMode endpointMode = ServerEndpointMode.Production)
    {
        if (!Enum.IsDefined(endpointMode))
        {
            throw new ArgumentOutOfRangeException(nameof(endpointMode));
        }

        _http = httpClient ?? new HttpClient();
        _ownsHttp = httpClient is null;
        _endpointMode = endpointMode;
        if (_ownsHttp)
        {
            _http.Timeout = TimeSpan.FromMinutes(30);
        }
    }

    public async Task RegisterEncryptionKeyAsync(
        DesktopAccount account,
        string algorithm,
        string publicKeySpkiBase64,
        CancellationToken cancellationToken)
    {
        await SendAsync<object>(
            account,
            HttpMethod.Put,
            "/api/v1/devices/encryption-key",
            new
            {
                version = 1,
                algorithm,
                public_key_spki = publicKeySpkiBase64,
            },
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<ChatSummary>> ListChatsAsync(
        DesktopAccount account,
        CancellationToken cancellationToken)
    {
        ChatListResponse response = await SendAsync<ChatListResponse>(
            account,
            HttpMethod.Get,
            "/api/v1/chats",
            null,
            cancellationToken).ConfigureAwait(false);
        return (response.Chats ?? []).Select(chat => new ChatSummary(
            chat.Id,
            chat.Kind,
            chat.Title,
            chat.Members ?? [],
            chat.LastSequence,
            chat.LastMessageAt,
            string.IsNullOrWhiteSpace(chat.PinnedMessageId) ? null : chat.PinnedMessageId,
            chat.UnreadCount)).ToArray();
    }

    public async Task<IReadOnlyList<ChatDevice>> ListDevicesAsync(
        DesktopAccount account,
        string chatId,
        CancellationToken cancellationToken)
    {
        DeviceListResponse response = await SendAsync<DeviceListResponse>(
            account,
            HttpMethod.Get,
            $"/api/v1/chats/{Segment(chatId)}/devices",
            null,
            cancellationToken).ConfigureAwait(false);
        return (response.Devices ?? []).Select(device => new ChatDevice(
            device.Id,
            device.Username,
            device.EncryptionAlgorithm,
            device.EncryptionPublicKeySpkiBase64,
            device.IdentityAlgorithm ?? string.Empty,
            device.IdentityPublicKeySpkiBase64 ?? string.Empty,
            device.RatchetBundleVersion)).ToArray();
    }

    public async Task<MessagePage> ListMessagesAsync(
        DesktopAccount account,
        string chatId,
        long after,
        long before,
        int limit,
        CancellationToken cancellationToken)
    {
        if (after > 0 && before > 0)
        {
            throw new ArgumentException("Only one message cursor can be used.");
        }

        string query = $"?limit={Math.Clamp(limit, 1, 200)}";
        if (after > 0) query += $"&after={after}";
        if (before > 0) query += $"&before={before}";
        MessageListResponse response = await SendAsync<MessageListResponse>(
            account,
            HttpMethod.Get,
            $"/api/v1/chats/{Segment(chatId)}/messages{query}",
            null,
            cancellationToken).ConfigureAwait(false);
        return new MessagePage((response.Messages ?? []).Select(ToWireMessage).ToArray(), response.HasMoreBefore);
    }

    public async Task<MessagePage> ListEnvelopeRepairMessagesAsync(
        DesktopAccount account,
        string chatId,
        long before,
        int limit,
        CancellationToken cancellationToken)
    {
        string query = $"?limit={Math.Clamp(limit, 1, 200)}";
        if (before > 0) query += $"&before={before}";
        MessageListResponse response = await SendAsync<MessageListResponse>(
            account,
            HttpMethod.Get,
            $"/api/v1/chats/{Segment(chatId)}/envelope-repair{query}",
            null,
            cancellationToken).ConfigureAwait(false);
        return new MessagePage((response.Messages ?? []).Select(ToWireMessage).ToArray(), response.HasMoreBefore);
    }

    public async Task<long> ReserveCryptoSequenceAsync(
        DesktopAccount account,
        string chatId,
        string requestId,
        string messageId,
        CancellationToken cancellationToken)
    {
        CryptoSequenceResponse response = await SendAsync<CryptoSequenceResponse>(
            account,
            HttpMethod.Post,
            $"/api/v3/chats/{Segment(chatId)}/crypto-sequence",
            new { version = 2, request_id = requestId, message_id = messageId },
            cancellationToken).ConfigureAwait(false);
        if (response.Version != 2 || !string.Equals(response.MessageId, messageId, StringComparison.Ordinal) ||
            response.CryptoSequence <= 0)
            throw new CryptographicException("Invalid crypto sequence response.");
        return response.CryptoSequence;
    }

    internal async Task<IReadOnlyList<CryptoSequenceLeaseItem>> ReserveCryptoSequenceLeaseAsync(
        DesktopAccount account,
        string chatId,
        IReadOnlyList<(string RequestId, string MessageId)> identifiers,
        CancellationToken cancellationToken)
    {
        if (identifiers.Count is < 1 or > 16) throw new ArgumentOutOfRangeException(nameof(identifiers));
        CryptoSequenceLeaseResponse response = await SendAsync<CryptoSequenceLeaseResponse>(
            account,
            HttpMethod.Post,
            $"/api/v3/chats/{Segment(chatId)}/crypto-sequence/lease",
            new
            {
                version = 1,
                items = identifiers.Select(value => new { request_id = value.RequestId, message_id = value.MessageId }).ToArray(),
            },
            cancellationToken).ConfigureAwait(false);
        IReadOnlyList<CryptoSequenceLeaseItem> items = response.Items ?? [];
        if (response.Version != 1 || items.Count != identifiers.Count ||
            items.Any(value => value.CryptoSequence <= 0 || string.IsNullOrWhiteSpace(value.RequestId) || string.IsNullOrWhiteSpace(value.MessageId)) ||
            items.Select(value => value.MessageId).Distinct(StringComparer.Ordinal).Count() != items.Count)
        {
            throw new CryptographicException("Invalid crypto sequence lease response.");
        }
        return items;
    }

    public async Task<CreatedMessageReceipt> CreateMessageAsync(
        DesktopAccount account,
        string chatId,
        PreparedMessage message,
        CancellationToken cancellationToken)
    {
        CreateMessageResponse response = await SendAsync<CreateMessageResponse>(
            account,
            HttpMethod.Post,
            $"/api/v1/chats/{Segment(chatId)}/messages",
            ToRequest(message),
            cancellationToken).ConfigureAwait(false);
        MessageWireModel created = response.Message;
        return new CreatedMessageReceipt(
            created.Sequence,
            created.Id,
            created.CreatedAt,
            new HashSet<string>(created.EnvelopeDeviceIds ?? [], StringComparer.Ordinal));
    }

    public async Task UpdateMessageAsync(
        DesktopAccount account,
        string chatId,
        PreparedMessage message,
        CancellationToken cancellationToken)
    {
        await SendAsync<object>(
            account,
            HttpMethod.Put,
            $"/api/v1/chats/{Segment(chatId)}/messages/{Segment(message.Id)}",
            ToRequest(message),
            cancellationToken).ConfigureAwait(false);
    }

    public async Task AddMessageEnvelopesAsync(
        DesktopAccount account,
        string chatId,
        string messageId,
        IReadOnlyList<MessageEnvelope> envelopes,
        CancellationToken cancellationToken)
    {
        if (envelopes.Count == 0) return;
        await SendAsync<object>(
            account,
            HttpMethod.Put,
            $"/api/v1/chats/{Segment(chatId)}/messages/{Segment(messageId)}/envelopes",
            new
            {
                version = 1,
                envelopes = envelopes.Select(envelope => new
                {
                    device_id = envelope.DeviceId,
                    algorithm = envelope.Algorithm,
                    ciphertext = envelope.CiphertextBase64,
                }).ToArray(),
            },
            cancellationToken).ConfigureAwait(false);
    }

    public async Task DeleteMessageAsync(
        DesktopAccount account,
        string chatId,
        string messageId,
        MessageDeleteScope scope,
        CancellationToken cancellationToken)
    {
        string wireScope = scope == MessageDeleteScope.Everyone ? "everyone" : "me";
        await SendAsync<object>(
            account,
            HttpMethod.Delete,
            $"/api/v1/chats/{Segment(chatId)}/messages/{Segment(messageId)}?scope={wireScope}",
            null,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task MarkReceiptsAsync(
        DesktopAccount account,
        string chatId,
        IReadOnlyCollection<string> deliveredMessageIds,
        IReadOnlyCollection<string> readMessageIds,
        CancellationToken cancellationToken)
    {
        if (deliveredMessageIds.Count == 0 && readMessageIds.Count == 0) return;
        await SendAsync<object>(
            account,
            HttpMethod.Post,
            $"/api/v1/chats/{Segment(chatId)}/receipts",
            new
            {
                version = 1,
                delivered_message_ids = deliveredMessageIds,
                read_message_ids = readMessageIds,
            },
            cancellationToken).ConfigureAwait(false);
    }

    public async Task MarkReadCursorAsync(
        DesktopAccount account,
        string chatId,
        long maxReadSequence,
        CancellationToken cancellationToken)
    {
        if (maxReadSequence <= 0) return;
        await SendAsync<object>(
            account,
            HttpMethod.Put,
            $"/api/v1/chats/{Segment(chatId)}/read-cursor",
            new { version = 1, max_read_sequence = maxReadSequence },
            cancellationToken).ConfigureAwait(false);
    }

    public async Task SetTypingAsync(
        DesktopAccount account,
        string chatId,
        bool typing,
        CancellationToken cancellationToken)
    {
        await SendAsync<object>(
            account,
            HttpMethod.Put,
            $"/api/v1/chats/{Segment(chatId)}/typing",
            new { version = 1, typing },
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<TypingState>> ListTypingAsync(
        DesktopAccount account,
        string chatId,
        CancellationToken cancellationToken)
    {
        TypingListResponse response = await SendAsync<TypingListResponse>(
            account,
            HttpMethod.Get,
            $"/api/v1/chats/{Segment(chatId)}/typing",
            null,
            cancellationToken).ConfigureAwait(false);
        return (response.Typing ?? []).Select(item => new TypingState(item.Username)).ToArray();
    }

    public async Task PinMessageAsync(
        DesktopAccount account,
        string chatId,
        string messageId,
        CancellationToken cancellationToken)
    {
        await SendAsync<object>(
            account,
            HttpMethod.Put,
            $"/api/v1/chats/{Segment(chatId)}/pin/{Segment(messageId)}",
            null,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task UnpinMessageAsync(
        DesktopAccount account,
        string chatId,
        CancellationToken cancellationToken)
    {
        await SendAsync<object>(
            account,
            HttpMethod.Delete,
            $"/api/v1/chats/{Segment(chatId)}/pin",
            null,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task HeartbeatAsync(
        DesktopAccount account,
        bool showExact,
        CancellationToken cancellationToken)
    {
        await SendAsync<object>(
            account,
            HttpMethod.Post,
            "/api/v1/presence/heartbeat",
            new { version = 1, show_exact = showExact },
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<PresenceState>> ListPresenceAsync(
        DesktopAccount account,
        CancellationToken cancellationToken)
    {
        PresenceListResponse response = await SendAsync<PresenceListResponse>(
            account,
            HttpMethod.Get,
            "/api/v1/presence",
            null,
            cancellationToken).ConfigureAwait(false);
        return (response.Presence ?? []).Select(item => new PresenceState(
            item.Username,
            item.Online,
            item.LastSeenAt,
            item.ShowExact,
            item.LastSeenCategory)).ToArray();
    }

    public async Task<long> WaitForEventsAsync(
        DesktopAccount account,
        long after,
        CancellationToken cancellationToken)
    {
        EventSequenceResponse response = await SendAsync<EventSequenceResponse>(
            account,
            HttpMethod.Get,
            $"/api/v1/events?after={Math.Max(0, after)}",
            null,
            cancellationToken).ConfigureAwait(false);
        return response.Sequence;
    }

    public async Task UploadMediaAsync(
        DesktopAccount account,
        string chatId,
        string mediaId,
        byte[] ciphertext,
        IProgress<double>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(ciphertext);
        using var request = CreateRequest(account, HttpMethod.Put, $"/api/v1/chats/{Segment(chatId)}/media/{Segment(mediaId)}");
        request.Content = progress is null
            ? new ByteArrayContent(ciphertext)
            : new ProgressByteArrayContent(ciphertext, progress);
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        using HttpResponseMessage response = await _http.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
    }

    public async Task<byte[]> DownloadMediaAsync(
        DesktopAccount account,
        string chatId,
        string mediaId,
        IProgress<double>? progress,
        CancellationToken cancellationToken)
    {
        using var request = CreateRequest(account, HttpMethod.Get, $"/api/v1/chats/{Segment(chatId)}/media/{Segment(mediaId)}");
        using HttpResponseMessage response = await _http.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        long? total = response.Content.Headers.ContentLength;
        if (total is < 0)
        {
            throw new InvalidDataException("The media response has an invalid length.");
        }

        await using Stream input = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        int initialCapacity = total is > 0 and <= MaximumInitialMediaBufferBytes ? (int)total.Value : 0;
        using var output = new MemoryStream(initialCapacity);
        byte[] buffer = new byte[64 * 1024];
        long readTotal = 0;
        try
        {
            while (true)
            {
                int count = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (count == 0) break;
                await output.WriteAsync(buffer.AsMemory(0, count), cancellationToken).ConfigureAwait(false);
                readTotal += count;

                if (total > 0) progress?.Report(Math.Clamp((double)readTotal / total.Value, 0, 1));
            }

            progress?.Report(1);
            return output.ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    public async Task DeleteMediaAsync(
        DesktopAccount account,
        string chatId,
        string mediaId,
        CancellationToken cancellationToken)
    {
        await SendAsync<object>(
            account,
            HttpMethod.Delete,
            $"/api/v1/chats/{Segment(chatId)}/media/{Segment(mediaId)}",
            null,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<AccountDevice>> ListAccountDevicesAsync(
        DesktopAccount account,
        CancellationToken cancellationToken)
    {
        AccountDeviceListResponse response = await SendAsync<AccountDeviceListResponse>(
            account,
            HttpMethod.Get,
            "/api/v1/account/devices",
            null,
            cancellationToken).ConfigureAwait(false);
        return (response.Devices ?? []).Select(device => new AccountDevice(
            device.Id,
            device.DisplayName,
            device.Platform,
            device.CreatedAt,
            device.LastSeenAt,
            device.Current)).ToArray();
    }

    public async Task RevokeDeviceAsync(
        DesktopAccount account,
        string deviceId,
        CancellationToken cancellationToken)
    {
        await SendAsync<object>(
            account,
            HttpMethod.Delete,
            $"/api/v1/account/devices/{Segment(deviceId)}",
            null,
            cancellationToken).ConfigureAwait(false);
    }

    public async Task TerminateOtherDevicesAsync(
        DesktopAccount account,
        CancellationToken cancellationToken)
    {
        await SendAsync<object>(
            account,
            HttpMethod.Post,
            "/api/v1/account/devices/terminate-others",
            null,
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<T> SendAsync<T>(
        DesktopAccount account,
        HttpMethod method,
        string path,
        object? body,
        CancellationToken cancellationToken)
    {
        using var request = CreateRequest(account, method, path);
        if (body is not null) request.Content = JsonContent.Create(body, options: JsonOptions);
        using HttpResponseMessage response = await _http.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken).ConfigureAwait(false);
        await EnsureSuccessAsync(response, cancellationToken).ConfigureAwait(false);
        if (typeof(T) == typeof(object) || response.StatusCode == HttpStatusCode.NoContent)
        {
            return (T)(object)new object();
        }

        return await HttpResponseReader.ReadJsonAsync<T>(
            response,
            JsonOptions,
            MaximumJsonResponseBytes,
            cancellationToken).ConfigureAwait(false);
    }

    private static object ToRequest(PreparedMessage message)
    {
        if (message.ProtocolVersion == 1)
        {
            return new
            {
                version = 1,
                id = message.Id,
                ciphertext = message.CiphertextBase64,
                nonce = message.NonceBase64,
                aad = message.Aad,
                envelopes = message.Envelopes.Select(envelope => new
                {
                    device_id = envelope.DeviceId,
                    algorithm = envelope.Algorithm,
                    ciphertext = envelope.CiphertextBase64,
                }).ToArray(),
            };
        }
        return new
        {
            version = message.ProtocolVersion,
            id = message.Id,
            ciphertext = message.CiphertextBase64,
            nonce = message.NonceBase64,
            aad = message.Aad,
            crypto_version = message.CryptoVersion,
            room_key_version = message.RoomKeyVersion,
            aad_version = message.AadVersion,
            crypto_sequence = message.CryptoSequence,
            encryption_algorithm = message.EncryptionAlgorithm,
            message_type = message.MessageType,
            sequence_request_id = message.SequenceRequestId,
            envelopes = Array.Empty<object>(),
            ratchet_envelopes = message.EffectiveRatchetEnvelopes.Select(envelope => new
            {
                recipient_device_id = envelope.RecipientDeviceId,
                sender_curve25519_key = envelope.SenderCurve25519Key,
                session_id = envelope.SessionId,
                message_type = envelope.MessageType,
                ciphertext = envelope.CiphertextBase64Url,
                ciphertext_sha256 = envelope.CiphertextSha256Hex,
            }).ToArray(),
        };
    }

    private HttpRequestMessage CreateRequest(DesktopAccount account, HttpMethod method, string path)
    {
        Uri server = ServerEndpointPolicy.Normalize(account.ServerUrl, _endpointMode);
        var request = new HttpRequestMessage(method, ServerEndpointPolicy.Build(server, path, _endpointMode));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", account.SessionToken);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.CacheControl = new CacheControlHeaderValue { NoStore = true };
        return request;
    }

    private static WireMessage ToWireMessage(MessageWireModel value)
    {
        MessageEnvelope? envelope = value.Envelope is null
            ? null
            : new MessageEnvelope(value.Envelope.DeviceId, value.Envelope.Algorithm, value.Envelope.CiphertextBase64);
        RatchetMessageEnvelope? ratchetEnvelope = value.RatchetEnvelope is null
            ? null
            : new RatchetMessageEnvelope(
                value.RatchetEnvelope.RecipientDeviceId,
                value.RatchetEnvelope.SenderCurve25519Key,
                value.RatchetEnvelope.SessionId,
                value.RatchetEnvelope.MessageType,
                value.RatchetEnvelope.CiphertextBase64Url,
                value.RatchetEnvelope.CiphertextSha256Hex);
        return new WireMessage(
            value.Sequence,
            value.Id,
            value.ChatId,
            value.SenderUsername,
            value.SenderDeviceId,
            value.CiphertextBase64,
            value.NonceBase64,
            value.Aad,
            value.CreatedAt,
            value.EditedAt,
            envelope,
            new HashSet<string>(value.EnvelopeDeviceIds ?? [], StringComparer.Ordinal),
            value.RecipientCount,
            value.DeliveredCount,
            value.ReadCount,
            value.CryptoVersion <= 0 ? 1 : value.CryptoVersion,
            value.RoomKeyVersion <= 0 ? 1 : value.RoomKeyVersion,
            value.AadVersion <= 0 ? 1 : value.AadVersion,
            value.CryptoSequence,
            string.IsNullOrWhiteSpace(value.EncryptionAlgorithm) ? "fedmes-aes256gcm-rsa-oaep-v1" : value.EncryptionAlgorithm,
            string.IsNullOrWhiteSpace(value.MessageType) ? "legacy" : value.MessageType,
            ratchetEnvelope);
    }

    private static async Task EnsureSuccessAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        if (response.IsSuccessStatusCode) return;
        string body = await HttpResponseReader.ReadErrorBodyAsync(response, cancellationToken).ConfigureAwait(false);
        string code = $"http_{(int)response.StatusCode}";
        try
        {
            using JsonDocument document = JsonDocument.Parse(body);
            code = document.RootElement.GetProperty("error").GetProperty("code").GetString() ?? code;
        }
        catch (JsonException)
        {
        }

        throw new FedMesApiException(response.StatusCode, code, code switch
        {
            "session_invalid" => "Сессия Desktop недействительна или устройство отключено.",
            "chat_forbidden" => "Нет доступа к этому чату.",
            "message_not_found" => "Сообщение уже удалено.",
            "media_not_found" => "Медиафайл больше недоступен.",
            "message_conflict" => "Сообщение было изменено на другом устройстве.",
            _ => $"Сервер FedMes отклонил запрос: {code}",
        });
    }

    private static string Segment(string value) => Uri.EscapeDataString(value);

    public void Dispose()
    {
        if (_ownsHttp) _http.Dispose();
    }

    private sealed class ProgressByteArrayContent : HttpContent
    {
        private readonly byte[] _buffer;
        private readonly IProgress<double> _progress;

        public ProgressByteArrayContent(byte[] buffer, IProgress<double> progress)
        {
            _buffer = buffer;
            _progress = progress;
            Headers.ContentLength = buffer.LongLength;
        }

        protected override bool TryComputeLength(out long length)
        {
            length = _buffer.LongLength;
            return true;
        }

        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            const int blockSize = 64 * 1024;
            long sent = 0;
            for (int offset = 0; offset < _buffer.Length; offset += blockSize)
            {
                int count = Math.Min(blockSize, _buffer.Length - offset);
                await stream.WriteAsync(_buffer.AsMemory(offset, count)).ConfigureAwait(false);
                sent += count;
                _progress.Report((double)sent / _buffer.LongLength);
            }

            _progress.Report(1);
        }
    }
}

public sealed class FedMesApiException : HttpRequestException
{
    public FedMesApiException(HttpStatusCode statusCode, string code, string message)
        : base(message, null, statusCode)
    {
        Code = code;
    }

    public string Code { get; }
}
