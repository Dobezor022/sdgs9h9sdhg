using System.Collections.Concurrent;
using System.Security.Cryptography;
using FedMes.Desktop.Core.Devices;
using FedMes.Desktop.Core.AccountSecurity;
using FedMes.Desktop.Core.CryptoCore;
using FedMes.Desktop.Core.Calling;
using FedMes.Desktop.Core.Transport2;
using FedMes.Desktop.Core.Sessions;
using FedMes.Desktop.Core.Storage;

namespace FedMes.Desktop.Core.Messaging;

public sealed class MessagingRepository : IDisposable
{
    private const int PageSize = 100;
    private const int EnvelopeRepairPageSize = 200;
    private const int MaxMediaItems = 10;
    private const int MaxTextLength = 16_384;
    private static readonly TimeSpan DeviceCacheLifetime = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan SequenceLeaseLifetime = TimeSpan.FromMinutes(8);
    private const int SequencePoolTarget = 8;
    private readonly DesktopSessionManager _sessionManager;
    private readonly MessagingApiClient _api;
    private readonly DesktopDeviceIdentity _identity;
    private readonly MessageCryptoService _crypto;
    private readonly RatchetHttpClient _ratchetApi;
    private readonly WindowsRatchetMessageCrypto _ratchetCrypto;
    private readonly FedMesSecurity2Client _security2;
    private readonly WindowsAccountVaultStore _vaultStore;
    private readonly ConcurrentDictionary<string, CachedDevices> _deviceCache = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, ChatSummary> _chatCache = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, ConcurrentQueue<ReservedSequence>> _sequencePools = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, ReservedSequence> _allocatedSequences = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _sequencePoolGates = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, CachedDecryptedMessage> _decryptedMessageCache = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim _encryptionRegistrationGate = new(1, 1);
    private string? _registeredEncryptionIdentity;
    private bool _disposed;

    public MessagingRepository(
        DesktopSessionManager sessionManager,
        MessagingApiClient api,
        DesktopDeviceIdentity identity,
        WindowsAccountVaultStore vaultStore,
        FedMesCryptoWorkerClient cryptoWorker)
    {
        _sessionManager = sessionManager ?? throw new ArgumentNullException(nameof(sessionManager));
        _api = api ?? throw new ArgumentNullException(nameof(api));
        _identity = identity ?? throw new ArgumentNullException(nameof(identity));
        _vaultStore = vaultStore ?? throw new ArgumentNullException(nameof(vaultStore));
        _crypto = new MessageCryptoService(_identity);
        _security2 = new FedMesSecurity2Client(cryptoWorker);
        _ratchetApi = new RatchetHttpClient();
        _ratchetCrypto = new WindowsRatchetMessageCrypto(
            cryptoWorker ?? throw new ArgumentNullException(nameof(cryptoWorker)),
            _ratchetApi,
            new WindowsRatchetStore(),
            _vaultStore,
            _identity);
    }

    public async Task<DesktopAccount> InitializeAsync(bool showExactPresence, CancellationToken cancellationToken)
    {
        DesktopAccount account = await AccountAsync(cancellationToken).ConfigureAwait(false);
        await EnsureCurrentEncryptionKeyRegisteredAsync(account, force: true, cancellationToken: cancellationToken)
            .ConfigureAwait(false);
        if (string.Equals(account.AuthenticationState, AccountSecurityProtocol.Ready, StringComparison.Ordinal) &&
            _vaultStore.Exists(account.ServerUrl, account.Username))
        {
            await _ratchetCrypto.InitializeAsync(account, cancellationToken).ConfigureAwait(false);
        }
        _deviceCache.Clear();
        _chatCache.Clear();
        _sequencePools.Clear();
        _allocatedSequences.Clear();
        await _api.HeartbeatAsync(account, false, cancellationToken).ConfigureAwait(false);
        return account;
    }

    public async Task<IReadOnlyList<ChatSummary>> ListChatsAsync(CancellationToken cancellationToken)
    {
        IReadOnlyList<ChatSummary> chats = await _api.ListChatsAsync(
            await AccountAsync(cancellationToken).ConfigureAwait(false), cancellationToken).ConfigureAwait(false);
        foreach (ChatSummary chat in chats) _chatCache[chat.Id] = chat;
        return chats;
    }

    public string AllocateOutgoingMessageId(string chatId)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        if (_sequencePools.TryGetValue(chatId, out ConcurrentQueue<ReservedSequence>? queue))
        {
            while (queue.TryDequeue(out ReservedSequence? reserved))
            {
                if (reserved.ExpiresAt > now)
                {
                    _allocatedSequences[reserved.MessageId] = reserved;
                    return reserved.MessageId;
                }
            }
        }
        return Guid.NewGuid().ToString();
    }

    public async Task PrewarmChatAsync(string chatId, CancellationToken cancellationToken)
    {
        DesktopAccount account = await AccountAsync(cancellationToken).ConfigureAwait(false);
        _ = await GetChatAsync(account, chatId, cancellationToken).ConfigureAwait(false);
        IReadOnlyList<ChatDevice> devices = await AllDevicesAsync(account, chatId, forceRefresh: false, cancellationToken)
            .ConfigureAwait(false);
        bool canUseRatchet = string.Equals(account.AuthenticationState, AccountSecurityProtocol.Ready, StringComparison.Ordinal) &&
            _vaultStore.Exists(account.ServerUrl, account.Username) &&
            devices.Count > 0 && devices.All(IsRatchetReady) &&
            devices.Any(value => string.Equals(value.Id, account.DeviceId, StringComparison.Ordinal));
        if (canUseRatchet) await TopUpSequencePoolAsync(account, chatId, cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<PresenceState>> ListPresenceAsync(CancellationToken cancellationToken) =>
        await _api.ListPresenceAsync(await AccountAsync(cancellationToken).ConfigureAwait(false), cancellationToken)
            .ConfigureAwait(false);

    public async Task<IReadOnlyList<TypingState>> ListTypingAsync(string chatId, CancellationToken cancellationToken) =>
        await _api.ListTypingAsync(await AccountAsync(cancellationToken).ConfigureAwait(false), chatId, cancellationToken)
            .ConfigureAwait(false);

    public async Task SetTypingAsync(string chatId, bool typing, CancellationToken cancellationToken) =>
        await _api.SetTypingAsync(await AccountAsync(cancellationToken).ConfigureAwait(false), chatId, typing, cancellationToken)
            .ConfigureAwait(false);

    public async Task HeartbeatAsync(bool showExactPresence, CancellationToken cancellationToken) =>
        await _api.HeartbeatAsync(
            await AccountAsync(cancellationToken).ConfigureAwait(false),
            false,
            cancellationToken).ConfigureAwait(false);

    public async Task<DecryptedMessagePage> LoadLatestMessagesAsync(
        string chatId,
        bool markRead,
        CancellationToken cancellationToken) =>
        await LoadPageAsync(chatId, 0, 0, PageSize, markRead, cancellationToken).ConfigureAwait(false);

    public async Task<DecryptedMessagePage> LoadOlderMessagesAsync(
        string chatId,
        long before,
        CancellationToken cancellationToken) =>
        await LoadPageAsync(chatId, 0, before, PageSize, false, cancellationToken).ConfigureAwait(false);

    public async Task<DecryptedMessagePage> LoadMessagesAfterAsync(
        string chatId,
        long after,
        bool markRead,
        CancellationToken cancellationToken) =>
        await LoadPageAsync(chatId, after, 0, 200, markRead, cancellationToken).ConfigureAwait(false);

    public async Task<DecryptedMessagePage> LoadRecentCallSignalsAsync(
        string chatId,
        CancellationToken cancellationToken) =>
        await LoadPageAsync(chatId, 0, 0, 24, false, cancellationToken).ConfigureAwait(false);

    public async Task<string> SendTextAsync(
        string chatId,
        string text,
        string? replyToId,
        bool spoiler,
        CancellationToken cancellationToken) =>
        (await SendTextMessageAsync(chatId, text, replyToId, spoiler, cancellationToken).ConfigureAwait(false)).Id;

    public Task<DecryptedMessage> SendTextMessageAsync(
        string chatId,
        string text,
        string? replyToId,
        bool spoiler,
        CancellationToken cancellationToken) =>
        SendTextMessageAsync(chatId, text, replyToId, spoiler, null, cancellationToken);

    public async Task<DecryptedMessage> SendTextMessageAsync(
        string chatId,
        string text,
        string? replyToId,
        bool spoiler,
        IReadOnlyList<TextEntity>? textEntities,
        CancellationToken cancellationToken,
        string? messageId = null)
    {
        NormalizedFormattedText normalized = TextFormatting.Normalize(text, textEntities);
        if (normalized.Text.Length == 0) throw new ArgumentException("Сообщение пустое.", nameof(text));
        if (normalized.Text.Length > MaxTextLength) throw new ArgumentException("Сообщение слишком длинное.", nameof(text));
        var content = new MessageContent(
            MessageKind.Text,
            normalized.Text,
            replyToId,
            null,
            [],
            spoiler,
            TextEntities: normalized.Entities);
        return await SendContentMessageAsync(chatId, content, messageId, cancellationToken).ConfigureAwait(false);
    }

    public Task<DecryptedMessage> SendCallSignalAsync(
        string chatId,
        CallDescriptor call,
        CancellationToken cancellationToken,
        string? messageId = null)
    {
        string text = call.Event switch
        {
            CallEvent.Invite => call.Mode == CallMode.Audio ? "Аудиозвонок" : "Видеозвонок",
            CallEvent.Ended => "Звонок завершён",
            CallEvent.Declined => "Звонок отклонён",
            CallEvent.NoAnswer => "Нет ответа",
            _ => "Звонок не состоялся",
        };
        return SendContentMessageAsync(
            chatId,
            new MessageContent(MessageKind.Call, text, null, null, [], Call: call),
            messageId ?? AllocateOutgoingMessageId(chatId),
            cancellationToken);
    }

    public async Task<DesktopCallSession> StartOutgoingCallAsync(
        string chatId,
        CallMode mode,
        CancellationToken cancellationToken)
    {
        DesktopAccount account = await AccountAsync(cancellationToken).ConfigureAwait(false);
        CallDescriptor descriptor = FedMesRealtimeCallTransport.CreateDescriptor(account.Username, mode);
        byte[] capability = FedMesRealtimeCallTransport.CapabilityBytes(descriptor);
        try
        {
            using var blind = new BlindObjectClient();
            await blind.RegisterRouteAsync(
                ServerUri(account),
                account.SessionToken,
                BlindObjectClient.RouteDigest(capability),
                descriptor.Generation,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(capability);
        }

        await PrewarmChatAsync(chatId, cancellationToken).ConfigureAwait(false);
        await SendCallSignalAsync(chatId, descriptor, cancellationToken).ConfigureAwait(false);
        var transport = new FedMesRealtimeCallTransport(account.DeviceId, descriptor, _security2);
        await transport.StartAsync(ServerUri(account), cancellationToken).ConfigureAwait(false);
        await transport.SendHelloAsync(cancellationToken).ConfigureAwait(false);
        return new DesktopCallSession(descriptor, transport);
    }

    public async Task<DesktopCallSession> AcceptIncomingCallAsync(
        CallDescriptor descriptor,
        CancellationToken cancellationToken)
    {
        DesktopAccount account = await AccountAsync(cancellationToken).ConfigureAwait(false);
        var transport = new FedMesRealtimeCallTransport(account.DeviceId, descriptor, _security2);
        await transport.StartAsync(ServerUri(account), cancellationToken).ConfigureAwait(false);
        await transport.SendJoinAsync(cancellationToken).ConfigureAwait(false);
        return new DesktopCallSession(descriptor, transport);
    }

    private static Uri ServerUri(DesktopAccount account) => new(account.ServerUrl.TrimEnd('/') + "/");

    public Task EditTextAsync(
        string chatId,
        string messageId,
        string text,
        string? replyToId,
        bool spoiler,
        CancellationToken cancellationToken) =>
        EditTextAsync(chatId, messageId, text, replyToId, spoiler, null, cancellationToken);

    public async Task EditTextAsync(
        string chatId,
        string messageId,
        string text,
        string? replyToId,
        bool spoiler,
        IReadOnlyList<TextEntity>? textEntities,
        CancellationToken cancellationToken)
    {
        NormalizedFormattedText normalized = TextFormatting.Normalize(text, textEntities);
        if (normalized.Text.Length == 0) throw new ArgumentException("Сообщение пустое.", nameof(text));
        DesktopAccount account = await AccountAsync(cancellationToken).ConfigureAwait(false);
        var content = new MessageContent(
            MessageKind.Text,
            normalized.Text,
            replyToId,
            null,
            [],
            spoiler,
            TextEntities: normalized.Entities);
        PreparedMessage prepared = await PrepareForCurrentProtocolAsync(
            account, chatId, content, messageId, cancellationToken).ConfigureAwait(false);
        await _api.UpdateMessageAsync(account, chatId, prepared, cancellationToken).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<string>> SendAttachmentsAsync(
        string chatId,
        PreparedDesktopAttachment[] attachments,
        string caption,
        string? replyToId,
        IReadOnlyList<TextEntity>? captionEntities,
        MessageKind? forcedKind,
        RoundVideoShape? roundVideoShape,
        string? forwardedFromUsername,
        IProgress<double>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(attachments);
        if (attachments.Length == 0) throw new ArgumentException("Нет вложений.", nameof(attachments));
        foreach (PreparedDesktopAttachment attachment in attachments)
        {
            if (attachment.Bytes.Length == 0) throw new ArgumentException("Файл пустой.", nameof(attachments));
        }

        var sentIds = new List<string>();
        int processed = 0;
        foreach (PreparedDesktopAttachment[] group in attachments.Chunk(MaxMediaItems))
        {
            var groupProgress = progress is null
                ? null
                : new Progress<double>(value => progress.Report((processed + value * group.Length) / attachments.Length));
            string id = await SendAttachmentGroupAsync(
                chatId,
                group,
                caption,
                replyToId,
                captionEntities,
                forcedKind,
                roundVideoShape,
                forwardedFromUsername,
                groupProgress,
                cancellationToken).ConfigureAwait(false);
            sentIds.Add(id);
            processed += group.Length;
            caption = string.Empty;
            captionEntities = [];
            replyToId = null;
        }

        progress?.Report(1);
        return sentIds;
    }

    public async Task<string> ForwardMessageAsync(
        DecryptedMessage message,
        string targetChatId,
        IProgress<double>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(message);
        if (!message.Decryptable) throw new InvalidOperationException("Сообщение недоступно для пересылки.");
        string forwardedFrom = message.Content.ForwardedFromUsername ?? message.SenderUsername;
        IReadOnlyList<MediaDescriptor> descriptors = message.Content.EffectiveMediaItems;
        if (descriptors.Count == 0)
        {
            MessageContent forwarded = message.Content with
            {
                ReplyToId = null,
                ForwardedFromUsername = forwardedFrom,
            };
            return await SendContentAsync(targetChatId, forwarded, null, cancellationToken).ConfigureAwait(false);
        }

        var prepared = new List<PreparedDesktopAttachment>(descriptors.Count);
        try
        {
            for (int index = 0; index < descriptors.Count; index++)
            {
                MediaDescriptor descriptor = descriptors[index];
                byte[] bytes = await DownloadAttachmentAsync(message.ChatId, message.Id, descriptor, null, cancellationToken)
                    .ConfigureAwait(false);
                byte[]? preview = await DownloadPreviewAsync(message.ChatId, message.Id, descriptor, cancellationToken)
                    .ConfigureAwait(false);
                prepared.Add(new PreparedDesktopAttachment(
                    descriptor.Name,
                    descriptor.MimeType,
                    bytes,
                    preview,
                    descriptor.Width,
                    descriptor.Height,
                    descriptor.DurationMilliseconds,
                    descriptors.Count == 1 ? message.Content.EffectiveWaveform : [],
                    message.Content.Kind == MessageKind.File,
                    message.Content.Spoiler));
                progress?.Report((double)(index + 1) / (descriptors.Count * 2));
            }

            IReadOnlyList<string> ids = await SendAttachmentsAsync(
                targetChatId,
                prepared.ToArray(),
                message.Content.Text,
                null,
                message.Content.EffectiveTextEntities,
                message.Content.Kind is MessageKind.Voice or MessageKind.RoundVideo ? message.Content.Kind : null,
                message.Content.RoundVideoShape,
                forwardedFrom,
                progress,
                cancellationToken).ConfigureAwait(false);
            return ids[0];
        }
        finally
        {
            foreach (PreparedDesktopAttachment attachment in prepared)
            {
                CryptographicOperations.ZeroMemory(attachment.Bytes);
                if (attachment.PreviewBytes is not null) CryptographicOperations.ZeroMemory(attachment.PreviewBytes);
            }
        }
    }

    public async Task<byte[]> DownloadAttachmentAsync(
        string chatId,
        string messageId,
        MediaDescriptor descriptor,
        IProgress<double>? progress,
        CancellationToken cancellationToken)
    {
        DesktopAccount account = await AccountAsync(cancellationToken).ConfigureAwait(false);
        byte[] ciphertext = await _api.DownloadMediaAsync(account, chatId, descriptor.Id, progress, cancellationToken)
            .ConfigureAwait(false);
        try
        {
            return _crypto.DecryptMedia(chatId, messageId, descriptor, ciphertext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ciphertext);
        }
    }

    public async Task<byte[]?> DownloadPreviewAsync(
        string chatId,
        string messageId,
        MediaDescriptor descriptor,
        CancellationToken cancellationToken)
    {
        if (descriptor.Preview is null) return null;
        var preview = new MediaDescriptor(
            descriptor.Preview.Id,
            "preview.jpg",
            "image/jpeg",
            descriptor.Preview.OriginalSize,
            descriptor.Preview.EncryptedSize,
            descriptor.Preview.KeyBase64,
            descriptor.Preview.NonceBase64);
        return await DownloadAttachmentAsync(chatId, messageId, preview, null, cancellationToken).ConfigureAwait(false);
    }

    public async Task DeleteMessageAsync(
        string chatId,
        DecryptedMessage message,
        MessageDeleteScope scope,
        CancellationToken cancellationToken)
    {
        DesktopAccount account = await AccountAsync(cancellationToken).ConfigureAwait(false);
        await _api.DeleteMessageAsync(account, chatId, message.Id, scope, cancellationToken).ConfigureAwait(false);
        if (scope != MessageDeleteScope.Everyone) return;
        foreach (string mediaId in message.Content.EffectiveMediaItems
                     .SelectMany(media => new[] { media.Id, media.Preview?.Id })
                     .Where(id => !string.IsNullOrWhiteSpace(id))
                     .Select(id => id!)
                     .Distinct(StringComparer.Ordinal))
        {
            try
            {
                await _api.DeleteMediaAsync(account, chatId, mediaId, cancellationToken).ConfigureAwait(false);
            }
            catch (FedMesApiException error) when (error.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
            }
        }
    }

    public async Task MarkReadAsync(
        string chatId,
        IReadOnlyCollection<DecryptedMessage> messages,
        CancellationToken cancellationToken)
    {
        DesktopAccount account = await AccountAsync(cancellationToken).ConfigureAwait(false);
        long maxReadSequence = messages
            .Where(message => message.Decryptable && !string.Equals(message.SenderUsername, account.Username, StringComparison.Ordinal))
            .Select(message => message.Sequence)
            .DefaultIfEmpty(0)
            .Max();
        if (maxReadSequence > 0)
        {
            await _api.MarkReadCursorAsync(account, chatId, maxReadSequence, cancellationToken).ConfigureAwait(false);
        }
    }

    public async Task MarkReadCursorAsync(
        string chatId,
        long maxReadSequence,
        CancellationToken cancellationToken)
    {
        if (maxReadSequence <= 0) return;
        DesktopAccount account = await AccountAsync(cancellationToken).ConfigureAwait(false);
        await _api.MarkReadCursorAsync(account, chatId, maxReadSequence, cancellationToken).ConfigureAwait(false);
    }

    public async Task PinMessageAsync(string chatId, string messageId, CancellationToken cancellationToken) =>
        await _api.PinMessageAsync(await AccountAsync(cancellationToken).ConfigureAwait(false), chatId, messageId, cancellationToken)
            .ConfigureAwait(false);

    public async Task UnpinMessageAsync(string chatId, CancellationToken cancellationToken) =>
        await _api.UnpinMessageAsync(await AccountAsync(cancellationToken).ConfigureAwait(false), chatId, cancellationToken)
            .ConfigureAwait(false);

    public async Task<long> WaitForEventsAsync(long after, CancellationToken cancellationToken) =>
        await _api.WaitForEventsAsync(await AccountAsync(cancellationToken).ConfigureAwait(false), after, cancellationToken)
            .ConfigureAwait(false);

    public async Task<IReadOnlyList<AccountDevice>> ListAccountDevicesAsync(CancellationToken cancellationToken) =>
        await _api.ListAccountDevicesAsync(await AccountAsync(cancellationToken).ConfigureAwait(false), cancellationToken)
            .ConfigureAwait(false);

    public async Task RevokeDeviceAsync(string deviceId, CancellationToken cancellationToken)
    {
        await _api.RevokeDeviceAsync(await AccountAsync(cancellationToken).ConfigureAwait(false), deviceId, cancellationToken)
            .ConfigureAwait(false);
        _deviceCache.Clear();
    }

    public async Task TerminateOtherDevicesAsync(CancellationToken cancellationToken)
    {
        await _api.TerminateOtherDevicesAsync(
            await AccountAsync(cancellationToken).ConfigureAwait(false),
            cancellationToken).ConfigureAwait(false);
        _deviceCache.Clear();
    }

    public async Task RepairAllChatsAsync(CancellationToken cancellationToken)
    {
        IReadOnlyList<ChatSummary> chats = await ListChatsAsync(cancellationToken).ConfigureAwait(false);
        foreach (ChatSummary chat in chats)
        {
            await RepairEnvelopeHistoryAsync(chat.Id, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task RepairEnvelopeHistoryAsync(string chatId, CancellationToken cancellationToken)
    {
        DesktopAccount account = await AccountAsync(cancellationToken).ConfigureAwait(false);
        IReadOnlyList<ChatDevice> readyDevices = (await EncryptionReadyDevicesAsync(
                account,
                chatId,
                forceRefresh: true,
                cancellationToken: cancellationToken).ConfigureAwait(false))
            .Where(device => string.Equals(device.Username, account.Username, StringComparison.Ordinal))
            .ToArray();
        if (readyDevices.All(device => !string.Equals(device.Id, account.DeviceId, StringComparison.Ordinal))) return;
        long before = 0;
        while (true)
        {
            MessagePage page = await _api.ListEnvelopeRepairMessagesAsync(
                account,
                chatId,
                before,
                EnvelopeRepairPageSize,
                cancellationToken).ConfigureAwait(false);
            await RepairPendingEnvelopesAsync(account, chatId, page.Messages, readyDevices, cancellationToken)
                .ConfigureAwait(false);
            before = page.Messages.Count == 0 ? 0 : page.Messages[0].Sequence;
            if (!page.HasMoreBefore || before <= 0) break;
        }
    }

    private async Task<DecryptedMessagePage> LoadPageAsync(
        string chatId,
        long after,
        long before,
        int limit,
        bool markRead,
        CancellationToken cancellationToken)
    {
        DesktopAccount account = await AccountAsync(cancellationToken).ConfigureAwait(false);
        MessagePage page = await _api.ListMessagesAsync(account, chatId, after, before, limit, cancellationToken)
            .ConfigureAwait(false);
        await RepairPendingEnvelopesAsync(account, chatId, page.Messages, null, cancellationToken)
            .ConfigureAwait(false);
        var decrypted = new List<DecryptedMessage>(page.Messages.Count);
        foreach (WireMessage wire in page.Messages)
        {
            if (wire.CryptoVersion == 1 && wire.Envelope is null) continue;
            if (wire.CryptoVersion == 2 && wire.RatchetEnvelope is null &&
                !string.Equals(wire.EncryptionAlgorithm, WindowsRatchetMessageCrypto.AlgorithmMegolm, StringComparison.Ordinal)) continue;
            string fingerprint = WireFingerprint(wire);
            if (_decryptedMessageCache.TryGetValue(wire.Id, out CachedDecryptedMessage? cached) &&
                string.Equals(cached.Fingerprint, fingerprint, StringComparison.Ordinal))
            {
                decrypted.Add(cached.Message with
                {
                    DeliveryState = MessageCryptoService.GetDeliveryState(wire),
                    EnvelopeDeviceIds = wire.EnvelopeDeviceIds,
                });
                continue;
            }
            try
            {
                DecryptedMessage message = wire.CryptoVersion == 2
                    ? await _ratchetCrypto.DecryptAsync(account, wire, cancellationToken).ConfigureAwait(false)
                    : _crypto.Decrypt(wire);
                _decryptedMessageCache[wire.Id] = new CachedDecryptedMessage(fingerprint, message);
                decrypted.Add(message);
            }
            catch (CryptographicException)
            {
                decrypted.Add(new DecryptedMessage(
                    wire.Sequence,
                    wire.Id,
                    wire.ChatId,
                    wire.SenderUsername,
                    wire.SenderDeviceId,
                    new MessageContent(MessageKind.System, "Зашифрованное сообщение недоступно на этом устройстве", null, null, []),
                    wire.CreatedAt,
                    wire.EditedAt,
                    false,
                    wire.EnvelopeDeviceIds,
                    MessageDeliveryState.Sent));
            }
        }

        if (markRead)
        {
            long maxReadSequence = decrypted
                .Where(message => message.Decryptable && !string.Equals(message.SenderUsername, account.Username, StringComparison.Ordinal))
                .Select(message => message.Sequence)
                .DefaultIfEmpty(0)
                .Max();
            if (maxReadSequence > 0)
            {
                await _api.MarkReadCursorAsync(account, chatId, maxReadSequence, cancellationToken)
                    .ConfigureAwait(false);
            }
        }
        return new DecryptedMessagePage(decrypted, page.HasMoreBefore);
    }

    private async Task RepairPendingEnvelopesAsync(
        DesktopAccount account,
        string chatId,
        IReadOnlyList<WireMessage> messages,
        IReadOnlyList<ChatDevice>? knownReadyDevices,
        CancellationToken cancellationToken)
    {
        WireMessage[] repairable = messages.Where(message => message.Envelope is not null).ToArray();
        if (repairable.Length == 0) return;
        IReadOnlyList<ChatDevice> readyDevices = knownReadyDevices ??
            (await _api.ListDevicesAsync(account, chatId, cancellationToken).ConfigureAwait(false))
            .Where(IsEncryptionReady)
            .ToArray();
        foreach (WireMessage message in repairable)
        {
            IEnumerable<ChatDevice> eligibleDevices = string.Equals(
                message.SenderUsername,
                account.Username,
                StringComparison.Ordinal)
                ? readyDevices
                : readyDevices.Where(device => string.Equals(device.Username, account.Username, StringComparison.Ordinal));
            ChatDevice[] missing = eligibleDevices.Where(device => !message.EnvelopeDeviceIds.Contains(device.Id)).ToArray();
            if (missing.Length == 0) continue;
            IReadOnlyList<MessageEnvelope> envelopes = _crypto.CreateAdditionalEnvelopes(message, missing);
            await _api.AddMessageEnvelopesAsync(account, chatId, message.Id, envelopes, cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private async Task<string> SendAttachmentGroupAsync(
        string chatId,
        PreparedDesktopAttachment[] attachments,
        string caption,
        string? replyToId,
        IReadOnlyList<TextEntity>? captionEntities,
        MessageKind? forcedKind,
        RoundVideoShape? roundVideoShape,
        string? forwardedFromUsername,
        IProgress<double>? progress,
        CancellationToken cancellationToken)
    {
        DesktopAccount account = await AccountAsync(cancellationToken).ConfigureAwait(false);
        string messageId = Guid.NewGuid().ToString();
        var uploadedIds = new List<string>();
        try
        {
            var descriptors = new List<MediaDescriptor>(attachments.Length);
            for (int index = 0; index < attachments.Length; index++)
            {
                double baseProgress = (double)index / attachments.Length;
                var itemProgress = progress is null
                    ? null
                    : new Progress<double>(value => progress.Report(baseProgress + value / attachments.Length));
                descriptors.Add(await UploadAttachmentAsync(
                    account,
                    chatId,
                    messageId,
                    attachments[index],
                    uploadedIds,
                    itemProgress,
                    cancellationToken).ConfigureAwait(false));
            }

            MessageKind kind = forcedKind ?? GetKind(attachments, descriptors);
            PreparedDesktopAttachment first = attachments[0];
            NormalizedFormattedText normalizedCaption = TextFormatting.Normalize(caption, captionEntities);
            var content = new MessageContent(
                kind,
                normalizedCaption.Text,
                replyToId,
                descriptors.FirstOrDefault(),
                descriptors,
                attachments.Any(item => item.Spoiler),
                null,
                first.Waveform,
                first.DurationMilliseconds,
                roundVideoShape,
                null,
                null,
                forwardedFromUsername,
                normalizedCaption.Entities);
            await SendContentAsync(chatId, content, messageId, cancellationToken).ConfigureAwait(false);
            return messageId;
        }
        catch
        {
            foreach (string mediaId in uploadedIds)
            {
                try
                {
                    await _api.DeleteMediaAsync(account, chatId, mediaId, CancellationToken.None).ConfigureAwait(false);
                }
                catch (Exception error) when (error is HttpRequestException or IOException)
                {
                }
            }

            throw;
        }
    }

    private async Task<MediaDescriptor> UploadAttachmentAsync(
        DesktopAccount account,
        string chatId,
        string messageId,
        PreparedDesktopAttachment attachment,
        List<string> uploadedIds,
        IProgress<double>? progress,
        CancellationToken cancellationToken)
    {
        string mediaId = Guid.NewGuid().ToString();
        using MessageCryptoService.EncryptedMedia encrypted = _crypto.EncryptMedia(chatId, messageId, mediaId, attachment.Bytes);
        await _api.UploadMediaAsync(account, chatId, mediaId, encrypted.Ciphertext, progress, cancellationToken)
            .ConfigureAwait(false);
        uploadedIds.Add(mediaId);
        MediaPreviewDescriptor? preview = null;
        if (attachment.PreviewBytes is not null)
        {
            string previewId = Guid.NewGuid().ToString();
            using MessageCryptoService.EncryptedMedia encryptedPreview = _crypto.EncryptMedia(
                chatId,
                messageId,
                previewId,
                attachment.PreviewBytes);
            await _api.UploadMediaAsync(account, chatId, previewId, encryptedPreview.Ciphertext, null, cancellationToken)
                .ConfigureAwait(false);
            uploadedIds.Add(previewId);
            preview = new MediaPreviewDescriptor(
                previewId,
                attachment.PreviewBytes.LongLength,
                encryptedPreview.Ciphertext.LongLength,
                Convert.ToBase64String(encryptedPreview.Key),
                Convert.ToBase64String(encryptedPreview.Nonce));
        }

        return new MediaDescriptor(
            mediaId,
            attachment.Name.Length > 255 ? attachment.Name[..255] : attachment.Name,
            attachment.MimeType.Length > 127 ? attachment.MimeType[..127] : attachment.MimeType,
            attachment.Bytes.LongLength,
            encrypted.Ciphertext.LongLength,
            Convert.ToBase64String(encrypted.Key),
            Convert.ToBase64String(encrypted.Nonce),
            attachment.Width,
            attachment.Height,
            attachment.DurationMilliseconds,
            preview);
    }

    private async Task<string> SendContentAsync(
        string chatId,
        MessageContent content,
        string? messageId,
        CancellationToken cancellationToken) =>
        (await SendContentMessageAsync(chatId, content, messageId, cancellationToken).ConfigureAwait(false)).Id;

    private async Task<DecryptedMessage> SendContentMessageAsync(
        string chatId,
        MessageContent content,
        string? messageId,
        CancellationToken cancellationToken)
    {
        DesktopAccount account = await AccountAsync(cancellationToken).ConfigureAwait(false);
        string resolvedMessageId = messageId ?? Guid.NewGuid().ToString();
        PreparedMessage prepared = await PrepareForCurrentProtocolAsync(
            account, chatId, content, resolvedMessageId, cancellationToken).ConfigureAwait(false);
        CreatedMessageReceipt receipt = await _api.CreateMessageAsync(account, chatId, prepared, cancellationToken)
            .ConfigureAwait(false);
        IReadOnlySet<string> envelopeDeviceIds = receipt.EnvelopeDeviceIds.Count > 0
            ? receipt.EnvelopeDeviceIds
            : new HashSet<string>(prepared.Envelopes.Select(envelope => envelope.DeviceId), StringComparer.Ordinal);
        return new DecryptedMessage(
            receipt.Sequence,
            receipt.Id,
            chatId,
            account.Username,
            account.DeviceId,
            content,
            receipt.CreatedAt,
            null,
            true,
            envelopeDeviceIds,
            MessageDeliveryState.Sent);
    }

    private async Task<PreparedMessage> PrepareForCurrentProtocolAsync(
        DesktopAccount account,
        string chatId,
        MessageContent content,
        string messageId,
        CancellationToken cancellationToken)
    {
        ChatSummary chat = await GetChatAsync(account, chatId, cancellationToken).ConfigureAwait(false);
        IReadOnlyList<ChatDevice> allDevices = await AllDevicesAsync(account, chatId, forceRefresh: false, cancellationToken)
            .ConfigureAwait(false);
        bool canUseRatchet = string.Equals(account.AuthenticationState, AccountSecurityProtocol.Ready, StringComparison.Ordinal) &&
            _vaultStore.Exists(account.ServerUrl, account.Username) &&
            allDevices.Count > 0 &&
            allDevices.All(IsRatchetReady) &&
            allDevices.Any(value => string.Equals(value.Id, account.DeviceId, StringComparison.Ordinal));
        if (canUseRatchet)
        {
            string requestId;
            long cryptoSequence;
            if (_allocatedSequences.TryRemove(messageId, out ReservedSequence? reserved) && reserved.ExpiresAt > DateTimeOffset.UtcNow)
            {
                requestId = reserved.RequestId;
                cryptoSequence = reserved.CryptoSequence;
            }
            else
            {
                requestId = Guid.NewGuid().ToString();
                cryptoSequence = await _api.ReserveCryptoSequenceAsync(
                    account, chatId, requestId, messageId, cancellationToken).ConfigureAwait(false);
            }
            return await _ratchetCrypto.PrepareAsync(
                account, chat, content, allDevices, messageId, cryptoSequence, requestId, cancellationToken)
                .ConfigureAwait(false);
        }
        ChatDevice[] legacyDevices = allDevices.Where(IsEncryptionReady).ToArray();
        if (legacyDevices.Length == 0 || legacyDevices.All(value => !string.Equals(value.Id, account.DeviceId, StringComparison.Ordinal)))
            throw new CryptographicException("В чате нет полного набора совместимых ключей устройств.");
        return _crypto.Prepare(chatId, account.Username, account.DeviceId, content, legacyDevices, messageId);
    }

    private static bool IsRatchetReady(ChatDevice device) =>
        device.RatchetBundleVersion > 0 &&
        !string.IsNullOrWhiteSpace(device.IdentityAlgorithm) &&
        !string.IsNullOrWhiteSpace(device.IdentityPublicKeySpkiBase64);

    private async Task EnsureCurrentEncryptionKeyRegisteredAsync(
        DesktopAccount account,
        bool force,
        CancellationToken cancellationToken)
    {
        string identity = string.Join("|", account.Username, account.DeviceId, _identity.EncryptionPublicKeySpkiBase64);
        if (!force && string.Equals(_registeredEncryptionIdentity, identity, StringComparison.Ordinal)) return;
        await _encryptionRegistrationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!force && string.Equals(_registeredEncryptionIdentity, identity, StringComparison.Ordinal)) return;
            await _api.RegisterEncryptionKeyAsync(
                account,
                DesktopDeviceIdentity.EncryptionAlgorithm,
                _identity.EncryptionPublicKeySpkiBase64,
                cancellationToken).ConfigureAwait(false);
            _registeredEncryptionIdentity = identity;
            _deviceCache.Clear();
        }
        finally
        {
            _encryptionRegistrationGate.Release();
        }
    }

    private async Task<ChatSummary> GetChatAsync(
        DesktopAccount account,
        string chatId,
        CancellationToken cancellationToken)
    {
        if (_chatCache.TryGetValue(chatId, out ChatSummary? cached)) return cached;
        IReadOnlyList<ChatSummary> chats = await _api.ListChatsAsync(account, cancellationToken).ConfigureAwait(false);
        foreach (ChatSummary chat in chats) _chatCache[chat.Id] = chat;
        return chats.FirstOrDefault(value => string.Equals(value.Id, chatId, StringComparison.Ordinal))
            ?? throw new InvalidOperationException("Чат не найден.");
    }

    private async Task<IReadOnlyList<ChatDevice>> AllDevicesAsync(
        DesktopAccount account,
        string chatId,
        bool forceRefresh,
        CancellationToken cancellationToken)
    {
        await EnsureCurrentEncryptionKeyRegisteredAsync(account, force: false, cancellationToken: cancellationToken).ConfigureAwait(false);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        if (!forceRefresh && _deviceCache.TryGetValue(chatId, out CachedDevices? cached) &&
            now - cached.LoadedAt < DeviceCacheLifetime)
        {
            return cached.Devices;
        }

        ChatDevice[] devices = (await _api.ListDevicesAsync(account, chatId, cancellationToken).ConfigureAwait(false)).ToArray();
        if (devices.All(device => !string.Equals(device.Id, account.DeviceId, StringComparison.Ordinal)))
        {
            throw new CryptographicException("Ключ текущего Desktop-устройства не зарегистрирован.");
        }
        _deviceCache[chatId] = new CachedDevices(devices, now);
        return devices;
    }

    private async Task<IReadOnlyList<ChatDevice>> EncryptionReadyDevicesAsync(
        DesktopAccount account,
        string chatId,
        bool forceRefresh,
        CancellationToken cancellationToken)
    {
        IReadOnlyList<ChatDevice> devices = await AllDevicesAsync(account, chatId, forceRefresh, cancellationToken)
            .ConfigureAwait(false);
        ChatDevice[] ready = devices.Where(IsEncryptionReady).ToArray();
        if (ready.All(device => !string.Equals(device.Id, account.DeviceId, StringComparison.Ordinal)))
            throw new CryptographicException("Ключ текущего Desktop-устройства не зарегистрирован.");
        return ready;
    }

    private async Task TopUpSequencePoolAsync(
        DesktopAccount account,
        string chatId,
        CancellationToken cancellationToken)
    {
        SemaphoreSlim gate = _sequencePoolGates.GetOrAdd(chatId, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ConcurrentQueue<ReservedSequence> queue = _sequencePools.GetOrAdd(chatId, _ => new ConcurrentQueue<ReservedSequence>());
            DateTimeOffset now = DateTimeOffset.UtcNow;
            while (queue.TryPeek(out ReservedSequence? expired) && expired.ExpiresAt <= now) queue.TryDequeue(out _);
            int missing = Math.Max(0, SequencePoolTarget - queue.Count);
            if (missing == 0) return;
            var identifiers = Enumerable.Range(0, missing)
                .Select(_ => (RequestId: Guid.NewGuid().ToString(), MessageId: Guid.NewGuid().ToString()))
                .ToArray();
            IReadOnlyList<CryptoSequenceLeaseItem> leased = await _api.ReserveCryptoSequenceLeaseAsync(
                account, chatId, identifiers, cancellationToken).ConfigureAwait(false);
            DateTimeOffset expiresAt = DateTimeOffset.UtcNow + SequenceLeaseLifetime;
            foreach (CryptoSequenceLeaseItem item in leased)
                queue.Enqueue(new ReservedSequence(item.RequestId, item.MessageId, item.CryptoSequence, expiresAt));
        }
        finally
        {
            gate.Release();
        }
    }

    private sealed record CachedDecryptedMessage(string Fingerprint, DecryptedMessage Message);

    private static string WireFingerprint(WireMessage wire) =>
        string.Concat(wire.CiphertextBase64, "|", wire.NonceBase64, "|", wire.Aad, "|", wire.EditedAt?.UtcDateTime.Ticks.ToString() ?? "0");

    private sealed record CachedDevices(
        IReadOnlyList<ChatDevice> Devices,
        DateTimeOffset LoadedAt);

    private sealed record ReservedSequence(
        string RequestId,
        string MessageId,
        long CryptoSequence,
        DateTimeOffset ExpiresAt);

    private static bool IsEncryptionReady(ChatDevice device) =>
        string.Equals(device.EncryptionAlgorithm, MessageCryptoService.MessageEnvelopeAlgorithm, StringComparison.Ordinal) &&
        !string.IsNullOrWhiteSpace(device.EncryptionPublicKeySpkiBase64);

    private static MessageKind GetKind(
        PreparedDesktopAttachment[] attachments,
        List<MediaDescriptor> descriptors)
    {
        if (attachments.All(item => item.SendAsFile)) return descriptors.Count == 1 ? MessageKind.File : MessageKind.MediaGroup;
        if (descriptors.Count > 1) return MessageKind.MediaGroup;
        string mime = descriptors[0].MimeType;
        if (mime.StartsWith("image/", StringComparison.OrdinalIgnoreCase)) return MessageKind.Photo;
        if (mime.StartsWith("video/", StringComparison.OrdinalIgnoreCase)) return MessageKind.Video;
        if (mime.StartsWith("audio/", StringComparison.OrdinalIgnoreCase)) return MessageKind.Audio;
        return MessageKind.File;
    }

    private async Task<DesktopAccount> AccountAsync(CancellationToken cancellationToken) =>
        await _sessionManager.GetActiveAccountAsync(cancellationToken).ConfigureAwait(false);

    public void Dispose()
    {
        if (_disposed) return;
        _crypto.Dispose();
        _ratchetApi.Dispose();
        _identity.Dispose();
        _encryptionRegistrationGate.Dispose();
        _disposed = true;
    }
}
