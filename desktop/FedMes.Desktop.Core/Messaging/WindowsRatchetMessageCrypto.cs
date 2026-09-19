using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FedMes.Desktop.Core.AccountSecurity;
using FedMes.Desktop.Core.CryptoCore;
using FedMes.Desktop.Core.Devices;
using FedMes.Desktop.Core.Storage;

namespace FedMes.Desktop.Core.Messaging;

/// <summary>
/// Windows crypto-version-2 message engine. Direct/favorites chats use a fresh
/// AES-256-GCM key per message delivered to every READY device through Olm.
/// The family room uses a rotated Megolm sender session distributed through Olm.
/// </summary>
public sealed class WindowsRatchetMessageCrypto
{
    public const string AlgorithmOlm = "fedmes-olm-v1";
    public const string AlgorithmMegolm = "fedmes-megolm-v1";
    private readonly FedMesCryptoWorkerClient _core;
    private readonly RatchetHttpClient _api;
    private readonly WindowsRatchetStore _store;
    private readonly WindowsAccountVaultStore _vaultStore;
    private readonly DesktopDeviceIdentity _identity;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public WindowsRatchetMessageCrypto(
        FedMesCryptoWorkerClient core,
        RatchetHttpClient api,
        WindowsRatchetStore store,
        WindowsAccountVaultStore vaultStore,
        DesktopDeviceIdentity identity)
    {
        _core = core ?? throw new ArgumentNullException(nameof(core));
        _api = api ?? throw new ArgumentNullException(nameof(api));
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _vaultStore = vaultStore ?? throw new ArgumentNullException(nameof(vaultStore));
        _identity = identity ?? throw new ArgumentNullException(nameof(identity));
    }

    public async Task InitializeAsync(DesktopAccount account, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using LocalAccountVault vault = LoadVault(account);
            byte[] pickleKey = PickleKey(vault.AccountRootKey, account);
            try
            {
                LocalOlmState state = await LoadOrCreateStateAsync(account, vault.AccountRootKey, pickleKey, cancellationToken).ConfigureAwait(false);
                await EnsurePublishableKeysAsync(account, vault.AccountRootKey, pickleKey, state, cancellationToken).ConfigureAwait(false);
            }
            finally { CryptographicOperations.ZeroMemory(pickleKey); }
        }
        finally { _gate.Release(); }
    }

    public async Task<PreparedMessage> PrepareAsync(
        DesktopAccount account,
        ChatSummary chat,
        MessageContent content,
        IReadOnlyList<ChatDevice> devices,
        string messageId,
        long cryptoSequence,
        string sequenceRequestId,
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            using LocalAccountVault vault = LoadVault(account);
            byte[] pickleKey = PickleKey(vault.AccountRootKey, account);
            try
            {
                LocalOlmState state = await LoadOrCreateStateAsync(account, vault.AccountRootKey, pickleKey, cancellationToken).ConfigureAwait(false);
                await EnsurePublishableKeysAsync(account, vault.AccountRootKey, pickleKey, state, cancellationToken).ConfigureAwait(false);
                return chat.Kind switch
                {
                    "family" => await PrepareGroupAsync(account, chat, content, devices, messageId, cryptoSequence, sequenceRequestId, vault.AccountRootKey, pickleKey, state, cancellationToken).ConfigureAwait(false),
                    "direct" or "favorites" => await PrepareDirectAsync(account, chat, content, devices, messageId, cryptoSequence, sequenceRequestId, vault.AccountRootKey, pickleKey, state, cancellationToken).ConfigureAwait(false),
                    _ => throw new CryptographicException("Unsupported encrypted chat kind."),
                };
            }
            finally { CryptographicOperations.ZeroMemory(pickleKey); }
        }
        finally { _gate.Release(); }
    }

    public async Task<DecryptedMessage> DecryptAsync(
        DesktopAccount account,
        WireMessage message,
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (message.CryptoVersion != 2 || message.AadVersion != 2 || message.CryptoSequence <= 0)
                throw new CryptographicException("Invalid crypto-version-2 message metadata.");
            string expected = CanonicalAad(message.ChatId, message.SenderUsername, message.SenderDeviceId,
                message.Id, message.MessageType, message.CryptoSequence, message.RoomKeyVersion);
            if (!string.Equals(expected, message.Aad, StringComparison.Ordinal))
                throw new CryptographicException("Message AAD does not match metadata.");

            using LocalAccountVault vault = LoadVault(account);
            byte[] pickleKey = PickleKey(vault.AccountRootKey, account);
            try
            {
                LocalOlmState state = await LoadOrCreateStateAsync(account, vault.AccountRootKey, pickleKey, cancellationToken).ConfigureAwait(false);
                return message.EncryptionAlgorithm switch
                {
                    AlgorithmOlm => await DecryptDirectAsync(account, message, vault.AccountRootKey, pickleKey, state, cancellationToken).ConfigureAwait(false),
                    AlgorithmMegolm => await DecryptGroupAsync(account, message, vault.AccountRootKey, pickleKey, state, cancellationToken).ConfigureAwait(false),
                    _ => throw new CryptographicException("Unsupported message ratchet algorithm."),
                };
            }
            finally { CryptographicOperations.ZeroMemory(pickleKey); }
        }
        finally { _gate.Release(); }
    }

    private async Task<PreparedMessage> PrepareDirectAsync(
        DesktopAccount account, ChatSummary chat, MessageContent content, IReadOnlyList<ChatDevice> devices,
        string messageId, long sequence, string requestId, byte[] rootKey, byte[] pickleKey,
        LocalOlmState state, CancellationToken cancellationToken)
    {
        if (devices.Count == 0 || devices.All(value => !string.Equals(value.Id, account.DeviceId, StringComparison.Ordinal)))
            throw new CryptographicException("Current READY device is missing from the chat device list.");
        string messageType = content.Kind.ToString().ToLowerInvariant();
        string aad = CanonicalAad(chat.Id, account.Username, account.DeviceId, messageId, messageType, sequence, 1);
        byte[] contentKey = RandomNumberGenerator.GetBytes(32);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] plaintext = MessageCryptoService.EncodeContent(content);
        byte[] padded = MessageCryptoService.Pad(plaintext);
        byte[] ciphertext = [];
        try
        {
            ciphertext = MessageCryptoService.EncryptAesGcm(contentKey, nonce, Encoding.UTF8.GetBytes(aad), padded);
            var envelopes = new List<RatchetMessageEnvelope>(devices.Count);
            foreach (ChatDevice device in devices.OrderBy(value => value.Id, StringComparer.Ordinal))
            {
                if (device.RatchetBundleVersion <= 0 || string.IsNullOrWhiteSpace(device.IdentityPublicKeySpkiBase64))
                    throw new CryptographicException($"Device {device.Id} has no verified ratchet bundle.");
                if (string.Equals(device.Id, account.DeviceId, StringComparison.Ordinal))
                {
                    state.OwnMessageKeys[messageId] = RatchetHttpClient.RawUrl(contentKey);
                    envelopes.Add(await CreateSelfEnvelopeAsync(account, device, contentKey, rootKey, pickleKey, state, cancellationToken).ConfigureAwait(false));
                }
                else
                {
                    envelopes.Add(await EncryptForPeerAsync(account, device, contentKey, pickleKey, state, cancellationToken).ConfigureAwait(false));
                }
            }
            Trim(state.OwnMessageKeys, 50_000);
            _store.Save(account.ServerUrl, account.Username, rootKey, state);
            return new PreparedMessage(messageId, Convert.ToBase64String(ciphertext), Convert.ToBase64String(nonce), aad, [],
                2, 2, 1, 2, sequence, AlgorithmOlm, messageType, requestId, envelopes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(contentKey);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(padded);
            CryptographicOperations.ZeroMemory(ciphertext);
        }
    }

    private async Task<PreparedMessage> PrepareGroupAsync(
        DesktopAccount account, ChatSummary chat, MessageContent content, IReadOnlyList<ChatDevice> devices,
        string messageId, long sequence, string requestId, byte[] rootKey, byte[] pickleKey,
        LocalOlmState state, CancellationToken cancellationToken)
    {
        if (!state.OutboundGroups.TryGetValue(chat.Id, out LocalMegolmOutbound? group))
            group = await CreateAndPublishGroupAsync(account, chat, devices, rootKey, pickleKey, state, cancellationToken).ConfigureAwait(false);
        string messageType = content.Kind.ToString().ToLowerInvariant();
        string aad = CanonicalAad(chat.Id, account.Username, account.DeviceId, messageId, messageType, sequence, group.RoomKeyVersion);
        byte[] contentBytes = MessageCryptoService.EncodeContent(content);
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(new { version = 1, aad, content = RatchetHttpClient.RawUrl(contentBytes) });
        CryptographicOperations.ZeroMemory(contentBytes);
        try
        {
            MegolmEncryptedResult encrypted = await _core.InvokeJsonAsync<MegolmEncryptedResult>("megolm.encrypt", new
            {
                session_pickle = group.Pickle,
                pickle_key = RatchetHttpClient.RawUrl(pickleKey),
                plaintext = RatchetHttpClient.RawUrl(payload),
            }, cancellationToken).ConfigureAwait(false);
            if (!string.Equals(encrypted.SessionId, group.SessionId, StringComparison.Ordinal))
                throw new CryptographicException("Megolm session identifier changed unexpectedly.");
            group.Pickle = encrypted.Pickle;
            byte[] ascii = Encoding.ASCII.GetBytes(encrypted.Ciphertext);
            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            try
            {
                _store.Save(account.ServerUrl, account.Username, rootKey, state);
                return new PreparedMessage(messageId, Convert.ToBase64String(ascii), Convert.ToBase64String(nonce), aad, [],
                    2, 2, group.RoomKeyVersion, 2, sequence, AlgorithmMegolm, messageType, requestId, []);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(ascii);
                CryptographicOperations.ZeroMemory(nonce);
            }
        }
        finally { CryptographicOperations.ZeroMemory(payload); }
    }

    private async Task<DecryptedMessage> DecryptDirectAsync(
        DesktopAccount account, WireMessage message, byte[] rootKey, byte[] pickleKey,
        LocalOlmState state, CancellationToken cancellationToken)
    {
        byte[] contentKey;
        if (state.OwnMessageKeys.TryGetValue(message.Id, out string? ownKey))
            contentKey = RatchetHttpClient.DecodeRawUrl(ownKey, 32, 32);
        else
        {
            RatchetMessageEnvelope envelope = message.RatchetEnvelope
                ?? throw new CryptographicException("Ratchet envelope is missing for this device.");
            if (!string.Equals(envelope.RecipientDeviceId, account.DeviceId, StringComparison.Ordinal))
                throw new CryptographicException("Ratchet envelope recipient mismatch.");
            contentKey = await DecryptOlmEnvelopeAsync(account, message.SenderDeviceId, envelope, pickleKey, state, cancellationToken).ConfigureAwait(false);
        }
        byte[] nonce = Convert.FromBase64String(message.NonceBase64);
        byte[] ciphertext = Convert.FromBase64String(message.CiphertextBase64);
        byte[] padded = [];
        byte[] plaintext = [];
        try
        {
            if (contentKey.Length != 32) throw new CryptographicException("Invalid message content key.");
            padded = MessageCryptoService.DecryptAesGcm(contentKey, nonce, Encoding.UTF8.GetBytes(message.Aad), ciphertext);
            plaintext = MessageCryptoService.Unpad(padded);
            MessageContent content = MessageCryptoService.DecodeContent(plaintext);
            return ToDecrypted(message, content);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(contentKey);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(padded);
            CryptographicOperations.ZeroMemory(plaintext);
            _store.Save(account.ServerUrl, account.Username, rootKey, state);
        }
    }

    private async Task<DecryptedMessage> DecryptGroupAsync(
        DesktopAccount account, WireMessage message, byte[] rootKey, byte[] pickleKey,
        LocalOlmState state, CancellationToken cancellationToken)
    {
        await ImportPendingGroupsAsync(account, rootKey, pickleKey, state, cancellationToken).ConfigureAwait(false);
        string groupKey = GroupKey(message.ChatId, message.RoomKeyVersion);
        if (!state.InboundGroups.TryGetValue(groupKey, out string? groupPickle) &&
            string.Equals(message.SenderDeviceId, account.DeviceId, StringComparison.Ordinal) &&
            state.OutboundGroups.TryGetValue(message.ChatId, out LocalMegolmOutbound? outbound) &&
            outbound.RoomKeyVersion == message.RoomKeyVersion)
        {
            groupPickle = await _core.InvokeAsync("megolm.inbound.create", new
            {
                session_key = outbound.SessionKey,
                pickle_key = RatchetHttpClient.RawUrl(pickleKey),
            }, cancellationToken).ConfigureAwait(false);
            state.InboundGroups[groupKey] = groupPickle;
        }
        if (string.IsNullOrWhiteSpace(groupPickle)) throw new CryptographicException("Group key is not available.");
        byte[] cipherAscii = Convert.FromBase64String(message.CiphertextBase64);
        try
        {
            MegolmDecryptedResult result = await _core.InvokeJsonAsync<MegolmDecryptedResult>("megolm.decrypt", new
            {
                session_pickle = groupPickle,
                pickle_key = RatchetHttpClient.RawUrl(pickleKey),
                ciphertext = Encoding.ASCII.GetString(cipherAscii),
            }, cancellationToken).ConfigureAwait(false);
            string replayKey = $"{result.SessionId}:{result.MessageIndex}";
            string hash = Convert.ToHexString(SHA256.HashData(cipherAscii)).ToLowerInvariant();
            if (state.SeenGroupIndexes.TryGetValue(replayKey, out string? prior) && !FixedHexEquals(prior, hash))
                throw new CryptographicException("Megolm replay conflict.");
            state.SeenGroupIndexes[replayKey] = hash;
            Trim(state.SeenGroupIndexes, 100_000);
            state.InboundGroups[groupKey] = result.Pickle;
            byte[] plaintext = RatchetHttpClient.DecodeRawUrl(result.Plaintext, 1, 16 * 1024 * 1024);
            try
            {
                using JsonDocument document = JsonDocument.Parse(plaintext);
                JsonElement root = document.RootElement;
                if (root.GetProperty("version").GetInt32() != 1 ||
                    !string.Equals(root.GetProperty("aad").GetString(), message.Aad, StringComparison.Ordinal))
                    throw new CryptographicException("Megolm payload metadata mismatch.");
                byte[] contentBytes = RatchetHttpClient.DecodeRawUrl(root.GetProperty("content").GetString() ?? string.Empty, 1, 16 * 1024 * 1024);
                try { return ToDecrypted(message, MessageCryptoService.DecodeContent(contentBytes)); }
                finally { CryptographicOperations.ZeroMemory(contentBytes); }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
                _store.Save(account.ServerUrl, account.Username, rootKey, state);
            }
        }
        finally { CryptographicOperations.ZeroMemory(cipherAscii); }
    }

    private async Task<LocalMegolmOutbound> CreateAndPublishGroupAsync(
        DesktopAccount account, ChatSummary chat, IReadOnlyList<ChatDevice> devices,
        byte[] rootKey, byte[] pickleKey, LocalOlmState state, CancellationToken cancellationToken)
    {
        if (devices.Count == 0) throw new CryptographicException("No READY devices are available for group key distribution.");
        string rotationId = Guid.NewGuid().ToString();
        RatchetHttpClient.GroupVersionReservation reservation = await _api.ReserveGroupVersionAsync(account, chat.Id, rotationId, cancellationToken).ConfigureAwait(false);
        MegolmOutboundResult created = await _core.InvokeJsonAsync<MegolmOutboundResult>("megolm.outbound.create", new
        {
            pickle_key = RatchetHttpClient.RawUrl(pickleKey),
        }, cancellationToken).ConfigureAwait(false);
        var group = new LocalMegolmOutbound
        {
            RoomKeyVersion = reservation.RoomKeyVersion,
            SessionId = created.SessionId,
            SessionKey = created.SessionKey,
            Pickle = created.Pickle,
        };
        byte[] keyBytes = Encoding.ASCII.GetBytes(group.SessionKey);
        var packages = new List<RatchetHttpClient.GroupKeyUpload>(devices.Count);
        try
        {
            foreach (ChatDevice device in devices.OrderBy(value => value.Id, StringComparer.Ordinal))
            {
                RatchetMessageEnvelope envelope = string.Equals(device.Id, account.DeviceId, StringComparison.Ordinal)
                    ? await CreateSelfEnvelopeAsync(account, device, keyBytes, rootKey, pickleKey, state, cancellationToken).ConfigureAwait(false)
                    : await EncryptForPeerAsync(account, device, keyBytes, pickleKey, state, cancellationToken).ConfigureAwait(false);
                packages.Add(new RatchetHttpClient.GroupKeyUpload(
                    device.Id,
                    envelope.SessionId,
                    envelope.MessageType,
                    RatchetHttpClient.DecodeRawUrl(envelope.CiphertextBase64Url, 16, 65536)));
            }
            await _api.PutGroupSessionAsync(account, chat.Id, group.RoomKeyVersion, group.SessionId, rotationId, packages, cancellationToken).ConfigureAwait(false);
            state.OutboundGroups[chat.Id] = group;
            state.InboundGroups[GroupKey(chat.Id, group.RoomKeyVersion)] = await _core.InvokeAsync("megolm.inbound.create", new
            {
                session_key = group.SessionKey,
                pickle_key = RatchetHttpClient.RawUrl(pickleKey),
            }, cancellationToken).ConfigureAwait(false);
            _store.Save(account.ServerUrl, account.Username, rootKey, state);
            return group;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
            foreach (RatchetHttpClient.GroupKeyUpload package in packages)
                CryptographicOperations.ZeroMemory(package.EncryptedSessionKey);
        }
    }

    private async Task ImportPendingGroupsAsync(
        DesktopAccount account, byte[] rootKey, byte[] pickleKey, LocalOlmState state, CancellationToken cancellationToken)
    {
        IReadOnlyList<RatchetHttpClient.GroupPackage> packages = await _api.ListGroupPackagesAsync(account, 100, cancellationToken).ConfigureAwait(false);
        foreach (RatchetHttpClient.GroupPackage package in packages)
        {
            try
            {
                var envelope = new RatchetMessageEnvelope(account.DeviceId, package.SenderCurve25519Key,
                    package.OlmSessionId, package.MessageType, RatchetHttpClient.RawUrl(package.EncryptedSessionKey),
                    Convert.ToHexString(SHA256.HashData(package.EncryptedSessionKey)).ToLowerInvariant());
                byte[] sessionKey = await DecryptOlmEnvelopeAsync(account, package.SenderDeviceId, envelope, pickleKey, state, cancellationToken).ConfigureAwait(false);
                try
                {
                    state.InboundGroups[GroupKey(package.ChatId, package.RoomKeyVersion)] = await _core.InvokeAsync("megolm.inbound.create", new
                    {
                        session_key = Encoding.ASCII.GetString(sessionKey),
                        pickle_key = RatchetHttpClient.RawUrl(pickleKey),
                    }, cancellationToken).ConfigureAwait(false);
                    await _api.ConsumeGroupPackageAsync(account, package.ChatId, package.RoomKeyVersion, cancellationToken).ConfigureAwait(false);
                }
                finally { CryptographicOperations.ZeroMemory(sessionKey); }
            }
            finally { CryptographicOperations.ZeroMemory(package.EncryptedSessionKey); }
        }
        _store.Save(account.ServerUrl, account.Username, rootKey, state);
    }

    private async Task<RatchetMessageEnvelope> EncryptForPeerAsync(
        DesktopAccount account, ChatDevice device, byte[] plaintext, byte[] pickleKey,
        LocalOlmState state, CancellationToken cancellationToken)
    {
        string peerKey = $"peer:{device.Id}";
        if (!state.Sessions.TryGetValue(peerKey, out string? sessionPickle))
        {
            RatchetHttpClient.ClaimedKey claimed = await _api.ClaimAsync(account, device.Id, cancellationToken).ConfigureAwait(false);
            try
            {
                VerifyClaim(device, claimed);
                OlmEncryptedResult outbound = await _core.InvokeJsonAsync<OlmEncryptedResult>("olm.session.outbound", new
                {
                    account_pickle = state.AccountPickle,
                    pickle_key = RatchetHttpClient.RawUrl(pickleKey),
                    identity_key = claimed.Curve25519IdentityKey,
                    one_time_key = claimed.OneTimeKey.PublicKey,
                }, cancellationToken).ConfigureAwait(false);
                sessionPickle = outbound.Pickle;
                state.Sessions[$"curve:{device.Id}"] = claimed.Curve25519IdentityKey;
            }
            finally { ClearClaim(claimed); }
        }
        OlmEncryptedResult encrypted = await _core.InvokeJsonAsync<OlmEncryptedResult>("olm.encrypt", new
        {
            session_pickle = sessionPickle,
            pickle_key = RatchetHttpClient.RawUrl(pickleKey),
            plaintext = RatchetHttpClient.RawUrl(plaintext),
        }, cancellationToken).ConfigureAwait(false);
        state.Sessions[peerKey] = encrypted.Pickle;
        state.Sessions[$"session:{encrypted.SessionId}"] = encrypted.Pickle;
        byte[] ascii = Encoding.ASCII.GetBytes(encrypted.Ciphertext);
        try
        {
            return new RatchetMessageEnvelope(device.Id, state.Curve25519IdentityKey, encrypted.SessionId,
                encrypted.MessageType, RatchetHttpClient.RawUrl(ascii),
                Convert.ToHexString(SHA256.HashData(ascii)).ToLowerInvariant());
        }
        finally { CryptographicOperations.ZeroMemory(ascii); }
    }

    private async Task<RatchetMessageEnvelope> CreateSelfEnvelopeAsync(
        DesktopAccount account, ChatDevice device, byte[] plaintext, byte[] rootKey, byte[] pickleKey,
        LocalOlmState state, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(state.SelfOneTimeKey))
            await EnsurePublishableKeysAsync(account, rootKey, pickleKey, state, cancellationToken).ConfigureAwait(false);
        OlmEncryptedResult outbound = await _core.InvokeJsonAsync<OlmEncryptedResult>("olm.session.outbound", new
        {
            account_pickle = state.AccountPickle,
            pickle_key = RatchetHttpClient.RawUrl(pickleKey),
            identity_key = state.Curve25519IdentityKey,
            one_time_key = state.SelfOneTimeKey,
        }, cancellationToken).ConfigureAwait(false);
        OlmEncryptedResult encrypted = await _core.InvokeJsonAsync<OlmEncryptedResult>("olm.encrypt", new
        {
            session_pickle = outbound.Pickle,
            pickle_key = RatchetHttpClient.RawUrl(pickleKey),
            plaintext = RatchetHttpClient.RawUrl(plaintext),
        }, cancellationToken).ConfigureAwait(false);
        OlmDecryptedResult inbound = await _core.InvokeJsonAsync<OlmDecryptedResult>("olm.session.inbound", new
        {
            account_pickle = state.AccountPickle,
            pickle_key = RatchetHttpClient.RawUrl(pickleKey),
            identity_key = state.Curve25519IdentityKey,
            ciphertext = encrypted.Ciphertext,
            message_type = encrypted.MessageType,
        }, cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(inbound.AccountPickle)) state.AccountPickle = inbound.AccountPickle;
        state.Sessions[$"session:{inbound.SessionId}"] = inbound.SessionPickle;
        state.SelfOneTimeKey = null;
        state.SelfOneTimeKeyId = null;
        byte[] ascii = Encoding.ASCII.GetBytes(encrypted.Ciphertext);
        try
        {
            return new RatchetMessageEnvelope(device.Id, state.Curve25519IdentityKey, inbound.SessionId,
                encrypted.MessageType, RatchetHttpClient.RawUrl(ascii),
                Convert.ToHexString(SHA256.HashData(ascii)).ToLowerInvariant());
        }
        finally { CryptographicOperations.ZeroMemory(ascii); }
    }

    private async Task<byte[]> DecryptOlmEnvelopeAsync(
        DesktopAccount account, string senderDeviceId, RatchetMessageEnvelope envelope, byte[] pickleKey,
        LocalOlmState state, CancellationToken cancellationToken)
    {
        byte[] ascii = RatchetHttpClient.DecodeRawUrl(envelope.CiphertextBase64Url, 16, 1 << 20);
        try
        {
            string hash = Convert.ToHexString(SHA256.HashData(ascii)).ToLowerInvariant();
            if (!FixedHexEquals(envelope.CiphertextSha256Hex, hash))
                throw new CryptographicException("Ratchet envelope hash mismatch.");
            string ciphertext = Encoding.ASCII.GetString(ascii);
            state.Sessions.TryGetValue($"session:{envelope.SessionId}", out string? sessionPickle);
            OlmDecryptedResult result;
            if (sessionPickle is null && envelope.MessageType == 0)
            {
                result = await _core.InvokeJsonAsync<OlmDecryptedResult>("olm.session.inbound", new
                {
                    account_pickle = state.AccountPickle,
                    pickle_key = RatchetHttpClient.RawUrl(pickleKey),
                    identity_key = envelope.SenderCurve25519Key,
                    ciphertext,
                    message_type = envelope.MessageType,
                }, cancellationToken).ConfigureAwait(false);
                if (!string.IsNullOrWhiteSpace(result.AccountPickle)) state.AccountPickle = result.AccountPickle;
            }
            else
            {
                if (sessionPickle is null) throw new CryptographicException("Olm session is unavailable.");
                result = await _core.InvokeJsonAsync<OlmDecryptedResult>("olm.decrypt", new
                {
                    session_pickle = sessionPickle,
                    pickle_key = RatchetHttpClient.RawUrl(pickleKey),
                    ciphertext,
                    message_type = envelope.MessageType,
                }, cancellationToken).ConfigureAwait(false);
            }
            state.Sessions[$"session:{envelope.SessionId}"] = result.SessionPickle;
            state.Sessions[$"peer:{senderDeviceId}"] = result.SessionPickle;
            state.Sessions[$"curve:{senderDeviceId}"] = envelope.SenderCurve25519Key;
            return RatchetHttpClient.DecodeRawUrl(result.Plaintext, 1, 65536);
        }
        finally { CryptographicOperations.ZeroMemory(ascii); }
    }

    private async Task EnsurePublishableKeysAsync(
        DesktopAccount account, byte[] rootKey, byte[] pickleKey, LocalOlmState state, CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(state.SelfOneTimeKey) && state.BundleVersion > 0) return;
        OlmAccountResult generated = await _core.InvokeJsonAsync<OlmAccountResult>("olm.account.refill", new
        {
            account_pickle = state.AccountPickle,
            pickle_key = RatchetHttpClient.RawUrl(pickleKey),
            count = 33,
        }, cancellationToken).ConfigureAwait(false);
        state.AccountPickle = generated.Pickle;
        using JsonDocument identity = JsonDocument.Parse(generated.IdentityKeys);
        state.Curve25519IdentityKey = identity.RootElement.GetProperty("curve25519").GetString()
            ?? throw new CryptographicException("Olm curve25519 identity key is missing.");
        state.Ed25519IdentityKey = identity.RootElement.GetProperty("ed25519").GetString()
            ?? throw new CryptographicException("Olm ed25519 identity key is missing.");
        using JsonDocument oneTimes = JsonDocument.Parse(generated.OneTimeKeys);
        JsonElement values = oneTimes.RootElement.GetProperty("curve25519");
        List<KeyValuePair<string, string>> entries = values.EnumerateObject()
            .Select(value => new KeyValuePair<string, string>(value.Name, value.Value.GetString() ?? string.Empty))
            .Where(value => value.Value.Length > 0)
            .OrderBy(value => value.Key, StringComparer.Ordinal)
            .ToList();
        if (entries.Count < 2) throw new CryptographicException("Crypto core generated too few one-time keys.");
        state.SelfOneTimeKeyId = entries[0].Key;
        state.SelfOneTimeKey = entries[0].Value;
        state.BundleVersion++;
        byte[] bundlePayload = CanonicalBundle(account.DeviceId, state.BundleVersion, state.Curve25519IdentityKey, state.Ed25519IdentityKey);
        byte[] bundleSignature = Convert.FromBase64String(_identity.SignSha256Base64(bundlePayload));
        var uploads = new List<RatchetHttpClient.OneTimeKey>(Math.Min(32, entries.Count - 1));
        try
        {
            foreach (KeyValuePair<string, string> entry in entries.Skip(1).Take(32))
            {
                byte[] payload = CanonicalOtk(account.DeviceId, entry.Key, entry.Value);
                try { uploads.Add(new RatchetHttpClient.OneTimeKey(entry.Key, entry.Value, Convert.FromBase64String(_identity.SignSha256Base64(payload)))); }
                finally { CryptographicOperations.ZeroMemory(payload); }
            }
            await _api.PutBundleAsync(account, state.BundleVersion, state.Curve25519IdentityKey, state.Ed25519IdentityKey,
                bundlePayload, bundleSignature, uploads, cancellationToken).ConfigureAwait(false);
            state.AccountPickle = await _core.InvokeAsync("olm.account.mark_published", new
            {
                account_pickle = state.AccountPickle,
                pickle_key = RatchetHttpClient.RawUrl(pickleKey),
            }, cancellationToken).ConfigureAwait(false);
            _store.Save(account.ServerUrl, account.Username, rootKey, state);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bundlePayload);
            CryptographicOperations.ZeroMemory(bundleSignature);
            foreach (RatchetHttpClient.OneTimeKey upload in uploads) CryptographicOperations.ZeroMemory(upload.Signature);
        }
    }

    private async Task<LocalOlmState> LoadOrCreateStateAsync(
        DesktopAccount account, byte[] rootKey, byte[] pickleKey, CancellationToken cancellationToken)
    {
        LocalOlmState? current = _store.Load(account.ServerUrl, account.Username, rootKey);
        if (current is not null) return current;
        OlmAccountResult created = await _core.InvokeJsonAsync<OlmAccountResult>("olm.account.create", new
        {
            pickle_key = RatchetHttpClient.RawUrl(pickleKey),
            count = 1,
        }, cancellationToken).ConfigureAwait(false);
        using JsonDocument identity = JsonDocument.Parse(created.IdentityKeys);
        var state = new LocalOlmState
        {
            AccountPickle = created.Pickle,
            Curve25519IdentityKey = identity.RootElement.GetProperty("curve25519").GetString() ?? string.Empty,
            Ed25519IdentityKey = identity.RootElement.GetProperty("ed25519").GetString() ?? string.Empty,
        };
        _store.Save(account.ServerUrl, account.Username, rootKey, state);
        return state;
    }

    private static void VerifyClaim(ChatDevice device, RatchetHttpClient.ClaimedKey claimed)
    {
        if (!string.Equals(claimed.DeviceId, device.Id, StringComparison.Ordinal))
            throw new CryptographicException("Claimed device identifier mismatch.");
        byte[] bundle = CanonicalBundle(claimed.DeviceId, claimed.BundleVersion, claimed.Curve25519IdentityKey, claimed.Ed25519IdentityKey);
        byte[] otk = CanonicalOtk(claimed.DeviceId, claimed.OneTimeKey.KeyId, claimed.OneTimeKey.PublicKey);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(bundle, claimed.SignedPayload) ||
                !VerifyDeviceSignature(device, bundle, claimed.BundleSignature) ||
                !VerifyDeviceSignature(device, otk, claimed.OneTimeKey.Signature))
                throw new CryptographicException("Ratchet key claim signature is invalid.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bundle);
            CryptographicOperations.ZeroMemory(otk);
        }
    }

    private static bool VerifyDeviceSignature(ChatDevice device, ReadOnlySpan<byte> payload, ReadOnlySpan<byte> signature)
    {
        if (!string.Equals(device.IdentityAlgorithm, "ecdsa-p256-sha256", StringComparison.Ordinal)) return false;
        byte[] spki = Convert.FromBase64String(device.IdentityPublicKeySpkiBase64);
        try
        {
            using ECDsa key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(spki, out int read);
            return read == spki.Length && key.VerifyData(payload, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        }
        catch (CryptographicException) { return false; }
        finally { CryptographicOperations.ZeroMemory(spki); }
    }

    private static void ClearClaim(RatchetHttpClient.ClaimedKey claimed)
    {
        CryptographicOperations.ZeroMemory(claimed.SignedPayload);
        CryptographicOperations.ZeroMemory(claimed.BundleSignature);
        CryptographicOperations.ZeroMemory(claimed.OneTimeKey.Signature);
    }

    private LocalAccountVault LoadVault(DesktopAccount account) =>
        _vaultStore.Load(account.ServerUrl, account.Username)
        ?? throw new CryptographicException("Account Root Key is not available on this device.");

    private static byte[] PickleKey(ReadOnlySpan<byte> rootKey, DesktopAccount account)
    {
        byte[] context = Encoding.UTF8.GetBytes($"fedmes-olm-pickle-key-v1\n{account.ServerUrl}\n{account.Username}\n{account.DeviceId}");
        try { return HMACSHA256.HashData(rootKey, context); }
        finally { CryptographicOperations.ZeroMemory(context); }
    }

    private static byte[] CanonicalBundle(string deviceId, int version, string curve, string ed) =>
        Encoding.UTF8.GetBytes($"fedmes-ratchet-bundle-v1\n{deviceId}\n{version}\n{curve}\n{ed}");
    private static byte[] CanonicalOtk(string deviceId, string keyId, string key) =>
        Encoding.UTF8.GetBytes($"fedmes-olm-otk-v1\n{deviceId}\n{keyId}\n{key}");
    public static string CanonicalAad(string chatId, string username, string deviceId, string messageId,
        string messageType, long sequence, long roomKeyVersion) =>
        string.Join("\n", "fedmes-message-v2", chatId, messageId, username, deviceId, messageType,
            sequence.ToString(System.Globalization.CultureInfo.InvariantCulture),
            roomKeyVersion.ToString(System.Globalization.CultureInfo.InvariantCulture), "aad-v2");
    private static string GroupKey(string chatId, long version) => $"{chatId}:{version}";

    private static DecryptedMessage ToDecrypted(WireMessage message, MessageContent content) => new(
        message.Sequence, message.Id, message.ChatId, message.SenderUsername, message.SenderDeviceId,
        content, message.CreatedAt, message.EditedAt, true, message.EnvelopeDeviceIds,
        MessageCryptoService.GetDeliveryState(message));

    private static bool FixedHexEquals(string left, string right)
    {
        byte[] a = Encoding.ASCII.GetBytes(left.ToLowerInvariant());
        byte[] b = Encoding.ASCII.GetBytes(right.ToLowerInvariant());
        try { return CryptographicOperations.FixedTimeEquals(a, b); }
        finally
        {
            CryptographicOperations.ZeroMemory(a);
            CryptographicOperations.ZeroMemory(b);
        }
    }

    private static void Trim(Dictionary<string, string> values, int maximum)
    {
        while (values.Count > maximum)
        {
            string first = values.Keys.First();
            values.Remove(first);
        }
    }
}
