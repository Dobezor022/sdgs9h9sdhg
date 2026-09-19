using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using FedMes.Desktop.Core.Storage;

namespace FedMes.Desktop.Core.Messaging;

internal sealed class LocalOlmState
{
    [JsonPropertyName("version")]
    public int Version { get; set; } = 1;

    [JsonPropertyName("account_pickle")]
    public string AccountPickle { get; set; } = string.Empty;

    [JsonPropertyName("curve25519")]
    public string Curve25519IdentityKey { get; set; } = string.Empty;

    [JsonPropertyName("ed25519")]
    public string Ed25519IdentityKey { get; set; } = string.Empty;

    [JsonPropertyName("self_otk_id")]
    public string? SelfOneTimeKeyId { get; set; }

    [JsonPropertyName("self_otk")]
    public string? SelfOneTimeKey { get; set; }

    [JsonPropertyName("bundle_version")]
    public int BundleVersion { get; set; }

    [JsonPropertyName("sessions")]
    public Dictionary<string, string> Sessions { get; init; } = new(StringComparer.Ordinal);

    [JsonPropertyName("outbound_groups")]
    public Dictionary<string, LocalMegolmOutbound> OutboundGroups { get; init; } = new(StringComparer.Ordinal);

    [JsonPropertyName("inbound_groups")]
    public Dictionary<string, string> InboundGroups { get; init; } = new(StringComparer.Ordinal);

    [JsonPropertyName("own_message_keys")]
    public Dictionary<string, string> OwnMessageKeys { get; init; } = new(StringComparer.Ordinal);

    [JsonPropertyName("seen_group_indexes")]
    public Dictionary<string, string> SeenGroupIndexes { get; init; } = new(StringComparer.Ordinal);
}

internal sealed class LocalMegolmOutbound
{
    [JsonPropertyName("room_key_version")]
    public long RoomKeyVersion { get; set; }

    [JsonPropertyName("session_id")]
    public string SessionId { get; set; } = string.Empty;

    [JsonPropertyName("session_key")]
    public string SessionKey { get; set; } = string.Empty;

    [JsonPropertyName("pickle")]
    public string Pickle { get; set; } = string.Empty;
}

/// <summary>
/// Atomically stores Olm/Megolm state encrypted with a key derived from the
/// account root key. The server never receives this file or its wrapping key.
/// </summary>
public sealed class WindowsRatchetStore
{
    private const int MaximumFileBytes = 64 * 1024 * 1024;
    private readonly string _directory;
    private readonly object _gate = new();

    public WindowsRatchetStore(string? directory = null)
    {
        _directory = directory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "FedMes",
            "ratchet-v2");
    }

    internal LocalOlmState? Load(string serverUrl, string username, ReadOnlySpan<byte> accountRootKey)
    {
        lock (_gate)
        {
            string path = PathFor(serverUrl, username);
            if (!File.Exists(path)) return null;
            byte[] encoded = Encoding.UTF8.GetBytes(LocalStateFile.ReadAllText(path, MaximumFileBytes));
            try { return Decrypt(serverUrl, username, accountRootKey, encoded); }
            finally { CryptographicOperations.ZeroMemory(encoded); }
        }
    }

    internal void Save(string serverUrl, string username, ReadOnlySpan<byte> accountRootKey, LocalOlmState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        lock (_gate)
        {
            Directory.CreateDirectory(_directory);
            byte[] encoded = Encrypt(serverUrl, username, accountRootKey, state);
            try { LocalStateFile.WriteAllTextAtomic(PathFor(serverUrl, username), Encoding.UTF8.GetString(encoded)); }
            finally { CryptographicOperations.ZeroMemory(encoded); }
        }
    }

    public void Delete(string serverUrl, string username)
    {
        lock (_gate)
        {
            try { File.Delete(PathFor(serverUrl, username)); } catch (FileNotFoundException) { }
        }
    }

    private static byte[] Encrypt(
        string serverUrl,
        string username,
        ReadOnlySpan<byte> accountRootKey,
        LocalOlmState state)
    {
        if (accountRootKey.Length != 32) throw new CryptographicException("Account Root Key has an invalid length.");
        byte[] plaintext = JsonSerializer.SerializeToUtf8Bytes(state, JsonOptions);
        byte[] key = DeriveKey(accountRootKey, serverUrl, username);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        byte[] aad = Encoding.UTF8.GetBytes($"fedmes-ratchet-state-envelope-v1\n{serverUrl}\n{username}");
        try
        {
            using var aes = new AesGcm(key, tag.Length);
            aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);
            return JsonSerializer.SerializeToUtf8Bytes(new RatchetEnvelopeFile(
                1,
                Convert.ToBase64String(nonce),
                Convert.ToBase64String(ciphertext),
                Convert.ToBase64String(tag)), JsonOptions);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(aad);
        }
    }

    private static LocalOlmState Decrypt(
        string serverUrl,
        string username,
        ReadOnlySpan<byte> accountRootKey,
        ReadOnlySpan<byte> encoded)
    {
        if (accountRootKey.Length != 32) throw new CryptographicException("Account Root Key has an invalid length.");
        RatchetEnvelopeFile envelope = JsonSerializer.Deserialize<RatchetEnvelopeFile>(encoded, JsonOptions)
            ?? throw new CryptographicException("Ratchet state envelope is invalid.");
        if (envelope.Version != 1) throw new CryptographicException("Ratchet state version is unsupported.");
        byte[] nonce = Convert.FromBase64String(envelope.Nonce);
        byte[] ciphertext = Convert.FromBase64String(envelope.Ciphertext);
        byte[] tag = Convert.FromBase64String(envelope.Tag);
        byte[] plaintext = new byte[ciphertext.Length];
        byte[] key = DeriveKey(accountRootKey, serverUrl, username);
        byte[] aad = Encoding.UTF8.GetBytes($"fedmes-ratchet-state-envelope-v1\n{serverUrl}\n{username}");
        try
        {
            if (nonce.Length != 12 || tag.Length != 16 || ciphertext.Length == 0)
                throw new CryptographicException("Ratchet state envelope is invalid.");
            using var aes = new AesGcm(key, tag.Length);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, aad);
            LocalOlmState state = JsonSerializer.Deserialize<LocalOlmState>(plaintext, JsonOptions)
                ?? throw new CryptographicException("Ratchet state is empty.");
            if (state.Version != 1 || string.IsNullOrWhiteSpace(state.AccountPickle) ||
                string.IsNullOrWhiteSpace(state.Curve25519IdentityKey) ||
                string.IsNullOrWhiteSpace(state.Ed25519IdentityKey))
                throw new CryptographicException("Ratchet state is invalid.");
            return state;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(aad);
        }
    }

    private static byte[] DeriveKey(ReadOnlySpan<byte> accountRootKey, string serverUrl, string username)
    {
        byte[] context = Encoding.UTF8.GetBytes($"fedmes-ratchet-local-state-v1\n{serverUrl}\n{username}");
        try { return HMACSHA256.HashData(accountRootKey, context); }
        finally { CryptographicOperations.ZeroMemory(context); }
    }

    private string PathFor(string serverUrl, string username)
    {
        byte[] scope = Encoding.UTF8.GetBytes($"{serverUrl}\n{username}");
        byte[] hash = SHA256.HashData(scope);
        try { return Path.Combine(_directory, Convert.ToHexString(hash).ToLowerInvariant() + ".json"); }
        finally
        {
            CryptographicOperations.ZeroMemory(scope);
            CryptographicOperations.ZeroMemory(hash);
        }
    }

    private sealed record RatchetEnvelopeFile(
        [property: JsonPropertyName("version")] int Version,
        [property: JsonPropertyName("nonce")] string Nonce,
        [property: JsonPropertyName("ciphertext")] string Ciphertext,
        [property: JsonPropertyName("tag")] string Tag);

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
    };
}
