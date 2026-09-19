using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FedMes.Desktop.Core.Security;
using FedMes.Desktop.Core.Storage;

namespace FedMes.Desktop.Core.AccountSecurity;

public sealed class WindowsAccountVaultStore
{
    private const int FileVersion = 1;
    private const int MaximumFileBytes = 256 * 1024;
    private readonly ISecretProtector _protector;
    private readonly string _directory;
    private readonly object _gate = new();

    public WindowsAccountVaultStore(ISecretProtector protector, string? directory = null)
    {
        _protector = protector ?? throw new ArgumentNullException(nameof(protector));
        _directory = directory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "FedMes",
            "account-security");
    }

    public bool Exists(string serverUrl, string username) => File.Exists(ActivePath(serverUrl, username));

    public bool PendingExists(string serverUrl, string username) => File.Exists(PendingPath(serverUrl, username));

    public void SavePending(string serverUrl, string username, LocalAccountVault vault)
    {
        ArgumentNullException.ThrowIfNull(vault);
        lock (_gate)
        {
            Directory.CreateDirectory(_directory);
            byte[] encoded = Encrypt(serverUrl, username, vault);
            try
            {
                LocalStateFile.WriteAllTextAtomic(PendingPath(serverUrl, username), Encoding.UTF8.GetString(encoded));
                using LocalAccountVault verified = Decrypt(serverUrl, username, encoded);
                if (!CryptographicOperations.FixedTimeEquals(verified.AccountRootKey, vault.AccountRootKey) ||
                    verified.VaultRevision != vault.VaultRevision || verified.CryptoVersion != vault.CryptoVersion)
                {
                    throw new CryptographicException("Staged account vault verification failed.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(encoded);
            }
        }
    }

    public LocalAccountVault PromotePending(string serverUrl, string username)
    {
        lock (_gate)
        {
            string pending = PendingPath(serverUrl, username);
            if (!File.Exists(pending)) throw new CryptographicException("Pending account vault is unavailable.");
            byte[] encoded = Encoding.UTF8.GetBytes(LocalStateFile.ReadAllText(pending, MaximumFileBytes));
            try
            {
                LocalAccountVault verified = Decrypt(serverUrl, username, encoded);
                try
                {
                    LocalStateFile.WriteAllTextAtomic(ActivePath(serverUrl, username), Encoding.UTF8.GetString(encoded));
                    TryDelete(pending);
                    return verified;
                }
                catch
                {
                    verified.Dispose();
                    throw;
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(encoded);
            }
        }
    }

    public void SaveStaged(string serverUrl, string username, LocalAccountVault vault)
    {
        SavePending(serverUrl, username, vault);
        using LocalAccountVault promoted = PromotePending(serverUrl, username);
    }

    public LocalAccountVault? Load(string serverUrl, string username) => LoadPath(ActivePath(serverUrl, username), serverUrl, username);

    public LocalAccountVault? LoadPending(string serverUrl, string username) => LoadPath(PendingPath(serverUrl, username), serverUrl, username);

    public void DiscardPending(string serverUrl, string username)
    {
        lock (_gate) TryDelete(PendingPath(serverUrl, username));
    }

    public void SavePendingRecoveryKey(string serverUrl, string username, string recoveryKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(recoveryKey);
        byte[] plaintext = Encoding.ASCII.GetBytes(recoveryKey);
        byte[] protectedBytes = _protector.Protect(plaintext);
        try
        {
            lock (_gate)
            {
                Directory.CreateDirectory(_directory);
                string json = JsonSerializer.Serialize(new
                {
                    version = FileVersion,
                    scope = Scope(serverUrl, username),
                    protected_key = Convert.ToBase64String(protectedBytes),
                });
                LocalStateFile.WriteAllTextAtomic(PendingRecoveryPath(serverUrl, username), json);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(protectedBytes);
        }
    }

    public string? LoadPendingRecoveryKey(string serverUrl, string username)
    {
        lock (_gate)
        {
            string path = PendingRecoveryPath(serverUrl, username);
            if (!File.Exists(path)) return null;
            using JsonDocument document = JsonDocument.Parse(LocalStateFile.ReadAllText(path, MaximumFileBytes));
            JsonElement root = document.RootElement;
            if (root.GetProperty("version").GetInt32() != FileVersion ||
                !string.Equals(root.GetProperty("scope").GetString(), Scope(serverUrl, username), StringComparison.Ordinal))
            {
                throw new CryptographicException("Pending Recovery Key scope mismatch.");
            }
            byte[] protectedBytes = Convert.FromBase64String(root.GetProperty("protected_key").GetString() ?? string.Empty);
            byte[] plaintext = _protector.Unprotect(protectedBytes);
            try
            {
                return Encoding.ASCII.GetString(plaintext);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(protectedBytes);
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
    }

    public void ClearPendingRecoveryKey(string serverUrl, string username)
    {
        lock (_gate) TryDelete(PendingRecoveryPath(serverUrl, username));
    }

    public void DeleteLocal(string serverUrl, string username)
    {
        lock (_gate)
        {
            TryDelete(ActivePath(serverUrl, username));
            TryDelete(PendingPath(serverUrl, username));
            TryDelete(PendingRecoveryPath(serverUrl, username));
        }
    }

    private LocalAccountVault? LoadPath(string path, string serverUrl, string username)
    {
        lock (_gate)
        {
            if (!File.Exists(path)) return null;
            byte[] encoded = Encoding.UTF8.GetBytes(LocalStateFile.ReadAllText(path, MaximumFileBytes));
            try { return Decrypt(serverUrl, username, encoded); }
            finally { CryptographicOperations.ZeroMemory(encoded); }
        }
    }

    private byte[] Encrypt(string serverUrl, string username, LocalAccountVault vault)
    {
        byte[] wrappingKey = RandomNumberGenerator.GetBytes(32);
        byte[] protectedWrappingKey = _protector.Protect(wrappingKey);
        byte[] plaintext = JsonSerializer.SerializeToUtf8Bytes(new
        {
            version = FileVersion,
            server_url = serverUrl,
            username,
            vault_revision = vault.VaultRevision,
            crypto_version = vault.CryptoVersion,
            account_root_key = Convert.ToBase64String(vault.AccountRootKey),
        });
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        byte[] aad = Encoding.UTF8.GetBytes($"fedmes-windows-local-vault-v1\n{serverUrl}\n{username}");
        try
        {
            using var aes = new AesGcm(wrappingKey, tag.Length);
            aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);
            return JsonSerializer.SerializeToUtf8Bytes(new
            {
                version = FileVersion,
                protected_wrapping_key = Convert.ToBase64String(protectedWrappingKey),
                nonce = Convert.ToBase64String(nonce),
                ciphertext = Convert.ToBase64String(ciphertext),
                tag = Convert.ToBase64String(tag),
            });
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrappingKey);
            CryptographicOperations.ZeroMemory(protectedWrappingKey);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(aad);
        }
    }

    private LocalAccountVault Decrypt(string serverUrl, string username, byte[] encoded)
    {
        using JsonDocument envelope = JsonDocument.Parse(encoded);
        JsonElement root = envelope.RootElement;
        if (root.GetProperty("version").GetInt32() != FileVersion) throw new CryptographicException("Local vault version is unsupported.");
        byte[] protectedWrappingKey = Convert.FromBase64String(root.GetProperty("protected_wrapping_key").GetString() ?? string.Empty);
        byte[] wrappingKey = _protector.Unprotect(protectedWrappingKey);
        byte[] nonce = Convert.FromBase64String(root.GetProperty("nonce").GetString() ?? string.Empty);
        byte[] ciphertext = Convert.FromBase64String(root.GetProperty("ciphertext").GetString() ?? string.Empty);
        byte[] tag = Convert.FromBase64String(root.GetProperty("tag").GetString() ?? string.Empty);
        byte[] plaintext = new byte[ciphertext.Length];
        byte[] aad = Encoding.UTF8.GetBytes($"fedmes-windows-local-vault-v1\n{serverUrl}\n{username}");
        try
        {
            if (wrappingKey.Length != 32 || nonce.Length != 12 || tag.Length != 16 || ciphertext.Length < 16)
            {
                throw new CryptographicException("Local vault envelope is invalid.");
            }
            using var aes = new AesGcm(wrappingKey, tag.Length);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, aad);
            using JsonDocument payload = JsonDocument.Parse(plaintext);
            JsonElement value = payload.RootElement;
            if (value.GetProperty("version").GetInt32() != FileVersion ||
                !string.Equals(value.GetProperty("server_url").GetString(), serverUrl, StringComparison.Ordinal) ||
                !string.Equals(value.GetProperty("username").GetString(), username, StringComparison.Ordinal))
            {
                throw new CryptographicException("Local vault scope mismatch.");
            }
            byte[] rootKey = Convert.FromBase64String(value.GetProperty("account_root_key").GetString() ?? string.Empty);
            if (rootKey.Length != AccountSecurityProtocol.AccountRootKeyBytes)
            {
                CryptographicOperations.ZeroMemory(rootKey);
                throw new CryptographicException("Local Account Root Key is invalid.");
            }
            return new LocalAccountVault(rootKey, value.GetProperty("vault_revision").GetInt64(), value.GetProperty("crypto_version").GetInt32());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedWrappingKey);
            CryptographicOperations.ZeroMemory(wrappingKey);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(aad);
        }
    }

    private string ActivePath(string serverUrl, string username) => Path.Combine(_directory, Scope(serverUrl, username) + ".vault.json");
    private string PendingPath(string serverUrl, string username) => Path.Combine(_directory, Scope(serverUrl, username) + ".pending.json");
    private string PendingRecoveryPath(string serverUrl, string username) => Path.Combine(_directory, Scope(serverUrl, username) + ".recovery.pending.json");

    private static string Scope(string serverUrl, string username)
    {
        byte[] input = Encoding.UTF8.GetBytes(serverUrl + "\n" + username);
        try { return Convert.ToHexStringLower(SHA256.HashData(input)); }
        finally { CryptographicOperations.ZeroMemory(input); }
    }

    private static void TryDelete(string path)
    {
        try { File.Delete(path); }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException) { }
    }
}
