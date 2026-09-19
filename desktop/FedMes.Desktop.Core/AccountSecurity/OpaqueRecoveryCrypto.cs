using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace FedMes.Desktop.Core.AccountSecurity;

public sealed record OpaqueRecoveryEnvelope(
    long VaultRevision,
    int PackageVersion,
    byte[] Nonce,
    byte[] Ciphertext,
    byte[] CiphertextHash);

public static class OpaqueRecoveryCrypto
{
    public static OpaqueRecoveryEnvelope Encrypt(
        string serverUrl,
        string username,
        ReadOnlySpan<byte> exportKey,
        ReadOnlySpan<byte> accountRootKey,
        long vaultRevision)
    {
        if (exportKey.Length < 32 || accountRootKey.Length != 32 || vaultRevision <= 0)
            throw new CryptographicException("OPAQUE recovery input is invalid.");
        byte[] key = Derive(exportKey, serverUrl, username);
        byte[] plaintext = JsonSerializer.SerializeToUtf8Bytes(new
        {
            version = 1,
            username,
            vault_revision = vaultRevision,
            account_root_key = Convert.ToBase64String(accountRootKey),
        });
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] encrypted = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        byte[] aad = Aad(serverUrl, username, vaultRevision);
        try
        {
            using var aes = new AesGcm(key, tag.Length);
            aes.Encrypt(nonce, plaintext, encrypted, tag, aad);
            byte[] combined = new byte[encrypted.Length + tag.Length];
            encrypted.CopyTo(combined, 0);
            tag.CopyTo(combined, encrypted.Length);
            return new OpaqueRecoveryEnvelope(vaultRevision, 1, nonce, combined, SHA256.HashData(combined));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(encrypted);
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(aad);
        }
    }

    public static byte[] Decrypt(
        string serverUrl,
        string username,
        ReadOnlySpan<byte> exportKey,
        OpaqueRecoveryEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        if (exportKey.Length < 32 || envelope.VaultRevision <= 0 || envelope.PackageVersion != 1 ||
            envelope.Nonce.Length != 12 || envelope.Ciphertext.Length < 48 || envelope.CiphertextHash.Length != 32)
            throw new CryptographicException("OPAQUE recovery package is invalid.");
        byte[] computed = SHA256.HashData(envelope.Ciphertext);
        if (!CryptographicOperations.FixedTimeEquals(computed, envelope.CiphertextHash))
        {
            CryptographicOperations.ZeroMemory(computed);
            throw new CryptographicException("OPAQUE recovery package is corrupted.");
        }
        CryptographicOperations.ZeroMemory(computed);
        byte[] key = Derive(exportKey, serverUrl, username);
        byte[] plaintext = new byte[envelope.Ciphertext.Length - 16];
        byte[] aad = Aad(serverUrl, username, envelope.VaultRevision);
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Decrypt(envelope.Nonce, envelope.Ciphertext.AsSpan(0, plaintext.Length), envelope.Ciphertext.AsSpan(plaintext.Length), plaintext, aad);
            using JsonDocument document = JsonDocument.Parse(plaintext);
            JsonElement root = document.RootElement;
            if (root.GetProperty("version").GetInt32() != 1 ||
                !string.Equals(root.GetProperty("username").GetString(), username, StringComparison.Ordinal) ||
                root.GetProperty("vault_revision").GetInt64() != envelope.VaultRevision)
                throw new CryptographicException("OPAQUE recovery scope mismatch.");
            byte[] accountRootKey = Convert.FromBase64String(root.GetProperty("account_root_key").GetString() ?? string.Empty);
            if (accountRootKey.Length != 32)
            {
                CryptographicOperations.ZeroMemory(accountRootKey);
                throw new CryptographicException("OPAQUE recovery key is invalid.");
            }
            return accountRootKey;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(aad);
        }
    }

    private static byte[] Derive(ReadOnlySpan<byte> exportKey, string serverUrl, string username)
    {
        byte[] saltInput = Encoding.UTF8.GetBytes($"fedmes-opaque-recovery-salt-v1\n{serverUrl}\n{username}");
        byte[] salt = SHA256.HashData(saltInput);
        byte[] extract = HMACSHA256.HashData(salt, exportKey);
        byte[] info = Encoding.UTF8.GetBytes("fedmes-opaque-recovery-key-v1\u0001");
        try
        {
            return HMACSHA256.HashData(extract, info).AsSpan(0, 32).ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(saltInput);
            CryptographicOperations.ZeroMemory(salt);
            CryptographicOperations.ZeroMemory(extract);
            CryptographicOperations.ZeroMemory(info);
        }
    }

    private static byte[] Aad(string serverUrl, string username, long revision) =>
        Encoding.UTF8.GetBytes($"fedmes-opaque-recovery-v1\n{serverUrl}\n{username}\n{revision}");
}
