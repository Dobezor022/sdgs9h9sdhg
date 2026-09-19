using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace FedMes.Desktop.Core.AccountSecurity;

public static class AccountVaultCrypto
{
    public static byte[] GenerateAccountRootKey() => RandomNumberGenerator.GetBytes(AccountSecurityProtocol.AccountRootKeyBytes);

    public static string GenerateRecoveryKey() => Base64UrlEncode(RandomNumberGenerator.GetBytes(AccountSecurityProtocol.RecoveryKeyBytes));

    public static EncryptedAccountVault EncryptVault(string serverUrl, string username, ReadOnlySpan<byte> accountRootKey, long previousRevision)
    {
        ValidateRootKey(accountRootKey);
        long revision = checked(previousRevision + 1);
        byte[] testRecord = RandomNumberGenerator.GetBytes(32);
        byte[] plaintext = JsonSerializer.SerializeToUtf8Bytes(new
        {
            version = AccountSecurityProtocol.VaultVersion,
            crypto_version = AccountSecurityProtocol.CryptoVersion,
            username,
            revision,
            test_record = Convert.ToBase64String(testRecord),
            room_keys = new { },
            file_keys = new { },
            rotation_state = new { },
        });
        byte[] nonce = RandomNumberGenerator.GetBytes(AccountSecurityProtocol.NonceBytes);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[16];
        byte[] aad = VaultAad(serverUrl, username, revision);
        try
        {
            using var aes = new AesGcm(accountRootKey, tag.Length);
            aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);
            byte[] combined = new byte[ciphertext.Length + tag.Length];
            ciphertext.CopyTo(combined, 0);
            tag.CopyTo(combined, ciphertext.Length);
            return new EncryptedAccountVault(
                revision,
                AccountSecurityProtocol.VaultVersion,
                AccountSecurityProtocol.CryptoVersion,
                AccountSecurityProtocol.AadVersion,
                nonce,
                combined,
                Convert.ToHexStringLower(SHA256.HashData(combined)));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(testRecord);
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(aad);
        }
    }

    public static void VerifyVault(string serverUrl, string username, ReadOnlySpan<byte> accountRootKey, EncryptedAccountVault vault)
    {
        ValidateRootKey(accountRootKey);
        if (vault.VaultVersion != AccountSecurityProtocol.VaultVersion ||
            vault.CryptoVersion != AccountSecurityProtocol.CryptoVersion ||
            vault.AadVersion != AccountSecurityProtocol.AadVersion ||
            vault.Revision <= 0 || vault.Ciphertext.Length < 17 ||
            vault.Nonce.Length != AccountSecurityProtocol.NonceBytes)
        {
            throw new CryptographicException("Encrypted vault metadata is invalid.");
        }
        byte[] computedHash = SHA256.HashData(vault.Ciphertext);
        byte[] expectedHash = ParseSha256(vault.CiphertextSha256);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(computedHash, expectedHash))
            {
                throw new CryptographicException("Encrypted vault hash mismatch.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(computedHash);
            CryptographicOperations.ZeroMemory(expectedHash);
        }
        int contentLength = vault.Ciphertext.Length - 16;
        byte[] plaintext = new byte[contentLength];
        byte[] aad = VaultAad(serverUrl, username, vault.Revision);
        try
        {
            using var aes = new AesGcm(accountRootKey, 16);
            aes.Decrypt(vault.Nonce, vault.Ciphertext.AsSpan(0, contentLength), vault.Ciphertext.AsSpan(contentLength), plaintext, aad);
            using JsonDocument document = JsonDocument.Parse(plaintext);
            JsonElement root = document.RootElement;
            byte[] testRecord = Convert.FromBase64String(root.GetProperty("test_record").GetString() ?? string.Empty);
            try
            {
                if (root.GetProperty("version").GetInt32() != vault.VaultVersion ||
                    root.GetProperty("crypto_version").GetInt32() != vault.CryptoVersion ||
                    !string.Equals(root.GetProperty("username").GetString(), username, StringComparison.Ordinal) ||
                    root.GetProperty("revision").GetInt64() != vault.Revision ||
                    testRecord.Length != 32)
                {
                    throw new CryptographicException("Encrypted vault test record failed.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(testRecord);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(aad);
        }
    }

    public static EncryptedRecoveryPackage CreateRecoveryPackage(
        string serverUrl,
        string username,
        string recoveryKeyText,
        ReadOnlySpan<byte> accountRootKey,
        long vaultRevision)
    {
        ValidateRootKey(accountRootKey);
        byte[] recoveryKey = ParseRecoveryKey(recoveryKeyText);
        byte[] salt = RandomNumberGenerator.GetBytes(AccountSecurityProtocol.RecoverySaltBytes);
        byte[] wrappingKey = DeriveRecoveryWrappingKey(recoveryKey, salt);
        string id = Guid.NewGuid().ToString();
        byte[] nonce = RandomNumberGenerator.GetBytes(AccountSecurityProtocol.NonceBytes);
        byte[] encrypted = new byte[AccountSecurityProtocol.AccountRootKeyBytes];
        byte[] tag = new byte[16];
        byte[] aad = RecoveryAad(serverUrl, username, id, vaultRevision);
        try
        {
            using var aes = new AesGcm(wrappingKey, tag.Length);
            aes.Encrypt(nonce, accountRootKey, encrypted, tag, aad);
            byte[] combined = new byte[encrypted.Length + tag.Length];
            encrypted.CopyTo(combined, 0);
            tag.CopyTo(combined, encrypted.Length);
            return new EncryptedRecoveryPackage(
                id,
                vaultRevision,
                AccountSecurityProtocol.RecoveryPackageVersion,
                AccountSecurityProtocol.CryptoVersion,
                AccountSecurityProtocol.AadVersion,
                "PBKDF2-HMAC-SHA256",
                JsonSerializer.Serialize(new
                {
                    iterations = AccountSecurityProtocol.RecoveryKdfIterations,
                    key_bits = 256,
                    password_encoding = "base64url-canonical",
                }),
                salt,
                nonce,
                combined,
                Convert.ToHexStringLower(SHA256.HashData(combined)));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(recoveryKey);
            CryptographicOperations.ZeroMemory(wrappingKey);
            CryptographicOperations.ZeroMemory(encrypted);
            CryptographicOperations.ZeroMemory(tag);
            CryptographicOperations.ZeroMemory(aad);
        }
    }

    public static byte[] CreateAccessVerifier(string serverUrl, string username, ReadOnlySpan<byte> accountRootKey, long vaultRevision)
    {
        ValidateRootKey(accountRootKey);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(vaultRevision);
        byte[] context = Encoding.UTF8.GetBytes($"fedmes-vault-access-v1\n{serverUrl}\n{username}\n{vaultRevision}");
        try
        {
            return HMACSHA256.HashData(accountRootKey, context);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(context);
        }
    }

    public static byte[] RecoverAccountRootKey(string serverUrl, string username, string recoveryKeyText, EncryptedRecoveryPackage package)
    {
        ValidateRecoveryPackage(package);
        byte[] recoveryKey = ParseRecoveryKey(recoveryKeyText);
        byte[] wrappingKey = DeriveRecoveryWrappingKey(recoveryKey, package.Salt);
        byte[] plaintext = new byte[AccountSecurityProtocol.AccountRootKeyBytes];
        byte[] aad = RecoveryAad(serverUrl, username, package.Id, package.VaultRevision);
        byte[] computedHash = SHA256.HashData(package.Ciphertext);
        byte[] expectedHash = ParseSha256(package.CiphertextSha256);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(computedHash, expectedHash))
            {
                throw new CryptographicException("Recovery package is invalid.");
            }
            using var aes = new AesGcm(wrappingKey, 16);
            aes.Decrypt(package.Nonce, package.Ciphertext.AsSpan(0, AccountSecurityProtocol.AccountRootKeyBytes), package.Ciphertext.AsSpan(AccountSecurityProtocol.AccountRootKeyBytes), plaintext, aad);
            return plaintext;
        }
        catch (CryptographicException ex)
        {
            // Normalize all recovery-authentication failures to the public base exception.
            // This keeps the API stable across .NET runtime versions where AesGcm may throw
            // a more specific AuthenticationTagMismatchException.
            CryptographicOperations.ZeroMemory(plaintext);
            throw new CryptographicException("Recovery package authentication failed.", ex);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(recoveryKey);
            CryptographicOperations.ZeroMemory(wrappingKey);
            CryptographicOperations.ZeroMemory(aad);
            CryptographicOperations.ZeroMemory(computedHash);
            CryptographicOperations.ZeroMemory(expectedHash);
        }
    }

    private static void ValidateRecoveryPackage(EncryptedRecoveryPackage package)
    {
        ArgumentNullException.ThrowIfNull(package);
        if (!string.Equals(package.KdfName, "PBKDF2-HMAC-SHA256", StringComparison.Ordinal) ||
            package.PackageVersion != AccountSecurityProtocol.RecoveryPackageVersion ||
            package.CryptoVersion != AccountSecurityProtocol.CryptoVersion ||
            package.AadVersion != AccountSecurityProtocol.AadVersion || package.VaultRevision <= 0 ||
            package.Salt.Length != AccountSecurityProtocol.RecoverySaltBytes ||
            package.Nonce.Length != AccountSecurityProtocol.NonceBytes ||
            package.Ciphertext.Length != AccountSecurityProtocol.AccountRootKeyBytes + 16)
        {
            throw new CryptographicException("Recovery package metadata is invalid.");
        }
        using JsonDocument parameters = JsonDocument.Parse(package.KdfParameters);
        JsonElement root = parameters.RootElement;
        if (root.GetProperty("iterations").GetInt32() != AccountSecurityProtocol.RecoveryKdfIterations ||
            root.GetProperty("key_bits").GetInt32() != 256 ||
            !string.Equals(root.GetProperty("password_encoding").GetString(), "base64url-canonical", StringComparison.Ordinal))
        {
            throw new CryptographicException("Recovery package KDF parameters are invalid.");
        }
    }

    private static byte[] ParseSha256(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length != 64 || !value.All(Uri.IsHexDigit))
        {
            throw new CryptographicException("SHA-256 value is invalid.");
        }
        return Convert.FromHexString(value);
    }

    private static byte[] ParseRecoveryKey(string text)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(text);
        string normalized = string.Concat(text.Where(c => !char.IsWhiteSpace(c)));
        byte[] key = Base64UrlDecode(normalized);
        if (key.Length != AccountSecurityProtocol.RecoveryKeyBytes)
        {
            CryptographicOperations.ZeroMemory(key);
            throw new CryptographicException("Recovery Key has an invalid size.");
        }
        return key;
    }

    private static void ValidateRootKey(ReadOnlySpan<byte> value)
    {
        if (value.Length != AccountSecurityProtocol.AccountRootKeyBytes) throw new CryptographicException("Account Root Key has an invalid size.");
    }

    private static byte[] VaultAad(string serverUrl, string username, long revision) =>
        Encoding.UTF8.GetBytes(
            $"fedmes-vault\nprotocol={AccountSecurityProtocol.Version}\nserver={serverUrl}\naccount={username}\n" +
            $"vault_version={AccountSecurityProtocol.VaultVersion}\nrevision={revision}\n" +
            $"crypto_version={AccountSecurityProtocol.CryptoVersion}\naad_version={AccountSecurityProtocol.AadVersion}");

    private static byte[] RecoveryAad(string serverUrl, string username, string id, long revision) =>
        Encoding.UTF8.GetBytes(
            $"fedmes-recovery\nprotocol={AccountSecurityProtocol.Version}\nserver={serverUrl}\naccount={username}\n" +
            $"package_id={id}\nvault_version={AccountSecurityProtocol.VaultVersion}\nvault_revision={revision}\n" +
            $"crypto_version={AccountSecurityProtocol.CryptoVersion}\naad_version={AccountSecurityProtocol.AadVersion}");

    private static byte[] DeriveRecoveryWrappingKey(byte[] recoveryKey, byte[] salt)
    {
        string canonical = Convert.ToBase64String(recoveryKey).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        byte[] password = Encoding.ASCII.GetBytes(canonical);
        try
        {
            return Rfc2898DeriveBytes.Pbkdf2(
                password,
                salt,
                AccountSecurityProtocol.RecoveryKdfIterations,
                HashAlgorithmName.SHA256,
                32);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(password);
        }
    }

    private static string Base64UrlEncode(byte[] bytes)
    {
        try { return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_'); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private static byte[] Base64UrlDecode(string text) => Convert.FromBase64String(text.Replace('-', '+').Replace('_', '/') + new string('=', (4 - text.Length % 4) % 4));
}
