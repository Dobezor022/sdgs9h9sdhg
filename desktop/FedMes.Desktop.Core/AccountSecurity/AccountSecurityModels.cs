namespace FedMes.Desktop.Core.AccountSecurity;

public static class AccountSecurityProtocol
{
    public const int Version = 3;
    public const int VaultVersion = 1;
    public const int CryptoVersion = 2;
    public const int AadVersion = 1;
    public const int RecoveryPackageVersion = 1;
    public const int AccountRootKeyBytes = 32;
    public const int RecoveryKeyBytes = 32;
    public const int NonceBytes = 12;
    public const int RecoverySaltBytes = 32;
    public const int RecoveryKdfIterations = 310_000;
    public const string Ready = "READY";
    public const string AuthenticatedNoKeys = "AUTHENTICATED_NO_KEYS";
}

public sealed record EncryptedAccountVault(
    long Revision,
    int VaultVersion,
    int CryptoVersion,
    int AadVersion,
    byte[] Nonce,
    byte[] Ciphertext,
    string CiphertextSha256);

public sealed record EncryptedRecoveryPackage(
    string Id,
    long VaultRevision,
    int PackageVersion,
    int CryptoVersion,
    int AadVersion,
    string KdfName,
    string KdfParameters,
    byte[] Salt,
    byte[] Nonce,
    byte[] Ciphertext,
    string CiphertextSha256);

public sealed record LocalAccountVault(byte[] AccountRootKey, long VaultRevision, int CryptoVersion) : IDisposable
{
    public void Dispose() => System.Security.Cryptography.CryptographicOperations.ZeroMemory(AccountRootKey);
}
