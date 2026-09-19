using System.Security.Cryptography;
using FedMes.Desktop.Core.AccountSecurity;
using FedMes.Desktop.Core.Security;

namespace FedMes.Desktop.Tests.AccountSecurity;

[TestClass]
public sealed class AccountVaultCryptoTests
{
    [TestMethod]
    public void VaultRoundTripsAndRejectsTampering()
    {
        byte[] rootKey = AccountVaultCrypto.GenerateAccountRootKey();
        try
        {
            EncryptedAccountVault vault = AccountVaultCrypto.EncryptVault("https://fedmes.example", "grisha", rootKey, 0);
            AccountVaultCrypto.VerifyVault("https://fedmes.example", "grisha", rootKey, vault);

            byte[] damaged = vault.Ciphertext.ToArray();
            damaged[0] ^= 0x40;
            var tampered = vault with { Ciphertext = damaged };
            Assert.ThrowsExactly<CryptographicException>(() =>
                AccountVaultCrypto.VerifyVault("https://fedmes.example", "grisha", rootKey, tampered));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rootKey);
        }
    }

    [TestMethod]
    public void RecoveryPackageRestoresRootKeyAndWrongKeyDoesNot()
    {
        byte[] rootKey = AccountVaultCrypto.GenerateAccountRootKey();
        string recoveryKey = AccountVaultCrypto.GenerateRecoveryKey();
        try
        {
            EncryptedRecoveryPackage package = AccountVaultCrypto.CreateRecoveryPackage(
                "https://fedmes.example",
                "grisha",
                recoveryKey,
                rootKey,
                1);
            byte[] restored = AccountVaultCrypto.RecoverAccountRootKey(
                "https://fedmes.example",
                "grisha",
                recoveryKey,
                package);
            try
            {
                CollectionAssert.AreEqual(rootKey, restored);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(restored);
            }

            string wrongKey = AccountVaultCrypto.GenerateRecoveryKey();
            Assert.ThrowsExactly<CryptographicException>(() =>
                AccountVaultCrypto.RecoverAccountRootKey("https://fedmes.example", "grisha", wrongKey, package));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rootKey);
        }
    }

    [TestMethod]
    public void RecoveryInteropVectorRestoresExpectedAccountRootKey()
    {
        const string recoveryKey = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8";
        var package = new EncryptedRecoveryPackage(
            "00000000-0000-4000-8000-000000000014",
            7,
            1,
            2,
            1,
            "PBKDF2-HMAC-SHA256",
            "{\"iterations\":310000,\"key_bits\":256,\"password_encoding\":\"base64url-canonical\"}",
            Convert.FromBase64String("QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8="),
            Convert.FromBase64String("YGFiY2RlZmdoaWpr"),
            Convert.FromBase64String("vpN1OM8iNs68w0Q6KCJXsB7lhUHDgvknuq/lg163PrWlYKgn6MDal2HLOe8JnzzC"),
            "b6dcdb83a6d8c9e29700f1b4ad6e33d1270d7dc60879a4e719a80798850f4449");
        byte[] restored = AccountVaultCrypto.RecoverAccountRootKey(
            "https://fedmes.example",
            "grisha",
            recoveryKey,
            package);
        byte[] expected = Convert.FromHexString(
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        try
        {
            CollectionAssert.AreEqual(expected, restored);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(restored);
            CryptographicOperations.ZeroMemory(expected);
            CryptographicOperations.ZeroMemory(package.Salt);
            CryptographicOperations.ZeroMemory(package.Nonce);
            CryptographicOperations.ZeroMemory(package.Ciphertext);
        }
    }

    [TestMethod]
    public void StagedWindowsVaultCommitPreservesPreviousActiveFileOnFailure()
    {
        string directory = Path.Combine(Path.GetTempPath(), "FedMes.Tests", Guid.NewGuid().ToString("N"));
        var store = new WindowsAccountVaultStore(new CopyProtector(), directory);
        byte[] firstKey = RandomNumberGenerator.GetBytes(AccountSecurityProtocol.AccountRootKeyBytes);
        byte[] secondKey = RandomNumberGenerator.GetBytes(AccountSecurityProtocol.AccountRootKeyBytes);
        try
        {
            using (var first = new LocalAccountVault(firstKey.ToArray(), 1, 2))
            {
                store.SaveStaged("https://fedmes.example", "grisha", first);
            }
            using LocalAccountVault? loaded = store.Load("https://fedmes.example", "grisha");
            Assert.IsNotNull(loaded);
            CollectionAssert.AreEqual(firstKey, loaded.AccountRootKey);

            using var second = new LocalAccountVault(secondKey.ToArray(), 2, 2);
            store.SaveStaged("https://fedmes.example", "grisha", second);
            using LocalAccountVault? replaced = store.Load("https://fedmes.example", "grisha");
            Assert.IsNotNull(replaced);
            CollectionAssert.AreEqual(secondKey, replaced.AccountRootKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(firstKey);
            CryptographicOperations.ZeroMemory(secondKey);
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    private sealed class CopyProtector : ISecretProtector
    {
        public byte[] Protect(ReadOnlySpan<byte> plaintext) => plaintext.ToArray();
        public byte[] Unprotect(ReadOnlySpan<byte> protectedData) => protectedData.ToArray();
    }
}
