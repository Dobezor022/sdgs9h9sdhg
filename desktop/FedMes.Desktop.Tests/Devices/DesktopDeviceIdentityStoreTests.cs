using System.Security.Cryptography;
using FedMes.Desktop.Core.Devices;
using FedMes.Desktop.Core.Security;

namespace FedMes.Desktop.Tests.Devices;

[TestClass]
public sealed class DesktopDeviceIdentityStoreTests
{
    [TestMethod]
    public void LoadOrCreatePersistsKeysAndDecryptsLinkedSessionToken()
    {
        string directory = Path.Combine(Path.GetTempPath(), "FedMes.Tests", Guid.NewGuid().ToString("N"));
        string path = Path.Combine(directory, "device.json");
        try
        {
            var store = new DesktopDeviceIdentityStore(new CopyProtector(), path);
            string firstPublicKey;
            using (DesktopDeviceIdentity first = store.LoadOrCreate())
            {
                firstPublicKey = first.IdentityPublicKeySpkiBase64;
                using RSA rsa = RSA.Create();
                rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(first.EncryptionPublicKeySpkiBase64), out _);
                byte[] token = RandomNumberGenerator.GetBytes(32);
                byte[] encrypted = rsa.Encrypt(token, RSAEncryptionPadding.OaepSHA256);
                byte[] decrypted = first.DecryptSessionToken(encrypted);
                try
                {
                    CollectionAssert.AreEqual(token, decrypted);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(token);
                    CryptographicOperations.ZeroMemory(encrypted);
                    CryptographicOperations.ZeroMemory(decrypted);
                }
            }

            using DesktopDeviceIdentity second = store.LoadOrCreate();
            Assert.AreEqual(firstPublicKey, second.IdentityPublicKeySpkiBase64);

            byte[] payload = "fedmes-device-link-test"u8.ToArray();
            byte[] signature = Convert.FromBase64String(second.SignSha256Base64(payload));
            using ECDsa verifier = ECDsa.Create();
            verifier.ImportSubjectPublicKeyInfo(Convert.FromBase64String(firstPublicKey), out _);
            try
            {
                Assert.IsTrue(verifier.VerifyData(
                    payload,
                    signature,
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.Rfc3279DerSequence));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(payload);
                CryptographicOperations.ZeroMemory(signature);
            }
        }
        finally
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    [TestMethod]
    public async Task ConcurrentLoadOrCreateUsesOnePersistedIdentity()
    {
        string directory = Path.Combine(Path.GetTempPath(), "FedMes.Tests", Guid.NewGuid().ToString("N"));
        string path = Path.Combine(directory, "device.json");
        try
        {
            var store = new DesktopDeviceIdentityStore(new CopyProtector(), path);
            Task<string>[] operations = Enumerable.Range(0, 8).Select(_ => Task.Run(() =>
            {
                using DesktopDeviceIdentity identity = store.LoadOrCreate();
                return identity.IdentityPublicKeySpkiBase64;
            })).ToArray();

            string[] publicKeys = await Task.WhenAll(operations);

            Assert.AreEqual(1, publicKeys.Distinct(StringComparer.Ordinal).Count());
        }
        finally
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    private sealed class CopyProtector : ISecretProtector
    {
        public byte[] Protect(ReadOnlySpan<byte> plaintext) => plaintext.ToArray();

        public byte[] Unprotect(ReadOnlySpan<byte> protectedData) => protectedData.ToArray();
    }
}
