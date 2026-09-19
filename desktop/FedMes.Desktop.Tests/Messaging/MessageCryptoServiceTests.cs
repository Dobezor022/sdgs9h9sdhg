using System.Security.Cryptography;
using FedMes.Desktop.Core.Devices;
using FedMes.Desktop.Core.Messaging;
using FedMes.Desktop.Core.Security;

namespace FedMes.Desktop.Tests.Messaging;

[TestClass]
public sealed class MessageCryptoServiceTests
{
    private static readonly int[] ExpectedWaveform = [10, 40, 80];

    [TestMethod]
    public void PrepareAndDecryptRoundTripsProtocolVersionTwo()
    {
        string root = Path.Combine(Path.GetTempPath(), $"fedmes-crypto-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            var store = new DesktopDeviceIdentityStore(new PassThroughProtector(), Path.Combine(root, "identity.json"));
            using DesktopDeviceIdentity identity = store.LoadOrCreate();
            using var crypto = new MessageCryptoService(identity);
            var device = new ChatDevice(
                "device-1",
                "grisha",
                DesktopDeviceIdentity.EncryptionAlgorithm,
                identity.EncryptionPublicKeySpkiBase64);
            var media = new MediaDescriptor(
                "media-1",
                "photo.jpg",
                "image/jpeg",
                100,
                116,
                Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
                Convert.ToBase64String(RandomNumberGenerator.GetBytes(12)));
            var content = new MessageContent(
                MessageKind.MediaGroup,
                "caption",
                "reply-id",
                media,
                [media],
                true,
                new HashSet<string>(["papa"], StringComparer.Ordinal),
                [10, 40, 80],
                1234,
                RoundVideoShape.Heart,
                null,
                null,
                "mama");

            PreparedMessage prepared = crypto.Prepare("chat-1", "grisha", "device-1", content, [device], "message-1");
            var wire = new WireMessage(
                1,
                prepared.Id,
                "chat-1",
                "grisha",
                "device-1",
                prepared.CiphertextBase64,
                prepared.NonceBase64,
                prepared.Aad,
                DateTimeOffset.UtcNow,
                null,
                prepared.Envelopes[0],
                new HashSet<string>(["device-1"], StringComparer.Ordinal),
                1,
                1,
                1);

            DecryptedMessage decrypted = crypto.Decrypt(wire);

            Assert.AreEqual(MessageKind.MediaGroup, decrypted.Content.Kind);
            Assert.AreEqual("caption", decrypted.Content.Text);
            Assert.AreEqual("reply-id", decrypted.Content.ReplyToId);
            Assert.IsTrue(decrypted.Content.Spoiler);
            Assert.AreEqual(RoundVideoShape.Heart, decrypted.Content.RoundVideoShape);
            Assert.AreEqual("mama", decrypted.Content.ForwardedFromUsername);
            CollectionAssert.AreEqual(ExpectedWaveform, decrypted.Content.EffectiveWaveform.ToArray());
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [TestMethod]
    public void MediaEncryptionRoundTripsAndroidCompatiblePayload()
    {
        string root = Path.Combine(Path.GetTempPath(), $"fedmes-media-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        try
        {
            var store = new DesktopDeviceIdentityStore(new PassThroughProtector(), Path.Combine(root, "identity.json"));
            using DesktopDeviceIdentity identity = store.LoadOrCreate();
            using var crypto = new MessageCryptoService(identity);
            byte[] plaintext = RandomNumberGenerator.GetBytes(4096);
            try
            {
                using MessageCryptoService.EncryptedMedia encrypted = crypto.EncryptMedia("chat", "message", "media", plaintext);
                var descriptor = new MediaDescriptor(
                    "media",
                    "file.bin",
                    "application/octet-stream",
                    plaintext.Length,
                    encrypted.Ciphertext.Length,
                    Convert.ToBase64String(encrypted.Key),
                    Convert.ToBase64String(encrypted.Nonce));
                byte[] decrypted = crypto.DecryptMedia("chat", "message", descriptor, encrypted.Ciphertext);
                try
                {
                    CollectionAssert.AreEqual(plaintext, decrypted);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(decrypted);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plaintext);
            }
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private sealed class PassThroughProtector : ISecretProtector
    {
        public byte[] Protect(ReadOnlySpan<byte> plaintext) => plaintext.ToArray();
        public byte[] Unprotect(ReadOnlySpan<byte> protectedData) => protectedData.ToArray();
    }
}
