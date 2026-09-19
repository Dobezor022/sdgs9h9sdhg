using System.Security.Cryptography;
using FedMes.Desktop.Core.Messaging;

namespace FedMes.Desktop.Core.Devices;

public sealed class DesktopDeviceIdentity : IDisposable
{
    private readonly ECDsa _identityKey;
    private readonly RSA _messageKey;
    private bool _disposed;

    internal DesktopDeviceIdentity(ECDsa identityKey, RSA messageKey)
    {
        _identityKey = identityKey ?? throw new ArgumentNullException(nameof(identityKey));
        _messageKey = messageKey ?? throw new ArgumentNullException(nameof(messageKey));
    }

    public static string IdentityAlgorithm => "ecdsa-p256-sha256";

    public static string EncryptionAlgorithm => "rsa-oaep-sha256";

    public string IdentityPublicKeySpkiBase64 => Convert.ToBase64String(_identityKey.ExportSubjectPublicKeyInfo());

    public string EncryptionPublicKeySpkiBase64 => Convert.ToBase64String(_messageKey.ExportSubjectPublicKeyInfo());

    public string SignSha256Base64(ReadOnlySpan<byte> payload)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        byte[] signature = _identityKey.SignData(
            payload,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence);
        try
        {
            return Convert.ToBase64String(signature);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    public byte[] DecryptSessionToken(ReadOnlySpan<byte> encryptedToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _messageKey.Decrypt(encryptedToken, RSAEncryptionPadding.OaepSHA256);
    }

    public byte[] UnwrapMessageKey(ReadOnlySpan<byte> encryptedKey)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return RsaOaepSha256Mgf1Sha1.Decrypt(_messageKey, encryptedKey);
    }

    internal byte[] ExportIdentityPrivateKey() => _identityKey.ExportPkcs8PrivateKey();

    internal byte[] ExportMessagePrivateKey() => _messageKey.ExportPkcs8PrivateKey();

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _identityKey.Dispose();
        _messageKey.Dispose();
    }
}
