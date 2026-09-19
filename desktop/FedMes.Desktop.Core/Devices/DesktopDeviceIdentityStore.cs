using System.Security.Cryptography;
using System.Text.Json;
using FedMes.Desktop.Core.Security;
using FedMes.Desktop.Core.Storage;

namespace FedMes.Desktop.Core.Devices;

public sealed class DesktopDeviceIdentityStore
{
    private const int FileVersion = 1;
    private const int MaximumStateFileBytes = 64 * 1024;
    private readonly ISecretProtector _protector;
    private readonly string _filePath;
    private readonly object _gate = new();

    public DesktopDeviceIdentityStore(ISecretProtector protector, string? filePath = null)
    {
        _protector = protector ?? throw new ArgumentNullException(nameof(protector));
        _filePath = filePath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "FedMes",
            "desktop-device-v1.json");
    }

    public DesktopDeviceIdentity LoadOrCreate()
    {
        lock (_gate)
        {
            return LoadOrCreateCore();
        }
    }

    private DesktopDeviceIdentity LoadOrCreateCore()
    {
        if (File.Exists(_filePath))
        {
            return Load();
        }

        Directory.CreateDirectory(Path.GetDirectoryName(_filePath) ?? throw new InvalidOperationException("Invalid device key path."));
        using ECDsa identity = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using RSA message = RSA.Create();
        message.KeySize = 3072;
        byte[] identityPkcs8 = identity.ExportPkcs8PrivateKey();
        byte[] messagePkcs8 = message.ExportPkcs8PrivateKey();
        byte[] protectedIdentity = [];
        byte[] protectedMessage = [];
        try
        {
            protectedIdentity = _protector.Protect(identityPkcs8);
            protectedMessage = _protector.Protect(messagePkcs8);
            var document = new IdentityDocument(
                FileVersion,
                Convert.ToBase64String(protectedIdentity),
                Convert.ToBase64String(protectedMessage));
            WriteAtomic(document);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(identityPkcs8);
            CryptographicOperations.ZeroMemory(messagePkcs8);
            CryptographicOperations.ZeroMemory(protectedIdentity);
            CryptographicOperations.ZeroMemory(protectedMessage);
        }

        return Load();
    }

    private DesktopDeviceIdentity Load()
    {
        IdentityDocument? document = JsonSerializer.Deserialize<IdentityDocument>(
            LocalStateFile.ReadAllText(_filePath, MaximumStateFileBytes));
        if (document is null || document.Version != FileVersion)
        {
            throw new CryptographicException("FedMes desktop device keys are invalid or unsupported.");
        }

        byte[] protectedIdentity = Convert.FromBase64String(document.ProtectedIdentityPrivateKey);
        byte[] protectedMessage = Convert.FromBase64String(document.ProtectedMessagePrivateKey);
        byte[] identityPkcs8 = [];
        byte[] messagePkcs8 = [];
        ECDsa? identity = null;
        RSA? message = null;
        try
        {
            identityPkcs8 = _protector.Unprotect(protectedIdentity);
            messagePkcs8 = _protector.Unprotect(protectedMessage);
            identity = ECDsa.Create();
            identity.ImportPkcs8PrivateKey(identityPkcs8, out int identityRead);
            if (identityRead != identityPkcs8.Length || identity.KeySize != 256)
            {
                throw new CryptographicException("FedMes identity key is invalid.");
            }

            message = RSA.Create();
            message.ImportPkcs8PrivateKey(messagePkcs8, out int messageRead);
            if (messageRead != messagePkcs8.Length || message.KeySize < 3072)
            {
                throw new CryptographicException("FedMes message key is invalid.");
            }

            var result = new DesktopDeviceIdentity(identity, message);
            identity = null;
            message = null;
            return result;
        }
        finally
        {
            identity?.Dispose();
            message?.Dispose();
            CryptographicOperations.ZeroMemory(protectedIdentity);
            CryptographicOperations.ZeroMemory(protectedMessage);
            CryptographicOperations.ZeroMemory(identityPkcs8);
            CryptographicOperations.ZeroMemory(messagePkcs8);
        }
    }

    private void WriteAtomic(IdentityDocument document)
    {
        LocalStateFile.WriteAllTextAtomic(_filePath, JsonSerializer.Serialize(document));
    }

    private sealed record IdentityDocument(
        int Version,
        string ProtectedIdentityPrivateKey,
        string ProtectedMessagePrivateKey);
}
