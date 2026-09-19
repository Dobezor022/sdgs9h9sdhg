using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FedMes.Desktop.Core.Security;

namespace FedMes.Desktop.Core.Storage;

public sealed record DesktopAccount(
    string ServerUrl,
    string Username,
    string DeviceId,
    string SessionId,
    string SessionToken,
    DateTimeOffset SessionExpiresAt,
    string DeviceDisplayName,
    string AuthenticationState = "READY");

public sealed class DesktopAccountStore
{
    private const int FileVersion = 2;
    private const int MaximumStateFileBytes = 64 * 1024;
    private readonly ISecretProtector _protector;
    private readonly string _filePath;
    private readonly string _candidatePath;
    private readonly object _gate = new();

    public DesktopAccountStore(ISecretProtector protector, string? filePath = null)
    {
        _protector = protector ?? throw new ArgumentNullException(nameof(protector));
        _filePath = filePath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "FedMes",
            "desktop-account-v1.json");
        _candidatePath = _filePath + ".candidate";
    }

    public DesktopAccount? Load()
    {
        lock (_gate)
        {
            return LoadCore(_filePath);
        }
    }

    public DesktopAccount? LoadCandidate()
    {
        lock (_gate)
        {
            return LoadCore(_candidatePath);
        }
    }

    private DesktopAccount? LoadCore(string path)
    {
        if (!File.Exists(path)) return null;
        AccountDocument? document = JsonSerializer.Deserialize<AccountDocument>(
            LocalStateFile.ReadAllText(path, MaximumStateFileBytes));
        if (document is null || document.Version is < 1 or > FileVersion)
        {
            throw new CryptographicException("FedMes desktop account is invalid or unsupported.");
        }

        byte[] protectedToken = Convert.FromBase64String(document.ProtectedSessionToken);
        byte[] tokenBytes = [];
        try
        {
            tokenBytes = _protector.Unprotect(protectedToken);
            string token = Encoding.UTF8.GetString(tokenBytes);
            return new DesktopAccount(
                document.ServerUrl,
                document.Username,
                document.DeviceId,
                document.SessionId,
                token,
                document.SessionExpiresAt,
                document.DeviceDisplayName,
                document.Version == 1 ? "READY" : document.AuthenticationState);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(protectedToken);
            CryptographicOperations.ZeroMemory(tokenBytes);
        }
    }

    public void Save(DesktopAccount account)
    {
        ArgumentNullException.ThrowIfNull(account);
        lock (_gate)
        {
            SaveCore(_filePath, account);
        }
    }

    public void SaveCandidate(DesktopAccount account)
    {
        ArgumentNullException.ThrowIfNull(account);
        lock (_gate)
        {
            SaveCore(_candidatePath, account);
        }
    }

    public void PromoteCandidate(DesktopAccount readyAccount)
    {
        ArgumentNullException.ThrowIfNull(readyAccount);
        if (!string.Equals(readyAccount.AuthenticationState, "READY", StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Only a fully restored FedMes account can replace the active account.");
        }
        lock (_gate)
        {
            SaveCore(_filePath, readyAccount);
            TryDelete(_candidatePath);
        }
    }

    private void SaveCore(string path, DesktopAccount account)
    {
        byte[] tokenBytes = Encoding.UTF8.GetBytes(account.SessionToken);
        byte[] protectedToken = [];
        try
        {
            protectedToken = _protector.Protect(tokenBytes);
            var document = new AccountDocument(
                FileVersion,
                account.ServerUrl,
                account.Username,
                account.DeviceId,
                account.SessionId,
                Convert.ToBase64String(protectedToken),
                account.SessionExpiresAt,
                account.DeviceDisplayName,
                account.AuthenticationState);
            LocalStateFile.WriteAllTextAtomic(path, JsonSerializer.Serialize(document));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(tokenBytes);
            CryptographicOperations.ZeroMemory(protectedToken);
        }
    }

    public void Clear()
    {
        lock (_gate)
        {
            TryDelete(_filePath);
        }
    }

    public void ClearCandidate()
    {
        lock (_gate)
        {
            TryDelete(_candidatePath);
        }
    }

    public void ClearAll()
    {
        lock (_gate)
        {
            TryDelete(_filePath);
            TryDelete(_candidatePath);
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
        }
    }

    private sealed record AccountDocument(
        int Version,
        string ServerUrl,
        string Username,
        string DeviceId,
        string SessionId,
        string ProtectedSessionToken,
        DateTimeOffset SessionExpiresAt,
        string DeviceDisplayName,
        string AuthenticationState = "READY");
}
