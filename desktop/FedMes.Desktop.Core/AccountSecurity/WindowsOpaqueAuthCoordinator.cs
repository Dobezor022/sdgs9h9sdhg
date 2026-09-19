using System.Security.Cryptography;
using System.Text;
using FedMes.Desktop.Core.CryptoCore;
using FedMes.Desktop.Core.Devices;
using FedMes.Desktop.Core.Storage;

namespace FedMes.Desktop.Core.AccountSecurity;

/// <summary>
/// Runs RFC 9807 OPAQUE without treating password authentication as access to
/// encrypted history. The active desktop account is replaced only after the
/// OPAQUE recovery package, encrypted vault and server access verifier have all
/// been verified.
/// </summary>
public sealed class WindowsOpaqueAuthCoordinator
{
    private readonly DesktopAccountStore _accounts;
    private readonly FedMesCryptoWorkerClient _crypto;
    private readonly OpaqueAuthHttpClient _opaqueApi;
    private readonly AccountSecurityHttpClient _securityApi;
    private readonly WindowsAccountVaultStore _vaults;

    public WindowsOpaqueAuthCoordinator(
        DesktopAccountStore accounts,
        FedMesCryptoWorkerClient crypto,
        OpaqueAuthHttpClient opaqueApi,
        AccountSecurityHttpClient securityApi,
        WindowsAccountVaultStore vaults)
    {
        _accounts = accounts ?? throw new ArgumentNullException(nameof(accounts));
        _crypto = crypto ?? throw new ArgumentNullException(nameof(crypto));
        _opaqueApi = opaqueApi ?? throw new ArgumentNullException(nameof(opaqueApi));
        _securityApi = securityApi ?? throw new ArgumentNullException(nameof(securityApi));
        _vaults = vaults ?? throw new ArgumentNullException(nameof(vaults));
    }

    public Task EnrollAsync(DesktopAccount account, char[] password, CancellationToken cancellationToken) =>
        RegisterAsync(account, password, passwordChange: false, cancellationToken);

    public Task ChangePasswordAsync(DesktopAccount account, char[] password, CancellationToken cancellationToken) =>
        RegisterAsync(account, password, passwordChange: true, cancellationToken);

    private async Task RegisterAsync(
        DesktopAccount account,
        char[] password,
        bool passwordChange,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(account);
        ValidatePasswordBuffer(password);
        if (!string.Equals(account.AuthenticationState, AccountSecurityProtocol.Ready, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("OPAQUE enrollment requires a READY trusted device.");
        }

        using LocalAccountVault local = _vaults.Load(account.ServerUrl, account.Username)
            ?? throw new InvalidOperationException("The local Account Root Key vault is required.");
        string? handle = null;
        byte[]? exportKey = null;
        try
        {
            OpaqueStartResult started = await _crypto.InvokeJsonAsync<OpaqueStartResult>(
                "opaque.registration.start",
                new { password = new string(password) },
                cancellationToken).ConfigureAwait(false);
            handle = started.Handle;
            OpaqueStartWire server = await _opaqueApi.RegistrationStartAsync(
                account,
                started.Message,
                passwordChange,
                cancellationToken).ConfigureAwait(false);
            RequireSuite(started.Suite, server.Suite);
            OpaqueFinishResult finished = await _crypto.InvokeJsonAsync<OpaqueFinishResult>(
                "opaque.registration.finish",
                new
                {
                    handle = started.Handle,
                    response = server.Message,
                    username = account.Username,
                    serverIdentity = account.ServerUrl,
                },
                cancellationToken).ConfigureAwait(false);
            RequireSuite(started.Suite, finished.Suite);
            exportKey = DecodeBase64Url(finished.ExportKey, 32, 128);
            await _opaqueApi.RegistrationFinishAsync(
                account,
                server.AttemptId,
                finished.Message,
                passwordChange,
                cancellationToken).ConfigureAwait(false);

            OpaqueRecoveryEnvelope package = OpaqueRecoveryCrypto.Encrypt(
                account.ServerUrl,
                account.Username,
                exportKey,
                local.AccountRootKey,
                local.VaultRevision);
            try
            {
                await _opaqueApi.PutRecoveryPackageAsync(account, package, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(package.Nonce);
                CryptographicOperations.ZeroMemory(package.Ciphertext);
                CryptographicOperations.ZeroMemory(package.CiphertextHash);
            }
        }
        finally
        {
            if (!string.IsNullOrWhiteSpace(handle))
            {
                try
                {
                    _ = await _crypto.InvokeAsync("opaque.cancel", new { handle }, CancellationToken.None).ConfigureAwait(false);
                }
                catch (Exception error) when (error is CryptographicException or IOException) { }
            }
            if (exportKey is not null) CryptographicOperations.ZeroMemory(exportKey);
            Array.Clear(password);
        }
    }

    public async Task<DesktopAccount> LoginAndRestoreAsync(
        string serverUrl,
        string username,
        char[] password,
        string displayName,
        DesktopDeviceIdentity identity,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(serverUrl);
        ArgumentException.ThrowIfNullOrWhiteSpace(username);
        ArgumentNullException.ThrowIfNull(identity);
        ValidatePasswordBuffer(password);

        DesktopAccount? previous = _accounts.Load();
        string deviceId = Guid.NewGuid().ToString();
        string? handle = null;
        byte[]? sessionKey = null;
        byte[]? exportKey = null;
        DesktopAccount? candidate = null;
        try
        {
            OpaqueStartResult started = await _crypto.InvokeJsonAsync<OpaqueStartResult>(
                "opaque.login.start",
                new { password = new string(password) },
                cancellationToken).ConfigureAwait(false);
            handle = started.Handle;
            OpaqueStartWire server = await _opaqueApi.LoginStartAsync(
                serverUrl,
                username,
                started.Message,
                deviceId,
                displayName,
                DesktopDeviceIdentity.IdentityAlgorithm,
                identity.IdentityPublicKeySpkiBase64,
                DesktopDeviceIdentity.EncryptionAlgorithm,
                identity.EncryptionPublicKeySpkiBase64,
                cancellationToken).ConfigureAwait(false);
            RequireSuite(started.Suite, server.Suite);
            if (string.IsNullOrWhiteSpace(server.ServerIdentity))
            {
                throw new CryptographicException("OPAQUE server identity is missing.");
            }

            OpaqueFinishResult finished = await _crypto.InvokeJsonAsync<OpaqueFinishResult>(
                "opaque.login.finish",
                new
                {
                    handle = started.Handle,
                    response = server.Message,
                    username,
                    serverIdentity = server.ServerIdentity,
                },
                cancellationToken).ConfigureAwait(false);
            RequireSuite(started.Suite, finished.Suite);
            sessionKey = DecodeBase64Url(finished.SessionKey ?? string.Empty, 32, 128);
            exportKey = DecodeBase64Url(finished.ExportKey, 32, 128);

            OpaqueLoginWire login = await _opaqueApi.LoginFinishAsync(
                serverUrl,
                server.AttemptId,
                finished.Message,
                cancellationToken).ConfigureAwait(false);
            if (!string.Equals(login.Username, username, StringComparison.Ordinal) ||
                !string.Equals(login.DeviceId, deviceId, StringComparison.Ordinal) ||
                !string.Equals(login.AuthenticationState, AccountSecurityProtocol.AuthenticatedNoKeys, StringComparison.Ordinal))
            {
                throw new CryptographicException("OPAQUE login response scope is invalid.");
            }
            VerifyServerProof(sessionKey, server.AttemptId, login);

            candidate = new DesktopAccount(
                serverUrl,
                username,
                login.DeviceId,
                login.SessionId,
                login.SessionToken,
                login.ExpiresAt,
                string.IsNullOrWhiteSpace(displayName) ? Environment.MachineName : displayName,
                login.AuthenticationState);
            _accounts.SaveCandidate(candidate);

            OpaqueRecoveryWire recovery = await _opaqueApi.GetRecoveryPackageAsync(candidate, cancellationToken).ConfigureAwait(false);
            byte[] nonce = OpaqueAuthHttpClient.Base64UrlDecode(recovery.Nonce);
            byte[] ciphertext = OpaqueAuthHttpClient.Base64UrlDecode(recovery.Ciphertext);
            byte[] hash = ParseHash(recovery.CiphertextSha256);
            byte[] rootKey;
            try
            {
                rootKey = OpaqueRecoveryCrypto.Decrypt(
                    serverUrl,
                    username,
                    exportKey,
                    new OpaqueRecoveryEnvelope(recovery.VaultRevision, recovery.PackageVersion, nonce, ciphertext, hash));
            }
            finally
            {
                CryptographicOperations.ZeroMemory(nonce);
                CryptographicOperations.ZeroMemory(ciphertext);
                CryptographicOperations.ZeroMemory(hash);
            }

            try
            {
                EncryptedAccountVault vault = await _securityApi.GetVaultAsync(candidate, cancellationToken).ConfigureAwait(false);
                if (vault.Revision != recovery.VaultRevision)
                {
                    throw new CryptographicException("OPAQUE recovery package does not match the latest vault.");
                }
                AccountVaultCrypto.VerifyVault(serverUrl, username, rootKey, vault);
                using (var pending = new LocalAccountVault(rootKey.ToArray(), vault.Revision, vault.CryptoVersion))
                {
                    _vaults.SavePending(serverUrl, username, pending);
                }
                byte[] verifier = AccountVaultCrypto.CreateAccessVerifier(serverUrl, username, rootKey, vault.Revision);
                try
                {
                    await _securityApi.CompleteRecoveryAsync(candidate, vault.Revision, verifier, cancellationToken).ConfigureAwait(false);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(verifier);
                }
                using LocalAccountVault promotedVault = _vaults.PromotePending(serverUrl, username);
                DesktopAccount ready = candidate with
                {
                    AuthenticationState = AccountSecurityProtocol.Ready,
                };
                _accounts.PromoteCandidate(ready);
                return ready;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(rootKey);
            }
        }
        catch
        {
            if (candidate is not null)
            {
                _vaults.DiscardPending(candidate.ServerUrl, candidate.Username);
            }
            _accounts.ClearCandidate();
            if (previous is not null) _accounts.Save(previous);
            throw;
        }
        finally
        {
            if (!string.IsNullOrWhiteSpace(handle))
            {
                try
                {
                    _ = await _crypto.InvokeAsync("opaque.cancel", new { handle }, CancellationToken.None).ConfigureAwait(false);
                }
                catch (Exception error) when (error is CryptographicException or IOException) { }
            }
            if (sessionKey is not null) CryptographicOperations.ZeroMemory(sessionKey);
            if (exportKey is not null) CryptographicOperations.ZeroMemory(exportKey);
            Array.Clear(password);
        }
    }

    private static void VerifyServerProof(byte[] sessionKey, string attemptId, OpaqueLoginWire login)
    {
        byte[] canonical = Encoding.UTF8.GetBytes(
            $"fedmes-opaque-server-proof-v1\n{attemptId}\n{login.DeviceId}\n{login.SessionId}");
        byte[] expected = HMACSHA256.HashData(sessionKey, canonical);
        byte[] actual = DecodeBase64Url(login.ServerProof, 32, 32);
        try
        {
            if (!CryptographicOperations.FixedTimeEquals(expected, actual))
            {
                throw new CryptographicException("OPAQUE server proof is invalid.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(canonical);
            CryptographicOperations.ZeroMemory(expected);
            CryptographicOperations.ZeroMemory(actual);
        }
    }

    private static byte[] ParseHash(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length != 64 || !value.All(Uri.IsHexDigit))
        {
            throw new CryptographicException("OPAQUE package hash is invalid.");
        }
        return Convert.FromHexString(value);
    }

    private static byte[] DecodeBase64Url(string value, int minimum, int maximum)
    {
        byte[] bytes;
        try { bytes = OpaqueAuthHttpClient.Base64UrlDecode(value); }
        catch (FormatException error) { throw new CryptographicException("OPAQUE message encoding is invalid.", error); }
        if (bytes.Length < minimum || bytes.Length > maximum)
        {
            CryptographicOperations.ZeroMemory(bytes);
            throw new CryptographicException("OPAQUE message size is invalid.");
        }
        return bytes;
    }

    private static void RequireSuite(string expected, string actual)
    {
        if (!string.Equals(expected, actual, StringComparison.Ordinal) || string.IsNullOrWhiteSpace(expected))
        {
            throw new CryptographicException("OPAQUE ciphersuite mismatch.");
        }
    }

    private static void ValidatePasswordBuffer(char[] password)
    {
        ArgumentNullException.ThrowIfNull(password);
        if (password.Length < 12 || password.Length > 512 || password.All(char.IsWhiteSpace))
        {
            Array.Clear(password);
            throw new ArgumentException("Use a password phrase of at least 12 characters.", nameof(password));
        }
    }
}
