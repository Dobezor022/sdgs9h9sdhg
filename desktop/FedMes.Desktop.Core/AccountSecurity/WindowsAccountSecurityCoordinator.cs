using System.Security.Cryptography;
using FedMes.Desktop.Core.Storage;

namespace FedMes.Desktop.Core.AccountSecurity;

public sealed class WindowsAccountSecurityCoordinator
{
    private readonly AccountSecurityHttpClient _api;
    private readonly WindowsAccountVaultStore _store;

    public WindowsAccountSecurityCoordinator(
        AccountSecurityHttpClient api,
        WindowsAccountVaultStore store)
    {
        _api = api ?? throw new ArgumentNullException(nameof(api));
        _store = store ?? throw new ArgumentNullException(nameof(store));
    }

    public async Task<AccountSecurityState> GetStateAsync(DesktopAccount account, CancellationToken cancellationToken) =>
        await _api.GetStateAsync(account, cancellationToken).ConfigureAwait(false);

    public async Task<string?> EnsureRecoveryConfiguredAsync(DesktopAccount account, CancellationToken cancellationToken)
    {
        AccountSecurityState state = await _api.GetStateAsync(account, cancellationToken).ConfigureAwait(false);
        if (!string.Equals(state.State, AccountSecurityProtocol.Ready, StringComparison.Ordinal)) return null;

        string? pendingRecoveryKey = _store.LoadPendingRecoveryKey(account.ServerUrl, account.Username);
        using LocalAccountVault? active = _store.Load(account.ServerUrl, account.Username);
        using LocalAccountVault? pending = _store.LoadPending(account.ServerUrl, account.Username);
        if (active is null && pending is null && state.VaultRevision > 0)
        {
            throw new InvalidOperationException("RECOVERY_REQUIRED");
        }

        byte[] rootKey = active?.AccountRootKey.ToArray()
            ?? pending?.AccountRootKey.ToArray()
            ?? AccountVaultCrypto.GenerateAccountRootKey();
        try
        {
            EncryptedAccountVault vault;
            if (state.VaultRevision == 0)
            {
                EncryptedAccountVault candidate = AccountVaultCrypto.EncryptVault(account.ServerUrl, account.Username, rootKey, 0);
                using (var localCandidate = new LocalAccountVault(rootKey.ToArray(), candidate.Revision, candidate.CryptoVersion))
                {
                    _store.SavePending(account.ServerUrl, account.Username, localCandidate);
                }
                byte[] accessVerifier = AccountVaultCrypto.CreateAccessVerifier(account.ServerUrl, account.Username, rootKey, candidate.Revision);
                try
                {
                    vault = await _api.PutVaultAsync(account, candidate, 0, accessVerifier, cancellationToken).ConfigureAwait(false);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(accessVerifier);
                }
                AccountVaultCrypto.VerifyVault(account.ServerUrl, account.Username, rootKey, vault);
                if (vault.Revision != candidate.Revision) throw new CryptographicException("Encrypted vault revision mismatch.");
                using LocalAccountVault promoted = _store.PromotePending(account.ServerUrl, account.Username);
            }
            else
            {
                vault = await _api.GetVaultAsync(account, cancellationToken).ConfigureAwait(false);
                if (vault.Revision != state.VaultRevision) throw new CryptographicException("Encrypted vault revision mismatch.");
                AccountVaultCrypto.VerifyVault(account.ServerUrl, account.Username, rootKey, vault);
                if (pending is not null)
                {
                    if (pending.VaultRevision != vault.Revision) throw new CryptographicException("Pending vault revision mismatch.");
                    using LocalAccountVault promoted = _store.PromotePending(account.ServerUrl, account.Username);
                }
                else if (active is null)
                {
                    using (var localCandidate = new LocalAccountVault(rootKey.ToArray(), vault.Revision, vault.CryptoVersion))
                    {
                        _store.SavePending(account.ServerUrl, account.Username, localCandidate);
                    }
                    using LocalAccountVault promoted = _store.PromotePending(account.ServerUrl, account.Username);
                }
            }

            if (state.RecoveryConfigured)
            {
                return pendingRecoveryKey;
            }

            string recoveryKey = pendingRecoveryKey ?? AccountVaultCrypto.GenerateRecoveryKey();
            if (pendingRecoveryKey is null)
            {
                _store.SavePendingRecoveryKey(account.ServerUrl, account.Username, recoveryKey);
            }
            EncryptedRecoveryPackage package = AccountVaultCrypto.CreateRecoveryPackage(
                account.ServerUrl,
                account.Username,
                recoveryKey,
                rootKey,
                vault.Revision);
            EncryptedRecoveryPackage stored = await _api.PutRecoveryPackageAsync(account, package, cancellationToken).ConfigureAwait(false);
            if (stored.VaultRevision != vault.Revision) throw new CryptographicException("Recovery package revision mismatch.");
            return recoveryKey;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rootKey);
        }
    }

    public void ConfirmRecoveryKeySaved(DesktopAccount account) =>
        _store.ClearPendingRecoveryKey(account.ServerUrl, account.Username);

    public async Task<DesktopAccount> RecoverAsync(
        DesktopAccount candidate,
        string recoveryKey,
        CancellationToken cancellationToken)
    {
        AccountSecurityState state = await _api.GetStateAsync(candidate, cancellationToken).ConfigureAwait(false);
        using (LocalAccountVault? active = _store.Load(candidate.ServerUrl, candidate.Username))
        {
            if (string.Equals(state.State, AccountSecurityProtocol.Ready, StringComparison.Ordinal) && active is not null)
            {
                return candidate with { AuthenticationState = AccountSecurityProtocol.Ready };
            }
        }
        using (LocalAccountVault? pending = _store.LoadPending(candidate.ServerUrl, candidate.Username))
        {
            if (string.Equals(state.State, AccountSecurityProtocol.Ready, StringComparison.Ordinal) && pending is not null)
            {
                using LocalAccountVault promoted = _store.PromotePending(candidate.ServerUrl, candidate.Username);
                return candidate with { AuthenticationState = AccountSecurityProtocol.Ready };
            }
        }

        EncryptedRecoveryPackage package = await _api.GetRecoveryPackageAsync(candidate, cancellationToken).ConfigureAwait(false);
        EncryptedAccountVault vault = await _api.GetVaultAsync(candidate, cancellationToken).ConfigureAwait(false);
        if (package.VaultRevision != vault.Revision) throw new CryptographicException("Recovery package does not match the latest encrypted vault.");

        byte[] rootKey = AccountVaultCrypto.RecoverAccountRootKey(candidate.ServerUrl, candidate.Username, recoveryKey, package);
        try
        {
            AccountVaultCrypto.VerifyVault(candidate.ServerUrl, candidate.Username, rootKey, vault);
            using (var localVault = new LocalAccountVault(rootKey.ToArray(), vault.Revision, vault.CryptoVersion))
            {
                _store.SavePending(candidate.ServerUrl, candidate.Username, localVault);
            }
            byte[] accessVerifier = AccountVaultCrypto.CreateAccessVerifier(candidate.ServerUrl, candidate.Username, rootKey, vault.Revision);
            try
            {
                await _api.CompleteRecoveryAsync(candidate, vault.Revision, accessVerifier, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(accessVerifier);
            }
            using LocalAccountVault promoted = _store.PromotePending(candidate.ServerUrl, candidate.Username);
            return candidate with { AuthenticationState = AccountSecurityProtocol.Ready };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(rootKey);
        }
    }

    public void CancelRecovery(DesktopAccount candidate) =>
        _store.DiscardPending(candidate.ServerUrl, candidate.Username);
}
