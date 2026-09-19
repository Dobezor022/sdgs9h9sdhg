using FedMes.Desktop.Core.Devices;
using FedMes.Desktop.Core.Storage;
using FedMes.Desktop.Core.Transport;

namespace FedMes.Desktop.Core.Sessions;

public sealed class DesktopSessionManager : IDisposable
{
    private readonly DesktopAccountStore _accountStore;
    private readonly DesktopDeviceIdentityStore _identityStore;
    private readonly DeviceLinkClient _linkClient;
    private readonly SemaphoreSlim _refreshLock = new(1, 1);
    private bool _disposed;

    public DesktopSessionManager(
        DesktopAccountStore accountStore,
        DesktopDeviceIdentityStore identityStore,
        DeviceLinkClient linkClient)
    {
        _accountStore = accountStore ?? throw new ArgumentNullException(nameof(accountStore));
        _identityStore = identityStore ?? throw new ArgumentNullException(nameof(identityStore));
        _linkClient = linkClient ?? throw new ArgumentNullException(nameof(linkClient));
    }

    public async Task<DesktopAccount> GetActiveAccountAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        DesktopAccount account = _accountStore.Load()
            ?? throw new InvalidOperationException("Desktop-аккаунт не подключён.");
        if (account.SessionExpiresAt > DateTimeOffset.UtcNow.AddMinutes(2))
        {
            return account;
        }

        await _refreshLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            account = _accountStore.Load()
                ?? throw new InvalidOperationException("Desktop-аккаунт не подключён.");
            if (account.SessionExpiresAt > DateTimeOffset.UtcNow.AddMinutes(2))
            {
                return account;
            }

            using DesktopDeviceIdentity identity = _identityStore.LoadOrCreate();
            DesktopAccount refreshed = await _linkClient.RefreshSessionAsync(account, identity, cancellationToken)
                .ConfigureAwait(false);
            _accountStore.Save(refreshed);
            return refreshed;
        }
        finally
        {
            _refreshLock.Release();
        }
    }

    public DesktopAccount? LoadStoredAccount() => _accountStore.Load();

    public DesktopDeviceIdentity LoadIdentity() => _identityStore.LoadOrCreate();

    public void ClearAccount() => _accountStore.Clear();

    public void Dispose()
    {
        if (_disposed) return;
        _refreshLock.Dispose();
        _disposed = true;
    }
}
