using System.ComponentModel;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Animation;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using FedMes.Desktop.Core.AccountSecurity;
using FedMes.Desktop.Core.Devices;
using FedMes.Desktop.Core.CryptoCore;
using FedMes.Desktop.Core.Messaging;
using FedMes.Desktop.Core.Security;
using FedMes.Desktop.Core.Sessions;
using FedMes.Desktop.Core.Storage;
using FedMes.Desktop.Core.Transport;
using FedMes.Desktop.Services;
using FedMes.Desktop.Updates;
using FedMes.Desktop.ViewModels;
using FedMes.Desktop.Views;
using Microsoft.Win32;

namespace FedMes.Desktop;

public partial class MainWindow : Window, IDisposable
{
    private const double CompactLayoutBreakpoint = 760;
    private const ServerEndpointMode EndpointMode = ServerEndpointMode.Production;
    private readonly WindowsDpapiSecretProtector _protector = new();
    private readonly DesktopDeviceIdentityStore _identityStore;
    private readonly DesktopAccountStore _accountStore;
    private readonly WindowsAccountVaultStore _accountVaultStore;
    private readonly AccountSecurityHttpClient _accountSecurityApi = new(endpointMode: EndpointMode);
    private readonly WindowsAccountSecurityCoordinator _accountSecurityCoordinator;
    private readonly FedMesCryptoWorkerClient _cryptoWorker = new();
    private readonly OpaqueAuthHttpClient _opaqueAuthApi = new();
    private readonly WindowsOpaqueAuthCoordinator _opaqueAuthCoordinator;
    private readonly DeviceLinkClient _linkClient = new(endpointMode: EndpointMode);
    private readonly VoiceRecorderService _voiceRecorder = new();
    private readonly DesktopPreferencesStore _preferencesStore = new();
    private readonly DesktopPreferences _preferences;
    private readonly DesktopUpdateClient _updateClient = new();
    private CancellationTokenSource? _loginCancellation;
    private CancellationTokenSource? _backgroundCancellation;
    private CancellationTokenSource? _uploadCancellation;
    private CancellationTokenSource? _typingCancellation;
    private CancellationTokenSource? _readCursorCancellation;
    private CancellationTokenSource? _previewCancellation;
    private readonly SemaphoreSlim _previewLoadGate = new(4, 4);
    private DeviceLinkTicket? _activeTicket;
    private Uri? _activeServer;
    private DesktopDeviceIdentity? _activeIdentity;
    private DesktopSessionManager? _sessionManager;
    private MessagingApiClient? _messagingApi;
    private MessagingRepository? _repository;
    private MediaCacheService? _mediaCache;
    private MainViewModel? _viewModel;
    private DispatcherTimer? _heartbeatTimer;
    private DispatcherTimer? _typingTimer;
    private DispatcherTimer? _updateTimer;
    private long _eventCursor;
    private bool _disposed;
    private bool _scrollAfterRefresh;
    private string _lastComposerText = string.Empty;
    private bool _suppressComposerFormattingRemap;
    private bool _isCompactLayout;
    private bool _compactChatOpen;
    private bool _suppressChatSelection;
    private bool _windowPlacementRestored;
    private bool _updateCheckActive;
    private bool _loadingOlderMessages;
    private long? _dismissedUpdateCode;
    private readonly Stack<ChatItemViewModel> _forwardBackStack = new();
    private bool _navigatingForwardHistory;

    public MainWindow()
    {
        _preferences = _preferencesStore.Load();
        DesktopThemeManager.Apply(_preferences.ThemeMode);
        InitializeComponent();
        UpdateThemeGlyph();
        _identityStore = new DesktopDeviceIdentityStore(_protector);
        _accountStore = new DesktopAccountStore(_protector);
        _accountVaultStore = new WindowsAccountVaultStore(_protector);
        _accountSecurityCoordinator = new WindowsAccountSecurityCoordinator(
            _accountSecurityApi,
            _accountVaultStore);
        _opaqueAuthCoordinator = new WindowsOpaqueAuthCoordinator(
            _accountStore,
            _cryptoWorker,
            _opaqueAuthApi,
            _accountSecurityApi,
            _accountVaultStore);
        ServerUrlTextBox.Text = Environment.GetEnvironmentVariable("FEDMES_SERVER_URL")
            ?? "https://support-walrus.msk.ru";
        Loaded += MainWindow_Loaded;
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        try
        {
            RestoreWindowPlacement();
            ApplyResponsiveLayout();
            await RestoreAccountAsync(forceRefresh: true).ConfigureAwait(true);
        }
        catch (Exception)
        {
            ShowWelcome("Не удалось безопасно восстановить FedMes. Повторите вход или проверьте адрес сервера.");
        }
        StartUpdateChecks();
        await CheckForUpdatesAsync().ConfigureAwait(true);
    }

    private void StartUpdateChecks()
    {
        _updateTimer?.Stop();
        _updateTimer = new DispatcherTimer(
            TimeSpan.FromMinutes(10),
            DispatcherPriority.Background,
            UpdateTimer_Tick,
            Dispatcher);
        _updateTimer.Start();
    }

    private async void UpdateTimer_Tick(object? sender, EventArgs e) =>
        await CheckForUpdatesAsync().ConfigureAwait(true);

    private async Task CheckForUpdatesAsync()
    {
        if (_disposed || _updateCheckActive) return;
        _updateCheckActive = true;
        try
        {
            DesktopAccount? account = _accountStore.Load();
            if (account is null || string.IsNullOrWhiteSpace(account.SessionToken)) return;
            _ = ServerEndpointPolicy.Normalize(account.ServerUrl, EndpointMode);
            DesktopUpdateRelease? release = await _updateClient.CheckAsync(account, CancellationToken.None)
                .ConfigureAwait(true);
            if (release is null || (!release.Required && _dismissedUpdateCode == release.VersionCode)) return;

            string notes = string.IsNullOrWhiteSpace(release.Notes) ? string.Empty : $"\n\n{release.Notes}";
            MessageBoxResult answer = MessageBox.Show(
                this,
                $"Доступна версия FedMes {release.VersionName}.{notes}\n\nСкачать и установить обновление сейчас?",
                release.Required ? "Требуется обновление FedMes" : "Обновление FedMes",
                MessageBoxButton.YesNo,
                release.Required ? MessageBoxImage.Warning : MessageBoxImage.Information);
            if (answer != MessageBoxResult.Yes)
            {
                if (release.Required)
                {
                    Close();
                }
                else
                {
                    _dismissedUpdateCode = release.VersionCode;
                }
                return;
            }

            var progress = new Progress<int>(value =>
            {
                if (_viewModel is not null) _viewModel.StatusText = $"Загрузка обновления: {value}%";
                WelcomeStatusText.Text = $"Загрузка обновления: {value}%";
            });
            string downloaded;
            try
            {
                downloaded = await _updateClient.DownloadAsync(
                    release,
                    account.SessionToken,
                    progress,
                    CancellationToken.None).ConfigureAwait(true);
            }
            catch (Exception error) when (error is DesktopUpdateTicketExpiredException or HttpRequestException or IOException or InvalidDataException or CryptographicException)
            {
                account = _accountStore.Load() ?? throw new InvalidOperationException("Сессия FedMes недоступна.");
                release = await _updateClient.CheckAsync(account, CancellationToken.None).ConfigureAwait(true)
                    ?? throw new InvalidOperationException("Обновление больше не доступно.");
                downloaded = await _updateClient.DownloadAsync(
                    release,
                    account.SessionToken,
                    progress,
                    CancellationToken.None).ConfigureAwait(true);
            }
            DesktopSelfUpdater.Launch(downloaded);
            Application.Current.Shutdown();
        }
        catch (Exception error) when (error is DesktopUpdateTicketExpiredException or HttpRequestException or IOException or InvalidDataException or TimeoutException or JsonException or FormatException or CryptographicException or ServerEndpointPolicyException or UnauthorizedAccessException or InvalidOperationException)
        {
            if (_viewModel is not null) _viewModel.StatusText = "Проверка обновлений временно недоступна";
        }
        finally
        {
            _updateCheckActive = false;
        }
    }

    private async Task RestoreAccountAsync(bool forceRefresh)
    {
        DesktopAccount? account = null;
        try
        {
            DesktopAccount? candidate = _accountStore.LoadCandidate();
            if (candidate is not null)
            {
                DesktopAccount? recovered = await RecoverCandidateAccountAsync(candidate).ConfigureAwait(true);
                if (recovered is not null)
                {
                    account = recovered;
                }
                else
                {
                    account = _accountStore.Load();
                }
            }
            else
            {
                account = _accountStore.Load();
            }
            if (account is null)
            {
                ShowWelcome();
                return;
            }

            if (forceRefresh || account.SessionExpiresAt <= DateTimeOffset.UtcNow.AddMinutes(2))
            {
                using DesktopDeviceIdentity identity = _identityStore.LoadOrCreate();
                account = await _linkClient.RefreshSessionAsync(account, identity, CancellationToken.None)
                    .ConfigureAwait(true);
                _accountStore.Save(account);
            }

            AccountSecurityState securityState = await _accountSecurityCoordinator.GetStateAsync(account, CancellationToken.None)
                .ConfigureAwait(true);
            string effectiveState = securityState.State;
            if (string.Equals(effectiveState, AccountSecurityProtocol.Ready, StringComparison.Ordinal) &&
                securityState.VaultRevision > 0 &&
                !_accountVaultStore.Exists(account.ServerUrl, account.Username))
            {
                effectiveState = "RECOVERY_REQUIRED";
            }
            account = account with { AuthenticationState = effectiveState };
            if (!string.Equals(account.AuthenticationState, AccountSecurityProtocol.Ready, StringComparison.Ordinal))
            {
                _accountStore.SaveCandidate(account);
                DesktopAccount? recovered = await RecoverCandidateAccountAsync(account).ConfigureAwait(true);
                if (recovered is null)
                {
                    ShowWelcome("Серверная сессия создана, но ключи истории ещё не восстановлены.");
                    return;
                }
                account = recovered;
            }
            else
            {
                _accountStore.Save(account);
                await EnsureRecoveryConfiguredAsync(account).ConfigureAwait(true);
            }

            await EnterMessengerAsync().ConfigureAwait(true);
        }
        catch (HttpRequestException error) when (error.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
        {
            _accountStore.Clear();
            ShowWelcome("Этот компьютер отключён на телефоне. Подключите его заново.");
        }
        catch (Exception error) when (error is CryptographicException or JsonException or FormatException)
        {
            ShowWelcome("Локальное защищённое состояние временно недоступно или повреждено. Оно не удалено; повторите запуск или восстановление.");
        }
        catch (Exception error) when (error is IOException or HttpRequestException or TimeoutException)
        {
            ShowWelcome(account is null
                ? "Не удалось прочитать сохранённый вход."
                : $"Сервер недоступен: {error.Message}");
        }
        catch (ServerEndpointPolicyException)
        {
            ShowWelcome("Сохранённый адрес сервера больше не разрешён. Используйте HTTPS или локальный адрес прототипа и выполните вход заново.");
        }
    }

    private async Task<DesktopAccount?> RecoverCandidateAccountAsync(DesktopAccount candidate)
    {
        var dialog = new RecoveryKeyWindow(this, candidate.Username);
        if (dialog.ShowDialog() != true)
        {
            _accountSecurityCoordinator.CancelRecovery(candidate);
            _accountStore.ClearCandidate();
            return null;
        }

        try
        {
            DesktopAccount recovered = await _accountSecurityCoordinator.RecoverAsync(
                candidate,
                dialog.RecoveryKey,
                CancellationToken.None).ConfigureAwait(true);
            _accountStore.PromoteCandidate(recovered);
            return recovered;
        }
        catch (CryptographicException)
        {
            MessageBox.Show(
                this,
                "Recovery Key неверен либо зашифрованное хранилище повреждено. Рабочий профиль не изменён.",
                "FedMes",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            return null;
        }
        catch (Exception error) when (error is HttpRequestException or IOException or TimeoutException or InvalidOperationException or UnauthorizedAccessException or JsonException)
        {
            MessageBox.Show(
                this,
                $"Безопасное восстановление не завершено: {error.Message}",
                "FedMes",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return null;
        }
    }

    private async Task EnsureRecoveryConfiguredAsync(DesktopAccount account)
    {
        try
        {
            string? recoveryKey = await _accountSecurityCoordinator.EnsureRecoveryConfiguredAsync(account, CancellationToken.None)
                .ConfigureAwait(true);
            if (string.IsNullOrWhiteSpace(recoveryKey)) return;
            var dialog = new RecoveryKeyDisplayWindow(this, recoveryKey);
            if (dialog.ShowDialog() == true)
            {
                _accountSecurityCoordinator.ConfirmRecoveryKeySaved(account);
            }
        }
        catch (AccountSecurityRecordNotFoundException)
        {
            // A server upgraded before the security migration may not have a vault yet.
        }
        catch (Exception error) when (error is HttpRequestException or IOException or TimeoutException or InvalidOperationException or UnauthorizedAccessException or JsonException or CryptographicException)
        {
            MessageBox.Show(
                this,
                $"Не удалось завершить настройку Recovery Key: {error.Message}",
                "FedMes",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
    }

    private async Task EnterMessengerAsync()
    {
        StopMessenger();
        _sessionManager = new DesktopSessionManager(_accountStore, _identityStore, _linkClient);
        _messagingApi = new MessagingApiClient(endpointMode: EndpointMode);
        DesktopDeviceIdentity identity = _identityStore.LoadOrCreate();
        _repository = new MessagingRepository(_sessionManager, _messagingApi, identity, _accountVaultStore, _cryptoWorker);
        _mediaCache = new MediaCacheService(_repository);
        _viewModel = new MainViewModel(_repository);
        DataContext = _viewModel;
        SplashPanel.Visibility = Visibility.Collapsed;
        LoginPanel.Visibility = Visibility.Collapsed;
        MessengerPanel.Visibility = Visibility.Visible;
        await _viewModel.InitializeAsync(_preferences.ShowExactPresence, CancellationToken.None).ConfigureAwait(true);
        UpdateComposerActions();
        ICollectionView chatView = CollectionViewSource.GetDefaultView(_viewModel.Chats);
        chatView.Filter = FilterChat;
        ChatItemViewModel? initialChat = _viewModel.Chats.FirstOrDefault(chat =>
            string.Equals(chat.Id, _preferences.LastChatId, StringComparison.Ordinal))
            ?? _viewModel.Chats.FirstOrDefault();
        if (initialChat is not null)
        {
            _suppressChatSelection = true;
            ChatListBox.SelectedItem = initialChat;
            _suppressChatSelection = false;
            await OpenChatAsync(initialChat, _preferences.CompactChatOpen).ConfigureAwait(true);
        }

        UpdateChatEmptyState();
        ApplyResponsiveLayout();
        StartBackgroundUpdates();
    }

    private void StartBackgroundUpdates()
    {
        _backgroundCancellation?.Cancel();
        _backgroundCancellation?.Dispose();
        _backgroundCancellation = new CancellationTokenSource();
        CancellationToken token = _backgroundCancellation.Token;
        _ = RunEventLoopAsync(token);

        _heartbeatTimer = new DispatcherTimer(TimeSpan.FromSeconds(20), DispatcherPriority.Background, HeartbeatTimer_Tick, Dispatcher);
        _heartbeatTimer.Start();
        _typingTimer = new DispatcherTimer(TimeSpan.FromSeconds(2), DispatcherPriority.Background, TypingTimer_Tick, Dispatcher);
        _typingTimer.Start();
    }

    private async Task RunEventLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                MessagingRepository repository = _repository ?? throw new InvalidOperationException("Messenger is not initialized.");
                _eventCursor = await repository.WaitForEventsAsync(_eventCursor, cancellationToken).ConfigureAwait(false);
                await Dispatcher.InvokeAsync(RefreshAfterEventAsync, DispatcherPriority.Background).Task.Unwrap().ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }
            catch (FedMesApiException error) when (error.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            {
                await Dispatcher.InvokeAsync(() => HandleRevokedSession(error.Message)).Task.ConfigureAwait(false);
                return;
            }
            catch (Exception error) when (error is HttpRequestException or IOException or TimeoutException)
            {
                await Dispatcher.InvokeAsync(() =>
                {
                    if (_viewModel is not null) _viewModel.StatusText = "Нет соединения — повторная попытка…";
                }).Task.ConfigureAwait(false);
                await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private async Task RefreshAfterEventAsync()
    {
        if (_viewModel is null) return;
        bool wasNearBottom = IsMessagesNearBottom();
        int previousCount = _viewModel.Messages.Count;
        // Message events are latency-sensitive. Keep the hot path to two requests: chat
        // summaries plus the selected conversation. Presence is refreshed by the heartbeat
        // timer and non-selected previews are updated lazily, avoiding an N+1 request burst
        // every time any family member types, reads or sends a message.
        await _viewModel.RefreshChatsAsync(CancellationToken.None).ConfigureAwait(true);
        await _viewModel.RefreshSelectedChatAsync(CancellationToken.None).ConfigureAwait(true);
        CollectionViewSource.GetDefaultView(_viewModel.Chats).Refresh();
        UpdateChatEmptyState();
        UpdatePinnedMessageBar();
        bool newMessageArrived = _viewModel.Messages.Count > previousCount;
        if (_scrollAfterRefresh || (wasNearBottom && newMessageArrived))
        {
            ScrollToBottom();
        }
        _scrollAfterRefresh = false;

        _viewModel.StatusText = "Подключено";
    }

    private async void HeartbeatTimer_Tick(object? sender, EventArgs e)
    {
        if (_repository is null || _viewModel is null) return;
        try
        {
            await _repository.HeartbeatAsync(false, CancellationToken.None).ConfigureAwait(true);
            await _viewModel.ApplyPresenceAsync(CancellationToken.None).ConfigureAwait(true);
            _viewModel.StatusText = "Подключено";
        }
        catch (Exception error) when (error is HttpRequestException or IOException)
        {
            _viewModel.StatusText = "Нет соединения";
        }
    }

    private async void TypingTimer_Tick(object? sender, EventArgs e)
    {
        if (_viewModel is null) return;
        try
        {
            await _viewModel.RefreshTypingAsync(CancellationToken.None).ConfigureAwait(true);
        }
        catch (Exception error) when (error is HttpRequestException or IOException)
        {
        }
    }

    private async void ChatListBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_suppressChatSelection || _viewModel is null || ChatListBox.SelectedItem is not ChatItemViewModel chat) return;
        if (!_navigatingForwardHistory) _forwardBackStack.Clear();
        await OpenChatAsync(chat, openCompactChat: true).ConfigureAwait(true);
    }

    private async void ChatListBox_PreviewMouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        if (!_isCompactLayout || _compactChatOpen || _viewModel is null || e.OriginalSource is not DependencyObject source) return;
        if (ItemsControl.ContainerFromElement(ChatListBox, source) is not ListBoxItem item ||
            item.DataContext is not ChatItemViewModel chat ||
            !ReferenceEquals(ChatListBox.SelectedItem, chat))
        {
            return;
        }

        await OpenChatAsync(chat, openCompactChat: true).ConfigureAwait(true);
    }

    private async Task OpenChatAsync(ChatItemViewModel chat, bool openCompactChat)
    {
        if (_viewModel is null) return;
        try
        {
            ResetPreviewLoading();
            await _viewModel.SelectChatAsync(chat, CancellationToken.None).ConfigureAwait(true);
            if (_viewModel.SelectedChat is null || !ReferenceEquals(_viewModel.SelectedChat, chat)) return;
            await LoadMessagePreviewsAsync().ConfigureAwait(true);
            if (_viewModel.SelectedChat is null || !ReferenceEquals(_viewModel.SelectedChat, chat)) return;
            UpdatePinnedMessageBar();
            ScrollToBottom();
            _ = Dispatcher.BeginInvoke(DispatcherPriority.Loaded, new Action(ScheduleVisibleReadCursorUpdate));
            _compactChatOpen = openCompactChat;
            _preferences.LastChatId = chat.Id;
            _preferences.CompactChatOpen = _compactChatOpen;
            SaveDesktopPreferences();
            ApplyResponsiveLayout();
            if (!_isCompactLayout || _compactChatOpen) MessageTextBox.Focus();
        }
        catch (Exception error) when (error is HttpRequestException or IOException or CryptographicException)
        {
            ShowError(error.Message);
        }
    }

    private async void BackToChatsButton_Click(object sender, RoutedEventArgs e)
    {
        if (_forwardBackStack.TryPop(out ChatItemViewModel? previous))
        {
            _navigatingForwardHistory = true;
            _suppressChatSelection = true;
            try
            {
                ChatListBox.SelectedItem = previous;
                await OpenChatAsync(previous, openCompactChat: true).ConfigureAwait(true);
            }
            finally
            {
                _suppressChatSelection = false;
                _navigatingForwardHistory = false;
            }
            return;
        }
        _compactChatOpen = false;
        _preferences.CompactChatOpen = false;
        _previewCancellation?.Cancel();
        _suppressChatSelection = true;
        try
        {
            ChatListBox.SelectedItem = null;
            _viewModel?.CloseChat();
        }
        finally
        {
            _suppressChatSelection = false;
        }
        SaveDesktopPreferences();
        ApplyResponsiveLayout();
        ChatListBox.Focus();
    }

    private void MainWindow_SizeChanged(object sender, SizeChangedEventArgs e) => ApplyResponsiveLayout();

    private void ApplyResponsiveLayout()
    {
        if (!IsInitialized || SidebarColumn is null || ConversationColumn is null) return;
        _isCompactLayout = ActualWidth > 0 && ActualWidth < CompactLayoutBreakpoint;
        bool showCompactConversation = _isCompactLayout && _compactChatOpen && _viewModel?.SelectedChat is not null;
        if (_isCompactLayout)
        {
            SidebarColumn.Width = showCompactConversation ? new GridLength(0) : new GridLength(1, GridUnitType.Star);
            ConversationColumn.Width = showCompactConversation ? new GridLength(1, GridUnitType.Star) : new GridLength(0);
            SidebarPanel.Visibility = showCompactConversation ? Visibility.Collapsed : Visibility.Visible;
            ConversationPanel.Visibility = showCompactConversation ? Visibility.Visible : Visibility.Collapsed;
            BackButtonColumn.Width = showCompactConversation ? new GridLength(48) : new GridLength(0);
            BackToChatsButton.Visibility = showCompactConversation ? Visibility.Visible : Visibility.Collapsed;
            MessagesListBox.Padding = new Thickness(8, 12, 8, 12);
        }
        else
        {
            SidebarColumn.Width = new GridLength(360);
            ConversationColumn.Width = new GridLength(1, GridUnitType.Star);
            SidebarPanel.Visibility = Visibility.Visible;
            ConversationPanel.Visibility = Visibility.Visible;
            BackButtonColumn.Width = new GridLength(0);
            BackToChatsButton.Visibility = Visibility.Collapsed;
            MessagesListBox.Padding = new Thickness(24, 18, 24, 18);
        }
    }

    private async void SendButton_Click(object sender, RoutedEventArgs e)
    {
        await SendTextAsync(false).ConfigureAwait(true);
    }

    private async Task SendTextAsync(bool spoiler)
    {
        if (_viewModel is null || string.IsNullOrWhiteSpace(_viewModel.DraftText)) return;
        try
        {
            _scrollAfterRefresh = true;
            await _viewModel.SendTextAsync(spoiler, CancellationToken.None).ConfigureAwait(true);
            PlaySendSound();
            _lastComposerText = string.Empty;
            UpdateComposerActions();
            await LoadMessagePreviewsAsync().ConfigureAwait(true);
            ScrollToBottom();
        }
        catch (Exception error) when (error is ArgumentException or InvalidOperationException or HttpRequestException or IOException or CryptographicException)
        {
            ShowError(error.Message);
        }
    }

    private static void PlaySendSound()
    {
        try
        {
            string path = Path.Combine(AppContext.BaseDirectory, "Assets", "fedmes_send.wav");
            if (File.Exists(path))
            {
                _ = Task.Run(() =>
                {
                    using var player = new System.Media.SoundPlayer(path);
                    player.PlaySync();
                });
            }
        }
        catch (InvalidOperationException)
        {
            // A UI sound must never interrupt message delivery.
        }
    }

    private async void MessageTextBox_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && Keyboard.Modifiers.HasFlag(ModifierKeys.Shift))
        {
            e.Handled = true;
            await SendTextAsync(false).ConfigureAwait(true);
        }
    }

    private async void MessageTextBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        UpdateComposerActions();
        if (_viewModel is null) return;
        string nextText = MessageTextBox.Text;
        if (!_suppressComposerFormattingRemap)
        {
            _viewModel.DraftTextEntities = TextFormatting.RemapAfterEdit(
                _lastComposerText,
                nextText,
                _viewModel.DraftTextEntities);
        }
        _lastComposerText = nextText;
        _typingCancellation?.Cancel();
        _typingCancellation?.Dispose();
        _typingCancellation = new CancellationTokenSource();
        CancellationToken token = _typingCancellation.Token;
        bool typing = !string.IsNullOrWhiteSpace(MessageTextBox.Text);
        try
        {
            await _viewModel.UpdateTypingAsync(typing, token).ConfigureAwait(true);
            if (typing)
            {
                await Task.Delay(TimeSpan.FromSeconds(4), token).ConfigureAwait(true);
                await _viewModel.UpdateTypingAsync(false, token).ConfigureAwait(true);
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception error) when (error is HttpRequestException or IOException)
        {
        }
    }

    private void MessageTextBox_GotKeyboardFocus(object sender, KeyboardFocusChangedEventArgs e)
    {
        Dispatcher.BeginInvoke(ScrollToBottom, DispatcherPriority.Loaded);
    }

    private void FormattingButton_Click(object sender, RoutedEventArgs e)
    {
        var menu = new ContextMenu
        {
            PlacementTarget = FormattingButton,
            Placement = System.Windows.Controls.Primitives.PlacementMode.Top,
            Background = (Brush)FindResource("FedMesFormattingSurfaceBrush"),
            Foreground = (Brush)FindResource("FedMesFormattingTextBrush"),
        };
        menu.Items.Add(CreateFormattingItem("Жирный", TextEntityType.Bold, FontWeights.Bold));
        menu.Items.Add(CreateFormattingItem("Курсив", TextEntityType.Italic, fontStyle: FontStyles.Italic));
        menu.Items.Add(CreateFormattingItem("Моно", TextEntityType.Monospace, fontFamily: new FontFamily("Consolas")));
        menu.Items.Add(CreateFormattingItem("Зачёркнутый", TextEntityType.Strikethrough, decorations: TextDecorations.Strikethrough));
        menu.Items.Add(CreateFormattingItem("Подчёркнутый", TextEntityType.Underline, decorations: TextDecorations.Underline));
        menu.Items.Add(CreateFormattingItem("Скрытый текст", TextEntityType.Spoiler));
        menu.Items.Add(new Separator());
        var normal = new MenuItem { Header = "Обычный" };
        normal.Click += ClearFormattingMenuItem_Click;
        menu.Items.Add(normal);
        menu.IsOpen = true;
    }

    private MenuItem CreateFormattingItem(
        string header,
        TextEntityType type,
        FontWeight? fontWeight = null,
        FontStyle? fontStyle = null,
        FontFamily? fontFamily = null,
        TextDecorationCollection? decorations = null)
    {
        var headerText = new TextBlock { Text = header };
        if (fontWeight is not null) headerText.FontWeight = fontWeight.Value;
        if (fontStyle is not null) headerText.FontStyle = fontStyle.Value;
        if (fontFamily is not null) headerText.FontFamily = fontFamily;
        if (decorations is not null) headerText.TextDecorations = decorations;

        var item = new MenuItem { Header = headerText };
        item.Click += (_, _) => ApplyTextFormat(type, lineBased: false);
        return item;
    }

    private void QuoteSelectionMenuItem_Click(object sender, RoutedEventArgs e) =>
        ApplyTextFormat(TextEntityType.Quote, lineBased: true);

    private void BoldSelectionMenuItem_Click(object sender, RoutedEventArgs e) =>
        ApplyTextFormat(TextEntityType.Bold, lineBased: false);

    private void ItalicSelectionMenuItem_Click(object sender, RoutedEventArgs e) =>
        ApplyTextFormat(TextEntityType.Italic, lineBased: false);

    private void MonospaceSelectionMenuItem_Click(object sender, RoutedEventArgs e) =>
        ApplyTextFormat(TextEntityType.Monospace, lineBased: false);

    private void StrikethroughSelectionMenuItem_Click(object sender, RoutedEventArgs e) =>
        ApplyTextFormat(TextEntityType.Strikethrough, lineBased: false);

    private void UnderlineSelectionMenuItem_Click(object sender, RoutedEventArgs e) =>
        ApplyTextFormat(TextEntityType.Underline, lineBased: false);

    private void SpoilerSelectionMenuItem_Click(object sender, RoutedEventArgs e) =>
        ApplyTextFormat(TextEntityType.Spoiler, lineBased: false);

    private void ClearFormattingMenuItem_Click(object sender, RoutedEventArgs e)
    {
        if (_viewModel is null || MessageTextBox.SelectionLength <= 0) return;
        _viewModel.DraftTextEntities = TextFormatting.Clear(
            MessageTextBox.Text,
            _viewModel.DraftTextEntities,
            MessageTextBox.SelectionStart,
            MessageTextBox.SelectionStart + MessageTextBox.SelectionLength);
        MessageTextBox.Focus();
    }

    private void ApplyTextFormat(TextEntityType type, bool lineBased)
    {
        if (_viewModel is null || MessageTextBox.SelectionLength <= 0) return;
        int start = MessageTextBox.SelectionStart;
        int end = start + MessageTextBox.SelectionLength;
        if (lineBased)
        {
            (start, end) = TextFormatting.ExpandToLineRange(MessageTextBox.Text, start, end);
            MessageTextBox.Select(start, end - start);
        }
        _viewModel.DraftTextEntities = TextFormatting.Toggle(
            MessageTextBox.Text,
            _viewModel.DraftTextEntities,
            type,
            start,
            end);
        MessageTextBox.Focus();
    }

    private async void RoundVideoButton_Click(object sender, RoutedEventArgs e)
    {
        if (_viewModel?.SelectedChat is null) return;
        var dialog = new OpenFileDialog
        {
            Multiselect = false,
            Title = "Выберите видео для видеосообщения",
            Filter = "Видео|*.mp4;*.mov;*.m4v;*.mkv;*.webm;*.avi|Все файлы|*.*",
        };
        if (dialog.ShowDialog(this) != true) return;
        await SendSelectedFilesAsync([dialog.FileName], forceRoundVideo: true).ConfigureAwait(true);
    }

    private void UpdateComposerActions()
    {
        if (!IsInitialized || MessageTextBox is null) return;
        bool hasText = !string.IsNullOrWhiteSpace(MessageTextBox.Text);
        SendButton.Visibility = hasText ? Visibility.Visible : Visibility.Collapsed;
        VoiceButton.Visibility = hasText ? Visibility.Collapsed : Visibility.Visible;
        RoundVideoButton.Visibility = hasText ? Visibility.Collapsed : Visibility.Visible;
        FormattingButton.Visibility = hasText ? Visibility.Visible : Visibility.Collapsed;
    }

    private void AttachButton_Click(object sender, RoutedEventArgs e)
    {
        if (_viewModel?.SelectedChat is null) return;
        var menu = new ContextMenu
        {
            PlacementTarget = AttachButton,
            Placement = System.Windows.Controls.Primitives.PlacementMode.Top,
        };
        var gallery = new MenuItem { Header = "Галерея" };
        gallery.Click += async (_, _) => await OpenAttachmentDialogAsync(
            "Выберите фото или видео",
            "Фото и видео|*.jpg;*.jpeg;*.png;*.webp;*.gif;*.bmp;*.heic;*.mp4;*.mkv;*.mov;*.webm;*.avi|Все файлы|*.*")
            .ConfigureAwait(true);
        var file = new MenuItem { Header = "Файл" };
        file.Click += async (_, _) => await OpenAttachmentDialogAsync(
            "Выберите файлы",
            "Все файлы|*.*")
            .ConfigureAwait(true);
        menu.Items.Add(gallery);
        menu.Items.Add(file);
        menu.IsOpen = true;
    }

    private async Task OpenAttachmentDialogAsync(string title, string filter)
    {
        var dialog = new OpenFileDialog
        {
            Multiselect = true,
            Title = title,
            Filter = filter,
        };
        if (dialog.ShowDialog(this) != true) return;
        await SendSelectedFilesAsync(dialog.FileNames).ConfigureAwait(true);
    }

    private async Task SendSelectedFilesAsync(string[] paths, bool forceRoundVideo = false)
    {
        if (_viewModel?.SelectedChat is null || paths.Length == 0) return;
        string[] files = paths.Where(File.Exists).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (files.Length == 0) return;
        var options = new AttachmentOptionsWindow(files, _viewModel.DraftText, forceRoundVideo) { Owner = this };
        if (options.ShowDialog() != true) return;

        _uploadCancellation?.Cancel();
        _uploadCancellation?.Dispose();
        _uploadCancellation = new CancellationTokenSource();
        try
        {
            _viewModel.UploadVisible = true;
            var prepareProgress = new Progress<double>(value => _viewModel.UploadProgress = value * 20);
            PreparedDesktopAttachment[] attachments = await AttachmentPreparationService.PrepareAsync(
                files,
                options.SendAsFile,
                options.Spoiler,
                prepareProgress,
                _uploadCancellation.Token).ConfigureAwait(true);
            try
            {
                MessageKind? kind = options.SendAsRoundVideo ? MessageKind.RoundVideo : null;
                await _viewModel.SendAttachmentsAsync(
                    attachments,
                    options.Caption,
                    kind,
                    options.SendAsRoundVideo ? options.RoundShape : null,
                    _uploadCancellation.Token).ConfigureAwait(true);
                await LoadMessagePreviewsAsync().ConfigureAwait(true);
                ScrollToBottom();
            }
            finally
            {
                ClearPreparedAttachments(attachments);
            }
        }
        catch (OperationCanceledException)
        {
            _viewModel.UploadVisible = false;
        }
        catch (Exception error) when (error is IOException or ArgumentException or InvalidOperationException or HttpRequestException or CryptographicException)
        {
            _viewModel.UploadVisible = false;
            ShowError(error.Message);
        }
    }

    private async void MainWindow_Drop(object sender, DragEventArgs e)
    {
        if (MessengerPanel.Visibility != Visibility.Visible || !e.Data.GetDataPresent(DataFormats.FileDrop)) return;
        if (e.Data.GetData(DataFormats.FileDrop) is string[] files)
        {
            e.Handled = true;
            await SendSelectedFilesAsync(files).ConfigureAwait(true);
        }
    }

    private void MainWindow_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = MessengerPanel.Visibility == Visibility.Visible && e.Data.GetDataPresent(DataFormats.FileDrop)
            ? DragDropEffects.Copy
            : DragDropEffects.None;
        e.Handled = true;
    }

    private void MainWindow_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (MessengerPanel.Visibility != Visibility.Visible) return;
        if (Keyboard.Modifiers.HasFlag(ModifierKeys.Control) && e.Key == Key.F)
        {
            ChatSearchTextBox.Focus();
            ChatSearchTextBox.SelectAll();
            e.Handled = true;
        }
        else if (Keyboard.Modifiers.HasFlag(ModifierKeys.Control) && e.Key == Key.O)
        {
            AttachButton_Click(this, new RoutedEventArgs());
            e.Handled = true;
        }
        else if (e.Key == Key.Escape)
        {
            if (_viewModel?.HasSelectedMessages == true)
            {
                _viewModel.ClearSelection();
            }
            else if (_voiceRecorder.IsRecording)
            {
                _voiceRecorder.Cancel();
                VoiceButton.Content = "🎤";
                VoiceButton.ClearValue(Control.ForegroundProperty);
                RoundVideoButton.IsEnabled = true;
                if (_viewModel is not null) _viewModel.StatusText = "Подключено";
            }
            else if (_isCompactLayout && _compactChatOpen)
            {
                BackToChatsButton_Click(this, new RoutedEventArgs());
            }
            else
            {
                _viewModel?.CancelComposerContext();
            }

            e.Handled = true;
        }
    }

    private void CancelUploadButton_Click(object sender, RoutedEventArgs e) => _uploadCancellation?.Cancel();

    private async void VoiceButton_Click(object sender, RoutedEventArgs e)
    {
        if (_viewModel?.SelectedChat is null) return;
        if (!_voiceRecorder.IsRecording)
        {
            try
            {
                _voiceRecorder.Start();
                VoiceButton.Content = "■";
                VoiceButton.Foreground = (System.Windows.Media.Brush)FindResource("FedMesDangerBrush");
                RoundVideoButton.IsEnabled = false;
                _viewModel.StatusText = "Идёт запись голосового сообщения…";
            }
            catch (Exception error) when (error is InvalidOperationException or NAudio.MmException)
            {
                ShowError($"Не удалось открыть микрофон: {error.Message}");
            }

            return;
        }

        try
        {
            PreparedDesktopAttachment? voice = await _voiceRecorder.StopAsync(CancellationToken.None).ConfigureAwait(true);
            VoiceButton.Content = "🎤";
            VoiceButton.ClearValue(Control.ForegroundProperty);
            RoundVideoButton.IsEnabled = true;
            _viewModel.StatusText = "Подключено";
            if (voice is null)
            {
                ShowError("Голосовое сообщение короче одной секунды и не отправлено.");
                return;
            }

            try
            {
                await _viewModel.SendAttachmentsAsync(
                    [voice],
                    string.Empty,
                    MessageKind.Voice,
                    null,
                    CancellationToken.None).ConfigureAwait(true);
                ScrollToBottom();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(voice.Bytes);
            }
        }
        catch (Exception error) when (error is IOException or InvalidOperationException or HttpRequestException or CryptographicException)
        {
            VoiceButton.Content = "🎤";
            VoiceButton.ClearValue(Control.ForegroundProperty);
            RoundVideoButton.IsEnabled = true;
            ShowError(error.Message);
        }
    }

    private void ReplyMenuItem_Click(object sender, RoutedEventArgs e)
    {
        if (_viewModel is not null && GetMessage(sender) is { } message)
        {
            _viewModel.BeginReply(message);
            MessageTextBox.Focus();
        }
    }

    private async void ForwardMenuItem_Click(object sender, RoutedEventArgs e)
    {
        if (_viewModel is null || GetMessage(sender) is not { } message) return;
        var dialog = new ForwardWindow(_viewModel.Chats) { Owner = this };
        if (dialog.ShowDialog() != true || dialog.SelectedChat is null) return;
        try
        {
            ChatItemViewModel? sourceChat = _viewModel.SelectedChat;
            ChatItemViewModel targetChat = dialog.SelectedChat;
            await _viewModel.ForwardMessageAsync(message, targetChat, CancellationToken.None).ConfigureAwait(true);
            if (sourceChat is not null && !ReferenceEquals(sourceChat, targetChat))
            {
                _forwardBackStack.Push(sourceChat);
                _navigatingForwardHistory = true;
                _suppressChatSelection = true;
                try
                {
                    ChatListBox.SelectedItem = targetChat;
                    await OpenChatAsync(targetChat, openCompactChat: true).ConfigureAwait(true);
                }
                finally
                {
                    _suppressChatSelection = false;
                    _navigatingForwardHistory = false;
                }
            }
        }
        catch (Exception error) when (error is IOException or HttpRequestException or CryptographicException or InvalidOperationException)
        {
            ShowError(error.Message);
        }
    }

    private void CopyMenuItem_Click(object sender, RoutedEventArgs e)
    {
        if (GetMessage(sender) is { HasText: true } message) Clipboard.SetText(message.Text);
    }

    private void EditMenuItem_Click(object sender, RoutedEventArgs e)
    {
        if (_viewModel is not null && GetMessage(sender) is { } message)
        {
            _suppressComposerFormattingRemap = true;
            _viewModel.BeginEdit(message);
            Dispatcher.BeginInvoke(() =>
            {
                _lastComposerText = MessageTextBox.Text;
                _suppressComposerFormattingRemap = false;
                MessageTextBox.Focus();
                MessageTextBox.CaretIndex = MessageTextBox.Text.Length;
            }, DispatcherPriority.Input);
        }
    }

    private void SelectMenuItem_Click(object sender, RoutedEventArgs e)
    {
        if (_viewModel is not null && GetMessage(sender) is { } message)
        {
            _viewModel.ToggleSelection(message);
        }
    }

    private void MessageActionLane_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        if (_viewModel is null || sender is not FrameworkElement lane || lane.DataContext is not MessageItemViewModel message) return;
        e.Handled = true;
        if (_viewModel.HasSelectedMessages || Keyboard.Modifiers.HasFlag(ModifierKeys.Control))
        {
            _viewModel.ToggleSelection(message);
            return;
        }

        if (lane.ContextMenu is { } menu)
        {
            menu.PlacementTarget = lane;
            menu.DataContext = message;
            menu.IsOpen = true;
        }
    }

    private void ClearSelectionButton_Click(object sender, RoutedEventArgs e) => _viewModel?.ClearSelection();

    private void EditSelectedButton_Click(object sender, RoutedEventArgs e)
    {
        if (_viewModel?.GetEditableSelectedMessage() is not { } message) return;
        _viewModel.ClearSelection();
        _suppressComposerFormattingRemap = true;
        _viewModel.BeginEdit(message);
        Dispatcher.BeginInvoke(() =>
        {
            _lastComposerText = MessageTextBox.Text;
            _suppressComposerFormattingRemap = false;
            MessageTextBox.Focus();
            MessageTextBox.CaretIndex = MessageTextBox.Text.Length;
        }, DispatcherPriority.Input);
    }

    private async void DeleteSelectedButton_Click(object sender, RoutedEventArgs e)
    {
        if (_viewModel is null) return;
        IReadOnlyList<MessageItemViewModel> selected = _viewModel.GetSelectedMessages();
        if (selected.Count == 0) return;

        bool canDeleteForEveryone = selected.All(message => message.IsMine);
        MessageDeleteScope scope;
        if (canDeleteForEveryone)
        {
            MessageBoxResult result = MessageBox.Show(
                this,
                $"Удалить выбранные сообщения: {selected.Count}?\n\nДа — удалить у всех.\nНет — удалить только у меня.",
                "FedMes",
                MessageBoxButton.YesNoCancel,
                MessageBoxImage.Question);
            if (result == MessageBoxResult.Cancel) return;
            scope = result == MessageBoxResult.Yes ? MessageDeleteScope.Everyone : MessageDeleteScope.Me;
        }
        else
        {
            MessageBoxResult result = MessageBox.Show(
                this,
                $"Удалить выбранные сообщения только у вас: {selected.Count}?",
                "FedMes",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);
            if (result != MessageBoxResult.Yes) return;
            scope = MessageDeleteScope.Me;
        }

        try
        {
            await _viewModel.DeleteSelectedMessagesAsync(scope, CancellationToken.None).ConfigureAwait(true);
        }
        catch (Exception error) when (error is HttpRequestException or IOException)
        {
            ShowError($"Удаление остановлено: {error.Message}");
        }
    }

    private async void PinMenuItem_Click(object sender, RoutedEventArgs e)
    {
        if (_viewModel is null || GetMessage(sender) is not { } message) return;
        try
        {
            await _viewModel.PinMessageAsync(message, CancellationToken.None).ConfigureAwait(true);
            UpdatePinnedMessageBar();
        }
        catch (Exception error) when (error is HttpRequestException or IOException)
        {
            ShowError(error.Message);
        }
    }

    private async void SaveMediaMenuItem_Click(object sender, RoutedEventArgs e)
    {
        if (GetMessage(sender) is not { } message || message.Media.Count == 0) return;
        await SaveMediaAsync(message, message.Media[0]).ConfigureAwait(true);
    }

    private async void DeleteForMeMenuItem_Click(object sender, RoutedEventArgs e)
    {
        await DeleteMessageAsync(GetMessage(sender), MessageDeleteScope.Me).ConfigureAwait(true);
    }

    private async void DeleteForEveryoneMenuItem_Click(object sender, RoutedEventArgs e)
    {
        MessageItemViewModel? message = GetMessage(sender);
        if (message is null || !message.IsMine)
        {
            ShowError("Удалить сообщение у всех может только отправитель.");
            return;
        }

        await DeleteMessageAsync(message, MessageDeleteScope.Everyone).ConfigureAwait(true);
    }

    private async Task DeleteMessageAsync(MessageItemViewModel? message, MessageDeleteScope scope)
    {
        if (_viewModel is null || message is null) return;
        string question = scope == MessageDeleteScope.Everyone ? "Удалить сообщение у всех?" : "Удалить сообщение только у вас?";
        if (MessageBox.Show(this, question, "FedMes", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        try
        {
            await _viewModel.DeleteMessageAsync(message, scope, CancellationToken.None).ConfigureAwait(true);
        }
        catch (Exception error) when (error is HttpRequestException or IOException)
        {
            ShowError(error.Message);
        }
    }

    private async void MediaButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button button || button.DataContext is not MediaTileViewModel tile || button.Tag is not MessageItemViewModel message) return;
        await OpenMediaAsync(message, tile).ConfigureAwait(true);
    }

    private async void AudioButton_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is not MessageItemViewModel message || message.Media.Count == 0) return;
        await OpenMediaAsync(message, message.Media[0]).ConfigureAwait(true);
    }

    private async void RoundVideo_SourceRequested(object sender, RoutedEventArgs e)
    {
        if (sender is not RoundVideoInlineControl control || control.DataContext is not MessageItemViewModel message) return;
        try
        {
            await PrepareRoundVideoAsync(message, CancellationToken.None).ConfigureAwait(true);
            control.SetLoading(false);
            control.Play();
        }
        catch (Exception error) when (error is IOException or HttpRequestException or CryptographicException or NotSupportedException)
        {
            control.SetLoading(false);
            ShowError(error.Message);
        }
    }

    private async Task OpenMediaAsync(MessageItemViewModel message, MediaTileViewModel tile)
    {
        if (_mediaCache is null) return;
        if (message.ShouldHideSpoiler)
        {
            message.IsSpoilerRevealed = true;
            await LoadPreviewAsync(message, tile).ConfigureAwait(true);
            return;
        }

        try
        {
            tile.Loading = true;
            var progress = new Progress<double>(value => tile.Progress = value * 100);
            string path = await _mediaCache.GetDecryptedFileAsync(message.Model, tile.Descriptor, progress, CancellationToken.None)
                .ConfigureAwait(true);
            string viewerTitle = !string.IsNullOrWhiteSpace(message.Text)
                ? message.Text.Trim()
                : tile.IsImage ? "Фото" : tile.IsVideo ? "Видео" : tile.IsAudio ? "Аудио" : "Медиа";
            if (tile.IsImage)
            {
                new PhotoViewerWindow(path, viewerTitle) { Owner = this }.ShowDialog();
            }
            else if (tile.IsVideo || tile.IsAudio || message.IsRoundVideo)
            {
                new MediaPlayerWindow(path, viewerTitle, tile.IsAudio) { Owner = this }.ShowDialog();
            }
            else
            {
                await SaveMediaAsync(message, tile).ConfigureAwait(true);
            }
        }
        catch (Exception error) when (error is IOException or HttpRequestException or CryptographicException or NotSupportedException)
        {
            ShowError(error.Message);
        }
        finally
        {
            tile.Loading = false;
        }
    }

    private async Task SaveMediaAsync(MessageItemViewModel message, MediaTileViewModel tile)
    {
        if (_mediaCache is null) return;
        var dialog = new SaveFileDialog { FileName = tile.Name, Title = "Сохранить файл" };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            var progress = new Progress<double>(value => tile.Progress = value * 100);
            await _mediaCache.SaveAsAsync(message.Model, tile.Descriptor, dialog.FileName, progress, CancellationToken.None)
                .ConfigureAwait(true);
        }
        catch (Exception error) when (error is IOException or HttpRequestException or CryptographicException)
        {
            ShowError(error.Message);
        }
    }

    private async void RevealSpoilerButton_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is not MessageItemViewModel message) return;
        message.IsSpoilerRevealed = true;
        foreach (MediaTileViewModel tile in message.Media) await LoadPreviewAsync(message, tile).ConfigureAwait(true);
    }

    private async void ReplyPreviewButton_Click(object sender, RoutedEventArgs e)
    {
        if (_viewModel is null || (sender as FrameworkElement)?.DataContext is not MessageItemViewModel message || !message.HasReply) return;
        MessageItemViewModel? target = _viewModel.FindMessage(message.ReplyToId);
        while (target is null && _viewModel.HasMoreBefore)
        {
            await _viewModel.LoadOlderAsync(CancellationToken.None).ConfigureAwait(true);
            target = _viewModel.FindMessage(message.ReplyToId);
        }

        if (target is null) return;
        MessagesListBox.ScrollIntoView(target);
        target.IsHighlighted = true;
        await Task.Delay(1100).ConfigureAwait(true);
        target.IsHighlighted = false;
    }

    private async void MessagesScrollViewer_ScrollChanged(object sender, ScrollChangedEventArgs e)
    {
        if (sender is not ScrollViewer viewer) return;
        double distanceFromBottom = Math.Max(0, viewer.ScrollableHeight - viewer.VerticalOffset);
        ScrollToBottomButton.Visibility = distanceFromBottom > 24
            ? Visibility.Visible
            : Visibility.Collapsed;
        ScheduleVisibleReadCursorUpdate();

        if (e.VerticalOffset > 20 || _viewModel is not { HasMoreBefore: true } || _loadingOlderMessages)
        {
            return;
        }

        _loadingOlderMessages = true;
        double previousExtent = viewer.ExtentHeight;
        double previousOffset = viewer.VerticalOffset;
        try
        {
            await _viewModel.LoadOlderAsync(CancellationToken.None).ConfigureAwait(true);
            await LoadMessagePreviewsAsync().ConfigureAwait(true);
            viewer.UpdateLayout();
            double insertedHeight = Math.Max(0, viewer.ExtentHeight - previousExtent);
            viewer.ScrollToVerticalOffset(previousOffset + insertedHeight);
        }
        finally
        {
            _loadingOlderMessages = false;
        }
    }

    private void ScheduleVisibleReadCursorUpdate()
    {
        _readCursorCancellation?.Cancel();
        _readCursorCancellation?.Dispose();
        _readCursorCancellation = new CancellationTokenSource();
        CancellationToken token = _readCursorCancellation.Token;
        _ = MarkVisibleMessagesReadAfterLayoutAsync(token);
    }

    private async Task MarkVisibleMessagesReadAfterLayoutAsync(CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(120, cancellationToken).ConfigureAwait(true);
            if (_viewModel?.SelectedChat is null || MessagesListBox.ActualHeight <= 0) return;
            var visible = new List<MessageItemViewModel>();
            Rect viewport = new(0, 0, MessagesListBox.ActualWidth, MessagesListBox.ActualHeight);
            for (int index = 0; index < MessagesListBox.Items.Count; index++)
            {
                if (MessagesListBox.ItemContainerGenerator.ContainerFromIndex(index) is not ListBoxItem container ||
                    container.DataContext is not MessageItemViewModel message ||
                    !container.IsVisible)
                {
                    continue;
                }
                try
                {
                    Rect bounds = container.TransformToAncestor(MessagesListBox)
                        .TransformBounds(new Rect(new Point(0, 0), container.RenderSize));
                    if (viewport.IntersectsWith(bounds)) visible.Add(message);
                }
                catch (InvalidOperationException)
                {
                    // A recycled virtualized container is no longer attached to this ListBox.
                }
            }
            if (visible.Count > 0)
            {
                await _viewModel.MarkVisibleMessagesReadAsync(visible, cancellationToken).ConfigureAwait(true);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception error) when (error is HttpRequestException or IOException)
        {
            if (_viewModel is not null) _viewModel.StatusText = "Нет соединения";
        }
    }

    private void CancelComposerContextButton_Click(object sender, RoutedEventArgs e) => _viewModel?.CancelComposerContext();

    private async void UnpinButton_Click(object sender, RoutedEventArgs e)
    {
        if (_viewModel is null) return;
        try
        {
            await _viewModel.UnpinAsync(CancellationToken.None).ConfigureAwait(true);
            UpdatePinnedMessageBar();
        }
        catch (Exception error) when (error is HttpRequestException or IOException)
        {
            ShowError(error.Message);
        }
    }

    private void MessageContextMenu_Opened(object sender, RoutedEventArgs e)
    {
        if (sender is ContextMenu menu && menu.PlacementTarget is FrameworkElement target)
        {
            menu.DataContext = target.DataContext;
            MessageItemViewModel? message = target.DataContext as MessageItemViewModel;
            if (menu.Items.OfType<MenuItem>().FirstOrDefault(item => Equals(item.Header, "Редактировать")) is { } edit)
            {
                edit.IsEnabled = message is { IsMine: true, IsText: true, IsForwarded: false };
            }

            if (menu.Items.OfType<MenuItem>().FirstOrDefault(item => Equals(item.Header, "Выбрать") || Equals(item.Header, "Снять выбор")) is { } select)
            {
                select.Header = message?.IsSelected == true ? "Снять выбор" : "Выбрать";
            }
        }
    }

    private static MessageItemViewModel? GetMessage(object sender) =>
        (sender as FrameworkElement)?.DataContext as MessageItemViewModel;

    private async void MessageItem_Loaded(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is not MessageItemViewModel message) return;
        try
        {
            await LoadMessagePreviewsAsync(message, _previewCancellation?.Token ?? CancellationToken.None)
                .ConfigureAwait(true);
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception error) when (error is IOException or HttpRequestException or CryptographicException or NotSupportedException)
        {
            // A broken or unavailable preview must not terminate the WPF dispatcher.
        }
    }

    private async void MessageItem_Unloaded(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is not MessageItemViewModel message) return;
        // Recycling may unload and immediately reload a row. Delay the release until WPF has
        // completed the layout pass; only non-realized rows drop their decoded bitmaps.
        await Dispatcher.Yield(DispatcherPriority.ContextIdle);
        if (MessagesListBox.ItemContainerGenerator.ContainerFromItem(message) is not null) return;
        foreach (MediaTileViewModel tile in message.Media) tile.Preview = null;
    }

    private async Task LoadMessagePreviewsAsync()
    {
        if (_viewModel is null) return;
        CancellationToken token = _previewCancellation?.Token ?? CancellationToken.None;
        var realized = new HashSet<MessageItemViewModel>();
        for (int index = 0; index < MessagesListBox.Items.Count; index++)
        {
            if (MessagesListBox.ItemContainerGenerator.ContainerFromIndex(index) is ListBoxItem container &&
                container.DataContext is MessageItemViewModel message)
            {
                realized.Add(message);
            }
        }

        if (realized.Count == 0)
        {
            foreach (MessageItemViewModel message in _viewModel.Messages.TakeLast(8)) realized.Add(message);
        }

        await Task.WhenAll(realized.Select(message => LoadMessagePreviewsAsync(message, token)))
            .ConfigureAwait(true);
    }

    private async Task LoadMessagePreviewsAsync(
        MessageItemViewModel message,
        CancellationToken cancellationToken)
    {
        if (message.ShouldHideSpoiler) return;
        foreach (MediaTileViewModel tile in message.Media)
        {
            if (tile.Preview is null && (tile.IsImage || tile.IsVideo || message.IsRoundVideo))
            {
                await LoadPreviewAsync(message, tile, cancellationToken).ConfigureAwait(true);
            }
        }

        // Prefetch only the newest four short round/square messages. The previous build downloaded six
        // full videos for every opened chat, which was slow and could exhaust memory. The remaining
        // videos are fetched on demand through the same deduplicated cache.
        if (message.IsRoundVideo && message.Media.Count > 0 &&
            message.Media[0].Descriptor.OriginalSize <= 48L * 1024 * 1024 &&
            _viewModel?.Messages.TakeLast(4).Contains(message) == true)
        {
            try
            {
                await PrepareRoundVideoAsync(message, cancellationToken).ConfigureAwait(true);
            }
            catch (Exception error) when (error is IOException or HttpRequestException or CryptographicException or NotSupportedException)
            {
            }
        }
    }

    private void ResetPreviewLoading()
    {
        _previewCancellation?.Cancel();
        _previewCancellation?.Dispose();
        _previewCancellation = new CancellationTokenSource();
    }

    private async Task PrepareRoundVideoAsync(MessageItemViewModel message, CancellationToken cancellationToken)
    {
        if (_mediaCache is null || !message.IsRoundVideo || message.Media.Count == 0 ||
            !string.IsNullOrWhiteSpace(message.RoundVideoPath) || message.RoundVideoLoading)
        {
            return;
        }

        message.RoundVideoLoading = true;
        try
        {
            message.RoundVideoPath = await _mediaCache.GetDecryptedFileAsync(
                message.Model,
                message.Media[0].Descriptor,
                null,
                cancellationToken).ConfigureAwait(true);
        }
        finally
        {
            message.RoundVideoLoading = false;
        }
    }

    private async Task LoadPreviewAsync(
        MessageItemViewModel message,
        MediaTileViewModel tile,
        CancellationToken cancellationToken = default)
    {
        if (_mediaCache is null || tile.Loading || tile.Preview is not null) return;
        tile.Loading = true;
        bool gateAcquired = false;
        try
        {
            await _previewLoadGate.WaitAsync(cancellationToken).ConfigureAwait(true);
            gateAcquired = true;
            if (_mediaCache is null || tile.Preview is not null) return;
            tile.Preview = await _mediaCache.GetPreviewAsync(message.Model, tile.Descriptor, cancellationToken)
                .ConfigureAwait(true);
        }
        finally
        {
            if (gateAcquired) _previewLoadGate.Release();
            tile.Loading = false;
        }
    }

    private void UpdatePinnedMessageBar()
    {
        if (_viewModel?.SelectedChat is not { } chat || string.IsNullOrWhiteSpace(chat.PinnedMessageId))
        {
            PinnedMessageBar.Visibility = Visibility.Collapsed;
            return;
        }

        MessageItemViewModel? pinned = _viewModel.FindMessage(chat.PinnedMessageId);
        PinnedMessageText.Text = pinned?.Summary() ?? "Более раннее сообщение";
        PinnedMessageBar.Visibility = Visibility.Visible;
    }

    private bool IsMessagesNearBottom()
    {
        ScrollViewer? viewer = FindVisualChild<ScrollViewer>(MessagesListBox);
        return viewer is null || viewer.ScrollableHeight - viewer.VerticalOffset <= 96;
    }

    private static T? FindVisualChild<T>(DependencyObject parent) where T : DependencyObject
    {
        int count = VisualTreeHelper.GetChildrenCount(parent);
        for (int index = 0; index < count; index++)
        {
            DependencyObject child = VisualTreeHelper.GetChild(parent, index);
            if (child is T match) return match;
            if (FindVisualChild<T>(child) is { } nested) return nested;
        }
        return null;
    }

    private void ScrollToBottom()
    {
        if (_viewModel?.Messages.LastOrDefault() is { } last) MessagesListBox.ScrollIntoView(last);
        ScrollToBottomButton.Visibility = Visibility.Collapsed;
    }

    private void ScrollToBottomButton_Click(object sender, RoutedEventArgs e) => ScrollToBottom();

    private void ChatSearchTextBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        SearchPlaceholderText.Visibility = string.IsNullOrEmpty(ChatSearchTextBox.Text)
            ? Visibility.Visible
            : Visibility.Collapsed;
        if (_viewModel is not null)
        {
            CollectionViewSource.GetDefaultView(_viewModel.Chats).Refresh();
        }

        UpdateChatEmptyState();
    }

    private void UpdateChatEmptyState()
    {
        if (!IsInitialized || ChatListBox is null || ChatEmptyState is null) return;
        ChatEmptyState.Visibility = ChatListBox.Items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        ChatEmptyState.Text = string.IsNullOrWhiteSpace(ChatSearchTextBox.Text)
            ? "Пока нет чатов. Нажмите поиск и найдите пользователя или группу."
            : "Ничего не найдено";
    }

    private bool FilterChat(object item)
    {
        if (item is not ChatItemViewModel chat) return false;
        string query = ChatSearchTextBox.Text.Trim();
        if (query.Length == 0) return chat.Model.LastSequence > 0;
        return chat.Title.Contains(query, StringComparison.CurrentCultureIgnoreCase) ||
               chat.Model.Title.Contains(query, StringComparison.CurrentCultureIgnoreCase) ||
               chat.Model.Members.Any(member => member.Contains(query, StringComparison.CurrentCultureIgnoreCase));
    }

    private async void AudioCallButton_Click(object sender, RoutedEventArgs e)
    {
        if (_viewModel?.SelectedChat is not { IsFavorites: false } chat) return;
        try { await _viewModel.Call.StartOutgoingAsync(chat, video: false, CancellationToken.None).ConfigureAwait(true); }
        catch (Exception error) when (error is HttpRequestException or IOException or InvalidOperationException or CryptographicException)
        {
            ShowError(error.Message);
        }
    }

    private async void VideoCallButton_Click(object sender, RoutedEventArgs e)
    {
        if (_viewModel?.SelectedChat is not { IsFavorites: false } chat) return;
        try { await _viewModel.Call.StartOutgoingAsync(chat, video: true, CancellationToken.None).ConfigureAwait(true); }
        catch (Exception error) when (error is HttpRequestException or IOException or InvalidOperationException or CryptographicException)
        {
            ShowError(error.Message);
        }
    }

    private async void AcceptCallButton_Click(object sender, RoutedEventArgs e)
    {
        if (_viewModel is null) return;
        try { await _viewModel.Call.AcceptAsync(CancellationToken.None).ConfigureAwait(true); }
        catch (Exception error) when (error is HttpRequestException or IOException or InvalidOperationException or CryptographicException)
        {
            ShowError(error.Message);
        }
    }

    private async void DeclineCallButton_Click(object sender, RoutedEventArgs e)
    {
        if (_viewModel is null) return;
        try { await _viewModel.Call.DeclineAsync(CancellationToken.None).ConfigureAwait(true); }
        catch (Exception error) when (error is HttpRequestException or IOException) { ShowError(error.Message); }
    }

    private void DesktopCallTray_MuteInvoked(object? sender, EventArgs e) => _viewModel?.Call.ToggleMute();
    private void DesktopCallTray_SpeakerInvoked(object? sender, EventArgs e) => _viewModel?.Call.ToggleSpeaker();
    private void DesktopCallTray_CameraInvoked(object? sender, EventArgs e) => _viewModel?.Call.ToggleCamera();

    private async void DesktopCallTray_EndInvoked(object? sender, EventArgs e)
    {
        if (_viewModel is null) return;
        try { await _viewModel.Call.EndAsync(CancellationToken.None).ConfigureAwait(true); } catch { }
    }

    private void ChatMenuButton_Click(object sender, RoutedEventArgs e)
    {
        var menu = new ContextMenu();
        var settings = new MenuItem { Header = "Настройки и устройства" };
        settings.Click += SettingsButton_Click;
        menu.Items.Add(settings);
        menu.IsOpen = true;
    }

    private void ThemeButton_Click(object sender, RoutedEventArgs e)
    {
        bool dark = DesktopThemeManager.IsDark(_preferences.ThemeMode);
        _preferences.ThemeMode = dark ? DesktopThemeMode.Light : DesktopThemeMode.Dark;
        SaveDesktopPreferences();
        DesktopThemeManager.Apply(_preferences.ThemeMode);
        UpdateThemeGlyph();

        if (ThemeGlyph.RenderTransform is RotateTransform rotation)
        {
            double from = rotation.Angle;
            double to = from + 180;
            var animation = new DoubleAnimation(from, to, TimeSpan.FromMilliseconds(280))
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseInOut },
            };
            rotation.BeginAnimation(RotateTransform.AngleProperty, animation);
        }
    }

    private void UpdateThemeGlyph()
    {
        if (ThemeGlyph is null) return;
        bool dark = DesktopThemeManager.IsDark(_preferences.ThemeMode);
        ThemeGlyph.Text = dark ? "☀" : "☾";
        ThemeButton.ToolTip = dark ? "Включить светлую тему" : "Включить тёмную тему";
    }

    private void MainMenuButton_Click(object sender, RoutedEventArgs e)
    {
        var menu = new ContextMenu { PlacementTarget = sender as UIElement };
        bool dark = DesktopThemeManager.IsDark(_preferences.ThemeMode);
        var theme = new MenuItem { Header = dark ? "Светлая тема" : "Тёмная тема" };
        theme.Click += ThemeButton_Click;
        menu.Items.Add(theme);

        var favorites = new MenuItem { Header = "Избранное" };
        favorites.Click += async (_, _) =>
        {
            ChatItemViewModel? chat = _viewModel?.Chats.FirstOrDefault(item => item.Kind == "favorites");
            if (chat is not null) await OpenChatAsync(chat, false).ConfigureAwait(true);
        };
        menu.Items.Add(favorites);

        var family = new MenuItem { Header = "Группа" };
        family.Click += async (_, _) =>
        {
            ChatItemViewModel? chat = _viewModel?.Chats.FirstOrDefault(item => item.Kind == "family");
            if (chat is not null) await OpenChatAsync(chat, false).ConfigureAwait(true);
        };
        menu.Items.Add(family);
        menu.Items.Add(new Separator());

        var signOut = new MenuItem
        {
            Header = "Выйти из аккаунта",
            Foreground = (System.Windows.Media.Brush)FindResource("FedMesDangerBrush"),
        };
        signOut.Click += async (_, _) => await SignOutAsync().ConfigureAwait(true);
        menu.Items.Add(signOut);
        menu.IsOpen = true;
    }

    private void ProfileButton_Click(object sender, RoutedEventArgs e)
    {
        if (_sessionManager?.LoadStoredAccount() is not { } account) return;

        var menu = new ContextMenu
        {
            PlacementTarget = sender as UIElement,
        };
        menu.Items.Add(new MenuItem
        {
            Header = $"Профиль: {FamilyPresentation.DisplayName(account.Username, account.Username)}",
            IsEnabled = false,
        });

        var exactPresence = new MenuItem
        {
            Header = "Показывать точное время посещения",
            IsCheckable = true,
            IsChecked = _preferences.ShowExactPresence,
        };
        exactPresence.Click += async (_, _) =>
        {
            _preferences.ShowExactPresence = exactPresence.IsChecked;
            SaveDesktopPreferences();
            if (_repository is null) return;
            try
            {
                await _repository.HeartbeatAsync(false, CancellationToken.None).ConfigureAwait(true);
                if (_viewModel is not null) await _viewModel.ApplyPresenceAsync(CancellationToken.None).ConfigureAwait(true);
            }
            catch (Exception error) when (error is HttpRequestException or IOException)
            {
                ShowError(error.Message);
            }
        };
        menu.Items.Add(exactPresence);

        menu.Items.Add(new Separator());

        var settings = new MenuItem { Header = "Настройки и устройства" };
        settings.Click += SettingsButton_Click;
        menu.Items.Add(settings);

        var signOut = new MenuItem
        {
            Header = "Выйти",
            Foreground = (System.Windows.Media.Brush)FindResource("FedMesDangerBrush"),
        };
        signOut.Click += async (_, _) => await SignOutAsync().ConfigureAwait(true);
        menu.Items.Add(signOut);
        menu.IsOpen = true;
    }

    private void AddThemeMenuItem(MenuItem parent, string header, DesktopThemeMode mode)
    {
        var item = new MenuItem
        {
            Header = header,
            IsCheckable = true,
            IsChecked = _preferences.ThemeMode == mode,
        };
        item.Click += (_, _) =>
        {
            _preferences.ThemeMode = mode;
            SaveDesktopPreferences();
            DesktopThemeManager.Apply(mode);
        };
        parent.Items.Add(item);
    }

    private void SaveDesktopPreferences()
    {
        try
        {
            _preferencesStore.Save(_preferences);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            ShowError(error.Message);
        }
    }

    private static string ThemeModeName(DesktopThemeMode mode) => mode switch
    {
        DesktopThemeMode.Light => "Светлая",
        DesktopThemeMode.Dark => "Тёмная",
        _ => "Системная",
    };

    private void SettingsButton_Click(object? sender, RoutedEventArgs e)
    {
        if (_repository is null || _sessionManager?.LoadStoredAccount() is not { } account) return;
        var window = new SettingsWindow(_repository, account, _preferencesStore, _preferences) { Owner = this };
        window.SignOutRequested += async (_, _) => await SignOutAsync().ConfigureAwait(true);
        window.ShowDialog();
    }

    private async Task SignOutAsync()
    {
        DesktopAccount? account = _accountStore.Load();
        if (account is not null)
        {
            try
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                await _linkClient.RevokeCurrentDeviceAsync(account, timeout.Token).ConfigureAwait(true);
            }
            catch (Exception error) when (error is HttpRequestException or OperationCanceledException)
            {
            }
        }

        _accountStore.Clear();
        _preferences.LastChatId = null;
        _preferences.CompactChatOpen = false;
        SaveDesktopPreferences();
        StopMessenger();
        ShowWelcome("Компьютер отключён.");
    }

    private async void StartLoginButton_Click(object sender, RoutedEventArgs e)
    {
        await StartLoginAsync().ConfigureAwait(true);
    }

    private async void OpaqueLoginButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpaquePasswordWindow(this, login: true);
        if (dialog.ShowDialog() != true) return;
        char[] password = dialog.TakePassword();
        OpaqueLoginButton.IsEnabled = false;
        StartLoginButton.IsEnabled = false;
        WelcomeStatusText.Text = "Пароль подтверждён локальным OPAQUE-клиентом. Восстановление ключей истории…";
        try
        {
            string serverUrl = ServerEndpointPolicy.Normalize(ServerUrlTextBox.Text, EndpointMode).AbsoluteUri.TrimEnd('/');
            using DesktopDeviceIdentity identity = _identityStore.LoadOrCreate();
            DesktopAccount account = await _opaqueAuthCoordinator.LoginAndRestoreAsync(
                serverUrl,
                dialog.Username,
                password,
                BuildDeviceName(),
                identity,
                CancellationToken.None).ConfigureAwait(true);
            await EnsureRecoveryConfiguredAsync(account).ConfigureAwait(true);
            await EnterMessengerAsync().ConfigureAwait(true);
        }
        catch (Exception error) when (error is CryptographicException or HttpRequestException or IOException or TimeoutException or ArgumentException or InvalidOperationException or JsonException)
        {
            Array.Clear(password);
            ShowWelcome("Безопасный вход не завершён. Активный профиль не изменён: " + error.Message);
        }
        finally
        {
            Array.Clear(password);
            OpaqueLoginButton.IsEnabled = true;
            StartLoginButton.IsEnabled = true;
        }
    }

    private async Task StartLoginAsync()
    {
        StartLoginButton.IsEnabled = false;
        WelcomeStatusText.Text = "Подготовка ключей компьютера…";
        try
        {
            Uri requestedServer = DeviceLinkClient.NormalizeServerUrl(ServerUrlTextBox.Text, EndpointMode);
            string deviceName = BuildDeviceName();
            _loginCancellation?.Dispose();
            _loginCancellation = new CancellationTokenSource();
            ShowQrPanel();
            if (_activeTicket is null || _activeServer != requestedServer || _activeIdentity is null)
            {
                ClearActiveLogin();
                _activeServer = requestedServer;
                _activeIdentity = _identityStore.LoadOrCreate();
                _activeTicket = await _linkClient.CreateAsync(
                    _activeServer,
                    deviceName,
                    _activeIdentity,
                    _loginCancellation.Token).ConfigureAwait(true);
            }

            QrImage.Source = DecodePng(_activeTicket.QrPng);
            QrProgress.Visibility = Visibility.Collapsed;
            RetryLoginButton.Visibility = Visibility.Collapsed;
            QrStatusText.Text = "Ожидание подтверждения на телефоне…";
            var progress = new Progress<string>(message => QrStatusText.Text = message);
            DesktopAccount account = await _linkClient.WaitForApprovalAsync(
                _activeServer,
                _activeTicket,
                _activeIdentity,
                deviceName,
                progress,
                _loginCancellation.Token).ConfigureAwait(true);
            AccountSecurityState linkedSecurityState = await _accountSecurityCoordinator.GetStateAsync(account, _loginCancellation.Token)
                .ConfigureAwait(true);
            string linkedEffectiveState = linkedSecurityState.State;
            if (string.Equals(linkedEffectiveState, AccountSecurityProtocol.Ready, StringComparison.Ordinal) &&
                linkedSecurityState.VaultRevision > 0 &&
                !_accountVaultStore.Exists(account.ServerUrl, account.Username))
            {
                linkedEffectiveState = "RECOVERY_REQUIRED";
            }
            account = account with { AuthenticationState = linkedEffectiveState };
            if (string.Equals(account.AuthenticationState, AccountSecurityProtocol.Ready, StringComparison.Ordinal))
            {
                _accountStore.Save(account);
            }
            else
            {
                _accountStore.SaveCandidate(account);
            }
            // The server authentication result is persisted before the cleanup acknowledgement.
            // Completing the one-time link is cleanup only; a lost cleanup response must never
            // force the user to scan the Windows QR a second time.
            try
            {
                using var completionTimeout = CancellationTokenSource.CreateLinkedTokenSource(_loginCancellation.Token);
                completionTimeout.CancelAfter(TimeSpan.FromSeconds(6));
                await _linkClient.AcknowledgeCompletedLinkAsync(
                    _activeServer,
                    _activeTicket,
                    completionTimeout.Token).ConfigureAwait(true);
            }
            catch (Exception error) when (error is HttpRequestException or OperationCanceledException)
            {
                // The server expires/consumes approved links independently. Continue with the
                // already persisted account and let normal session refresh verify it later.
            }
            ClearActiveLogin();
            if (!string.Equals(account.AuthenticationState, AccountSecurityProtocol.Ready, StringComparison.Ordinal))
            {
                DesktopAccount? recovered = await RecoverCandidateAccountAsync(account).ConfigureAwait(true);
                if (recovered is null)
                {
                    ShowWelcome("Серверная сессия создана, но ключи истории ещё не восстановлены.");
                    return;
                }
                account = recovered;
            }
            else
            {
                await EnsureRecoveryConfiguredAsync(account).ConfigureAwait(true);
            }
            await EnterMessengerAsync().ConfigureAwait(true);
        }
        catch (OperationCanceledException)
        {
            ClearActiveLogin();
            ShowWelcome("Вход отменён.");
        }
        catch (Exception error) when (error is InvalidOperationException or TimeoutException or CryptographicException or ArgumentException or IOException or HttpRequestException)
        {
            // Do not throw the user back to the welcome page on a transient QR/network failure.
            // That old behaviour looked like an endless spinner followed by a reset. Keep the
            // onboarding context visible and make retry explicit.
            ClearActiveLogin();
            ShowQrPanel();
            QrProgress.Visibility = Visibility.Collapsed;
            RetryLoginButton.Visibility = Visibility.Visible;
            QrStatusText.Text = $"Не удалось создать или подтвердить QR: {error.Message}";
        }
        finally
        {
            StartLoginButton.IsEnabled = true;
        }
    }

    private async void CancelLoginButton_Click(object sender, RoutedEventArgs e)
    {
        DeviceLinkTicket? ticket = _activeTicket;
        Uri? server = _activeServer;
        _loginCancellation?.Cancel();
        if (ticket is not null && server is not null)
        {
            try
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                await _linkClient.CancelAsync(server, ticket, timeout.Token).ConfigureAwait(true);
            }
            catch (Exception error) when (error is HttpRequestException or OperationCanceledException)
            {
            }
        }

        ClearActiveLogin();
        ShowWelcome("Вход отменён.");
    }

    private void HandleRevokedSession(string message)
    {
        _accountStore.Clear();
        StopMessenger();
        ShowWelcome(message);
    }

    private void ShowWelcome(string? status = null)
    {
        SplashPanel.Visibility = Visibility.Collapsed;
        LoginPanel.Visibility = Visibility.Visible;
        MessengerPanel.Visibility = Visibility.Collapsed;
        WelcomePanel.Visibility = Visibility.Visible;
        QrPanel.Visibility = Visibility.Collapsed;
        QrImage.Source = null;
        QrProgress.Visibility = Visibility.Visible;
        WelcomeStatusText.Text = status ?? "На телефоне откройте Настройки → Устройства.";
    }

    private void ShowQrPanel()
    {
        SplashPanel.Visibility = Visibility.Collapsed;
        LoginPanel.Visibility = Visibility.Visible;
        MessengerPanel.Visibility = Visibility.Collapsed;
        WelcomePanel.Visibility = Visibility.Collapsed;
        QrPanel.Visibility = Visibility.Visible;
        QrImage.Source = null;
        QrProgress.Visibility = Visibility.Visible;
        RetryLoginButton.Visibility = Visibility.Collapsed;
        QrStatusText.Text = "Создание защищённого QR…";
    }

    private void StopMessenger()
    {
        _heartbeatTimer?.Stop();
        _typingTimer?.Stop();
        _heartbeatTimer = null;
        _typingTimer = null;
        _backgroundCancellation?.Cancel();
        _backgroundCancellation?.Dispose();
        _backgroundCancellation = null;
        _uploadCancellation?.Cancel();
        _uploadCancellation?.Dispose();
        _uploadCancellation = null;
        _typingCancellation?.Cancel();
        _typingCancellation?.Dispose();
        _typingCancellation = null;
        _readCursorCancellation?.Cancel();
        _readCursorCancellation?.Dispose();
        _readCursorCancellation = null;
        _previewCancellation?.Cancel();
        _previewCancellation?.Dispose();
        _previewCancellation = null;
        _mediaCache?.Dispose();
        _mediaCache = null;
        _viewModel?.Call.Abort();
        _repository?.Dispose();
        _repository = null;
        _messagingApi?.Dispose();
        _messagingApi = null;
        _sessionManager?.Dispose();
        _sessionManager = null;
        _viewModel = null;
        DataContext = null;
        _eventCursor = 0;
    }

    private void ClearActiveLogin()
    {
        _activeTicket = null;
        _activeServer = null;
        _activeIdentity?.Dispose();
        _activeIdentity = null;
    }

    private void RestoreWindowPlacement()
    {
        if (_windowPlacementRestored) return;
        _windowPlacementRestored = true;
        if (_preferences.WindowWidth is not { } storedWidth ||
            _preferences.WindowHeight is not { } storedHeight ||
            !double.IsFinite(storedWidth) ||
            !double.IsFinite(storedHeight))
        {
            return;
        }

        double width = Math.Clamp(storedWidth, MinWidth, Math.Max(MinWidth, SystemParameters.VirtualScreenWidth));
        double height = Math.Clamp(storedHeight, MinHeight, Math.Max(MinHeight, SystemParameters.VirtualScreenHeight));
        Width = width;
        Height = height;
        if (_preferences.WindowLeft is { } storedLeft &&
            _preferences.WindowTop is { } storedTop &&
            double.IsFinite(storedLeft) &&
            double.IsFinite(storedTop))
        {
            WindowStartupLocation = WindowStartupLocation.Manual;
            double minimumLeft = SystemParameters.VirtualScreenLeft;
            double minimumTop = SystemParameters.VirtualScreenTop;
            double maximumLeft = minimumLeft + SystemParameters.VirtualScreenWidth - Math.Min(width, 120);
            double maximumTop = minimumTop + SystemParameters.VirtualScreenHeight - Math.Min(height, 80);
            Left = Math.Clamp(storedLeft, minimumLeft, Math.Max(minimumLeft, maximumLeft));
            Top = Math.Clamp(storedTop, minimumTop, Math.Max(minimumTop, maximumTop));
        }

        if (_preferences.WindowMaximized) WindowState = WindowState.Maximized;
    }

    private void SaveWindowPlacement()
    {
        Rect bounds = WindowState == WindowState.Normal
            ? new Rect(Left, Top, ActualWidth, ActualHeight)
            : RestoreBounds;
        if (bounds.Width >= MinWidth && bounds.Height >= MinHeight &&
            double.IsFinite(bounds.Left) && double.IsFinite(bounds.Top) &&
            double.IsFinite(bounds.Width) && double.IsFinite(bounds.Height))
        {
            _preferences.WindowLeft = bounds.Left;
            _preferences.WindowTop = bounds.Top;
            _preferences.WindowWidth = bounds.Width;
            _preferences.WindowHeight = bounds.Height;
        }

        _preferences.LastChatId = _viewModel?.SelectedChat?.Id ?? _preferences.LastChatId;
        _preferences.CompactChatOpen = _compactChatOpen;
        _preferences.WindowMaximized = WindowState == WindowState.Maximized;
        SaveDesktopPreferences();
    }

    private void MainWindow_Closing(object? sender, CancelEventArgs e)
    {
        SaveWindowPlacement();
        Dispose();
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _loginCancellation?.Cancel();
        _loginCancellation?.Dispose();
        _voiceRecorder.Dispose();
        _updateTimer?.Stop();
        _updateTimer = null;
        _updateClient.Dispose();
        StopMessenger();
        ClearActiveLogin();
        _linkClient.Dispose();
        _cryptoWorker.Dispose();
        _accountSecurityApi.Dispose();
        GC.SuppressFinalize(this);
    }

    private static void ClearPreparedAttachments(PreparedDesktopAttachment[] attachments)
    {
        foreach (PreparedDesktopAttachment attachment in attachments)
        {
            CryptographicOperations.ZeroMemory(attachment.Bytes);
            if (attachment.PreviewBytes is not null) CryptographicOperations.ZeroMemory(attachment.PreviewBytes);
        }
    }

    private static string BuildDeviceName()
    {
        string machine = Environment.MachineName.Trim();
        return string.IsNullOrEmpty(machine) ? "FedMes Desktop" : $"Desktop · {machine}";
    }

    private static BitmapImage DecodePng(byte[] png)
    {
        using var stream = new MemoryStream(png, writable: false);
        var image = new BitmapImage();
        image.BeginInit();
        image.CacheOption = BitmapCacheOption.OnLoad;
        image.StreamSource = stream;
        image.EndInit();
        image.Freeze();
        return image;
    }

    private void ShowError(string message) =>
        MessageBox.Show(this, message, "FedMes", MessageBoxButton.OK, MessageBoxImage.Warning);
}
