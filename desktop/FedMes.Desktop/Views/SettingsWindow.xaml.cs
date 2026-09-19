using System.Collections.ObjectModel;
using System.IO;
using System.Net.Http;
using System.Windows;
using System.Windows.Controls;
using FedMes.Desktop.Core.Messaging;
using FedMes.Desktop.Core.Storage;
using FedMes.Desktop.Services;
using FedMes.Desktop.ViewModels;

namespace FedMes.Desktop.Views;

public partial class SettingsWindow : Window
{
    private readonly MessagingRepository _repository;
    private readonly DesktopPreferencesStore _preferencesStore;
    private readonly DesktopPreferences _preferences;
    private readonly DesktopAccount _account;
    private readonly ObservableCollection<AccountDevice> _devices = [];
    private bool _loadingPreferences;

    public SettingsWindow(
        MessagingRepository repository,
        DesktopAccount account,
        DesktopPreferencesStore preferencesStore,
        DesktopPreferences preferences)
    {
        _repository = repository ?? throw new ArgumentNullException(nameof(repository));
        _account = account ?? throw new ArgumentNullException(nameof(account));
        _preferencesStore = preferencesStore ?? throw new ArgumentNullException(nameof(preferencesStore));
        _preferences = preferences ?? throw new ArgumentNullException(nameof(preferences));
        InitializeComponent();

        UserText.Text = account.Username;
        UserAvatarText.Text = string.IsNullOrWhiteSpace(account.Username) ? "F" : account.Username[..1].ToUpperInvariant();
        UserAvatarBorder.Background = AvatarPalette.ForUser(account.Username);
        ServerText.Text = $"FedMes ID: {account.DeviceId[..Math.Min(8, account.DeviceId.Length)]}";
        DevicesListBox.ItemsSource = _devices;
        LoadPreferences();
        Loaded += SettingsWindow_Loaded;
    }

    public event EventHandler? SignOutRequested;

    private async void SettingsWindow_Loaded(object sender, RoutedEventArgs e) => await RefreshAsync().ConfigureAwait(true);

    private async void RefreshButton_Click(object sender, RoutedEventArgs e) => await RefreshAsync().ConfigureAwait(true);

    private void LoadPreferences()
    {
        _loadingPreferences = true;
        try
        {
            ShowExactPresenceCheckBox.IsChecked = _preferences.ShowExactPresence;
            switch (_preferences.ThemeMode)
            {
                case DesktopThemeMode.Light:
                    LightThemeRadio.IsChecked = true;
                    break;
                case DesktopThemeMode.Dark:
                    DarkThemeRadio.IsChecked = true;
                    break;
                default:
                    SystemThemeRadio.IsChecked = true;
                    break;
            }
        }
        finally
        {
            _loadingPreferences = false;
        }
    }

    private async void ShowExactPresenceCheckBox_Changed(object sender, RoutedEventArgs e)
    {
        if (_loadingPreferences) return;
        _preferences.ShowExactPresence = ShowExactPresenceCheckBox.IsChecked == true;
        SavePreferences();
        try
        {
            await _repository.HeartbeatAsync(_preferences.ShowExactPresence, CancellationToken.None).ConfigureAwait(true);
        }
        catch (Exception error) when (error is HttpRequestException or IOException)
        {
            MessageBox.Show(this, error.Message, "FedMes", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void ThemeRadio_Checked(object sender, RoutedEventArgs e)
    {
        if (_loadingPreferences || sender is not RadioButton { Tag: string value }) return;
        _preferences.ThemeMode = Enum.TryParse(value, ignoreCase: true, out DesktopThemeMode mode)
            ? mode
            : DesktopThemeMode.System;
        SavePreferences();
        DesktopThemeManager.Apply(_preferences.ThemeMode);
    }

    private void SavePreferences()
    {
        try
        {
            _preferencesStore.Save(_preferences);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            MessageBox.Show(this, error.Message, "FedMes", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private async Task RefreshAsync()
    {
        try
        {
            IReadOnlyList<AccountDevice> devices = await _repository.ListAccountDevicesAsync(CancellationToken.None).ConfigureAwait(true);
            _devices.Clear();
            foreach (AccountDevice device in devices) _devices.Add(device);
        }
        catch (Exception error) when (error is HttpRequestException or IOException)
        {
            MessageBox.Show(this, error.Message, "FedMes", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private async void RevokeDeviceButton_Click(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is not AccountDevice device || device.Current) return;
        if (MessageBox.Show(this, $"Отключить устройство «{device.DisplayName}»?", "FedMes", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        try
        {
            await _repository.RevokeDeviceAsync(device.Id, CancellationToken.None).ConfigureAwait(true);
            await RefreshAsync().ConfigureAwait(true);
        }
        catch (Exception error) when (error is HttpRequestException or IOException)
        {
            MessageBox.Show(this, error.Message, "FedMes", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async void TerminateOthersButton_Click(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(this, "Завершить все другие сеансы FedMes?", "FedMes", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        try
        {
            await _repository.TerminateOtherDevicesAsync(CancellationToken.None).ConfigureAwait(true);
            await RefreshAsync().ConfigureAwait(true);
        }
        catch (Exception error) when (error is HttpRequestException or IOException)
        {
            MessageBox.Show(this, error.Message, "FedMes", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void SignOutButton_Click(object sender, RoutedEventArgs e)
    {
        SignOutRequested?.Invoke(this, EventArgs.Empty);
        Close();
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e) => Close();
}
