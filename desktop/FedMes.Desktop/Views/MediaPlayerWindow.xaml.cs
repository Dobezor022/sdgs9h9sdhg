using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Threading;
using FedMes.Desktop.Services;

namespace FedMes.Desktop.Views;

public partial class MediaPlayerWindow : Window
{
    private readonly DispatcherTimer? _timer;
    private readonly DispatcherTimer? _controlsTimer;
    private bool _playing;
    private bool _dragging;
    private bool _audioOnly;
    private bool _muted;
    private double _volumeBeforeMute = 1;
    private WindowState _windowStateBeforeFullscreen;
    private WindowStyle _windowStyleBeforeFullscreen;
    private ResizeMode _resizeModeBeforeFullscreen;
    private bool _fullscreen;

    public MediaPlayerWindow(string path, string title, bool audioOnly)
    {
        InitializeComponent();
        _audioOnly = audioOnly;
        TitleText.Text = string.IsNullOrWhiteSpace(title) ? (audioOnly ? "Аудио" : "Видео") : title.Trim();
        AudioPlaceholder.Visibility = audioOnly ? Visibility.Visible : Visibility.Collapsed;
        PlayerRotation.Angle = audioOnly ? 0 : Mp4VideoRotationReader.TryReadDegrees(path);
        Player.Source = new Uri(path, UriKind.Absolute);
        _timer = new DispatcherTimer(TimeSpan.FromMilliseconds(200), DispatcherPriority.Background, Timer_Tick, Dispatcher);
        _controlsTimer = new DispatcherTimer(TimeSpan.FromSeconds(3), DispatcherPriority.Background, ControlsTimer_Tick, Dispatcher);
        Player.Play();
        SetPlaying(true);
        _timer?.Start();
        RestartControlsTimer();
    }

    private void Player_MediaOpened(object sender, RoutedEventArgs e)
    {
        if (Player.NaturalDuration.HasTimeSpan)
        {
            PositionSlider.Maximum = Math.Max(1, Player.NaturalDuration.TimeSpan.TotalMilliseconds);
        }
    }

    private void Player_MediaEnded(object sender, RoutedEventArgs e)
    {
        Player.Position = TimeSpan.Zero;
        Player.Play();
        SetPlaying(true);
    }

    private void Player_MediaFailed(object sender, ExceptionRoutedEventArgs e)
    {
        SetPlaying(false);
        MessageBox.Show(this, e.ErrorException?.Message ?? "Не удалось воспроизвести медиа.", "FedMes", MessageBoxButton.OK, MessageBoxImage.Error);
    }

    private void PlayPauseButton_Click(object sender, RoutedEventArgs e)
    {
        if (_playing)
        {
            Player.Pause();
            SetPlaying(false);
        }
        else
        {
            Player.Play();
            SetPlaying(true);
        }
        ShowControls();
    }

    private void RewindButton_Click(object sender, RoutedEventArgs e) => SeekBy(TimeSpan.FromSeconds(-10));
    private void ForwardButton_Click(object sender, RoutedEventArgs e) => SeekBy(TimeSpan.FromSeconds(10));

    private void SeekBy(TimeSpan delta)
    {
        TimeSpan total = Player.NaturalDuration.HasTimeSpan ? Player.NaturalDuration.TimeSpan : TimeSpan.MaxValue;
        TimeSpan target = Player.Position + delta;
        if (target < TimeSpan.Zero) target = TimeSpan.Zero;
        if (target > total) target = total;
        Player.Position = target;
        ShowControls();
    }

    private void Timer_Tick(object? sender, EventArgs e)
    {
        if (!_dragging) PositionSlider.Value = Player.Position.TotalMilliseconds;
        TimeSpan total = Player.NaturalDuration.HasTimeSpan ? Player.NaturalDuration.TimeSpan : TimeSpan.Zero;
        TimeText.Text = $"{Format(Player.Position)} / {Format(total)}";
    }

    private void PositionSlider_PreviewMouseDown(object sender, MouseButtonEventArgs e) => _dragging = true;

    private void PositionSlider_PreviewMouseUp(object sender, MouseButtonEventArgs e)
    {
        Player.Position = TimeSpan.FromMilliseconds(PositionSlider.Value);
        _dragging = false;
        ShowControls();
    }

    private void PositionSlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
    {
        if (_dragging)
        {
            TimeSpan total = Player.NaturalDuration.HasTimeSpan ? Player.NaturalDuration.TimeSpan : TimeSpan.Zero;
            TimeText.Text = $"{Format(TimeSpan.FromMilliseconds(e.NewValue))} / {Format(total)}";
        }
    }

    private void SpeedComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (SpeedComboBox.SelectedItem is ComboBoxItem item &&
            double.TryParse(item.Tag as string, NumberStyles.Float, CultureInfo.InvariantCulture, out double speed))
        {
            Player.SpeedRatio = speed;
        }
        ShowControls();
    }

    private void VolumeSlider_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
    {
        if (Player is null) return;
        Player.Volume = Math.Clamp(e.NewValue, 0, 1);
        _muted = Player.Volume <= 0.001;
        MuteButton.Content = _muted ? "🔇" : Player.Volume < 0.45 ? "🔉" : "🔊";
    }

    private void MuteButton_Click(object sender, RoutedEventArgs e)
    {
        if (_muted)
        {
            VolumeSlider.Value = Math.Max(0.15, _volumeBeforeMute);
        }
        else
        {
            _volumeBeforeMute = VolumeSlider.Value;
            VolumeSlider.Value = 0;
        }
        ShowControls();
    }

    private void FullscreenButton_Click(object sender, RoutedEventArgs e)
    {
        if (!_fullscreen)
        {
            _windowStateBeforeFullscreen = WindowState;
            _windowStyleBeforeFullscreen = WindowStyle;
            _resizeModeBeforeFullscreen = ResizeMode;
            WindowStyle = WindowStyle.None;
            ResizeMode = ResizeMode.NoResize;
            WindowState = WindowState.Maximized;
            _fullscreen = true;
            FullscreenButton.Content = "⧉";
        }
        else
        {
            WindowStyle = _windowStyleBeforeFullscreen;
            ResizeMode = _resizeModeBeforeFullscreen;
            WindowState = _windowStateBeforeFullscreen;
            _fullscreen = false;
            FullscreenButton.Content = "⛶";
        }
        ShowControls();
    }

    private void Window_KeyDown(object sender, KeyEventArgs e)
    {
        switch (e.Key)
        {
            case Key.Escape when _fullscreen:
                FullscreenButton_Click(sender, e);
                e.Handled = true;
                break;
            case Key.Escape:
                Close();
                break;
            case Key.Space:
                PlayPauseButton_Click(sender, e);
                e.Handled = true;
                break;
            case Key.Left:
                SeekBy(TimeSpan.FromSeconds(-10));
                break;
            case Key.Right:
                SeekBy(TimeSpan.FromSeconds(10));
                break;
            case Key.Up:
                VolumeSlider.Value = Math.Min(1, VolumeSlider.Value + 0.05);
                break;
            case Key.Down:
                VolumeSlider.Value = Math.Max(0, VolumeSlider.Value - 0.05);
                break;
            case Key.F:
                FullscreenButton_Click(sender, e);
                break;
        }
    }

    private void Window_MouseMove(object sender, MouseEventArgs e) => ShowControls();

    private void ShowControls()
    {
        ControlsOverlay.Visibility = Visibility.Visible;
        Cursor = Cursors.Arrow;
        RestartControlsTimer();
    }

    private void RestartControlsTimer()
    {
        _controlsTimer?.Stop();
        if (_playing && !_audioOnly) _controlsTimer?.Start();
    }

    private void ControlsTimer_Tick(object? sender, EventArgs e)
    {
        _controlsTimer?.Stop();
        if (_playing && !_dragging && !_audioOnly)
        {
            ControlsOverlay.Visibility = Visibility.Collapsed;
            Cursor = Cursors.None;
        }
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e) => Close();

    private void Window_Closed(object? sender, EventArgs e)
    {
        _timer?.Stop();
        _controlsTimer?.Stop();
        Player.Stop();
        Player.Source = null;
        PlayerRotation.Angle = 0;
    }

    private void SetPlaying(bool playing)
    {
        _playing = playing;
        string glyph = playing ? "❚❚" : "▶";
        PlayPauseButton.Content = glyph;
        CenterPlayButton.Content = glyph;
        CenterPlayButton.Opacity = playing ? 0.22 : 1;
        RestartControlsTimer();
    }

    private static string Format(TimeSpan value) => value.TotalHours >= 1 ? value.ToString(@"h\:mm\:ss") : value.ToString(@"m\:ss");
}
