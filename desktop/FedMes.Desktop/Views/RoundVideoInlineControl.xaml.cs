using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using FedMes.Desktop.Core.Messaging;
using FedMes.Desktop.Services;

namespace FedMes.Desktop.Views;

public partial class RoundVideoInlineControl : UserControl
{
    public static readonly DependencyProperty SourcePathProperty = DependencyProperty.Register(
        nameof(SourcePath),
        typeof(string),
        typeof(RoundVideoInlineControl),
        new PropertyMetadata(string.Empty, SourcePathChanged));

    public static readonly DependencyProperty PreviewSourceProperty = DependencyProperty.Register(
        nameof(PreviewSource),
        typeof(ImageSource),
        typeof(RoundVideoInlineControl));

    public static readonly DependencyProperty ShapeProperty = DependencyProperty.Register(
        nameof(Shape),
        typeof(RoundVideoShape),
        typeof(RoundVideoInlineControl),
        new PropertyMetadata(RoundVideoShape.Circle));

    public static readonly RoutedEvent SourceRequestedEvent = EventManager.RegisterRoutedEvent(
        nameof(SourceRequested),
        RoutingStrategy.Bubble,
        typeof(RoutedEventHandler),
        typeof(RoundVideoInlineControl));

    private readonly DispatcherTimer _timer;
    private bool _playing;
    private bool _sourceReady;
    private int _rotationDegrees;

    public RoundVideoInlineControl()
    {
        InitializeComponent();
        _timer = new DispatcherTimer(TimeSpan.FromMilliseconds(160), DispatcherPriority.Background, Timer_Tick, Dispatcher);
    }

    public string SourcePath
    {
        get => (string)GetValue(SourcePathProperty);
        set => SetValue(SourcePathProperty, value);
    }

    public ImageSource? PreviewSource
    {
        get => (ImageSource?)GetValue(PreviewSourceProperty);
        set => SetValue(PreviewSourceProperty, value);
    }

    public RoundVideoShape Shape
    {
        get => (RoundVideoShape)GetValue(ShapeProperty);
        set => SetValue(ShapeProperty, value);
    }

    public event RoutedEventHandler SourceRequested
    {
        add => AddHandler(SourceRequestedEvent, value);
        remove => RemoveHandler(SourceRequestedEvent, value);
    }

    public void SetLoading(bool loading)
    {
        LoadingBar.Visibility = loading ? Visibility.Visible : Visibility.Collapsed;
        PlayOverlay.Visibility = loading ? Visibility.Collapsed : Visibility.Visible;
    }

    public void Play()
    {
        if (string.IsNullOrWhiteSpace(SourcePath) || !File.Exists(SourcePath)) return;
        if (_sourceReady && Player.NaturalDuration.HasTimeSpan && Player.Position >= Player.NaturalDuration.TimeSpan - TimeSpan.FromMilliseconds(120))
        {
            Player.Position = TimeSpan.Zero;
        }

        Player.Play();
        SetPlaying(true);
    }

    private static void SourcePathChanged(DependencyObject dependencyObject, DependencyPropertyChangedEventArgs e)
    {
        var control = (RoundVideoInlineControl)dependencyObject;
        string path = e.NewValue as string ?? string.Empty;
        control.StopAndReset();
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            control.Player.Source = null;
            control._rotationDegrees = 0;
            control.PlayerRotation.Angle = 0;
            control.ResetPlayerLayout();
            control._sourceReady = false;
            return;
        }

        control._rotationDegrees = Mp4VideoRotationReader.TryReadDegrees(path);
        control.PlayerRotation.Angle = control._rotationDegrees;
        control.ResetPlayerLayout();
        control.Player.Source = new Uri(path, UriKind.Absolute);
        control._sourceReady = false;
        control.SetLoading(false);
    }

    private void RootGrid_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        e.Handled = true;
        if (string.IsNullOrWhiteSpace(SourcePath) || !File.Exists(SourcePath))
        {
            SetLoading(true);
            RaiseEvent(new RoutedEventArgs(SourceRequestedEvent, this));
            return;
        }

        if (_playing)
        {
            Player.Pause();
            SetPlaying(false);
        }
        else
        {
            Play();
        }
    }

    private void Player_MediaOpened(object sender, RoutedEventArgs e)
    {
        _sourceReady = true;
        ApplyPlayerCoverLayout();
        PreviewImage.Visibility = Visibility.Collapsed;
        SetLoading(false);
        PositionBar.Maximum = Math.Max(1, Player.NaturalDuration.HasTimeSpan
            ? Player.NaturalDuration.TimeSpan.TotalMilliseconds
            : 1);
    }


    private void RootGrid_SizeChanged(object sender, SizeChangedEventArgs e)
    {
        if (_sourceReady) ApplyPlayerCoverLayout();
    }

    /// <summary>
    /// MediaElement performs Stretch before RenderTransform. For phone videos whose MP4 track
    /// stores a 90/270-degree matrix this produces a small frame in one corner of the 220x220
    /// viewport. Size the unrotated video from its encoded dimensions first, then rotate the
    /// already cover-scaled surface around its centre.
    /// </summary>
    private void ApplyPlayerCoverLayout()
    {
        int naturalWidth = Player.NaturalVideoWidth;
        int naturalHeight = Player.NaturalVideoHeight;
        double viewportWidth = RootGrid.ActualWidth;
        double viewportHeight = RootGrid.ActualHeight;
        if (naturalWidth <= 0 || naturalHeight <= 0 || viewportWidth <= 0 || viewportHeight <= 0) return;

        bool swapsAxes = _rotationDegrees is 90 or 270;
        double displayedWidth = swapsAxes ? naturalHeight : naturalWidth;
        double displayedHeight = swapsAxes ? naturalWidth : naturalHeight;
        double scale = Math.Max(viewportWidth / displayedWidth, viewportHeight / displayedHeight);

        Player.Width = Math.Ceiling(naturalWidth * scale);
        Player.Height = Math.Ceiling(naturalHeight * scale);
        PlayerRotation.Angle = _rotationDegrees;
    }

    private void ResetPlayerLayout()
    {
        Player.Width = double.NaN;
        Player.Height = double.NaN;
    }

    private void Player_MediaEnded(object sender, RoutedEventArgs e)
    {
        Player.Position = TimeSpan.Zero;
        Player.Pause();
        PositionBar.Value = 0;
        SetPlaying(false);
    }

    private void Player_MediaFailed(object sender, ExceptionRoutedEventArgs e)
    {
        _sourceReady = false;
        PreviewImage.Visibility = Visibility.Visible;
        SetLoading(false);
        SetPlaying(false);
        ToolTip = e.ErrorException?.Message ?? "Не удалось воспроизвести видеосообщение.";
    }

    private void Timer_Tick(object? sender, EventArgs e)
    {
        PositionBar.Value = Player.Position.TotalMilliseconds;
    }

    private void SetPlaying(bool playing)
    {
        _playing = playing;
        PlayGlyph.Text = playing ? "❚❚" : "▶";
        PlayOverlay.Opacity = playing ? 0.28 : 1;
        if (playing) _timer.Start();
        else _timer.Stop();
    }

    private void StopAndReset()
    {
        _timer.Stop();
        _playing = false;
        _sourceReady = false;
        try
        {
            Player.Stop();
        }
        catch (InvalidOperationException)
        {
        }

        PreviewImage.Visibility = Visibility.Visible;
        PositionBar.Value = 0;
        PlayGlyph.Text = "▶";
        PlayOverlay.Opacity = 1;
    }

    private void UserControl_Unloaded(object sender, RoutedEventArgs e)
    {
        StopAndReset();
        Player.Source = null;
        _rotationDegrees = 0;
        PlayerRotation.Angle = 0;
        ResetPlayerLayout();
    }
}
