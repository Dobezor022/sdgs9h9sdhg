using System.Globalization;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;

namespace FedMes.Desktop.FedUI3;

/// <summary>
/// Frozen FedMes 2026 / Bridge 1.9 semantic design tokens shared with Android.
/// Values correspond to freeze19-inventory (queue sequence 682).
/// </summary>
public static class FedMes26Tokens
{
    public static readonly Color Background = Color.FromRgb(0x0E, 0x16, 0x21);
    public static readonly Color Surface = Color.FromRgb(0x17, 0x21, 0x2B);
    public static readonly Color Raised = Color.FromRgb(0x20, 0x2B, 0x36);
    public static readonly Color Border = Color.FromRgb(0x2B, 0x3A, 0x48);
    public static readonly Color Text = Color.FromRgb(0xF4, 0xF7, 0xFA);
    public static readonly Color Muted = Color.FromRgb(0x8E, 0x9D, 0xAA);
    public static readonly Color Accent = Color.FromRgb(0x33, 0x90, 0xEC);
    public static readonly Color Incoming = Color.FromRgb(0x18, 0x25, 0x33);
    public static readonly Color Outgoing = Color.FromRgb(0x2B, 0x52, 0x78);
    public static readonly Color Danger = Color.FromRgb(0xD9, 0x4B, 0x4B);

    public const double ChatRowHeight = 68;
    public const double ChatAvatar = 54;
    public const double BottomBarHeight = 72;
    public const double CallTrayHeight = 104;
}

public enum FedMes26PlaybackState { Paused, Playing, Buffering }
public enum FedMes26CallMode { Audio, Video, Group }

/// <summary>
/// Custom-rendered Figma VideoPlayerPro chrome. The actual decoded video is hosted by the
/// existing MediaPlayerWindow; this element owns only FedMes chrome/state rendering.
/// </summary>
public sealed class FedMes26VideoChrome : FrameworkElement
{
    private static readonly Typeface UiTypeface = new(new FontFamily("Segoe UI Variable Text"), FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);
    private static readonly Brush RaisedBrush = Frozen(FedMes26Tokens.Raised);
    private static readonly Brush BorderBrush = Frozen(FedMes26Tokens.Border);
    private static readonly Brush TextBrush = Frozen(FedMes26Tokens.Text);
    private static readonly Brush AccentBrush = Frozen(FedMes26Tokens.Accent);

    public FedMes26PlaybackState PlaybackState
    {
        get => (FedMes26PlaybackState)GetValue(PlaybackStateProperty);
        set => SetValue(PlaybackStateProperty, value);
    }
    public static readonly DependencyProperty PlaybackStateProperty = DependencyProperty.Register(
        nameof(PlaybackState), typeof(FedMes26PlaybackState), typeof(FedMes26VideoChrome),
        new FrameworkPropertyMetadata(FedMes26PlaybackState.Paused, FrameworkPropertyMetadataOptions.AffectsRender));

    public double Progress
    {
        get => (double)GetValue(ProgressProperty);
        set => SetValue(ProgressProperty, value);
    }
    public static readonly DependencyProperty ProgressProperty = DependencyProperty.Register(
        nameof(Progress), typeof(double), typeof(FedMes26VideoChrome),
        new FrameworkPropertyMetadata(0d, FrameworkPropertyMetadataOptions.AffectsRender));

    public bool ChromeVisible
    {
        get => (bool)GetValue(ChromeVisibleProperty);
        set => SetValue(ChromeVisibleProperty, value);
    }
    public static readonly DependencyProperty ChromeVisibleProperty = DependencyProperty.Register(
        nameof(ChromeVisible), typeof(bool), typeof(FedMes26VideoChrome),
        new FrameworkPropertyMetadata(true, FrameworkPropertyMetadataOptions.AffectsRender));

    public string CurrentTime
    {
        get => (string)GetValue(CurrentTimeProperty);
        set => SetValue(CurrentTimeProperty, value);
    }
    public static readonly DependencyProperty CurrentTimeProperty = DependencyProperty.Register(
        nameof(CurrentTime), typeof(string), typeof(FedMes26VideoChrome),
        new FrameworkPropertyMetadata("0:00", FrameworkPropertyMetadataOptions.AffectsRender));

    public string Duration
    {
        get => (string)GetValue(DurationProperty);
        set => SetValue(DurationProperty, value);
    }
    public static readonly DependencyProperty DurationProperty = DependencyProperty.Register(
        nameof(Duration), typeof(string), typeof(FedMes26VideoChrome),
        new FrameworkPropertyMetadata("0:00", FrameworkPropertyMetadataOptions.AffectsRender));

    protected override void OnRender(DrawingContext dc)
    {
        base.OnRender(dc);
        if (!ChromeVisible) return;
        var width = RenderSize.Width;
        var height = RenderSize.Height;
        if (width <= 0 || height <= 0) return;

        var center = new Point(width / 2, height / 2);
        if (PlaybackState == FedMes26PlaybackState.Buffering)
        {
            dc.DrawEllipse(null, new Pen(AccentBrush, 3), center, 15, 15);
        }
        else
        {
            dc.DrawEllipse(RaisedBrush, null, center, 32, 32);
            DrawText(dc, PlaybackState == FedMes26PlaybackState.Playing ? "Ⅱ" : "▶", new Point(center.X - 9, center.Y - 15), 22, TextBrush, FontWeights.SemiBold);
        }

        var y = Math.Max(20, height - 62);
        var left = 18d;
        var right = Math.Max(left, width - 18);
        var p = Math.Clamp(Progress, 0, 1);
        dc.DrawLine(new Pen(BorderBrush, 4), new Point(left, y), new Point(right, y));
        dc.DrawLine(new Pen(AccentBrush, 4), new Point(left, y), new Point(left + (right - left) * p, y));
        dc.DrawEllipse(AccentBrush, null, new Point(left + (right - left) * p, y), 8, 8);
        DrawText(dc, CurrentTime, new Point(left, height - 30), 9, TextBrush, FontWeights.Normal);
        DrawText(dc, $"1×    ⛶    {Duration}", new Point(Math.Max(left, width - 135), height - 30), 9, TextBrush, FontWeights.Normal);
    }

    private void DrawText(DrawingContext dc, string text, Point point, double size, Brush brush, FontWeight weight)
    {
        var formatted = new FormattedText(text, CultureInfo.CurrentUICulture, FlowDirection.LeftToRight,
            new Typeface(UiTypeface.FontFamily, FontStyles.Normal, weight, FontStretches.Normal),
            size, brush, VisualTreeHelper.GetDpi(this).PixelsPerDip);
        dc.DrawText(formatted, point);
    }

    private static SolidColorBrush Frozen(Color color)
    {
        var brush = new SolidColorBrush(color);
        brush.Freeze();
        return brush;
    }
}

/// <summary>Figma Call/ControlTray implementation (audio/video/group states).</summary>
public sealed class FedMes26CallTray : FrameworkElement
{
    private static readonly Typeface UiTypeface = new(new FontFamily("Segoe UI Variable Text"), FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);
    private static readonly Brush SurfaceBrush = Frozen(FedMes26Tokens.Surface);
    private static readonly Brush RaisedBrush = Frozen(FedMes26Tokens.Raised);
    private static readonly Brush TextBrush = Frozen(FedMes26Tokens.Text);
    private static readonly Brush AccentBrush = Frozen(FedMes26Tokens.Accent);
    private static readonly Brush DangerBrush = Frozen(FedMes26Tokens.Danger);

    public FedMes26CallMode Mode
    {
        get => (FedMes26CallMode)GetValue(ModeProperty);
        set => SetValue(ModeProperty, value);
    }
    public static readonly DependencyProperty ModeProperty = DependencyProperty.Register(
        nameof(Mode), typeof(FedMes26CallMode), typeof(FedMes26CallTray),
        new FrameworkPropertyMetadata(FedMes26CallMode.Audio, FrameworkPropertyMetadataOptions.AffectsRender));

    public bool Muted
    {
        get => (bool)GetValue(MutedProperty);
        set => SetValue(MutedProperty, value);
    }
    public static readonly DependencyProperty MutedProperty = DependencyProperty.Register(
        nameof(Muted), typeof(bool), typeof(FedMes26CallTray),
        new FrameworkPropertyMetadata(false, FrameworkPropertyMetadataOptions.AffectsRender));

    public bool Speaker
    {
        get => (bool)GetValue(SpeakerProperty);
        set => SetValue(SpeakerProperty, value);
    }
    public static readonly DependencyProperty SpeakerProperty = DependencyProperty.Register(
        nameof(Speaker), typeof(bool), typeof(FedMes26CallTray),
        new FrameworkPropertyMetadata(false, FrameworkPropertyMetadataOptions.AffectsRender));

    public bool Camera
    {
        get => (bool)GetValue(CameraProperty);
        set => SetValue(CameraProperty, value);
    }
    public static readonly DependencyProperty CameraProperty = DependencyProperty.Register(
        nameof(Camera), typeof(bool), typeof(FedMes26CallTray),
        new FrameworkPropertyMetadata(false, FrameworkPropertyMetadataOptions.AffectsRender));

    public event EventHandler? MuteInvoked;
    public event EventHandler? SpeakerInvoked;
    public event EventHandler? CameraInvoked;
    public event EventHandler? FlipInvoked;
    public event EventHandler? EndInvoked;

    protected override Size MeasureOverride(Size availableSize) => new(
        double.IsInfinity(availableSize.Width) ? 390 : availableSize.Width,
        Math.Min(FedMes26Tokens.CallTrayHeight, availableSize.Height));

    protected override void OnRender(DrawingContext dc)
    {
        base.OnRender(dc);
        var rect = new Rect(0, 0, RenderSize.Width, Math.Min(RenderSize.Height, FedMes26Tokens.CallTrayHeight));
        dc.DrawRoundedRectangle(SurfaceBrush, null, rect, 26, 26);
        var items = GetItems();
        var slot = RenderSize.Width / items.Count;
        for (var i = 0; i < items.Count; i++)
        {
            var item = items[i];
            var cx = slot * i + slot / 2;
            var fill = item.IsEnd ? DangerBrush : item.Active ? AccentBrush : RaisedBrush;
            dc.DrawEllipse(fill, null, new Point(cx, 32), 23, 23);
            DrawText(dc, item.Glyph, new Point(cx - 8, 20), 16, TextBrush, FontWeights.SemiBold);
            DrawText(dc, item.Label, new Point(cx - 25, 64), 9, TextBrush, FontWeights.Normal);
        }
    }

    protected override void OnMouseLeftButtonDown(MouseButtonEventArgs e)
    {
        base.OnMouseLeftButtonDown(e);
        var items = GetItems();
        if (items.Count == 0 || RenderSize.Width <= 0) return;
        var index = Math.Clamp((int)(e.GetPosition(this).X / (RenderSize.Width / items.Count)), 0, items.Count - 1);
        switch (items[index].Action)
        {
            case "mute": MuteInvoked?.Invoke(this, EventArgs.Empty); break;
            case "speaker": SpeakerInvoked?.Invoke(this, EventArgs.Empty); break;
            case "camera": CameraInvoked?.Invoke(this, EventArgs.Empty); break;
            case "flip": FlipInvoked?.Invoke(this, EventArgs.Empty); break;
            case "end": EndInvoked?.Invoke(this, EventArgs.Empty); break;
        }
    }

    private List<Item> GetItems()
    {
        var result = new List<Item>
        {
            new("mute", "●", Muted ? "Микр. выкл." : "Микрофон", Muted, false),
            new("speaker", "◖", Speaker ? "Динамик" : "Аудио", Speaker, false),
            new("camera", "▣", Camera ? "Камера" : "Видео", Camera, false),
        };
        if (Mode != FedMes26CallMode.Audio) result.Add(new("flip", "↻", "Сменить", false, false));
        result.Add(new("end", "×", "Завершить", true, true));
        return result;
    }

    private void DrawText(DrawingContext dc, string text, Point point, double size, Brush brush, FontWeight weight)
    {
        var formatted = new FormattedText(text, CultureInfo.CurrentUICulture, FlowDirection.LeftToRight,
            new Typeface(UiTypeface.FontFamily, FontStyles.Normal, weight, FontStretches.Normal),
            size, brush, VisualTreeHelper.GetDpi(this).PixelsPerDip);
        dc.DrawText(formatted, point);
    }

    private sealed record Item(string Action, string Glyph, string Label, bool Active, bool IsEnd);
    private static SolidColorBrush Frozen(Color color) { var b = new SolidColorBrush(color); b.Freeze(); return b; }
}
