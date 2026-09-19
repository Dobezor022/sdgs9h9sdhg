using System.IO;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace FedMes.Desktop.Views;

public partial class PhotoViewerWindow : Window
{
    private readonly BitmapSource _source;
    private readonly double _pixelWidth;
    private readonly double _pixelHeight;
    private double _fitScale = 1;
    private double _zoom = 1;
    private bool _ready;

    public PhotoViewerWindow(string path, string title)
    {
        InitializeComponent();
        TitleText.Text = string.IsNullOrWhiteSpace(title) ? "Фото" : title;
        _source = LoadOrientedBitmap(path);
        _pixelWidth = Math.Max(1, _source.PixelWidth);
        _pixelHeight = Math.Max(1, _source.PixelHeight);
        PhotoImage.Source = _source;
    }

    private void Window_Loaded(object sender, RoutedEventArgs e)
    {
        _ready = true;
        FitToWindow(resetZoom: true);
    }

    private void Window_SizeChanged(object sender, SizeChangedEventArgs e)
    {
        if (!_ready) return;
        FitToWindow(resetZoom: false);
    }

    private void ImageScrollViewer_PreviewMouseWheel(object sender, MouseWheelEventArgs e)
    {
        SetZoom(_zoom * (e.Delta > 0 ? 1.18 : 1 / 1.18));
        e.Handled = true;
    }

    private void ZoomInButton_Click(object sender, RoutedEventArgs e) => SetZoom(_zoom * 1.25);
    private void ZoomOutButton_Click(object sender, RoutedEventArgs e) => SetZoom(_zoom / 1.25);
    private void ResetZoomButton_Click(object sender, RoutedEventArgs e) => SetZoom(1);
    private void CloseButton_Click(object sender, RoutedEventArgs e) => Close();

    private void Window_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Escape) Close();
        if (e.Key is Key.Add or Key.OemPlus) SetZoom(_zoom * 1.25);
        if (e.Key is Key.Subtract or Key.OemMinus) SetZoom(_zoom / 1.25);
        if (e.Key is Key.D0 or Key.NumPad0) SetZoom(1);
    }

    private void FitToWindow(bool resetZoom)
    {
        double availableWidth = Math.Max(1, ImageScrollViewer.ActualWidth - 28);
        double availableHeight = Math.Max(1, ImageScrollViewer.ActualHeight - 28);
        _fitScale = Math.Min(availableWidth / _pixelWidth, availableHeight / _pixelHeight);
        // Do not enlarge a small source above its native resolution in the initial Telegram-like fit.
        _fitScale = Math.Clamp(_fitScale, 0.01, 1.0);
        if (resetZoom) _zoom = 1;
        ApplySize(preserveCenter: false);
    }

    private void SetZoom(double value)
    {
        _zoom = Math.Clamp(value, 0.25, 8.0);
        ApplySize(preserveCenter: true);
    }

    private void ApplySize(bool preserveCenter)
    {
        double horizontalRatio = 0.5;
        double verticalRatio = 0.5;
        if (preserveCenter && ImageScrollViewer.ExtentWidth > 0 && ImageScrollViewer.ExtentHeight > 0)
        {
            horizontalRatio = (ImageScrollViewer.HorizontalOffset + ImageScrollViewer.ViewportWidth / 2) /
                              ImageScrollViewer.ExtentWidth;
            verticalRatio = (ImageScrollViewer.VerticalOffset + ImageScrollViewer.ViewportHeight / 2) /
                            ImageScrollViewer.ExtentHeight;
        }

        double scale = _fitScale * _zoom;
        PhotoImage.Width = Math.Max(1, _pixelWidth * scale);
        PhotoImage.Height = Math.Max(1, _pixelHeight * scale);
        ImageHost.Width = Math.Max(PhotoImage.Width, ImageScrollViewer.ViewportWidth);
        ImageHost.Height = Math.Max(PhotoImage.Height, ImageScrollViewer.ViewportHeight);
        ZoomText.Text = $"{Math.Round(_zoom * 100):0}%";

        if (!preserveCenter) return;
        _ = Dispatcher.BeginInvoke(DispatcherPriority.Loaded, new Action(() =>
        {
            ImageScrollViewer.ScrollToHorizontalOffset(
                Math.Max(0, horizontalRatio * ImageScrollViewer.ExtentWidth - ImageScrollViewer.ViewportWidth / 2));
            ImageScrollViewer.ScrollToVerticalOffset(
                Math.Max(0, verticalRatio * ImageScrollViewer.ExtentHeight - ImageScrollViewer.ViewportHeight / 2));
        }));
    }

    private static BitmapSource LoadOrientedBitmap(string path)
    {
        ushort orientation = 1;
        int sourceWidth = 0;
        int sourceHeight = 0;
        using (FileStream metadataStream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            BitmapDecoder decoder = BitmapDecoder.Create(
                metadataStream,
                BitmapCreateOptions.PreservePixelFormat,
                BitmapCacheOption.OnDemand);
            BitmapFrame frame = decoder.Frames[0];
            sourceWidth = frame.PixelWidth;
            sourceHeight = frame.PixelHeight;
            orientation = ReadOrientation(frame.Metadata as BitmapMetadata);
        }

        using FileStream pixelStream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var image = new BitmapImage();
        image.BeginInit();
        image.CacheOption = BitmapCacheOption.OnLoad;
        image.CreateOptions = BitmapCreateOptions.IgnoreColorProfile;
        if (Math.Max(sourceWidth, sourceHeight) > MaximumDecodedEdge)
        {
            if (sourceWidth >= sourceHeight) image.DecodePixelWidth = MaximumDecodedEdge;
            else image.DecodePixelHeight = MaximumDecodedEdge;
        }
        image.StreamSource = pixelStream;
        image.EndInit();
        image.Freeze();

        TransformGroup? transform = OrientationTransform(orientation);
        BitmapSource result = transform is null ? image : new TransformedBitmap(image, transform);
        result.Freeze();
        return result;
    }

    private static ushort ReadOrientation(BitmapMetadata? metadata)
    {
        if (metadata is null) return 1;
        foreach (string query in new[] { "/app1/ifd/{ushort=274}", "/ifd/{ushort=274}" })
        {
            try
            {
                object? value = metadata.GetQuery(query);
                if (value is ushort orientation) return orientation;
            }
            catch (Exception error) when (error is NotSupportedException or ArgumentException)
            {
            }
        }
        return 1;
    }

    private const int MaximumDecodedEdge = 8192;

    private static TransformGroup? OrientationTransform(ushort orientation)
    {
        var group = new TransformGroup();
        switch (orientation)
        {
            case 2: group.Children.Add(new ScaleTransform(-1, 1)); break;
            case 3: group.Children.Add(new RotateTransform(180)); break;
            case 4: group.Children.Add(new ScaleTransform(1, -1)); break;
            case 5:
                group.Children.Add(new ScaleTransform(-1, 1));
                group.Children.Add(new RotateTransform(90));
                break;
            case 6: group.Children.Add(new RotateTransform(90)); break;
            case 7:
                group.Children.Add(new ScaleTransform(-1, 1));
                group.Children.Add(new RotateTransform(270));
                break;
            case 8: group.Children.Add(new RotateTransform(270)); break;
            default: return null;
        }
        return group;
    }
}
