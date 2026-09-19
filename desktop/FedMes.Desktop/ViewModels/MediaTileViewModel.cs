using System.Windows.Media;
using FedMes.Desktop.Core.Messaging;

namespace FedMes.Desktop.ViewModels;

public sealed class MediaTileViewModel : ObservableObject
{
    private ImageSource? _preview;
    private bool _loading;
    private double _progress;

    public MediaTileViewModel(MediaDescriptor descriptor, int index)
    {
        Descriptor = descriptor;
        Index = index;
    }

    public MediaDescriptor Descriptor { get; }
    public int Index { get; }
    public string Name => Descriptor.Name;
    public string MimeType => Descriptor.MimeType;
    public bool IsImage => MimeType.StartsWith("image/", StringComparison.OrdinalIgnoreCase);
    public bool IsVideo => MimeType.StartsWith("video/", StringComparison.OrdinalIgnoreCase);
    public bool IsAudio => MimeType.StartsWith("audio/", StringComparison.OrdinalIgnoreCase);
    public string MediaKindLabel => IsImage ? "Фото" : IsVideo ? "Видео" : IsAudio ? "Аудио" : "Файл";
    public string SizeText => FormatBytes(Descriptor.OriginalSize);
    public string DurationText => Descriptor.DurationMilliseconds is > 0
        ? TimeSpan.FromMilliseconds(Descriptor.DurationMilliseconds.Value).ToString(@"m\:ss")
        : string.Empty;

    public bool HasPreview => Preview is not null;

    public ImageSource? Preview
    {
        get => _preview;
        set
        {
            if (SetProperty(ref _preview, value)) RaisePropertyChanged(nameof(HasPreview));
        }
    }

    public bool Loading
    {
        get => _loading;
        set => SetProperty(ref _loading, value);
    }

    public double Progress
    {
        get => _progress;
        set => SetProperty(ref _progress, value);
    }

    private static string FormatBytes(long size)
    {
        string[] units = ["Б", "КБ", "МБ", "ГБ"];
        double value = size;
        int index = 0;
        while (value >= 1024 && index < units.Length - 1)
        {
            value /= 1024;
            index++;
        }

        return $"{value:0.#} {units[index]}";
    }
}
