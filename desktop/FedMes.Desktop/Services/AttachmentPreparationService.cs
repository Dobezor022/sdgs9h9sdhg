using System.IO;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Windows.Media.Imaging;
using FedMes.Desktop.Core.Messaging;
using NAudio.Wave;

namespace FedMes.Desktop.Services;

public static class AttachmentPreparationService
{
    public static async Task<PreparedDesktopAttachment[]> PrepareAsync(
        string[] paths,
        bool sendAsFile,
        bool spoiler,
        IProgress<double>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(paths);
        var result = new List<PreparedDesktopAttachment>(paths.Length);
        for (int index = 0; index < paths.Length; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string path = paths[index];
            var info = new FileInfo(path);
            if (!info.Exists) throw new FileNotFoundException("Файл не найден.", path);
            if (info.Length <= 0) throw new InvalidDataException($"Файл {info.Name} пустой.");
            byte[] bytes = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
            try
            {
                string mime = MimeTypes.FromPath(path);
                byte[]? preview = null;
                int? width = null;
                int? height = null;
                long? duration = null;
                int[] waveform = [];
                if (!sendAsFile && mime.StartsWith("image/", StringComparison.OrdinalIgnoreCase))
                {
                    (preview, width, height) = CreateImagePreview(bytes);
                }
                else if (mime.StartsWith("audio/", StringComparison.OrdinalIgnoreCase))
                {
                    duration = TryReadAudioDuration(path);
                    waveform = ApproximateWaveform(bytes);
                }

                result.Add(new PreparedDesktopAttachment(
                    info.Name,
                    mime,
                    bytes,
                    preview,
                    width,
                    height,
                    duration,
                    waveform,
                    sendAsFile,
                    spoiler));
                bytes = [];
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }

            progress?.Report((double)(index + 1) / paths.Length);
        }

        return result.ToArray();
    }

    private static (byte[] Preview, int Width, int Height) CreateImagePreview(byte[] bytes)
    {
        using var input = new MemoryStream(bytes, writable: false);
        BitmapDecoder decoder = BitmapDecoder.Create(
            input,
            BitmapCreateOptions.PreservePixelFormat,
            BitmapCacheOption.OnLoad);
        BitmapFrame frame = decoder.Frames[0];
        int width = frame.PixelWidth;
        int height = frame.PixelHeight;
        double scale = Math.Min(1, 720d / Math.Max(width, height));
        BitmapSource source = frame;
        if (scale < 1)
        {
            source = new TransformedBitmap(frame, new System.Windows.Media.ScaleTransform(scale, scale));
        }

        var encoder = new JpegBitmapEncoder { QualityLevel = 78 };
        encoder.Frames.Add(BitmapFrame.Create(source));
        using var output = new MemoryStream();
        encoder.Save(output);
        return (output.ToArray(), width, height);
    }

    private static long? TryReadAudioDuration(string path)
    {
        try
        {
            using var reader = new AudioFileReader(path);
            return (long)reader.TotalTime.TotalMilliseconds;
        }
        catch (Exception error) when (error is InvalidOperationException or NotSupportedException or COMException)
        {
            return null;
        }
    }

    private static int[] ApproximateWaveform(ReadOnlySpan<byte> bytes, int bars = 56)
    {
        if (bytes.Length == 0) return [];
        int step = Math.Max(1, bytes.Length / bars);
        var result = new int[bars];
        for (int index = 0; index < bars; index++)
        {
            int from = Math.Min(index * step, bytes.Length - 1);
            int to = Math.Min((index + 1) * step, bytes.Length);
            long total = 0;
            int count = 0;
            for (int cursor = from; cursor < to; cursor += 8)
            {
                total += Math.Abs((sbyte)bytes[cursor]);
                count++;
            }

            result[index] = Math.Clamp((int)(total / Math.Max(1, count) * 100 / 128), 5, 100);
        }

        return result;
    }
}

internal static class MimeTypes
{
    public static string FromPath(string path) => Path.GetExtension(path).ToLowerInvariant() switch
    {
        ".jpg" or ".jpeg" => "image/jpeg",
        ".png" => "image/png",
        ".webp" => "image/webp",
        ".gif" => "image/gif",
        ".bmp" => "image/bmp",
        ".heic" or ".heif" => "image/heic",
        ".mp4" => "video/mp4",
        ".mkv" => "video/x-matroska",
        ".mov" => "video/quicktime",
        ".webm" => "video/webm",
        ".avi" => "video/x-msvideo",
        ".mp3" => "audio/mpeg",
        ".m4a" or ".aac" => "audio/mp4",
        ".wav" => "audio/wav",
        ".ogg" or ".oga" => "audio/ogg",
        ".opus" => "audio/opus",
        ".flac" => "audio/flac",
        ".pdf" => "application/pdf",
        ".zip" => "application/zip",
        ".json" => "application/json",
        ".txt" => "text/plain",
        _ => "application/octet-stream",
    };
}
