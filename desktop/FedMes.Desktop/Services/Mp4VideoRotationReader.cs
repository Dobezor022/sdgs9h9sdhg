using System.Buffers.Binary;
using System.IO;

namespace FedMes.Desktop.Services;

/// <summary>
/// Reads the display rotation stored in the MP4/MOV track header matrix.
/// WPF MediaElement does not reliably apply this metadata, while Android CameraX does.
/// </summary>
internal static class Mp4VideoRotationReader
{
    private const long MinimumBoxSize = 8;
    private const int MatrixLength = 36;

    public static int TryReadDegrees(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return 0;
        string extension = Path.GetExtension(path);
        if (!extension.Equals(".mp4", StringComparison.OrdinalIgnoreCase) &&
            !extension.Equals(".mov", StringComparison.OrdinalIgnoreCase) &&
            !extension.Equals(".m4v", StringComparison.OrdinalIgnoreCase))
        {
            return 0;
        }

        try
        {
            using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            Box? moov = FindFirstChild(stream, 0, stream.Length, "moov");
            if (moov is null) return 0;

            foreach (Box track in EnumerateChildren(stream, moov.Value.PayloadOffset, moov.Value.EndOffset, "trak"))
            {
                if (!IsVideoTrack(stream, track)) continue;
                Box? trackHeader = FindFirstChild(stream, track.PayloadOffset, track.EndOffset, "tkhd");
                if (trackHeader is null) continue;
                return ReadTrackHeaderRotation(stream, trackHeader.Value);
            }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or EndOfStreamException or InvalidDataException)
        {
            return 0;
        }

        return 0;
    }

    private static bool IsVideoTrack(FileStream stream, Box track)
    {
        Box? media = FindFirstChild(stream, track.PayloadOffset, track.EndOffset, "mdia");
        if (media is null) return false;
        Box? handler = FindFirstChild(stream, media.Value.PayloadOffset, media.Value.EndOffset, "hdlr");
        if (handler is null || handler.Value.PayloadSize < 12) return false;

        byte[] type = new byte[4];
        stream.Position = handler.Value.PayloadOffset + 8;
        ReadExactly(stream, type);
        return type[0] == (byte)'v' && type[1] == (byte)'i' && type[2] == (byte)'d' && type[3] == (byte)'e';
    }

    private static int ReadTrackHeaderRotation(FileStream stream, Box box)
    {
        if (box.PayloadSize < 4) return 0;
        stream.Position = box.PayloadOffset;
        int version = stream.ReadByte();
        if (version < 0) return 0;

        long matrixOffset = box.PayloadOffset + (version == 1 ? 52 : 40);
        if (matrixOffset + MatrixLength > box.EndOffset) return 0;

        Span<byte> matrix = stackalloc byte[MatrixLength];
        stream.Position = matrixOffset;
        ReadExactly(stream, matrix);

        int a = BinaryPrimitives.ReadInt32BigEndian(matrix[0..4]);
        int b = BinaryPrimitives.ReadInt32BigEndian(matrix[4..8]);
        int c = BinaryPrimitives.ReadInt32BigEndian(matrix[12..16]);
        int d = BinaryPrimitives.ReadInt32BigEndian(matrix[16..20]);

        const int one = 1 << 16;
        const int tolerance = 1 << 10;
        if (Near(a, 0, tolerance) && Near(b, one, tolerance) && Near(c, -one, tolerance) && Near(d, 0, tolerance)) return 90;
        if (Near(a, -one, tolerance) && Near(b, 0, tolerance) && Near(c, 0, tolerance) && Near(d, -one, tolerance)) return 180;
        if (Near(a, 0, tolerance) && Near(b, -one, tolerance) && Near(c, one, tolerance) && Near(d, 0, tolerance)) return 270;
        return 0;
    }

    private static bool Near(int value, int expected, int tolerance) => Math.Abs((long)value - expected) <= tolerance;

    private static Box? FindFirstChild(FileStream stream, long start, long end, string expectedType)
    {
        foreach (Box child in EnumerateChildren(stream, start, end, expectedType)) return child;
        return null;
    }

    private static IEnumerable<Box> EnumerateChildren(FileStream stream, long start, long end, string? expectedType = null)
    {
        long cursor = start;
        byte[] header = new byte[16];
        while (cursor + MinimumBoxSize <= end)
        {
            stream.Position = cursor;
            ReadExactly(stream, header.AsSpan(0, 8));
            uint smallSize = BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(0, 4));
            string type = System.Text.Encoding.ASCII.GetString(header, 4, 4);
            long headerSize = 8;
            long size;
            if (smallSize == 1)
            {
                if (cursor + 16 > end) yield break;
                ReadExactly(stream, header.AsSpan(8, 8));
                ulong largeSize = BinaryPrimitives.ReadUInt64BigEndian(header.AsSpan(8, 8));
                if (largeSize > long.MaxValue) yield break;
                size = (long)largeSize;
                headerSize = 16;
            }
            else if (smallSize == 0)
            {
                size = end - cursor;
            }
            else
            {
                size = smallSize;
            }

            if (size < headerSize || cursor + size > end) yield break;
            var box = new Box(type, cursor + headerSize, cursor + size);
            if (expectedType is null || string.Equals(type, expectedType, StringComparison.Ordinal)) yield return box;
            cursor += size;
        }
    }

    private static void ReadExactly(Stream stream, Span<byte> buffer)
    {
        int readTotal = 0;
        while (readTotal < buffer.Length)
        {
            int read = stream.Read(buffer[readTotal..]);
            if (read == 0) throw new EndOfStreamException();
            readTotal += read;
        }
    }

    private readonly record struct Box(string Type, long PayloadOffset, long EndOffset)
    {
        public long PayloadSize => EndOffset - PayloadOffset;
    }
}
