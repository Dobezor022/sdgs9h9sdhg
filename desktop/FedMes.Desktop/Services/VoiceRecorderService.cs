using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using FedMes.Desktop.Core.Messaging;
using NAudio.Wave;

namespace FedMes.Desktop.Services;

public sealed class VoiceRecorderService : IDisposable
{
    private readonly object _gate = new();
    private WaveInEvent? _input;
    private WaveFileWriter? _writer;
    private string? _path;
    private Stopwatch? _stopwatch;
    private readonly List<int> _levels = [];
    private TaskCompletionSource<bool>? _stopped;
    private bool _disposed;

    public bool IsRecording { get; private set; }

    public void Start()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        lock (_gate)
        {
            if (IsRecording) throw new InvalidOperationException("Запись уже выполняется.");
            _path = Path.Combine(Path.GetTempPath(), $"fedmes-voice-{Guid.NewGuid():N}.wav");
            _input = new WaveInEvent
            {
                WaveFormat = new WaveFormat(16_000, 16, 1),
                BufferMilliseconds = 50,
                NumberOfBuffers = 3,
            };
            _writer = new WaveFileWriter(_path, _input.WaveFormat);
            _levels.Clear();
            _stopped = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            _input.DataAvailable += Input_DataAvailable;
            _input.RecordingStopped += Input_RecordingStopped;
            _stopwatch = Stopwatch.StartNew();
            _input.StartRecording();
            IsRecording = true;
        }
    }

    public async Task<PreparedDesktopAttachment?> StopAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        Task stoppedTask;
        lock (_gate)
        {
            if (!IsRecording || _input is null || _stopped is null) return null;
            _input.StopRecording();
            stoppedTask = _stopped.Task;
        }

        await stoppedTask.WaitAsync(cancellationToken).ConfigureAwait(false);
        string? path;
        long duration;
        int[] waveform;
        lock (_gate)
        {
            path = _path;
            duration = _stopwatch?.ElapsedMilliseconds ?? 0;
            waveform = NormalizeLevels(_levels);
            CleanupCaptureObjects();
        }

        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path) || duration < 1_000)
        {
            TryDelete(path);
            return null;
        }

        byte[] bytes = await File.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false);
        TryDelete(path);
        return new PreparedDesktopAttachment(
            $"voice-{DateTimeOffset.Now:yyyyMMdd-HHmmss}.wav",
            "audio/wav",
            bytes,
            null,
            null,
            null,
            duration,
            waveform,
            false,
            false);
    }

    public void Cancel()
    {
        lock (_gate)
        {
            if (_input is not null && IsRecording)
            {
                _input.StopRecording();
            }

            string? path = _path;
            CleanupCaptureObjects();
            TryDelete(path);
        }
    }

    private void Input_DataAvailable(object? sender, WaveInEventArgs e)
    {
        lock (_gate)
        {
            _writer?.Write(e.Buffer, 0, e.BytesRecorded);
            int peak = 0;
            for (int offset = 0; offset + 1 < e.BytesRecorded; offset += 2)
            {
                short sample = BitConverter.ToInt16(e.Buffer, offset);
                peak = Math.Max(peak, Math.Abs((int)sample));
            }

            _levels.Add(Math.Clamp(peak * 100 / short.MaxValue, 3, 100));
        }
    }

    private void Input_RecordingStopped(object? sender, StoppedEventArgs e)
    {
        lock (_gate)
        {
            _writer?.Flush();
            IsRecording = false;
            if (e.Exception is null) _stopped?.TrySetResult(true);
            else _stopped?.TrySetException(e.Exception);
        }
    }

    private void CleanupCaptureObjects()
    {
        IsRecording = false;
        _stopwatch?.Stop();
        if (_input is not null)
        {
            _input.DataAvailable -= Input_DataAvailable;
            _input.RecordingStopped -= Input_RecordingStopped;
            _input.Dispose();
            _input = null;
        }

        _writer?.Dispose();
        _writer = null;
        _stopwatch = null;
        _stopped = null;
        _path = null;
    }

    private static int[] NormalizeLevels(List<int> levels)
    {
        if (levels.Count == 0) return [];
        const int bars = 56;
        var result = new int[bars];
        for (int index = 0; index < bars; index++)
        {
            int source = Math.Min(levels.Count - 1, index * levels.Count / bars);
            result[index] = levels[source];
        }

        return result;
    }

    private static void TryDelete(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return;
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        Cancel();
        _disposed = true;
        GC.SuppressFinalize(this);
    }
}
