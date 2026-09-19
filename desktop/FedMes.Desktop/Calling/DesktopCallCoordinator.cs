using System.Security.Cryptography;
using System.Windows;
using System.Windows.Media.Imaging;
using FedMes.Desktop.Core.Calling;
using FedMes.Desktop.Core.Messaging;
using FedMes.Desktop.ViewModels;
using FedMes.Desktop.FedUI3;
using NAudio.Wave;
using OpenCvSharp;

namespace FedMes.Desktop.Calling;

public enum DesktopCallPhase { None, Incoming, Outgoing, Connecting, Active, Reconnecting, Ended, Failed }

/// <summary>WPF media/device controller for the shared FSA2 call transport.</summary>
public sealed class DesktopCallCoordinator : ObservableObject, IAsyncDisposable
{
    private readonly MessagingRepository _repository;
    private readonly SemaphoreSlim _transitionGate = new(1, 1);
    private readonly CancellationTokenSource _lifetime = new();
    private DesktopCallSession? _session;
    private string _chatId = string.Empty;
    private string _peerTitle = string.Empty;
    private CallDescriptor? _descriptor;
    private DesktopCallPhase _phase;
    private string _status = string.Empty;
    private bool _muted;
    private bool _cameraEnabled;
    private bool _speakerEnabled = true;
    private BitmapImage? _remoteVideo;
    private BitmapImage? _localVideo;
    private WaveInEvent? _capture;
    private WaveOutEvent? _playback;
    private BufferedWaveProvider? _playbackBuffer;
    private CancellationTokenSource? _cameraCancellation;
    private Task? _cameraTask;
    private long _startedAtTicks;

    public DesktopCallCoordinator(MessagingRepository repository) => _repository = repository;

    public bool IsVisible => Phase != DesktopCallPhase.None;
    public bool IsIncoming => Phase == DesktopCallPhase.Incoming;
    public bool IsConnected => Phase is DesktopCallPhase.Active or DesktopCallPhase.Reconnecting;
    public string PeerTitle { get => _peerTitle; private set => SetProperty(ref _peerTitle, value); }
    public string Status { get => _status; private set => SetProperty(ref _status, value); }
    public string DurationText => _startedAtTicks == 0 ? string.Empty : (DateTimeOffset.UtcNow - new DateTimeOffset(_startedAtTicks, TimeSpan.Zero)).ToString(@"hh\:mm\:ss");
    public bool Muted { get => _muted; private set => SetProperty(ref _muted, value); }
    public bool CameraEnabled { get => _cameraEnabled; private set => SetProperty(ref _cameraEnabled, value); }
    public bool SpeakerEnabled { get => _speakerEnabled; private set => SetProperty(ref _speakerEnabled, value); }
    public BitmapImage? RemoteVideo { get => _remoteVideo; private set => SetProperty(ref _remoteVideo, value); }
    public BitmapImage? LocalVideo { get => _localVideo; private set => SetProperty(ref _localVideo, value); }
    public bool HasRemoteVideo => RemoteVideo is not null;
    public bool HasLocalVideo => LocalVideo is not null && CameraEnabled;
    public bool IsVideoCall => _descriptor?.Mode is CallMode.Video or CallMode.Group;
    public FedMes26CallMode FedUiMode => _descriptor?.Mode switch
    {
        CallMode.Video => FedMes26CallMode.Video,
        CallMode.Group => FedMes26CallMode.Group,
        _ => FedMes26CallMode.Audio,
    };

    public DesktopCallPhase Phase
    {
        get => _phase;
        private set
        {
            if (!SetProperty(ref _phase, value)) return;
            RaisePropertyChanged(nameof(IsVisible));
            RaisePropertyChanged(nameof(IsIncoming));
            RaisePropertyChanged(nameof(IsConnected));
        }
    }

    public async Task StartOutgoingAsync(ChatItemViewModel chat, bool video, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(chat);
        await _transitionGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (IsVisible) return;
            _chatId = chat.Id;
            PeerTitle = chat.Title;
            CallMode mode = string.Equals(chat.Model.Kind, "group", StringComparison.OrdinalIgnoreCase)
                ? CallMode.Group
                : video ? CallMode.Video : CallMode.Audio;
            Phase = DesktopCallPhase.Outgoing;
            Status = video ? "Видеовызов…" : "Вызов…";
            CameraEnabled = video || mode == CallMode.Group;
            try
            {
                _session = await _repository.StartOutgoingCallAsync(chat.Id, mode, ct).ConfigureAwait(false);
                _descriptor = _session.Descriptor;
                RaisePropertyChanged(nameof(IsVideoCall));
                RaisePropertyChanged(nameof(FedUiMode));
                AttachTransport(_session.Transport);
                await StartAudioAsync(ct).ConfigureAwait(false);
                if (CameraEnabled) StartCamera();
            }
            catch (Exception error)
            {
                Phase = DesktopCallPhase.Failed;
                Status = "Не удалось начать звонок: " + error.Message;
                throw;
            }
        }
        finally { _transitionGate.Release(); }
    }

    public void ObserveMessages(string chatId, string peerTitle, string currentUsername, IReadOnlyList<DecryptedMessage> messages)
    {
        var signals = messages
            .Where(message => message.Content.Kind == MessageKind.Call && message.Content.Call is not null)
            .Select(message => (Message: message, Call: message.Content.Call!))
            .GroupBy(value => value.Call.CallId, StringComparer.Ordinal)
            .Select(group => group.MaxBy(value => value.Message.Sequence))
            .Where(value => value.Message is not null)
            .ToArray();
        if (signals.Length == 0) return;

        CallDescriptor? active = _descriptor;
        if (active is not null)
        {
            var terminal = signals.FirstOrDefault(value => string.Equals(value.Call.CallId, active.CallId, StringComparison.Ordinal));
            if (terminal.Message is not null && terminal.Call.Event is CallEvent.Ended or CallEvent.Declined or CallEvent.NoAnswer or CallEvent.Failed)
            {
                _ = Application.Current.Dispatcher.InvokeAsync(async () =>
                {
                    Status = terminal.Call.Event switch
                    {
                        CallEvent.Declined => "Вызов отклонён",
                        CallEvent.NoAnswer => "Нет ответа",
                        CallEvent.Failed => "Ошибка звонка",
                        _ => "Звонок завершён",
                    };
                    Phase = terminal.Call.Event == CallEvent.Failed ? DesktopCallPhase.Failed : DesktopCallPhase.Ended;
                    await StopMediaAsync(sendLeave: false, CancellationToken.None).ConfigureAwait(true);
                    await Task.Delay(500).ConfigureAwait(true);
                    ResetState();
                });
            }
            return;
        }

        var incoming = signals
            .Where(value => value.Call.Event == CallEvent.Invite &&
                            !string.Equals(value.Call.InitiatorUsername, currentUsername, StringComparison.Ordinal) &&
                            !string.Equals(value.Message.SenderUsername, currentUsername, StringComparison.Ordinal) &&
                            value.Call.ExpiresAt > DateTimeOffset.UtcNow)
            .MaxBy(value => value.Message.Sequence);
        if (incoming.Message is null || IsVisible) return;

        _chatId = chatId;
        _descriptor = incoming.Call;
        RaisePropertyChanged(nameof(IsVideoCall));
        RaisePropertyChanged(nameof(FedUiMode));
        PeerTitle = peerTitle;
        CameraEnabled = false;
        Status = incoming.Call.Mode == CallMode.Audio ? "Входящий аудиозвонок" : "Входящий видеозвонок";
        Phase = DesktopCallPhase.Incoming;
        RaisePropertyChanged(nameof(IsVideoCall));
    }

    public async Task AcceptAsync(CancellationToken ct)
    {
        CallDescriptor descriptor = _descriptor ?? throw new InvalidOperationException("Нет входящего звонка.");
        if (Phase != DesktopCallPhase.Incoming) return;
        await _transitionGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            Phase = DesktopCallPhase.Connecting;
            Status = "Соединение…";
            _session = await _repository.AcceptIncomingCallAsync(descriptor, ct).ConfigureAwait(false);
            AttachTransport(_session.Transport);
            await StartAudioAsync(ct).ConfigureAwait(false);
            CameraEnabled = descriptor.Mode is CallMode.Video or CallMode.Group;
            if (CameraEnabled) StartCamera();
            MarkActive();
        }
        catch (Exception error)
        {
            Phase = DesktopCallPhase.Failed;
            Status = "Ошибка соединения: " + error.Message;
            throw;
        }
        finally { _transitionGate.Release(); }
    }

    public async Task DeclineAsync(CancellationToken ct)
    {
        CallDescriptor? descriptor = _descriptor;
        if (descriptor is null || Phase != DesktopCallPhase.Incoming) return;
        await _repository.SendCallSignalAsync(_chatId, descriptor with { Event = CallEvent.Declined }, ct).ConfigureAwait(false);
        ResetState();
    }

    public async Task EndAsync(CancellationToken ct)
    {
        CallDescriptor? descriptor = _descriptor;
        if (descriptor is not null && _chatId.Length > 0)
        {
            try { await _repository.SendCallSignalAsync(_chatId, descriptor with { Event = CallEvent.Ended }, ct).ConfigureAwait(false); }
            catch { }
        }
        await StopMediaAsync(sendLeave: true, ct).ConfigureAwait(false);
        await Application.Current.Dispatcher.InvokeAsync(() =>
        {
            Phase = DesktopCallPhase.Ended;
            Status = "Звонок завершён";
        });
        await Task.Delay(300, ct).ConfigureAwait(false);
        await Application.Current.Dispatcher.InvokeAsync(ResetState);
    }

    public void ToggleMute() => Muted = !Muted;
    public void ToggleSpeaker() => SpeakerEnabled = !SpeakerEnabled;
    public void ToggleCamera()
    {
        CameraEnabled = !CameraEnabled;
        if (CameraEnabled) StartCamera(); else StopCamera();
    }

    private void AttachTransport(FedMesRealtimeCallTransport transport)
    {
        transport.PeerJoined += (_, _) => Application.Current.Dispatcher.BeginInvoke(MarkActive);
        transport.PeerLeft += (_, _) => Application.Current.Dispatcher.BeginInvoke(async () =>
        {
            Status = "Звонок завершён";
            Phase = DesktopCallPhase.Ended;
            await StopMediaAsync(sendLeave: false, CancellationToken.None).ConfigureAwait(true);
            await Task.Delay(400).ConfigureAwait(true);
            ResetState();
        });
        transport.TransportFaulted += error => Application.Current.Dispatcher.BeginInvoke(() =>
        {
            if (Phase == DesktopCallPhase.Active) Phase = DesktopCallPhase.Reconnecting;
            Status = "Восстановление соединения…";
        });
        transport.AudioFrameReceived += pcm =>
        {
            byte[] copy = pcm.ToArray();
            try { _playbackBuffer?.AddSamples(copy, 0, copy.Length); }
            finally { CryptographicOperations.ZeroMemory(copy); }
        };
        transport.VideoFrameReceived += jpeg =>
        {
            byte[] copy = jpeg.ToArray();
            Application.Current.Dispatcher.BeginInvoke(() =>
            {
                try
                {
                    RemoteVideo = DecodeBitmap(copy);
                    RaisePropertyChanged(nameof(HasRemoteVideo));
                }
                finally { CryptographicOperations.ZeroMemory(copy); }
            });
        };
    }

    private async Task StartAudioAsync(CancellationToken ct)
    {
        await Application.Current.Dispatcher.InvokeAsync(() =>
        {
            _playbackBuffer = new BufferedWaveProvider(new WaveFormat(16_000, 16, 1))
            {
                DiscardOnBufferOverflow = true,
                BufferDuration = TimeSpan.FromSeconds(2),
            };
            _playback = new WaveOutEvent { DesiredLatency = 80, NumberOfBuffers = 3 };
            _playback.Init(_playbackBuffer);
            _playback.Play();

            _capture = new WaveInEvent
            {
                WaveFormat = new WaveFormat(16_000, 16, 1),
                BufferMilliseconds = 20,
                NumberOfBuffers = 4,
            };
            _capture.DataAvailable += Capture_DataAvailable;
            _capture.StartRecording();
        });
        await Task.CompletedTask;
    }

    private void Capture_DataAvailable(object? sender, WaveInEventArgs e)
    {
        DesktopCallSession? current = _session;
        if (current is null || Muted || e.BytesRecorded <= 0) return;
        byte[] copy = e.Buffer.AsSpan(0, e.BytesRecorded).ToArray();
        _ = Task.Run(async () =>
        {
            try { await current.Transport.SendAudioAsync(copy, _lifetime.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) { }
            catch { }
            finally { CryptographicOperations.ZeroMemory(copy); }
        });
    }

    private void StartCamera()
    {
        if (_cameraTask is { IsCompleted: false }) return;
        _cameraCancellation = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);
        CancellationToken token = _cameraCancellation.Token;
        _cameraTask = Task.Run(async () =>
        {
            using var capture = new VideoCapture(0, VideoCaptureAPIs.DSHOW);
            capture.Set(VideoCaptureProperties.FrameWidth, 640);
            capture.Set(VideoCaptureProperties.FrameHeight, 480);
            capture.Set(VideoCaptureProperties.Fps, 5);
            using var frame = new Mat();
            var jpegQuality = new ImageEncodingParam(ImwriteFlags.JpegQuality, 45);
            while (!token.IsCancellationRequested && CameraEnabled)
            {
                if (!capture.IsOpened() || !capture.Read(frame) || frame.Empty())
                {
                    await Task.Delay(250, token).ConfigureAwait(false);
                    continue;
                }
                if (!Cv2.ImEncode(".jpg", frame, out byte[] jpeg, jpegQuality)) continue;
                try
                {
                    if (jpeg.Length <= FedMesRealtimeCallTransport.MaxVideoJpegBytes)
                    {
                        byte[] preview = jpeg.ToArray();
                        Application.Current.Dispatcher.BeginInvoke(() =>
                        {
                            try
                            {
                                LocalVideo = DecodeBitmap(preview);
                                RaisePropertyChanged(nameof(HasLocalVideo));
                            }
                            finally { CryptographicOperations.ZeroMemory(preview); }
                        });
                        DesktopCallSession? current = _session;
                        if (current is not null) await current.Transport.SendVideoJpegAsync(jpeg, token).ConfigureAwait(false);
                    }
                }
                finally { CryptographicOperations.ZeroMemory(jpeg); }
                await Task.Delay(170, token).ConfigureAwait(false);
            }
        }, token);
    }

    private void StopCamera()
    {
        _cameraCancellation?.Cancel();
        _cameraCancellation?.Dispose();
        _cameraCancellation = null;
        _cameraTask = null;
        LocalVideo = null;
        RaisePropertyChanged(nameof(HasLocalVideo));
    }

    private async Task StopMediaAsync(bool sendLeave, CancellationToken ct)
    {
        DesktopCallSession? current = _session;
        _session = null;
        if (sendLeave && current is not null)
        {
            try { await current.Transport.SendLeaveAsync(ct).ConfigureAwait(false); } catch { }
        }
        StopCamera();
        await Application.Current.Dispatcher.InvokeAsync(() =>
        {
            if (_capture is not null)
            {
                _capture.DataAvailable -= Capture_DataAvailable;
                try { _capture.StopRecording(); } catch { }
                _capture.Dispose();
                _capture = null;
            }
            if (_playback is not null)
            {
                try { _playback.Stop(); } catch { }
                _playback.Dispose();
                _playback = null;
            }
            _playbackBuffer = null;
            RemoteVideo = null;
            RaisePropertyChanged(nameof(HasRemoteVideo));
        });
        if (current is not null) await current.Transport.DisposeAsync().ConfigureAwait(false);
    }

    private void MarkActive()
    {
        _startedAtTicks = DateTimeOffset.UtcNow.Ticks;
        Phase = DesktopCallPhase.Active;
        Status = "Защищённый звонок";
        RaisePropertyChanged(nameof(DurationText));
    }

    private void ResetState()
    {
        _descriptor = null;
        _chatId = string.Empty;
        _startedAtTicks = 0;
        PeerTitle = string.Empty;
        Status = string.Empty;
        Muted = false;
        CameraEnabled = false;
        RemoteVideo = null;
        LocalVideo = null;
        Phase = DesktopCallPhase.None;
        RaisePropertyChanged(nameof(HasRemoteVideo));
        RaisePropertyChanged(nameof(HasLocalVideo));
        RaisePropertyChanged(nameof(IsVideoCall));
        RaisePropertyChanged(nameof(FedUiMode));
    }

    private static BitmapImage DecodeBitmap(byte[] jpeg)
    {
        using var stream = new MemoryStream(jpeg, writable: false);
        var bitmap = new BitmapImage();
        bitmap.BeginInit();
        bitmap.CacheOption = BitmapCacheOption.OnLoad;
        bitmap.StreamSource = stream;
        bitmap.EndInit();
        bitmap.Freeze();
        return bitmap;
    }

    public void Abort()
    {
        if (!_lifetime.IsCancellationRequested) _lifetime.Cancel();
        StopCamera();
        if (_capture is not null)
        {
            _capture.DataAvailable -= Capture_DataAvailable;
            try { _capture.StopRecording(); } catch { }
            _capture.Dispose();
            _capture = null;
        }
        if (_playback is not null)
        {
            try { _playback.Stop(); } catch { }
            _playback.Dispose();
            _playback = null;
        }
        _playbackBuffer = null;
        DesktopCallSession? current = _session;
        _session = null;
        if (current is not null) _ = current.Transport.DisposeAsync().AsTask();
        ResetState();
    }

    public async ValueTask DisposeAsync()
    {
        _lifetime.Cancel();
        await StopMediaAsync(sendLeave: false, CancellationToken.None).ConfigureAwait(false);
        _transitionGate.Dispose();
        _lifetime.Dispose();
    }
}
