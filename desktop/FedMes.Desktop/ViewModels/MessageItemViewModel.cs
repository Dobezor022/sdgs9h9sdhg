using System.Collections.ObjectModel;
using System.Windows;
using FedMes.Desktop.Core.Messaging;

namespace FedMes.Desktop.ViewModels;

public sealed class MessageItemViewModel : ObservableObject
{
    private DecryptedMessage _model;
    private string _replyPreview = string.Empty;
    private bool _isHighlighted;
    private bool _isSpoilerRevealed;
    private string _roundVideoPath = string.Empty;
    private bool _roundVideoLoading;
    private bool _isSelected;

    public MessageItemViewModel(DecryptedMessage model, string currentUsername)
    {
        _model = model;
        CurrentUsername = currentUsername;
        Media = new ObservableCollection<MediaTileViewModel>(
            model.Content.EffectiveMediaItems.Select((item, index) => new MediaTileViewModel(item, index)));
    }

    public DecryptedMessage Model => _model;
    public string CurrentUsername { get; }
    public bool IsMine => string.Equals(_model.SenderUsername, CurrentUsername, StringComparison.Ordinal);
    public HorizontalAlignment Alignment => IsMine ? HorizontalAlignment.Right : HorizontalAlignment.Left;
    public string SenderName => IsMine ? "Вы" : FamilyPresentation.DisplayName(_model.SenderUsername, CurrentUsername);
    public string Text => _model.Content.Text;
    public IReadOnlyList<TextEntity> TextEntities => _model.Content.EffectiveTextEntities;
    public bool HasText => !string.IsNullOrWhiteSpace(Text);
    public bool IsText => _model.Content.Kind == MessageKind.Text;
    public bool IsFile => _model.Content.Kind == MessageKind.File;
    public bool IsPhoto => _model.Content.Kind == MessageKind.Photo;
    public bool IsVideo => _model.Content.Kind == MessageKind.Video;
    public bool IsMediaGroup => _model.Content.Kind == MessageKind.MediaGroup;
    public bool IsAudio => _model.Content.Kind is MessageKind.Audio or MessageKind.Voice;
    public bool IsVoice => _model.Content.Kind == MessageKind.Voice;
    public bool IsRoundVideo => _model.Content.Kind == MessageKind.RoundVideo;
    public bool IsMedia => _model.Content.EffectiveMediaItems.Count > 0;
    public bool IsStandardMedia => IsMedia && !IsRoundVideo && !IsAudio;
    public bool IsPlainMedia => IsStandardMedia && !HasText && !HasReply && !IsForwarded;
    public bool IsSystem => _model.Content.Kind == MessageKind.System;
    public bool HasReply => !string.IsNullOrWhiteSpace(_model.Content.ReplyToId);
    public string ReplyToId => _model.Content.ReplyToId ?? string.Empty;
    public string ForwardedFrom => _model.Content.ForwardedFromUsername ?? string.Empty;
    public string ForwardedFromDisplay => string.IsNullOrWhiteSpace(ForwardedFrom) ? string.Empty : FamilyPresentation.DisplayName(ForwardedFrom, CurrentUsername);
    public bool IsForwarded => !string.IsNullOrWhiteSpace(ForwardedFrom);
    public bool IsEdited => _model.EditedAt is not null;
    public string TimeText => _model.CreatedAt.LocalDateTime.ToString("HH:mm");
    public string DeliveryText => IsMine ? _model.DeliveryState switch
    {
        MessageDeliveryState.Pending => string.Empty,
        MessageDeliveryState.Read => "✓✓",
        _ => "✓",
    } : string.Empty;
    public bool IsPending => IsMine && _model.DeliveryState == MessageDeliveryState.Pending;
    public bool IsRead => IsMine && _model.DeliveryState == MessageDeliveryState.Read;
    public string KindLabel => _model.Content.Kind switch
    {
        MessageKind.Photo => "Фото",
        MessageKind.Video => "Видео",
        MessageKind.MediaGroup => "Альбом",
        MessageKind.Audio => "Аудио",
        MessageKind.Voice => "Голосовое сообщение",
        MessageKind.RoundVideo => "Видеосообщение",
        MessageKind.File => "Файл",
        MessageKind.System => "Зашифрованное сообщение",
        _ => string.Empty,
    };
    public bool IsSpoiler => _model.Content.Spoiler;
    public bool IsOwnSpoiler => IsSpoiler && IsMine;
    public bool ShouldHideSpoiler => IsSpoiler && !IsMine && !_isSpoilerRevealed;
    public bool ShouldHideTextSpoiler => IsText && ShouldHideSpoiler;
    public bool ShowText => HasText && !ShouldHideTextSpoiler;
    public bool ShowStandardMedia => IsStandardMedia && !ShouldHideSpoiler;
    public bool ShowAudio => IsAudio && !ShouldHideSpoiler;
    public bool ShowRoundVideo => IsRoundVideo && !ShouldHideSpoiler;
    public string WaveformText => BuildWaveformText(_model.Content.EffectiveWaveform);
    public string DurationText => _model.Content.DurationMilliseconds is > 0
        ? TimeSpan.FromMilliseconds(_model.Content.DurationMilliseconds.Value).ToString(@"m\:ss")
        : Media.FirstOrDefault()?.DurationText ?? string.Empty;
    public RoundVideoShape RoundShape => _model.Content.RoundVideoShape ?? RoundVideoShape.Circle;
    public ObservableCollection<MediaTileViewModel> Media { get; }

    public bool IsSelected
    {
        get => _isSelected;
        set => SetProperty(ref _isSelected, value);
    }


    public string RoundVideoPath
    {
        get => _roundVideoPath;
        set => SetProperty(ref _roundVideoPath, value);
    }

    public bool RoundVideoLoading
    {
        get => _roundVideoLoading;
        set => SetProperty(ref _roundVideoLoading, value);
    }

    public string ReplyPreview
    {
        get => _replyPreview;
        set => SetProperty(ref _replyPreview, value);
    }

    public bool IsHighlighted
    {
        get => _isHighlighted;
        set => SetProperty(ref _isHighlighted, value);
    }

    public bool IsSpoilerRevealed
    {
        get => _isSpoilerRevealed;
        set
        {
            if (SetProperty(ref _isSpoilerRevealed, value))
            {
                RaisePropertyChanged(nameof(ShouldHideSpoiler));
                RaisePropertyChanged(nameof(ShouldHideTextSpoiler));
                RaisePropertyChanged(nameof(ShowText));
                RaisePropertyChanged(nameof(ShowStandardMedia));
                RaisePropertyChanged(nameof(ShowAudio));
                RaisePropertyChanged(nameof(ShowRoundVideo));
            }
        }
    }

    public void Update(DecryptedMessage model)
    {
        _model = model;
        Media.Clear();
        int index = 0;
        foreach (MediaDescriptor item in model.Content.EffectiveMediaItems)
        {
            Media.Add(new MediaTileViewModel(item, index++));
        }

        RaisePropertyChanged(string.Empty);
    }

    private static string BuildWaveformText(IReadOnlyList<int> waveform)
    {
        if (waveform.Count == 0) return "▂▃▄▅▄▃▆▅▄▃▂";
        const string levels = "▁▂▃▄▅▆▇█";
        var builder = new System.Text.StringBuilder(waveform.Count);
        foreach (int value in waveform)
        {
            int index = Math.Clamp(value, 0, 100) * (levels.Length - 1) / 100;
            builder.Append(levels[index]);
        }

        return builder.ToString();
    }

    public string Summary() => _model.Content.Kind switch
    {
        MessageKind.Text => Text.Length > 80 ? Text[..80] + "…" : Text,
        MessageKind.RoundVideo => "◉ Видеосообщение",
        MessageKind.Voice => "🎤 Голосовое сообщение",
        MessageKind.Photo => "🖼 Фото",
        MessageKind.Video => "▶ Видео",
        MessageKind.Audio => "♫ Аудио",
        MessageKind.File => $"📎 {_model.Content.Media?.Name ?? "Файл"}",
        MessageKind.MediaGroup => $"Альбом · {_model.Content.EffectiveMediaItems.Count}",
        _ => KindLabel,
    };
}
