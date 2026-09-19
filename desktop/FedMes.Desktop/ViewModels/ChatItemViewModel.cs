using FedMes.Desktop.Core.Messaging;
using System.Windows.Media;

namespace FedMes.Desktop.ViewModels;

public sealed class ChatItemViewModel : ObservableObject
{
    private ChatSummary _model;
    private readonly string _currentUsername;
    private string _lastMessage = "Нет сообщений";
    private string _presence = string.Empty;

    public ChatItemViewModel(ChatSummary model, string currentUsername)
    {
        _model = model;
        _currentUsername = currentUsername;
    }

    public ChatSummary Model => _model;
    public string Id => _model.Id;
    public string Title => _model.Kind switch
    {
        "favorites" => "Избранное",
        "family" => "Семья",
        _ => FamilyPresentation.DisplayName(PeerUsername ?? _model.Title, _currentUsername),
    };
    public string AvatarText
    {
        get
        {
            string owner = _model.Kind switch
            {
                "favorites" => "Избранное",
                "family" => "Семья",
                _ => FamilyPresentation.DisplayName(PeerUsername ?? Title, _currentUsername),
            };
            return string.IsNullOrWhiteSpace(owner) ? "?" : owner[..1].ToUpperInvariant();
        }
    }
    public Brush AvatarBrush => AvatarPalette.ForChat(_model, _currentUsername);
    public int UnreadCount => _model.UnreadCount;
    public bool HasUnread => UnreadCount > 0;
    public string UnreadCountText => UnreadCount > 99 ? "99+" : UnreadCount.ToString(System.Globalization.CultureInfo.InvariantCulture);
    public string TimeText => _model.LastMessageAt?.LocalDateTime.ToString("HH:mm") ?? string.Empty;
    public string PinnedMessageId => _model.PinnedMessageId ?? string.Empty;
    public string Kind => _model.Kind;
    public bool IsFavorites => string.Equals(_model.Kind, "favorites", StringComparison.Ordinal);
    public bool IsBlueTitle => IsFavorites;

    private string? PeerUsername => _model.Members.FirstOrDefault(member =>
        !string.Equals(member, _currentUsername, StringComparison.Ordinal));

    public string LastMessage
    {
        get => _lastMessage;
        set => SetProperty(ref _lastMessage, value);
    }

    public string Presence
    {
        get => _presence;
        set
        {
            if (SetProperty(ref _presence, value))
            {
                RaisePropertyChanged(nameof(IsOnline));
            }
        }
    }

    public bool IsOnline => string.Equals(_presence, "в сети", StringComparison.Ordinal);

    public void Update(ChatSummary model)
    {
        _model = model;
        RaisePropertyChanged(nameof(Model));
        RaisePropertyChanged(nameof(Title));
        RaisePropertyChanged(nameof(AvatarText));
        RaisePropertyChanged(nameof(AvatarBrush));
        RaisePropertyChanged(nameof(UnreadCount));
        RaisePropertyChanged(nameof(HasUnread));
        RaisePropertyChanged(nameof(UnreadCountText));
        RaisePropertyChanged(nameof(TimeText));
        RaisePropertyChanged(nameof(PinnedMessageId));
        RaisePropertyChanged(nameof(Kind));
        RaisePropertyChanged(nameof(IsFavorites));
        RaisePropertyChanged(nameof(IsBlueTitle));
    }
}
