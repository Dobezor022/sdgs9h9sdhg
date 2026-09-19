using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Media;
using FedMes.Desktop.Core.Messaging;
using FedMes.Desktop.Core.Storage;
using FedMes.Desktop.Calling;

namespace FedMes.Desktop.ViewModels;

public sealed class MainViewModel : ObservableObject
{
    private readonly MessagingRepository _repository;
    private ChatItemViewModel? _selectedChat;
    private string _currentUsername = string.Empty;
    private string _draftText = string.Empty;
    private IReadOnlyList<TextEntity> _draftTextEntities = [];
    private string _statusText = "Подключение…";
    private string _typingText = string.Empty;
    private bool _isBusy;
    private bool _hasMoreBefore;
    private MessageItemViewModel? _replyingTo;
    private MessageItemViewModel? _editingMessage;
    private double _uploadProgress;
    private bool _uploadVisible;
    private long _chatNavigationGeneration;
    private readonly Dictionary<string, long> _readCursorHighWater = new(StringComparer.Ordinal);
    // Prevent stale event refreshes from re-inserting an optimistically deleted message.
    private readonly Dictionary<string, HashSet<string>> _locallyDeletedMessageIds = new(StringComparer.Ordinal);
    // Local UI revision per chat. Network refreshes compare the captured revision with the current
    // one so a slow response cannot roll back a send/delete that happened while it was in flight.
    private readonly Dictionary<string, long> _messageMutationGeneration = new(StringComparer.Ordinal);
    // Hot in-memory message pages make revisiting chats instant. Network refresh reconciles on top.
    private readonly Dictionary<string, CachedChatPage> _messageCache = new(StringComparer.Ordinal);
    private readonly Dictionary<string, long> _callScanHighWater = new(StringComparer.Ordinal);

    public MainViewModel(MessagingRepository repository)
    {
        _repository = repository ?? throw new ArgumentNullException(nameof(repository));
        Call = new DesktopCallCoordinator(_repository);
    }

    public DesktopCallCoordinator Call { get; }

    public ObservableCollection<ChatItemViewModel> Chats { get; } = [];
    public ObservableCollection<MessageItemViewModel> Messages { get; } = [];

    public Brush CurrentUserAvatarBrush => AvatarPalette.ForUser(CurrentUsername);

    public string CurrentUserAvatarText => string.IsNullOrWhiteSpace(CurrentUsername)
        ? "F"
        : FamilyPresentation.Initial(CurrentUsername, CurrentUsername);

    public int SelectedMessageCount => Messages.Count(message => message.IsSelected);

    public bool HasSelectedMessages => SelectedMessageCount > 0;

    public string SelectedMessageCountText => $"Выбрано: {SelectedMessageCount}";

    public bool CanEditSelectedMessage => GetEditableSelectedMessage() is not null;

    public string CurrentUsername
    {
        get => _currentUsername;
        private set
        {
            if (SetProperty(ref _currentUsername, value))
            {
                RaisePropertyChanged(nameof(CurrentUserAvatarBrush));
                RaisePropertyChanged(nameof(CurrentUserAvatarText));
            }
        }
    }

    public ChatItemViewModel? SelectedChat
    {
        get => _selectedChat;
        set => SetProperty(ref _selectedChat, value);
    }

    public string DraftText
    {
        get => _draftText;
        set => SetProperty(ref _draftText, value);
    }

    public IReadOnlyList<TextEntity> DraftTextEntities
    {
        get => _draftTextEntities;
        set => SetProperty(ref _draftTextEntities, TextFormatting.Sanitize(DraftText, value));
    }

    public string StatusText
    {
        get => _statusText;
        set
        {
            if (SetProperty(ref _statusText, value))
            {
                RaisePropertyChanged(nameof(HeaderSubtitle));
                RaisePropertyChanged(nameof(ChatStatusText));
            }
        }
    }

    public bool IsOffline => StatusText.StartsWith("Нет соединения", StringComparison.Ordinal);

    public string HeaderSubtitle => IsOffline ? StatusText : string.Empty;

    public string ChatStatusText => IsOffline ? StatusText : TypingText;

    public string TypingText
    {
        get => _typingText;
        set
        {
            if (SetProperty(ref _typingText, value))
            {
                RaisePropertyChanged(nameof(ChatStatusText));
            }
        }
    }

    public bool IsBusy
    {
        get => _isBusy;
        set => SetProperty(ref _isBusy, value);
    }

    public bool HasMoreBefore
    {
        get => _hasMoreBefore;
        private set => SetProperty(ref _hasMoreBefore, value);
    }

    public MessageItemViewModel? ReplyingTo
    {
        get => _replyingTo;
        private set
        {
            if (SetProperty(ref _replyingTo, value))
            {
                RaisePropertyChanged(nameof(HasComposerContext));
                RaisePropertyChanged(nameof(ComposerContextTitle));
                RaisePropertyChanged(nameof(ComposerContextText));
            }
        }
    }

    public MessageItemViewModel? EditingMessage
    {
        get => _editingMessage;
        private set
        {
            if (SetProperty(ref _editingMessage, value))
            {
                RaisePropertyChanged(nameof(HasComposerContext));
                RaisePropertyChanged(nameof(ComposerContextTitle));
                RaisePropertyChanged(nameof(ComposerContextText));
            }
        }
    }

    public bool HasComposerContext => ReplyingTo is not null || EditingMessage is not null;
    public string ComposerContextTitle => EditingMessage is not null ? "Редактирование" : ReplyingTo is not null ? $"Ответ · {ReplyingTo.SenderName}" : string.Empty;
    public string ComposerContextText => EditingMessage?.Summary() ?? ReplyingTo?.Summary() ?? string.Empty;

    public double UploadProgress
    {
        get => _uploadProgress;
        set => SetProperty(ref _uploadProgress, value);
    }

    public bool UploadVisible
    {
        get => _uploadVisible;
        set => SetProperty(ref _uploadVisible, value);
    }

    public async Task InitializeAsync(bool showExactPresence, CancellationToken cancellationToken)
    {
        DesktopAccount account = await _repository.InitializeAsync(showExactPresence, cancellationToken);
        CurrentUsername = account.Username;
        await RefreshChatsAsync(cancellationToken);
        StatusText = "Подключено";
    }

    public async Task RefreshChatsAsync(CancellationToken cancellationToken)
    {
        IReadOnlyList<ChatSummary> models = await _repository.ListChatsAsync(cancellationToken);
        var existingById = Chats.ToDictionary(chat => chat.Id, StringComparer.Ordinal);
        var ordered = new List<ChatItemViewModel>(models.Count);
        foreach (ChatSummary model in models)
        {
            if (existingById.TryGetValue(model.Id, out ChatItemViewModel? existing))
            {
                existing.Update(model);
                ordered.Add(existing);
            }
            else
            {
                ordered.Add(new ChatItemViewModel(model, CurrentUsername));
            }
        }

        for (int index = 0; index < ordered.Count; index++)
        {
            ChatItemViewModel item = ordered[index];
            int current = Chats.IndexOf(item);
            if (current < 0) Chats.Insert(index, item);
            else if (current != index) Chats.Move(current, index);
        }

        while (Chats.Count > ordered.Count) Chats.RemoveAt(Chats.Count - 1);
        _ = ScanCallSignalsBestEffortAsync(models);
    }

    public async Task ApplyPresenceAsync(CancellationToken cancellationToken)
    {
        Dictionary<string, PresenceState> presence = (await _repository.ListPresenceAsync(cancellationToken))
            .ToDictionary(item => item.Username, StringComparer.Ordinal);
        foreach (ChatItemViewModel chat in Chats)
        {
            string? peer = chat.Model.Members.FirstOrDefault(member => !string.Equals(member, CurrentUsername, StringComparison.Ordinal));
            if (peer is null || !presence.TryGetValue(peer, out PresenceState? state))
            {
                chat.Presence = string.Empty;
                continue;
            }

            chat.Presence = state.Online ? "в сети" : FormatLastSeen(state);
        }
    }

    public async Task SelectChatAsync(ChatItemViewModel chat, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(chat);
        long navigationGeneration = ++_chatNavigationGeneration;
        SelectedChat = chat;
        ClearSelection();
        ReplyingTo = null;
        EditingMessage = null;
        DraftText = string.Empty;
        DraftTextEntities = [];

        bool renderedFromCache = _messageCache.TryGetValue(chat.Id, out CachedChatPage? cached);
        Messages.Clear();
        if (renderedFromCache && cached is not null)
        {
            foreach (DecryptedMessage message in cached.Messages
                         .Where(message => !IsLocallyDeleted(chat.Id, message.Id))
                         .OrderBy(message => message.Sequence))
            {
                Messages.Add(new MessageItemViewModel(message, CurrentUsername));
            }
            HasMoreBefore = cached.HasMoreBefore;
            ResolveReplyPreviews();
            UpdateChatPreview(chat);
            ObserveCallSignals(chat, cached.Messages);
        }

        // Device membership + sequence leases are not part of rendering. Warm them concurrently so
        // the first send normally needs only the create-message RTT.
        _ = PrewarmChatBestEffortAsync(chat.Id);
        IsBusy = !renderedFromCache;
        try
        {
            DecryptedMessagePage page = await _repository.LoadLatestMessagesAsync(chat.Id, markRead: false, cancellationToken)
                .ConfigureAwait(true);
            if (navigationGeneration != _chatNavigationGeneration || !ReferenceEquals(SelectedChat, chat)) return;

            Messages.Clear();
            foreach (DecryptedMessage message in page.Messages
                         .Where(message => !IsLocallyDeleted(chat.Id, message.Id))
                         .OrderBy(message => message.Sequence))
            {
                Messages.Add(new MessageItemViewModel(message, CurrentUsername));
            }

            HasMoreBefore = page.HasMoreBefore;
            _messageCache[chat.Id] = new CachedChatPage(page.Messages, page.HasMoreBefore);
            ResolveReplyPreviews();
            UpdateChatPreview(chat);
            ObserveCallSignals(chat, page.Messages);
        }
        finally
        {
            if (navigationGeneration == _chatNavigationGeneration) IsBusy = false;
        }
    }

    public void CloseChat()
    {
        _chatNavigationGeneration++;
        SelectedChat = null;
        Messages.Clear();
        HasMoreBefore = false;
        ReplyingTo = null;
        EditingMessage = null;
        DraftText = string.Empty;
        DraftTextEntities = [];
        TypingText = string.Empty;
        ClearSelection();
    }

    public async Task RefreshSelectedChatAsync(CancellationToken cancellationToken)
    {
        ChatItemViewModel? chat = SelectedChat;
        if (chat is null) return;
        long navigationGeneration = _chatNavigationGeneration;
        long mutationGenerationAtStart = MessageMutationGeneration(chat.Id);
        bool hadLoadedMessages = Messages.Count > 0;
        DecryptedMessagePage page = await _repository.LoadLatestMessagesAsync(chat.Id, markRead: false, cancellationToken)
            .ConfigureAwait(true);
        if (navigationGeneration != _chatNavigationGeneration || !ReferenceEquals(SelectedChat, chat)) return;

        // Only reconcile the server's latest window. Older pages already loaded by the user stay in
        // the collection and are outside SynchronizeLatestMessages' sequence range. The previous build
        // re-downloaded as many as 50 historical pages after every event, which could exhaust memory
        // and terminate WPF when a chat contained many photos or videos.
        SynchronizeLatestMessages(page.Messages.ToList(), mutationGenerationAtStart);
        if (!hadLoadedMessages) HasMoreBefore = page.HasMoreBefore;
        _messageCache[chat.Id] = new CachedChatPage(Messages.Select(item => item.Model).ToArray(), HasMoreBefore);
        ResolveReplyPreviews();
        UpdateChatPreview(chat);
        ObserveCallSignals(chat, page.Messages);
    }

    public async Task MarkVisibleMessagesReadAsync(
        IReadOnlyCollection<MessageItemViewModel> visibleMessages,
        CancellationToken cancellationToken)
    {
        ChatItemViewModel? chat = SelectedChat;
        if (chat is null || visibleMessages.Count == 0) return;
        long navigationGeneration = _chatNavigationGeneration;
        long maxSequence = visibleMessages
            .Select(item => item.Model)
            .Where(message => message.Decryptable &&
                              !string.Equals(message.SenderUsername, CurrentUsername, StringComparison.Ordinal))
            .Select(message => message.Sequence)
            .DefaultIfEmpty(0)
            .Max();
        if (maxSequence <= 0) return;
        long previous = _readCursorHighWater.GetValueOrDefault(chat.Id);
        if (maxSequence <= previous) return;
        _readCursorHighWater[chat.Id] = maxSequence;
        try
        {
            await _repository.MarkReadCursorAsync(chat.Id, maxSequence, cancellationToken).ConfigureAwait(true);
            if (navigationGeneration == _chatNavigationGeneration && ReferenceEquals(SelectedChat, chat))
            {
                await RefreshChatsAsync(cancellationToken).ConfigureAwait(true);
            }
        }
        catch
        {
            if (_readCursorHighWater.GetValueOrDefault(chat.Id) == maxSequence)
            {
                _readCursorHighWater[chat.Id] = previous;
            }
            throw;
        }
    }

    public async Task LoadOlderAsync(CancellationToken cancellationToken)
    {
        ChatItemViewModel? chat = SelectedChat;
        MessageItemViewModel? first = Messages.FirstOrDefault();
        if (chat is null || first is null || !HasMoreBefore || IsBusy) return;
        long navigationGeneration = _chatNavigationGeneration;
        IsBusy = true;
        try
        {
            DecryptedMessagePage page = await _repository
                .LoadOlderMessagesAsync(chat.Id, first.Model.Sequence, cancellationToken)
                .ConfigureAwait(true);
            if (navigationGeneration != _chatNavigationGeneration || !ReferenceEquals(SelectedChat, chat)) return;
            var existingIds = Messages.Select(item => item.Model.Id).ToHashSet(StringComparer.Ordinal);
            int index = 0;
            foreach (DecryptedMessage message in page.Messages
                         .Where(message => !IsLocallyDeleted(chat.Id, message.Id))
                         .OrderBy(message => message.Sequence))
            {
                if (existingIds.Add(message.Id))
                {
                    Messages.Insert(index++, new MessageItemViewModel(message, CurrentUsername));
                }
            }

            HasMoreBefore = page.HasMoreBefore;
            ResolveReplyPreviews();
        }
        finally
        {
            if (navigationGeneration == _chatNavigationGeneration) IsBusy = false;
        }
    }

    public async Task SendTextAsync(bool spoiler, CancellationToken cancellationToken)
    {
        ChatItemViewModel chat = SelectedChat ?? throw new InvalidOperationException("Чат не выбран.");
        string text = DraftText;
        IReadOnlyList<TextEntity> entities = DraftTextEntities;
        MessageItemViewModel? reply = ReplyingTo;
        MessageItemViewModel? editing = EditingMessage;
        MessageItemViewModel? pending = null;
        string? messageId = null;

        if (editing is null)
        {
            messageId = _repository.AllocateOutgoingMessageId(chat.Id);
            long localSequence = (Messages.LastOrDefault()?.Model.Sequence ?? 0) + 1;
            var pendingModel = new DecryptedMessage(
                localSequence,
                messageId,
                chat.Id,
                CurrentUsername,
                string.Empty,
                new MessageContent(
                    MessageKind.Text,
                    text,
                    reply?.Model.Id,
                    null,
                    [],
                    spoiler,
                    TextEntities: entities),
                DateTimeOffset.UtcNow,
                null,
                true,
                new HashSet<string>(StringComparer.Ordinal),
                MessageDeliveryState.Pending);
            pending = new MessageItemViewModel(pendingModel, CurrentUsername);
            Messages.Add(pending);
            MarkMessageMutation(chat.Id);
            DraftText = string.Empty;
            DraftTextEntities = [];
            ReplyingTo = null;
            ResolveReplyPreviews();
        }

        try
        {
            DecryptedMessage? sentMessage = null;
            if (editing is not null)
            {
                await _repository.EditTextAsync(
                    chat.Id,
                    editing.Model.Id,
                    text,
                    editing.Model.Content.ReplyToId,
                    spoiler,
                    entities,
                    cancellationToken);
            }
            else
            {
                sentMessage = await _repository.SendTextMessageAsync(
                    chat.Id,
                    text,
                    reply?.Model.Id,
                    spoiler,
                    entities,
                    cancellationToken,
                    messageId);
            }

            bool chatStillSelected = ReferenceEquals(SelectedChat, chat);
            if (chatStillSelected)
            {
                DraftText = string.Empty;
                DraftTextEntities = [];
                ReplyingTo = null;
                EditingMessage = null;
            }
            if (sentMessage is not null) MarkMessageMutation(chat.Id);
            if (sentMessage is not null && chatStillSelected)
            {
                MessageItemViewModel? existing = FindMessage(sentMessage.Id);
                if (existing is null) Messages.Add(new MessageItemViewModel(sentMessage, CurrentUsername));
                else existing.Update(sentMessage);
                ResolveReplyPreviews();
                UpdateChatPreview(chat);
            }
            else if (sentMessage is null && chatStillSelected)
            {
                await RefreshSelectedChatAsync(cancellationToken).ConfigureAwait(true);
            }
            _messageCache[chat.Id] = new CachedChatPage(Messages.Select(item => item.Model).ToArray(), HasMoreBefore);
            _ = RefreshChatsBestEffortAsync();
            _ = PrewarmChatBestEffortAsync(chat.Id);
        }
        catch
        {
            if (pending is not null)
            {
                MarkMessageMutation(chat.Id);
                if (ReferenceEquals(SelectedChat, chat)) Messages.Remove(pending);
            }
            if (editing is null && ReferenceEquals(SelectedChat, chat) && string.IsNullOrWhiteSpace(DraftText))
            {
                DraftText = text;
                DraftTextEntities = entities;
                ReplyingTo = reply;
            }
            throw;
        }
    }

    public async Task SendAttachmentsAsync(
        PreparedDesktopAttachment[] attachments,
        string caption,
        MessageKind? forcedKind,
        RoundVideoShape? roundVideoShape,
        CancellationToken cancellationToken)
    {
        ChatItemViewModel chat = SelectedChat ?? throw new InvalidOperationException("Чат не выбран.");
        UploadVisible = true;
        UploadProgress = 0;
        try
        {
            var progress = new Progress<double>(value => UploadProgress = value * 100);
            await _repository.SendAttachmentsAsync(
                chat.Id,
                attachments,
                caption,
                ReplyingTo?.Model.Id,
                DraftTextEntities,
                forcedKind,
                roundVideoShape,
                null,
                progress,
                cancellationToken);
            ReplyingTo = null;
            DraftText = string.Empty;
            DraftTextEntities = [];
            await RefreshSelectedChatAsync(cancellationToken);
            await RefreshChatsAsync(cancellationToken);
        }
        finally
        {
            UploadVisible = false;
            UploadProgress = 0;
        }
    }

    public void BeginReply(MessageItemViewModel message)
    {
        EditingMessage = null;
        ReplyingTo = message;
    }

    public void BeginEdit(MessageItemViewModel message)
    {
        if (!message.IsMine || !message.IsText || message.IsForwarded) return;
        ReplyingTo = null;
        EditingMessage = message;
        DraftText = message.Text;
        DraftTextEntities = message.TextEntities;
    }

    public void CancelComposerContext()
    {
        ReplyingTo = null;
        EditingMessage = null;
        DraftText = string.Empty;
        DraftTextEntities = [];
    }

    public void ToggleSelection(MessageItemViewModel message)
    {
        ArgumentNullException.ThrowIfNull(message);
        if (!Messages.Contains(message)) return;
        message.IsSelected = !message.IsSelected;
        NotifySelectionChanged();
    }

    public void ClearSelection()
    {
        bool changed = false;
        foreach (MessageItemViewModel message in Messages.Where(message => message.IsSelected))
        {
            message.IsSelected = false;
            changed = true;
        }

        if (changed) NotifySelectionChanged();
    }

    public MessageItemViewModel? GetEditableSelectedMessage()
    {
        MessageItemViewModel[] selected = Messages.Where(message => message.IsSelected).Take(2).ToArray();
        if (selected.Length != 1) return null;
        MessageItemViewModel editable = selected[0];
        return editable is { IsMine: true, IsText: true, IsForwarded: false } ? editable : null;
    }

    public IReadOnlyList<MessageItemViewModel> GetSelectedMessages() => Messages
        .Where(message => message.IsSelected)
        .OrderBy(message => message.Model.Sequence)
        .ToArray();

    public async Task DeleteSelectedMessagesAsync(
        MessageDeleteScope scope,
        CancellationToken cancellationToken)
    {
        ChatItemViewModel chat = SelectedChat ?? throw new InvalidOperationException("Чат не выбран.");
        MessageItemViewModel[] selected = GetSelectedMessages().ToArray();
        HashSet<string> tombstones = DeletedIdsForChat(chat.Id);
        foreach (MessageItemViewModel message in selected)
        {
            tombstones.Add(message.Model.Id);
            Messages.Remove(message);
        }
        if (selected.Length > 0) MarkMessageMutation(chat.Id);
        NotifySelectionChanged();
        UpdateChatPreview(chat);

        var completed = new HashSet<string>(StringComparer.Ordinal);
        try
        {
            foreach (MessageItemViewModel message in selected)
            {
                cancellationToken.ThrowIfCancellationRequested();
                await _repository.DeleteMessageAsync(chat.Id, message.Model, scope, cancellationToken);
                completed.Add(message.Model.Id);
            }
            await RefreshChatsAsync(cancellationToken);
        }
        catch
        {
            MessageItemViewModel[] rolledBack = selected.Where(item => !completed.Contains(item.Model.Id)).ToArray();
            foreach (MessageItemViewModel message in rolledBack)
            {
                tombstones.Remove(message.Model.Id);
                if (ReferenceEquals(SelectedChat, chat)) InsertMessageOrdered(message);
            }
            if (rolledBack.Length > 0) MarkMessageMutation(chat.Id);
            ResolveReplyPreviews();
            UpdateChatPreview(chat);
            NotifySelectionChanged();
            throw;
        }
    }

    public async Task DeleteMessageAsync(
        MessageItemViewModel message,
        MessageDeleteScope scope,
        CancellationToken cancellationToken)
    {
        ChatItemViewModel chat = SelectedChat ?? throw new InvalidOperationException("Чат не выбран.");
        HashSet<string> tombstones = DeletedIdsForChat(chat.Id);
        tombstones.Add(message.Model.Id);
        Messages.Remove(message);
        MarkMessageMutation(chat.Id);
        NotifySelectionChanged();
        UpdateChatPreview(chat);
        try
        {
            await _repository.DeleteMessageAsync(chat.Id, message.Model, scope, cancellationToken);
            await RefreshChatsAsync(cancellationToken);
        }
        catch
        {
            tombstones.Remove(message.Model.Id);
            MarkMessageMutation(chat.Id);
            if (ReferenceEquals(SelectedChat, chat)) InsertMessageOrdered(message);
            ResolveReplyPreviews();
            UpdateChatPreview(chat);
            NotifySelectionChanged();
            throw;
        }
    }

    public async Task ForwardMessageAsync(
        MessageItemViewModel message,
        ChatItemViewModel target,
        CancellationToken cancellationToken)
    {
        UploadVisible = true;
        UploadProgress = 0;
        try
        {
            var progress = new Progress<double>(value => UploadProgress = value * 100);
            await _repository.ForwardMessageAsync(message.Model, target.Id, progress, cancellationToken);
            await RefreshChatsAsync(cancellationToken);
        }
        finally
        {
            UploadVisible = false;
            UploadProgress = 0;
        }
    }

    public async Task PinMessageAsync(MessageItemViewModel message, CancellationToken cancellationToken)
    {
        ChatItemViewModel chat = SelectedChat ?? throw new InvalidOperationException("Чат не выбран.");
        await _repository.PinMessageAsync(chat.Id, message.Model.Id, cancellationToken);
        await RefreshChatsAsync(cancellationToken);
    }

    public async Task UnpinAsync(CancellationToken cancellationToken)
    {
        ChatItemViewModel chat = SelectedChat ?? throw new InvalidOperationException("Чат не выбран.");
        await _repository.UnpinMessageAsync(chat.Id, cancellationToken);
        await RefreshChatsAsync(cancellationToken);
    }

    public async Task UpdateTypingAsync(bool typing, CancellationToken cancellationToken)
    {
        ChatItemViewModel? chat = SelectedChat;
        if (chat is null) return;
        await _repository.SetTypingAsync(chat.Id, typing, cancellationToken);
    }

    public async Task RefreshTypingAsync(CancellationToken cancellationToken)
    {
        ChatItemViewModel? chat = SelectedChat;
        if (chat is null)
        {
            TypingText = string.Empty;
            return;
        }

        string[] usernames = (await _repository.ListTypingAsync(chat.Id, cancellationToken))
            .Select(item => item.Username)
            .Where(username => !string.Equals(username, CurrentUsername, StringComparison.Ordinal))
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        TypingText = usernames.Length switch
        {
            0 => chat.Presence,
            1 => $"{FamilyPresentation.DisplayName(usernames[0], CurrentUsername)} печатает…",
            _ => "Печатают несколько участников…",
        };
    }

    public MessageItemViewModel? FindMessage(string messageId) =>
        Messages.FirstOrDefault(message => string.Equals(message.Model.Id, messageId, StringComparison.Ordinal));

    private void SynchronizeLatestMessages(
        List<DecryptedMessage> incoming,
        long mutationGenerationAtStart)
    {
        string? chatId = SelectedChat?.Id;
        if (chatId is null) return;
        List<DecryptedMessage> visibleIncoming = incoming
            .Where(message => !IsLocallyDeleted(chatId, message.Id))
            .ToList();

        if (visibleIncoming.Count == 0)
        {
            bool localMutationAfterRequest = MessageMutationGeneration(chatId) != mutationGenerationAtStart;
            if (!localMutationAfterRequest && SelectedChat?.Model.LastSequence == 0)
            {
                // A confirmed empty snapshot may clear old rows, but an in-flight local send is kept.
                MessageItemViewModel[] removable = Messages.Where(item => !item.IsPending).ToArray();
                foreach (MessageItemViewModel item in removable) Messages.Remove(item);
                NotifySelectionChanged();
            }
            return;
        }

        var incomingById = visibleIncoming.ToDictionary(message => message.Id, StringComparer.Ordinal);
        long firstLatestSequence = visibleIncoming.Min(message => message.Sequence);
        long lastLatestSequence = visibleIncoming.Max(message => message.Sequence);
        MessageItemViewModel[] removed = Messages
            .Where(item => !item.IsPending &&
                           item.Model.Sequence >= firstLatestSequence &&
                           item.Model.Sequence <= lastLatestSequence &&
                           !incomingById.ContainsKey(item.Model.Id))
            .ToArray();
        foreach (MessageItemViewModel item in removed) Messages.Remove(item);

        var existing = Messages.ToDictionary(item => item.Model.Id, StringComparer.Ordinal);
        foreach (DecryptedMessage model in visibleIncoming.OrderBy(message => message.Sequence))
        {
            if (existing.TryGetValue(model.Id, out MessageItemViewModel? item))
            {
                long previousSequence = item.Model.Sequence;
                DateTimeOffset previousCreatedAt = item.Model.CreatedAt;
                item.Update(model);
                if (previousSequence != model.Sequence || previousCreatedAt != model.CreatedAt)
                {
                    Messages.Remove(item);
                    InsertMessageOrdered(item);
                }
            }
            else
            {
                var added = new MessageItemViewModel(model, CurrentUsername);
                InsertMessageOrdered(added);
                existing.Add(model.Id, added);
            }
        }

        // Do not sort and move the entire ObservableCollection after every long-poll event.
        // Repositioning only changed/new rows keeps updates near O(latest-window) on large chats.
        NotifySelectionChanged();
    }

    private long MessageMutationGeneration(string chatId) =>
        _messageMutationGeneration.GetValueOrDefault(chatId);

    private long MarkMessageMutation(string chatId)
    {
        long next = MessageMutationGeneration(chatId) + 1;
        _messageMutationGeneration[chatId] = next;
        return next;
    }

    private HashSet<string> DeletedIdsForChat(string chatId)
    {
        if (_locallyDeletedMessageIds.TryGetValue(chatId, out HashSet<string>? ids)) return ids;
        ids = new HashSet<string>(StringComparer.Ordinal);
        _locallyDeletedMessageIds.Add(chatId, ids);
        return ids;
    }

    private bool IsLocallyDeleted(string chatId, string messageId) =>
        _locallyDeletedMessageIds.TryGetValue(chatId, out HashSet<string>? ids) && ids.Contains(messageId);

    private void InsertMessageOrdered(MessageItemViewModel message)
    {
        int index = 0;
        while (index < Messages.Count && Messages[index].Model.Sequence <= message.Model.Sequence) index++;
        Messages.Insert(index, message);
    }

    private void ResolveReplyPreviews()
    {
        var byId = Messages.ToDictionary(message => message.Model.Id, StringComparer.Ordinal);
        foreach (MessageItemViewModel message in Messages)
        {
            message.ReplyPreview = message.HasReply && byId.TryGetValue(message.ReplyToId, out MessageItemViewModel? replied)
                ? $"{replied.SenderName}: {replied.Summary()}"
                : message.HasReply ? "Ответ на более раннее сообщение" : string.Empty;
        }
    }

    private void NotifySelectionChanged()
    {
        RaisePropertyChanged(nameof(SelectedMessageCount));
        RaisePropertyChanged(nameof(HasSelectedMessages));
        RaisePropertyChanged(nameof(SelectedMessageCountText));
        RaisePropertyChanged(nameof(CanEditSelectedMessage));
    }

    private void UpdateChatPreview(ChatItemViewModel chat)
    {
        MessageItemViewModel? last = Messages.LastOrDefault();
        chat.LastMessage = last is null ? "Нет сообщений" : $"{last.SenderName}: {last.Summary()}";
    }

    private async Task PrewarmChatBestEffortAsync(string chatId)
    {
        try
        {
            await _repository.PrewarmChatAsync(chatId, CancellationToken.None).ConfigureAwait(false);
        }
        catch
        {
            // Prewarm is an optimization; normal send retains the one-off reservation fallback.
        }
    }

    private async Task RefreshChatsBestEffortAsync()
    {
        try
        {
            await RefreshChatsAsync(CancellationToken.None).ConfigureAwait(true);
        }
        catch
        {
            // Event/sync loops will retry. An ACKed optimistic send must not feel blocked by preview refresh.
        }
    }

    private void ObserveCallSignals(ChatItemViewModel chat, IReadOnlyList<DecryptedMessage> messages)
    {
        if (messages.Count == 0) return;
        _callScanHighWater[chat.Id] = Math.Max(_callScanHighWater.GetValueOrDefault(chat.Id), messages.Max(message => message.Sequence));
        Call.ObserveMessages(chat.Id, chat.Title, CurrentUsername, messages);
    }

    private async Task ScanCallSignalsBestEffortAsync(IReadOnlyList<ChatSummary> chats)
    {
        foreach (ChatSummary model in chats)
        {
            if (model.LastSequence <= _callScanHighWater.GetValueOrDefault(model.Id)) continue;
            try
            {
                DecryptedMessagePage page = await _repository.LoadRecentCallSignalsAsync(model.Id, CancellationToken.None).ConfigureAwait(false);
                _callScanHighWater[model.Id] = Math.Max(_callScanHighWater.GetValueOrDefault(model.Id), model.LastSequence);
                ChatItemViewModel? chat = Chats.FirstOrDefault(value => string.Equals(value.Id, model.Id, StringComparison.Ordinal));
                if (chat is null) continue;
                await Application.Current.Dispatcher.InvokeAsync(() => ObserveCallSignals(chat, page.Messages));
            }
            catch
            {
                // Call discovery is ephemeral and must never block normal chat refresh.
            }
        }
    }

    private sealed record CachedChatPage(IReadOnlyList<DecryptedMessage> Messages, bool HasMoreBefore);

    private static string FormatLastSeen(PresenceState state)
    {
        if (state.ShowExact && state.LastSeenAt is not null)
        {
            DateTime local = state.LastSeenAt.Value.LocalDateTime;
            DateTime today = DateTime.Today;
            int days = (today - local.Date).Days;
            return days switch
            {
                <= 0 => $"был(а) в {local:HH:mm}",
                1 => $"был(а) вчера в {local:HH:mm}",
                <= 7 => "был(а) на этой неделе",
                _ when local.Year == today.Year && local.Month == today.Month => "был(а) в этом месяце",
                _ => "был(а) давно",
            };
        }

        return state.LastSeenCategory switch
        {
            "today" or "recently" => "был(а) сегодня",
            "yesterday" => "был(а) вчера",
            "week" => "был(а) на этой неделе",
            "month" => "был(а) в этом месяце",
            _ => "был(а) давно",
        };
    }
}
