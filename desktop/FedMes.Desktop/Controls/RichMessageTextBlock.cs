using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using FedMes.Desktop.Core.Messaging;

namespace FedMes.Desktop.Controls;

public sealed class RichMessageTextBlock : TextBlock
{
    public static readonly DependencyProperty PlainTextProperty = DependencyProperty.Register(
        nameof(PlainText),
        typeof(string),
        typeof(RichMessageTextBlock),
        new FrameworkPropertyMetadata(string.Empty, FrameworkPropertyMetadataOptions.AffectsMeasure, OnContentChanged));

    public static readonly DependencyProperty TextEntitiesProperty = DependencyProperty.Register(
        nameof(TextEntities),
        typeof(IReadOnlyList<TextEntity>),
        typeof(RichMessageTextBlock),
        new FrameworkPropertyMetadata(Array.Empty<TextEntity>(), FrameworkPropertyMetadataOptions.AffectsMeasure, OnContentChanged));

    private bool _spoilersRevealed;

    public RichMessageTextBlock()
    {
        MouseLeftButtonUp += (_, _) =>
        {
            if (_spoilersRevealed || !TextEntities.Any(entity => entity.Type == TextEntityType.Spoiler)) return;
            _spoilersRevealed = true;
            RebuildInlines();
        };
    }

    public string PlainText
    {
        get => (string)GetValue(PlainTextProperty);
        set => SetValue(PlainTextProperty, value);
    }

    public IReadOnlyList<TextEntity> TextEntities
    {
        get => (IReadOnlyList<TextEntity>)GetValue(TextEntitiesProperty);
        set => SetValue(TextEntitiesProperty, value);
    }

    private static void OnContentChanged(DependencyObject sender, DependencyPropertyChangedEventArgs args)
    {
        var block = (RichMessageTextBlock)sender;
        block._spoilersRevealed = false;
        block.RebuildInlines();
    }

    private void RebuildInlines()
    {
        string text = PlainText ?? string.Empty;
        IReadOnlyList<TextEntity> entities = TextFormatting.Sanitize(text, TextEntities);
        Inlines.Clear();
        Cursor = entities.Any(entity => entity.Type == TextEntityType.Spoiler) && !_spoilersRevealed
            ? Cursors.Hand
            : Cursors.Arrow;
        if (text.Length == 0) return;

        int[] boundaries = entities
            .SelectMany(entity => new[] { entity.Offset, entity.EndExclusive })
            .Append(0)
            .Append(text.Length)
            .Distinct()
            .Where(value => value >= 0 && value <= text.Length)
            .OrderBy(value => value)
            .ToArray();
        bool quoteWasActive = false;
        for (int index = 0; index + 1 < boundaries.Length; index++)
        {
            int start = boundaries[index];
            int end = boundaries[index + 1];
            if (end <= start) continue;
            TextEntityType[] active = entities
                .Where(entity => entity.Offset <= start && entity.EndExclusive >= end)
                .Select(entity => entity.Type)
                .Distinct()
                .ToArray();
            bool quoteActive = active.Contains(TextEntityType.Quote);
            if (quoteActive && !quoteWasActive)
            {
                var quoteBar = new Run("▏ ") { FontWeight = FontWeights.Bold };
                if (TryFindResource("FedMesQuoteBarBrush") is Brush barBrush) quoteBar.Foreground = barBrush;
                if (TryFindResource("FedMesQuoteBackgroundBrush") is Brush quoteBackground) quoteBar.Background = quoteBackground;
                Inlines.Add(quoteBar);
            }
            else if (!quoteActive && quoteWasActive)
            {
                AddQuoteMark();
            }

            var run = new Run(text[start..end]);
            if (active.Contains(TextEntityType.Bold)) run.FontWeight = FontWeights.Bold;
            if (active.Contains(TextEntityType.Italic)) run.FontStyle = FontStyles.Italic;
            if (active.Contains(TextEntityType.Monospace)) run.FontFamily = new FontFamily("Consolas");
            var decorations = new TextDecorationCollection();
            if (active.Contains(TextEntityType.Strikethrough)) decorations.Add(System.Windows.TextDecorations.Strikethrough[0]);
            if (active.Contains(TextEntityType.Underline)) decorations.Add(System.Windows.TextDecorations.Underline[0]);
            if (decorations.Count > 0) run.TextDecorations = decorations;
            if (quoteActive && TryFindResource("FedMesQuoteBackgroundBrush") is Brush background)
            {
                run.Background = background;
            }
            if (active.Contains(TextEntityType.Spoiler) && !_spoilersRevealed)
            {
                run.Foreground = Brushes.Transparent;
                run.Background = new SolidColorBrush(Color.FromRgb(127, 138, 148));
            }
            Inlines.Add(run);
            quoteWasActive = quoteActive;
        }

        if (quoteWasActive) AddQuoteMark();
    }

    private void AddQuoteMark()
    {
        var quoteMark = new Run("  ”") { FontWeight = FontWeights.Bold };
        if (TryFindResource("FedMesQuoteMarksBrush") is Brush quoteMarks) quoteMark.Foreground = quoteMarks;
        if (TryFindResource("FedMesQuoteBackgroundBrush") is Brush quoteBackground) quoteMark.Background = quoteBackground;
        Inlines.Add(quoteMark);
    }
}
