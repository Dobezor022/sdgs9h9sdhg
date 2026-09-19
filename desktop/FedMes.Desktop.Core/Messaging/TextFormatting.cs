namespace FedMes.Desktop.Core.Messaging;

public sealed record NormalizedFormattedText(string Text, IReadOnlyList<TextEntity> Entities);

public static class TextFormatting
{
    public static IReadOnlyList<TextEntity> Sanitize(string text, IEnumerable<TextEntity>? entities)
    {
        ArgumentNullException.ThrowIfNull(text);
        if (entities is null) return [];
        var safe = new List<TextEntity>();
        foreach (TextEntity entity in entities)
        {
            if (entity.Length <= 0 || entity.Offset >= text.Length) continue;
            int start = Math.Max(0, entity.Offset);
            long rawEnd = (long)entity.Offset + entity.Length;
            int end = (int)Math.Min(text.Length, Math.Max(start, rawEnd));
            if (end > start) safe.Add(new TextEntity(entity.Type, start, end - start));
        }

        return Merge(safe);
    }

    public static NormalizedFormattedText Normalize(string text, IEnumerable<TextEntity>? entities)
    {
        ArgumentNullException.ThrowIfNull(text);
        int start = 0;
        while (start < text.Length && char.IsWhiteSpace(text[start])) start++;
        int end = text.Length;
        while (end > start && char.IsWhiteSpace(text[end - 1])) end--;
        if (end <= start) return new NormalizedFormattedText(string.Empty, []);

        string normalized = text[start..end];
        var shifted = new List<TextEntity>();
        foreach (TextEntity entity in Sanitize(text, entities))
        {
            int entityStart = Math.Max(entity.Offset, start);
            int entityEnd = Math.Min(entity.EndExclusive, end);
            if (entityEnd > entityStart)
            {
                shifted.Add(new TextEntity(entity.Type, entityStart - start, entityEnd - entityStart));
            }
        }

        return new NormalizedFormattedText(normalized, Sanitize(normalized, shifted));
    }

    public static IReadOnlyList<TextEntity> Toggle(
        string text,
        IEnumerable<TextEntity>? entities,
        TextEntityType type,
        int rawStart,
        int rawEnd)
    {
        int start = Math.Clamp(Math.Min(rawStart, rawEnd), 0, text.Length);
        int end = Math.Clamp(Math.Max(rawStart, rawEnd), 0, text.Length);
        IReadOnlyList<TextEntity> current = Sanitize(text, entities);
        if (end <= start) return current;
        bool alreadyApplied = current.Any(entity =>
            entity.Type == type && entity.Offset <= start && entity.EndExclusive >= end);
        var result = new List<TextEntity>();
        foreach (TextEntity entity in current)
        {
            if (entity.Type != type || entity.EndExclusive <= start || entity.Offset >= end)
            {
                result.Add(entity);
                continue;
            }

            if (entity.Offset < start) result.Add(new TextEntity(type, entity.Offset, start - entity.Offset));
            if (entity.EndExclusive > end) result.Add(new TextEntity(type, end, entity.EndExclusive - end));
        }

        if (!alreadyApplied) result.Add(new TextEntity(type, start, end - start));
        return Sanitize(text, result);
    }

    public static IReadOnlyList<TextEntity> Clear(
        string text,
        IEnumerable<TextEntity>? entities,
        int rawStart,
        int rawEnd)
    {
        int start = Math.Clamp(Math.Min(rawStart, rawEnd), 0, text.Length);
        int end = Math.Clamp(Math.Max(rawStart, rawEnd), 0, text.Length);
        IReadOnlyList<TextEntity> current = Sanitize(text, entities);
        if (end <= start) return current;
        var result = new List<TextEntity>();
        foreach (TextEntity entity in current)
        {
            if (entity.EndExclusive <= start || entity.Offset >= end)
            {
                result.Add(entity);
                continue;
            }

            if (entity.Offset < start) result.Add(new TextEntity(entity.Type, entity.Offset, start - entity.Offset));
            if (entity.EndExclusive > end) result.Add(new TextEntity(entity.Type, end, entity.EndExclusive - end));
        }

        return Sanitize(text, result);
    }

    public static IReadOnlyList<TextEntity> RemapAfterEdit(
        string oldText,
        string newText,
        IEnumerable<TextEntity>? entities)
    {
        ArgumentNullException.ThrowIfNull(oldText);
        ArgumentNullException.ThrowIfNull(newText);
        if (oldText == newText) return Sanitize(newText, entities);

        int prefix = 0;
        int maxPrefix = Math.Min(oldText.Length, newText.Length);
        while (prefix < maxPrefix && oldText[prefix] == newText[prefix]) prefix++;

        int suffix = 0;
        int oldRemaining = oldText.Length - prefix;
        int newRemaining = newText.Length - prefix;
        while (suffix < oldRemaining && suffix < newRemaining &&
               oldText[oldText.Length - 1 - suffix] == newText[newText.Length - 1 - suffix])
        {
            suffix++;
        }

        int oldChangedEnd = oldText.Length - suffix;
        int newChangedEnd = newText.Length - suffix;
        int delta = newText.Length - oldText.Length;

        int MapStart(int position) => position <= prefix
            ? position
            : position >= oldChangedEnd ? position + delta : prefix;
        int MapEnd(int position) => position <= prefix
            ? position
            : position >= oldChangedEnd ? position + delta : newChangedEnd;

        var mapped = new List<TextEntity>();
        foreach (TextEntity entity in Sanitize(oldText, entities))
        {
            int start = Math.Clamp(MapStart(entity.Offset), 0, newText.Length);
            int end = Math.Clamp(MapEnd(entity.EndExclusive), start, newText.Length);
            if (end > start) mapped.Add(new TextEntity(entity.Type, start, end - start));
        }

        return Sanitize(newText, mapped);
    }

    public static (int Start, int End) ExpandToLineRange(string text, int rawStart, int rawEnd)
    {
        int start = Math.Clamp(Math.Min(rawStart, rawEnd), 0, text.Length);
        int end = Math.Clamp(Math.Max(rawStart, rawEnd), 0, text.Length);
        int lineStart = start == 0 ? 0 : text.LastIndexOf('\n', start - 1) + 1;
        int nextBreak = text.IndexOf('\n', end);
        int lineEnd = nextBreak < 0 ? text.Length : nextBreak;
        return (lineStart, lineEnd);
    }

    private static TextEntity[] Merge(IEnumerable<TextEntity> entities)
    {
        var sorted = entities
            .Where(entity => entity.Length > 0)
            .OrderBy(entity => entity.Type)
            .ThenBy(entity => entity.Offset)
            .ThenBy(entity => entity.EndExclusive)
            .ToArray();
        var merged = new List<TextEntity>();
        foreach (TextEntity entity in sorted)
        {
            TextEntity? last = merged.LastOrDefault();
            if (last is not null && last.Type == entity.Type && entity.Offset <= last.EndExclusive)
            {
                int end = Math.Max(last.EndExclusive, entity.EndExclusive);
                merged[^1] = new TextEntity(last.Type, last.Offset, end - last.Offset);
            }
            else
            {
                merged.Add(entity);
            }
        }

        return merged
            .OrderBy(entity => entity.Offset)
            .ThenBy(entity => entity.EndExclusive)
            .ThenBy(entity => entity.Type)
            .ToArray();
    }
}
