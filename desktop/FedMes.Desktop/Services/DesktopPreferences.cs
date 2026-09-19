using System.IO;
using System.Text.Json;

namespace FedMes.Desktop.Services;

public enum DesktopThemeMode
{
    System,
    Light,
    Dark,
}

public sealed class DesktopPreferences
{
    public DesktopThemeMode ThemeMode { get; set; } = DesktopThemeMode.System;

    public bool ShowExactPresence { get; set; } = true;

    public string? LastChatId { get; set; }

    public bool CompactChatOpen { get; set; }

    public double? WindowLeft { get; set; }

    public double? WindowTop { get; set; }

    public double? WindowWidth { get; set; }

    public double? WindowHeight { get; set; }

    public bool WindowMaximized { get; set; }
}

public sealed class DesktopPreferencesStore
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
    };

    private readonly string _path;

    public DesktopPreferencesStore()
    {
        string directory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "FedMes");
        _path = Path.Combine(directory, "desktop-preferences.json");
    }

    public DesktopPreferences Load()
    {
        try
        {
            if (!File.Exists(_path)) return new DesktopPreferences();
            string json = File.ReadAllText(_path);
            return JsonSerializer.Deserialize<DesktopPreferences>(json, SerializerOptions) ?? new DesktopPreferences();
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException)
        {
            return new DesktopPreferences();
        }
    }

    public void Save(DesktopPreferences preferences)
    {
        ArgumentNullException.ThrowIfNull(preferences);
        string? directory = Path.GetDirectoryName(_path);
        if (string.IsNullOrWhiteSpace(directory)) throw new InvalidOperationException("Не удалось определить каталог настроек FedMes.");
        Directory.CreateDirectory(directory);

        string temporaryPath = _path + ".tmp";
        string json = JsonSerializer.Serialize(preferences, SerializerOptions);
        File.WriteAllText(temporaryPath, json);
        File.Move(temporaryPath, _path, overwrite: true);
    }
}
