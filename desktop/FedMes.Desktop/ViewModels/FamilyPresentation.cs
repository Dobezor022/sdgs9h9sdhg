namespace FedMes.Desktop.ViewModels;

public static class FamilyPresentation
{
    public static string DisplayName(string username, string currentUsername) => username.ToLowerInvariant() switch
    {
        "papa" => string.Equals(currentUsername, "mama", StringComparison.OrdinalIgnoreCase) ? "Муж" : "Папа",
        "mama" => string.Equals(currentUsername, "papa", StringComparison.OrdinalIgnoreCase) ? "Жена" : "Мама",
        "yura" => "Юра",
        "vasya" => "Вася",
        "grisha" => "Гриша",
        _ => username,
    };

    public static string Initial(string username, string currentUsername)
    {
        string name = DisplayName(username, currentUsername);
        return string.IsNullOrWhiteSpace(name) ? "?" : name[..1].ToUpperInvariant();
    }
}
