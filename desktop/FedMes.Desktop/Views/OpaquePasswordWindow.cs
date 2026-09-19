using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace FedMes.Desktop.Views;

public sealed class OpaquePasswordWindow : Window
{
    private readonly TextBox? _username;
    private readonly PasswordBox _password;
    private readonly PasswordBox? _confirm;

    public OpaquePasswordWindow(Window owner, bool login, string? username = null)
    {
        Owner = owner;
        Title = login ? "Вход по парольной фразе FedMes" : "Парольная фраза FedMes";
        Width = 440;
        SizeToContent = SizeToContent.Height;
        MinHeight = 330;
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = (Brush)Application.Current.FindResource("FedMesBackgroundBrush");

        var panel = new StackPanel { Margin = new Thickness(26) };
        panel.Children.Add(new TextBlock
        {
            Text = login ? "Безопасный вход OPAQUE" : "Настройка безопасного входа OPAQUE",
            FontSize = 23,
            FontWeight = FontWeights.SemiBold,
            TextWrapping = TextWrapping.Wrap,
        });
        panel.Children.Add(new TextBlock
        {
            Text = login
                ? "Пароль не передаётся серверу. Доступ к истории будет восстановлен только после локальной проверки зашифрованного хранилища."
                : "Используйте уникальную парольную фразу не короче 12 символов. Recovery Key остаётся независимым способом восстановления.",
            Margin = new Thickness(0, 10, 0, 18),
            TextWrapping = TextWrapping.Wrap,
            Foreground = (Brush)Application.Current.FindResource("FedMesSecondaryTextBrush"),
        });
        if (login)
        {
            panel.Children.Add(Label("Пользователь"));
            _username = new TextBox { Height = 42, Text = username ?? string.Empty, VerticalContentAlignment = VerticalAlignment.Center };
            panel.Children.Add(_username);
        }
        panel.Children.Add(Label("Парольная фраза"));
        _password = new PasswordBox { Height = 42, VerticalContentAlignment = VerticalAlignment.Center };
        panel.Children.Add(_password);
        if (!login)
        {
            panel.Children.Add(Label("Повторите парольную фразу", new Thickness(0, 12, 0, 4)));
            _confirm = new PasswordBox { Height = 42, VerticalContentAlignment = VerticalAlignment.Center };
            panel.Children.Add(_confirm);
        }

        var buttons = new Grid { Margin = new Thickness(0, 22, 0, 0) };
        buttons.ColumnDefinitions.Add(new ColumnDefinition());
        buttons.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(12) });
        buttons.ColumnDefinitions.Add(new ColumnDefinition());
        var cancel = new Button { Content = "Отмена", Height = 42, IsCancel = true };
        var accept = new Button { Content = login ? "Войти" : "Сохранить", Height = 42, IsDefault = true };
        accept.Click += (_, _) => Accept();
        Grid.SetColumn(accept, 2);
        buttons.Children.Add(cancel);
        buttons.Children.Add(accept);
        panel.Children.Add(buttons);
        Content = panel;
    }

    public string Username => _username?.Text.Trim() ?? string.Empty;
    public char[] TakePassword() => _password.SecurePassword.Length == 0 ? [] : _password.Password.ToCharArray();

    private void Accept()
    {
        if (_username is not null && string.IsNullOrWhiteSpace(_username.Text))
        {
            MessageBox.Show(this, "Выберите пользователя.", "FedMes", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        if (_password.Password.Length < 12 || string.IsNullOrWhiteSpace(_password.Password))
        {
            MessageBox.Show(this, "Парольная фраза должна содержать не менее 12 символов.", "FedMes", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        if (_confirm is not null && !string.Equals(_password.Password, _confirm.Password, StringComparison.Ordinal))
        {
            MessageBox.Show(this, "Парольные фразы не совпадают.", "FedMes", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        DialogResult = true;
    }

    private static TextBlock Label(string text, Thickness? margin = null) => new()
    {
        Text = text,
        Margin = margin ?? new Thickness(0, 0, 0, 4),
        FontWeight = FontWeights.SemiBold,
    };
}
