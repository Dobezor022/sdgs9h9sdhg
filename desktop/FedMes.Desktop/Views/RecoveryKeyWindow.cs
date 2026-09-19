using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace FedMes.Desktop.Views;

public sealed class RecoveryKeyWindow : Window
{
    private readonly TextBox _keyTextBox;

    public RecoveryKeyWindow(Window owner, string username)
    {
        Owner = owner;
        Title = "Восстановление FedMes";
        Width = 520;
        Height = 330;
        MinWidth = 440;
        MinHeight = 300;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ResizeMode = ResizeMode.CanResize;
        ShowInTaskbar = false;
        Background = SystemColors.WindowBrush;

        var root = new Grid { Margin = new Thickness(24) };
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var title = new TextBlock
        {
            Text = "Восстановление ключей истории",
            FontSize = 22,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 0, 0, 12),
        };
        Grid.SetRow(title, 0);
        root.Children.Add(title);

        var explanation = new TextBlock
        {
            Text = $"Сервер подтвердил пользователя {username}, но этому компьютеру ещё недоступны ключи истории. Введите Recovery Key. Он обрабатывается только на этом компьютере.",
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 16),
        };
        Grid.SetRow(explanation, 1);
        root.Children.Add(explanation);

        _keyTextBox = new TextBox
        {
            AcceptsReturn = true,
            TextWrapping = TextWrapping.Wrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            FontFamily = new FontFamily("Consolas"),
            FontSize = 14,
            Padding = new Thickness(10),
            MinHeight = 100,
        };
        Grid.SetRow(_keyTextBox, 2);
        root.Children.Add(_keyTextBox);

        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(0, 18, 0, 0),
        };
        var cancel = new Button
        {
            Content = "Отмена",
            MinWidth = 100,
            Padding = new Thickness(14, 8, 14, 8),
            IsCancel = true,
            Margin = new Thickness(0, 0, 10, 0),
        };
        var recover = new Button
        {
            Content = "Восстановить",
            MinWidth = 120,
            Padding = new Thickness(14, 8, 14, 8),
            IsDefault = true,
        };
        recover.Click += (_, _) =>
        {
            if (string.IsNullOrWhiteSpace(_keyTextBox.Text))
            {
                MessageBox.Show(this, "Введите Recovery Key.", "FedMes", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            DialogResult = true;
        };
        buttons.Children.Add(cancel);
        buttons.Children.Add(recover);
        Grid.SetRow(buttons, 3);
        root.Children.Add(buttons);

        Content = root;
        Loaded += (_, _) => _keyTextBox.Focus();
    }

    public string RecoveryKey => _keyTextBox.Text.Trim();
}

public sealed class RecoveryKeyDisplayWindow : Window
{
    private bool _confirmed;

    public RecoveryKeyDisplayWindow(Window owner, string recoveryKey)
    {
        Owner = owner;
        Title = "Recovery Key FedMes";
        Width = 560;
        Height = 360;
        MinWidth = 460;
        MinHeight = 320;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;
        Background = SystemColors.WindowBrush;

        var root = new Grid { Margin = new Thickness(24) };
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var title = new TextBlock
        {
            Text = "Сохраните Recovery Key",
            FontSize = 22,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 0, 0, 12),
        };
        Grid.SetRow(title, 0);
        root.Children.Add(title);

        var explanation = new TextBlock
        {
            Text = "Этот ключ восстанавливает доступ к зашифрованной истории после переустановки Windows или потери устройства. Сервер его не хранит. Сохраните ключ отдельно и не отправляйте посторонним.",
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 16),
        };
        Grid.SetRow(explanation, 1);
        root.Children.Add(explanation);

        var keyBox = new TextBox
        {
            Text = recoveryKey,
            IsReadOnly = true,
            AcceptsReturn = true,
            TextWrapping = TextWrapping.Wrap,
            FontFamily = new FontFamily("Consolas"),
            FontSize = 15,
            Padding = new Thickness(10),
            VerticalContentAlignment = VerticalAlignment.Center,
        };
        Grid.SetRow(keyBox, 2);
        root.Children.Add(keyBox);

        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(0, 18, 0, 0),
        };
        var copy = new Button
        {
            Content = "Копировать",
            MinWidth = 110,
            Padding = new Thickness(14, 8, 14, 8),
            Margin = new Thickness(0, 0, 10, 0),
        };
        copy.Click += (_, _) => Clipboard.SetText(recoveryKey);
        var saved = new Button
        {
            Content = "Я сохранил ключ",
            MinWidth = 150,
            Padding = new Thickness(14, 8, 14, 8),
            IsDefault = true,
        };
        saved.Click += (_, _) =>
        {
            _confirmed = true;
            DialogResult = true;
        };
        buttons.Children.Add(copy);
        buttons.Children.Add(saved);
        Grid.SetRow(buttons, 3);
        root.Children.Add(buttons);

        Content = root;
        Closing += (_, args) =>
        {
            if (!_confirmed)
            {
                args.Cancel = true;
                MessageBox.Show(this, "Подтвердите, что Recovery Key сохранён.", "FedMes", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        };
    }
}
