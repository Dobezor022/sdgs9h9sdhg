using System.Windows;
using System.Windows.Input;
using FedMes.Desktop.ViewModels;

namespace FedMes.Desktop.Views;

public partial class ForwardWindow : Window
{
    public ForwardWindow(IEnumerable<ChatItemViewModel> chats)
    {
        InitializeComponent();
        ChatsListBox.ItemsSource = chats
            .OrderBy(chat => !chat.IsFavorites)
            .ThenBy(chat => chat.Title, StringComparer.CurrentCultureIgnoreCase)
            .ToArray();
    }

    public ChatItemViewModel? SelectedChat => ChatsListBox.SelectedItem as ChatItemViewModel;

    private void ForwardButton_Click(object sender, RoutedEventArgs e)
    {
        if (SelectedChat is null) return;
        DialogResult = true;
        Close();
    }

    private void ChatsListBox_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (SelectedChat is null) return;
        DialogResult = true;
        Close();
    }

    private void CancelButton_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}
