using System.IO;
using System.Windows;
using System.Windows.Controls;
using FedMes.Desktop.Core.Messaging;
using FedMes.Desktop.Services;

namespace FedMes.Desktop.Views;

public partial class AttachmentOptionsWindow : Window
{
    private readonly bool _singleVideo;

    public AttachmentOptionsWindow(IReadOnlyList<string> paths, string initialCaption, bool forceRoundVideo = false)
    {
        InitializeComponent();
        ArgumentNullException.ThrowIfNull(paths);
        CaptionTextBox.Text = initialCaption;
        FilesText.Text = paths.Count == 1
            ? Path.GetFileName(paths[0])
            : $"Выбрано файлов: {paths.Count}";
        _singleVideo = paths.Count == 1 && MimeTypes.FromPath(paths[0]).StartsWith("video/", StringComparison.OrdinalIgnoreCase);
        RoundVideoCheckBox.Visibility = _singleVideo && !forceRoundVideo ? Visibility.Visible : Visibility.Collapsed;
        RoundShapePanel.Visibility = _singleVideo ? Visibility.Visible : Visibility.Collapsed;
        if (forceRoundVideo && _singleVideo)
        {
            TitleText.Text = "Видеосообщение";
            RoundVideoCheckBox.IsChecked = true;
        }
        else
        {
            ApplyRoundVideoState();
        }
    }

    public string Caption => SendAsRoundVideo ? string.Empty : CaptionTextBox.Text;
    public bool SendAsFile => SendAsFileCheckBox.IsChecked == true;
    public bool Spoiler => SpoilerCheckBox.IsChecked == true;
    public bool SendAsRoundVideo => _singleVideo && RoundVideoCheckBox.IsChecked == true;

    public RoundVideoShape RoundShape
    {
        get
        {
            string? value = (RoundShapeComboBox.SelectedItem as ComboBoxItem)?.Tag as string;
            return Enum.TryParse(value, ignoreCase: true, out RoundVideoShape shape) ? shape : RoundVideoShape.Circle;
        }
    }

    private void RoundVideoCheckBox_Changed(object sender, RoutedEventArgs e) => ApplyRoundVideoState();

    private void ApplyRoundVideoState()
    {
        bool roundVideo = _singleVideo && RoundVideoCheckBox.IsChecked == true;
        RoundShapePanel.IsEnabled = roundVideo;
        CaptionTextBox.IsEnabled = !roundVideo;
        if (roundVideo)
        {
            SendAsFileCheckBox.IsChecked = false;
            SendAsFileCheckBox.IsEnabled = false;
        }
        else
        {
            SendAsFileCheckBox.IsEnabled = true;
        }
    }

    private void SendButton_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = true;
        Close();
    }

    private void CancelButton_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}
