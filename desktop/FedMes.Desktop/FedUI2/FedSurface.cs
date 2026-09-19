using System.Globalization;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;

namespace FedMes.Desktop.FedUI2;

/// <summary>
/// FedUI 2 is one custom-rendered WPF surface. WPF supplies only the native
/// window/input/text infrastructure; FedMes draws its own component system.
/// No Button/ListBox/TextBox is required by this surface.
/// </summary>
public sealed class FedSurface : FrameworkElement
{
    private static readonly Typeface Typeface = new(new FontFamily("Segoe UI Variable Text"), FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);
    private static readonly Brush Background = Freeze(new SolidColorBrush(Color.FromRgb(14,22,33)));
    private static readonly Brush Surface = Freeze(new SolidColorBrush(Color.FromRgb(23,33,43)));
    private static readonly Brush Raised = Freeze(new SolidColorBrush(Color.FromRgb(32,43,54)));
    private static readonly Brush Line = Freeze(new SolidColorBrush(Color.FromRgb(43,58,72)));
    private static readonly Brush Text = Freeze(new SolidColorBrush(Color.FromRgb(244,247,250)));
    private static readonly Brush Muted = Freeze(new SolidColorBrush(Color.FromRgb(142,157,170)));
    private static readonly Brush Secure = Freeze(new SolidColorBrush(Color.FromRgb(51,144,236)));

    public string ConversationTitle { get; set; } = "FedMes";
    public string SecurityText { get; set; } = "Verified · Generation 1";
    public IReadOnlyList<FedConversationRow> Conversations { get; set; } = Array.Empty<FedConversationRow>();
    public event EventHandler<int>? ConversationInvoked;

    protected override void OnRender(DrawingContext dc)
    {
        base.OnRender(dc);
        dc.DrawRectangle(Background, null, new Rect(RenderSize));
        double rail = 56, ledger = Math.Min(360, Math.Max(300, RenderSize.Width * .28));
        dc.DrawRectangle(Surface, null, new Rect(0,0,rail,RenderSize.Height));
        dc.DrawRectangle(Surface, null, new Rect(rail,0,ledger,RenderSize.Height));
        dc.DrawLine(new Pen(Line,1),new Point(rail+ledger,0),new Point(rail+ledger,RenderSize.Height));
        DrawText(dc,"F",new Point(16,15),16,Secure,FontWeights.Bold);
        DrawText(dc,ConversationTitle,new Point(rail+ledger+18,16),16,Text,FontWeights.SemiBold);
        DrawText(dc,SecurityText,new Point(rail+ledger+18,40),11,Secure,FontWeights.Normal);
        dc.DrawLine(new Pen(Line,1),new Point(rail+ledger,66),new Point(RenderSize.Width,66));
        double y=8;
        for(int i=0;i<Conversations.Count && y<RenderSize.Height-68;i++,y+=68)
        {
            var row=Conversations[i];
            if(row.Selected) dc.DrawRoundedRectangle(Raised,null,new Rect(rail+4,y,ledger-8,64),14,14);
            dc.DrawEllipse(Freeze(new SolidColorBrush(Color.FromRgb(51,144,236))), null, new Point(rail+35,y+34),27,27);
            DrawText(dc,row.Title,new Point(rail+74,y+8),14,Text,FontWeights.SemiBold);
            DrawText(dc,row.Preview,new Point(rail+74,y+34),12,Muted,FontWeights.Normal);
            DrawText(dc,row.Time,new Point(rail+ledger-56,y+9),9,Muted,FontWeights.Normal);
            dc.DrawLine(new Pen(Line,1),new Point(rail+74,y+67),new Point(rail+ledger-8,y+67));
        }
        dc.DrawRectangle(Raised,null,new Rect(rail+ledger+12,RenderSize.Height-58,Math.Max(80,RenderSize.Width-rail-ledger-70),42));
        DrawText(dc,"Message",new Point(rail+ledger+24,RenderSize.Height-45),13,Muted,FontWeights.Normal);
    }

    protected override void OnMouseLeftButtonDown(MouseButtonEventArgs e)
    {
        var p=e.GetPosition(this);double rail=56, ledger=Math.Min(360,Math.Max(300,RenderSize.Width*.28));if(p.X<rail||p.X>rail+ledger)return;int index=(int)((p.Y-8)/68);if(index>=0&&index<Conversations.Count)ConversationInvoked?.Invoke(this,index);
    }

    private void DrawText(DrawingContext dc,string value,Point point,double size,Brush brush,FontWeight weight){var ft=new FormattedText(value,CultureInfo.CurrentUICulture,FlowDirection.LeftToRight,new Typeface(Typeface.FontFamily,FontStyles.Normal,weight,FontStretches.Normal),size,brush,VisualTreeHelper.GetDpi(this).PixelsPerDip);dc.DrawText(ft,point);}
    private static T Freeze<T>(T value) where T:Freezable{value.Freeze();return value;}
}

public sealed record FedConversationRow(string Title,string Preview,string Time,bool Selected=false);
