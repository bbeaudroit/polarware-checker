using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Media;

namespace PolarWare.Checker;

public partial class MainWindow : Window
{
    private const string WebUrl     = "https://polarware.vercel.app";
    private const string DiscordUrl = "https://discord.gg/GZPErdvX7y";

    public ObservableCollection<CheckRow> Rows { get; } = new();

    public MainWindow()
    {
        InitializeComponent();
        ChecksList.ItemsSource = Rows;
        Loaded += (_, _) => OnRun(this, new RoutedEventArgs());
    }

    private void OnRun(object sender, RoutedEventArgs e)
    {
        RunBtn.IsEnabled = false;
        Rows.Clear();
        SummaryText.Text = "running…";

        var dispatcher = Dispatcher;
        _ = System.Threading.Tasks.Task.Run(() =>
        {
            var results = Checks.RunAll();
            dispatcher.Invoke(() =>
            {
                foreach (var r in results) Rows.Add(CheckRow.From(r));
                var pass = results.Count(r => r.State == CheckState.Pass);
                var warn = results.Count(r => r.State == CheckState.Warn);
                var fail = results.Count(r => r.State == CheckState.Fail);
                SummaryText.Text = fail > 0
                    ? $"{fail} fail  ·  {warn} warn  ·  {pass} pass"
                    : warn > 0
                        ? $"{warn} warn  ·  {pass} pass  —  ready"
                        : $"{pass} pass  —  ready";
                RunBtn.IsEnabled = true;
            });
        });
    }

    private void OnTitleBarDrag(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        if (e.ButtonState == System.Windows.Input.MouseButtonState.Pressed) DragMove();
    }
    private void OnMinimize(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    private void OnClose(object sender, RoutedEventArgs e) => Close();

    private void OnOpenWeb(object sender, RoutedEventArgs e) => OpenUrl(WebUrl);
    private void OnOpenDiscord(object sender, RoutedEventArgs e) => OpenUrl(DiscordUrl);

    private static void OpenUrl(string url)
    {
        try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); }
        catch { }
    }
}

public sealed class CheckRow
{
    public string Name { get; init; } = "";
    public string Detail { get; init; } = "";
    public string Fix { get; init; } = "";
    public string StateLabel { get; init; } = "";
    public Brush StateBrush { get; init; } = Brushes.Gray;
    public Visibility FixVisibility => string.IsNullOrWhiteSpace(Fix) ? Visibility.Collapsed : Visibility.Visible;
    public CheckResult Raw { get; init; } = new("", CheckState.Unknown, "", "");

    public static CheckRow From(CheckResult r)
    {
        var (label, brush) = r.State switch
        {
            CheckState.Pass => ("PASS", (Brush)new SolidColorBrush(Color.FromRgb(0x22, 0xC5, 0x5E))),
            CheckState.Warn => ("WARN", (Brush)new SolidColorBrush(Color.FromRgb(0xF5, 0x9E, 0x0B))),
            CheckState.Fail => ("FAIL", (Brush)new SolidColorBrush(Color.FromRgb(0xEF, 0x44, 0x44))),
            _ => ("  ?  ", (Brush)new SolidColorBrush(Color.FromRgb(0x8A, 0x95, 0xA8))),
        };
        return new CheckRow
        {
            Name = r.Name, Detail = r.Detail, Fix = r.FixHint,
            StateLabel = label, StateBrush = brush, Raw = r,
        };
    }
}
