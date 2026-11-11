using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace PolarWare.Checker;

public partial class MainWindow : Window
{
    private bool busy;
    private string? uuid;

    public MainWindow()
    {
        InitializeComponent();
        Loaded += async (_, _) =>
        {
            var area = SystemParameters.WorkArea;
            var scale = Math.Min(1, Math.Min(area.Width / 900, area.Height / 620));
            Shell.LayoutTransform = new ScaleTransform(scale, scale);
            Width = 900 * scale;
            Height = 620 * scale;
            Left = area.Left + (area.Width - Width) / 2;
            Top = area.Top + (area.Height - Height) / 2;
            await RunAsync();
        };
    }

    private async Task RunAsync(DiagnosticRow? package = null)
    {
        if (busy) return;
        busy = true;
        RefreshButton.IsEnabled = RuntimeRows.IsEnabled = false;
        Message.Text = package == null ? "Reading system status…" : $"{package.Action}: {package.Name}…";
        string? result = null;
        try
        {
            if (package != null)
            {
                try { result = await Packages.ExecuteAsync(package); }
                catch (Win32Exception e) when (e.NativeErrorCode == 1223) { result = "Operation canceled."; }
                catch (Exception e) { result = $"Package error: {e.Message}"; }
            }

            var data = await Task.Run(Diagnostics.Read);
            SystemRows.ItemsSource = data.System;
            WindowsRows.ItemsSource = data.Windows;
            BoosterRows.ItemsSource = data.Boosters;
            AnticheatRows.ItemsSource = data.Anticheats;
            RuntimeRows.ItemsSource = data.Runtimes;
            uuid = data.Uuid;
            HardwareValue.Text = uuid ?? "Unavailable";
            FooterUuid.Text = $"Hardware UUID · {HardwareValue.Text}";
            CopyButton.IsEnabled = uuid != null;
            Message.Text = result ?? "System status updated.";
        }
        catch (Exception e) { Message.Text = $"Could not refresh: {e.Message}"; }
        finally
        {
            busy = false;
            RefreshButton.IsEnabled = RuntimeRows.IsEnabled = true;
        }
    }

    private async void RefreshClicked(object sender, RoutedEventArgs e) => await RunAsync();

    private async void RunPackage(object sender, RoutedEventArgs e)
    {
        if (busy || sender is not Button { DataContext: DiagnosticRow row }) return;
        if (row.Action == "Uninstall" &&
            MessageBox.Show(this, $"Uninstall {row.Name}? Other applications may depend on it.",
                Title, MessageBoxButton.OKCancel, MessageBoxImage.Warning) != MessageBoxResult.OK) return;
        await RunAsync(row);
    }

    private void CopyUuid(object sender, RoutedEventArgs e)
    {
        if (uuid == null) return;
        try
        {
            Clipboard.SetText(uuid);
            Message.Text = "Hardware UUID copied.";
        }
        catch (System.Runtime.InteropServices.ExternalException) { Message.Text = "Clipboard unavailable. Try again."; }
    }

    private void DragTitle(object sender, MouseButtonEventArgs e)
    {
        if (e.LeftButton == MouseButtonState.Pressed) DragMove();
    }
    private void MinimizeWindow(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
    private void CloseWindow(object sender, RoutedEventArgs e) => Close();
    private void OpenSecurity(object sender, RoutedEventArgs e) => OpenSettings("windowsdefender:");
    private void OpenApps(object sender, RoutedEventArgs e) => OpenSettings("ms-settings:appsfeatures");
    private void OpenSettings(string uri)
    {
        try { Process.Start(new ProcessStartInfo(uri) { UseShellExecute = true }); }
        catch (Win32Exception e) { Message.Text = $"Could not open settings: {e.Message}"; }
    }
}
