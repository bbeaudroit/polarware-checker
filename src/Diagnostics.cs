using System.Management;
using System.Security.Principal;
using Microsoft.Win32;
using System.IO;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace PolarWare.Checker;

internal sealed record DiagnosticRow(string Name, string Detail, string Status,
    Package? Package = null, InstalledApp? Installed = null)
{
    public string? Action => Package == null ? null : Status == "Not installed" ? "Install"
        : (Installed?.Product != null || Packages.CachedInstaller(Installed) != null) ? "Uninstall" : null;
}

internal sealed record Snapshot(DiagnosticRow[] System, DiagnosticRow[] Windows,
    DiagnosticRow[] Boosters, DiagnosticRow[] Anticheats, DiagnosticRow[] Runtimes, string? Uuid);

internal sealed record InstalledApp(string Name, string Version, string? Uninstaller, Guid? Product);

internal static class Diagnostics
{
    internal static Snapshot Read()
    {
        var apps = ReadInstalledApps();
        return new(
            [
                Read("Windows version", () => RuntimeInformation.OSDescription),
                Read("Architecture", () => RuntimeInformation.OSArchitecture.ToString()),
                Read("Permissions", () =>
                {
                    using var identity = WindowsIdentity.GetCurrent();
                    return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator)
                        ? "Administrator" : "Standard user";
                }),
                Read("System drive free space", () => $"{new DriveInfo(Path.GetPathRoot(Environment.SystemDirectory)!).AvailableFreeSpace / Math.Pow(1024, 3):F1} GB"),
                Read("Network", () =>
                {
                    using var ping = new Ping();
                    var reply = ping.Send("1.1.1.1", 1500);
                    return reply.Status == IPStatus.Success ? $"Reachable · {reply.RoundtripTime} ms" : "Probe did not reply";
                })
            ],
            [
                Flag("UAC", () => Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", null)),
                Flag("Windows Defender", () => Wmi(@"root\Microsoft\Windows\Defender", "MSFT_MpComputerStatus", "AntivirusEnabled")),
                Flag("Real-time protection", () => Wmi(@"root\Microsoft\Windows\Defender", "MSFT_MpComputerStatus", "RealTimeProtectionEnabled")),
                Flag("Secure Boot", () => Registry.GetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled", null)),
                Flag("TPM", () => Wmi(@"root\CIMV2\Security\MicrosoftTpm", "Win32_Tpm", "IsEnabled_InitialValue")),
                Flag("Memory integrity (HVCI)", () => (Wmi(@"root\Microsoft\Windows\DeviceGuard", "Win32_DeviceGuard", "SecurityServicesRunning") as uint[]) is { } services ? services.Contains(2u) : null)
            ],
            Inventory(apps, "Razer Cortex", "Dragon Center", "MSI SDK"),
            Inventory(apps, "Riot Vanguard", "FACEIT", "ESEA Client", "Malwarebytes"),
            [.. Packages.Catalog.Select(package => package.Detect(apps)),
             Read("DirectX", () => Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\DirectX", "Version", null) as string)],
            HardwareUuid());
    }

    private static DiagnosticRow[] Inventory(List<InstalledApp>? apps, params string[] names) =>
        names.Select(name =>
        {
            var app = apps?.FirstOrDefault(a => a.Name.StartsWith(name, StringComparison.OrdinalIgnoreCase));
            return new DiagnosticRow(name, app?.Version ?? "—",
                apps == null ? "Unknown" : app == null ? "Not detected" : "Installed");
        }).ToArray();

    private static string? HardwareUuid()
    {
        try
        {
            var value = Wmi(@"root\CIMV2", "Win32_ComputerSystemProduct", "UUID") as string;
            return Guid.TryParse(value, out var id) && id != Guid.Empty &&
                id != new Guid("ffffffff-ffff-ffff-ffff-ffffffffffff")
                ? id.ToString("D").ToUpperInvariant() : null;
        }
        catch { return null; }
    }

    private static object? Wmi(string scope, string table, string property)
    {
        using var query = new ManagementObjectSearcher(scope, $"SELECT {property} FROM {table}");
        query.Options.Timeout = TimeSpan.FromSeconds(4);
        using var results = query.Get();
        foreach (ManagementBaseObject item in results)
        {
            using (item) return item[property];
        }
        return null;
    }

    private static DiagnosticRow Flag(string name, Func<object?> read)
    {
        try
        {
            var status = read() switch
            {
                true or 1 => "Enabled",
                false or 0 => "Disabled",
                _ => "Unknown"
            };
            return new(name, "—", status);
        }
        catch { return new(name, "Could not read state", "Unknown"); }
    }

    private static DiagnosticRow Read(string name, Func<string?> read)
    {
        try
        {
            var detail = read();
            return new(name, detail ?? "—", detail == null ? "Unknown" : "Detected");
        }
        catch { return new(name, "Could not read state", "Unknown"); }
    }

    private static List<InstalledApp>? ReadInstalledApps()
    {
        const string uninstall = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
        var apps = new List<InstalledApp>();
        try
        {
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            foreach (var hive in new[] { RegistryHive.LocalMachine, RegistryHive.CurrentUser })
            {
                using var root = RegistryKey.OpenBaseKey(hive, view);
                using var key = root.OpenSubKey(uninstall);
                if (key == null) continue;
                foreach (var subkey in key.GetSubKeyNames())
                {
                    using var item = key.OpenSubKey(subkey);
                    if (item?.GetValue("DisplayName") is not string name) continue;
                    var version = item.GetValue("DisplayVersion") as string ?? "—";
                    var command = hive == RegistryHive.LocalMachine ? item.GetValue("UninstallString") as string : null;
                    Guid? product = hive == RegistryHive.LocalMachine && item.GetValue("WindowsInstaller") is 1 && Guid.TryParse(subkey, out var id) ? id : null;
                    apps.Add(new(name, version, command, product));
                }
            }
            return apps;
        }
        catch { return null; }
    }
}

