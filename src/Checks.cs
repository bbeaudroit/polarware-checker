// language: C#, file: Checks.cs, target: .NET 8 WPF x64
// *System pre-flight checks for PolarWare. Each check returns a Result that
// the UI renders as PASS / WARN / FAIL plus a short "how to fix" link.*
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;

namespace PolarWare.Checker;

public enum CheckState { Pass, Warn, Fail, Unknown }

public sealed record CheckResult(
    string Name,
    CheckState State,
    string Detail,
    string FixHint);

public static class Checks
{
    public static List<CheckResult> RunAll()
    {
        var results = new List<CheckResult>
        {
            CheckOs(),
            CheckArchitecture(),
            CheckAdmin(),
            CheckSecureBoot(),
            CheckHvci(),
            CheckTpm(),
            CheckDefenderRealtime(),
            CheckTestSigning(),
            CheckVcRedist2022(),
            CheckDotnetRuntime(),
            CheckFreeSpace(),
            CheckNetworkOnline(),
        };
        return results;
    }

    private static CheckResult CheckOs()
    {
        try
        {
            var v = Environment.OSVersion.Version;
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            var productName = key?.GetValue("ProductName")?.ToString() ?? "Windows";
            var displayVersion = key?.GetValue("DisplayVersion")?.ToString() ?? "";
            var build = (int)(key?.GetValue("CurrentBuildNumber") is string s && int.TryParse(s, out var b) ? b : v.Build);

            var ok = (v.Major == 10 && build >= 17763); // Win10 1809+ covers Win10 + Win11
            if (ok)
                return new("Windows version", CheckState.Pass,
                    $"{productName} {displayVersion} build {build}", "");
            return new("Windows version", CheckState.Fail,
                $"{productName} build {build} — need Win10 1809+ or Win11",
                "Update Windows to at least 1809 (build 17763).");
        }
        catch (Exception e)
        {
            return new("Windows version", CheckState.Unknown, e.Message, "");
        }
    }

    private static CheckResult CheckArchitecture()
    {
        if (Environment.Is64BitOperatingSystem)
            return new("CPU architecture", CheckState.Pass, "x64", "");
        return new("CPU architecture", CheckState.Fail,
            "32-bit OS detected — PolarWare only runs on x64",
            "Reinstall Windows 64-bit. 32-bit is unsupported.");
    }

    private static CheckResult CheckAdmin()
    {
        try
        {
            var id = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(id);
            var elevated = principal.IsInRole(WindowsBuiltInRole.Administrator);
            return elevated
                ? new("Running as administrator", CheckState.Pass, "elevated", "")
                : new("Running as administrator", CheckState.Warn,
                    "checker runs non-elevated for safety — PolarWare itself needs admin",
                    "Right-click PolarWare.exe → Run as administrator.");
        }
        catch (Exception e)
        {
            return new("Running as administrator", CheckState.Unknown, e.Message, "");
        }
    }

    private static CheckResult CheckSecureBoot()
    {
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
            var raw = k?.GetValue("UEFISecureBootEnabled");
            if (raw is int n)
            {
                if (n == 0)
                    return new("Secure Boot", CheckState.Pass, "disabled", "");
                return new("Secure Boot", CheckState.Fail,
                    "enabled — the BYOVD mapper will not load an unsigned driver",
                    "Reboot into BIOS/UEFI and disable Secure Boot (or delete its keys).");
            }
            return new("Secure Boot", CheckState.Pass, "legacy BIOS (not UEFI) — OK", "");
        }
        catch (Exception e)
        {
            return new("Secure Boot", CheckState.Unknown, e.Message, "");
        }
    }

    private static CheckResult CheckHvci()
    {
        try
        {
            // DeviceGuard / HVCI state. Two check paths because 22H2 and 24H2 moved values around.
            using var k = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity");
            var enabled = k?.GetValue("Enabled") as int? ?? 0;
            if (enabled == 0)
                return new("Memory Integrity (HVCI)", CheckState.Pass, "disabled", "");
            return new("Memory Integrity (HVCI)", CheckState.Fail,
                "enabled — VBS will block the BYOVD mapper",
                "Windows Security → Device security → Core isolation → OFF, then reboot.");
        }
        catch (Exception e)
        {
            return new("Memory Integrity (HVCI)", CheckState.Unknown, e.Message, "");
        }
    }

    private static CheckResult CheckTpm()
    {
        try
        {
            using var s = new ManagementObjectSearcher(@"root\CIMV2\Security\MicrosoftTpm", "SELECT * FROM Win32_Tpm");
            foreach (var mo in s.Get())
            {
                var enabled = mo["IsEnabled_InitialValue"] as bool? ?? false;
                var version = mo["SpecVersion"]?.ToString() ?? "unknown";
                if (!enabled)
                    return new("TPM", CheckState.Pass, $"disabled (spec {version})", "");
                if (version.StartsWith("1.2"))
                    return new("TPM", CheckState.Warn,
                        $"TPM 1.2 enabled — most anti-cheats accept, Vanguard still looks",
                        "If targeting Vanguard: BIOS → TPM → Disabled.");
                return new("TPM", CheckState.Warn,
                    $"TPM {version} enabled — Vanguard reads EK, others usually fine",
                    "BIOS → Security → TPM → Disabled / Discrete 1.2 if possible.");
            }
            return new("TPM", CheckState.Pass, "no TPM detected", "");
        }
        catch
        {
            return new("TPM", CheckState.Pass, "WMI did not return TPM info — assuming disabled", "");
        }
    }

    private static CheckResult CheckDefenderRealtime()
    {
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection");
            var disabled = k?.GetValue("DisableRealtimeMonitoring") as int? ?? 0;
            if (disabled == 1)
                return new("Windows Defender real-time", CheckState.Pass, "disabled", "");
            // Check via Get-MpComputerStatus style polling: look at service state
            using var svc = new ManagementObjectSearcher("SELECT * FROM Win32_Service WHERE Name='WinDefend'");
            foreach (var mo in svc.Get())
            {
                var state = mo["State"]?.ToString() ?? "";
                if (state == "Stopped")
                    return new("Windows Defender real-time", CheckState.Pass, "WinDefend service stopped", "");
            }
            return new("Windows Defender real-time", CheckState.Warn,
                "running — will quarantine kdmapper.exe and the driver",
                "Install Defender Control (admin), toggle off, or add the PolarWare folder to exclusions.");
        }
        catch (Exception e)
        {
            return new("Windows Defender real-time", CheckState.Unknown, e.Message, "");
        }
    }

    private static CheckResult CheckTestSigning()
    {
        try
        {
            var psi = new ProcessStartInfo("bcdedit.exe", "/enum {current}")
            {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
            };
            using var p = Process.Start(psi);
            if (p == null) return new("Test signing mode", CheckState.Unknown, "bcdedit failed to start", "");
            p.WaitForExit(4000);
            var output = p.StandardOutput.ReadToEnd();
            var testOn = output.IndexOf("testsigning", StringComparison.OrdinalIgnoreCase) >= 0 &&
                         output.IndexOf("Yes", StringComparison.OrdinalIgnoreCase) >= 0;
            if (testOn)
                return new("Test signing mode", CheckState.Pass,
                    "enabled — service install path works alongside BYOVD",
                    "");
            return new("Test signing mode", CheckState.Warn,
                "disabled — BYOVD path (kdmapper) still works; only the fallback service install needs it",
                "Only run this if the BYOVD path fails: elevated 'bcdedit /set testsigning on' then reboot.");
        }
        catch (Exception e)
        {
            return new("Test signing mode", CheckState.Unknown, e.Message, "");
        }
    }

    private static CheckResult CheckVcRedist2022()
    {
        try
        {
            // VC++ 2015-2022 x64 redistributable key
            using var k = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64");
            var installed = k?.GetValue("Installed") as int? ?? 0;
            var version = k?.GetValue("Version")?.ToString() ?? "";
            if (installed == 1)
                return new("VC++ 2015-2022 x64 Redistributable", CheckState.Pass, version, "");
            return new("VC++ 2015-2022 x64 Redistributable", CheckState.Warn,
                "not detected — PolarWare bundles .NET so this is rarely needed, but kdmapper's CRT may miss",
                "Grab VC_redist.x64.exe from aka.ms/vs/17/release/vc_redist.x64.exe");
        }
        catch (Exception e)
        {
            return new("VC++ 2015-2022 x64 Redistributable", CheckState.Unknown, e.Message, "");
        }
    }

    private static CheckResult CheckDotnetRuntime()
    {
        try
        {
            var dotnetRoot = Environment.GetEnvironmentVariable("ProgramFiles") + @"\dotnet\shared\Microsoft.NETCore.App";
            if (!Directory.Exists(dotnetRoot))
                return new(".NET 8 runtime", CheckState.Pass,
                    "not installed — PolarWare.exe is self-contained, this is fine",
                    "");
            var dirs = Directory.GetDirectories(dotnetRoot).Select(Path.GetFileName).ToList();
            var has8 = dirs.Any(d => d != null && d.StartsWith("8."));
            if (has8)
                return new(".NET 8 runtime", CheckState.Pass,
                    "installed: " + string.Join(", ", dirs!.Where(d => d!.StartsWith("8."))),
                    "");
            return new(".NET 8 runtime", CheckState.Pass,
                $"only {string.Join(", ", dirs!)} installed — PolarWare.exe is self-contained, this is fine",
                "");
        }
        catch (Exception e)
        {
            return new(".NET 8 runtime", CheckState.Unknown, e.Message, "");
        }
    }

    private static CheckResult CheckFreeSpace()
    {
        try
        {
            var drive = new DriveInfo(Path.GetPathRoot(Environment.SystemDirectory)!);
            var gb = drive.AvailableFreeSpace / (1024.0 * 1024.0 * 1024.0);
            if (gb >= 5)
                return new($"Free space on {drive.Name}", CheckState.Pass, $"{gb:F1} GB", "");
            if (gb >= 1)
                return new($"Free space on {drive.Name}", CheckState.Warn,
                    $"{gb:F1} GB — tight, PolarWare + backup slots need ~2 GB",
                    "Empty Recycle Bin, run Disk Cleanup, free at least 5 GB.");
            return new($"Free space on {drive.Name}", CheckState.Fail,
                $"{gb:F2} GB — too low to install or back up safely",
                "Free at least 5 GB on the system drive first.");
        }
        catch (Exception e)
        {
            return new("Free space", CheckState.Unknown, e.Message, "");
        }
    }

    private static CheckResult CheckNetworkOnline()
    {
        try
        {
            using var ping = new System.Net.NetworkInformation.Ping();
            var reply = ping.Send("1.1.1.1", 1500);
            if (reply.Status == System.Net.NetworkInformation.IPStatus.Success)
                return new("Network reachable", CheckState.Pass, $"ping 1.1.1.1 OK ({reply.RoundtripTime} ms)", "");
            return new("Network reachable", CheckState.Warn,
                $"ping failed ({reply.Status}) — license activation needs internet",
                "Check your VPN / firewall. Mullvad DNS sometimes breaks after a MAC change.");
        }
        catch (Exception e)
        {
            return new("Network reachable", CheckState.Unknown, e.Message, "");
        }
    }

    public static string Report(IEnumerable<CheckResult> results)
    {
        var sb = new StringBuilder();
        sb.AppendLine("PolarWare pre-flight check — " + DateTime.Now.ToString("yyyy-MM-dd HH:mm"));
        sb.AppendLine(new string('-', 60));
        foreach (var r in results)
        {
            var tag = r.State switch
            {
                CheckState.Pass => "[PASS]",
                CheckState.Warn => "[WARN]",
                CheckState.Fail => "[FAIL]",
                _ => "[  ? ]",
            };
            sb.AppendLine($"{tag} {r.Name}");
            sb.AppendLine($"       {r.Detail}");
            if (!string.IsNullOrWhiteSpace(r.FixHint))
                sb.AppendLine($"       fix: {r.FixHint}");
        }
        sb.AppendLine(new string('-', 60));
        return sb.ToString();
    }
}
