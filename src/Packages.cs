using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Text.RegularExpressions;

namespace PolarWare.Checker;

internal sealed record Package(string Name, string Years, string Architecture, string Url)
{
    internal DiagnosticRow Detect(List<InstalledApp>? apps)
    {
        if (apps == null) return new(Name, "—", "Unknown");
        var app = apps.Where(a => Regex.IsMatch(a.Name,
            $@"^Microsoft Visual C\+\+ {Years} Redistributable\s*\({Architecture}\)",
            RegexOptions.IgnoreCase))
            .OrderByDescending(a => Version.TryParse(a.Version.TrimStart('v'), out var version) ? version : null)
            .FirstOrDefault();
        return new(Name, app?.Version ?? "—", app == null ? "Not installed" : "Installed", this, app);
    }
}

internal static class Packages
{
    private static readonly HttpClient Client = new() { Timeout = TimeSpan.FromMinutes(3) };
    internal static readonly Package[] Catalog = [Legacy("x64"), Legacy("x86"), Modern("x64"), Modern("x86")];

    private static Package Legacy(string arch) => new($"Visual C++ 2013 {arch}", "2013", arch,
        $"https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_{arch}.exe");

    private static Package Modern(string arch) => new($"Visual C++ 2015–2022 {arch}",
        @"(?:2015(?:-20\d\d)?|2017|2019|2022|v14)", arch,
        $"https://aka.ms/vs/17/release/vc_redist.{arch}.exe");

    internal static string? CachedInstaller(InstalledApp? app)
    {
        var match = Regex.Match(app?.Uninstaller ?? "", @"^""(?<file>[^""]+\.exe)""\s+/uninstall\s*$", RegexOptions.IgnoreCase);
        return match.Success && Path.IsPathFullyQualified(match.Groups["file"].Value)
            ? match.Groups["file"].Value : null;
    }

    internal static async Task<string> ExecuteAsync(DiagnosticRow row)
    {
        if (row.Action == "Uninstall" && row.Installed is { } installed)
        {
            if (installed.Product is Guid product)
                return await RunAsync(Path.Combine(Environment.SystemDirectory, "msiexec.exe"), $"/x {product:B} /norestart");
            var cached = CachedInstaller(installed) ?? throw new IOException("Registered installer unavailable.");
            await VerifyAsync(cached);
            return await RunAsync(cached, "/uninstall /passive /norestart");
        }

        var package = row.Package ?? throw new InvalidOperationException("Package unavailable.");
        var directory = Directory.CreateTempSubdirectory("polarware-vc-");
        var executable = Path.Combine(directory.FullName, $"vcredist_{package.Architecture}.exe");
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(3));
            using (var output = File.Create(executable))
            using (var input = await Client.GetStreamAsync(package.Url, timeout.Token))
                await input.CopyToAsync(output, timeout.Token);
            await VerifyAsync(executable);
            return await RunAsync(executable, "/install /passive /norestart");
        }
        finally
        {
            try { File.Delete(executable); directory.Delete(); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    private static async Task VerifyAsync(string executable)
    {
        var powershell = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
        var start = new ProcessStartInfo(powershell)
        {
            UseShellExecute = false,
            CreateNoWindow = true
        };
        foreach (var argument in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
            "$s = Get-AuthenticodeSignature -LiteralPath $env:POLAR_PACKAGE; if ($s.Status -eq 'Valid' -and $s.SignerCertificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) -eq 'Microsoft Corporation') { exit 0 }; exit 1" })
            start.ArgumentList.Add(argument);
        start.Environment["POLAR_PACKAGE"] = executable;
        using var process = Process.Start(start) ?? throw new IOException("Signature verification could not start.");
        await process.WaitForExitAsync();
        if (process.ExitCode != 0) throw new IOException("Microsoft signature verification failed.");
    }

    private static async Task<string> RunAsync(string file, string arguments)
    {
        using var process = Process.Start(new ProcessStartInfo(file, arguments) { UseShellExecute = true })
            ?? throw new IOException("Installer could not start.");
        await process.WaitForExitAsync();
        return process.ExitCode switch
        {
            0 => "Package operation completed.",
            3010 or 1641 => "Package operation completed. Restart required.",
            1602 or 1223 or unchecked((int)0x80070642) or unchecked((int)0x800704C7) => "Operation canceled.",
            _ => $"Installer returned error 0x{process.ExitCode:X8}."
        };
    }
}
