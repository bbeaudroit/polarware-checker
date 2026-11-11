# PolarWare Checker

Windows x64 desktop diagnostic with six tabs for system information, hardware UUID,
Windows protections, installed utilities, and Visual C++ runtimes.

The hardware UUID comes from Windows and can be copied locally. Refresh re-reads
the current state. Windows Security and Installed apps open the corresponding
Windows settings.

The Visual C++ Install buttons download official Microsoft packages on demand and
check the Authenticode publisher before launch. Uninstall is offered for supported
machine-wide registered uninstallers. DirectX is shown for information.

## Build

Run from the repository root with the .NET SDK:

    dotnet publish src -c Release -r win-x64 --self-contained true

The single-file executable is under the project's Release publish directory.
