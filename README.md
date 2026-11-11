# PolarWare Checker

Read-only pre-flight diagnostic for the [PolarWare](https://polarware.vercel.app) kernel loader. Runs a dozen checks so you know your system is ready before loading the driver. Modifies nothing.

## Download

Grab the latest `PolarWareChecker.exe` from the [releases page](https://github.com/bbeaudroit/polarware-checker/releases/latest).

Direct link: [PolarWareChecker.exe (latest)](https://github.com/bbeaudroit/polarware-checker/releases/latest/download/PolarWareChecker.exe)

## What it checks

- Administrator rights
- Secure Boot state
- HVCI / Memory Integrity
- Virtualization-Based Security (VBS)
- Windows Defender real-time protection
- Driver Signature Enforcement
- Test signing mode
- Hypervisor launch type
- VM detection (nested virtualization caveats)
- CPU / OS / build

Each check reports **PASS / WARN / FAIL** with a one-line fix hint when relevant.

## Build

```bash
cd src
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true
```

Requires .NET 8 SDK + Windows 10 SDK.

## Links

- Website — https://polarware.vercel.app
- Instructions — https://polarware.vercel.app/instructions
- Discord — https://discord.gg/GZPErdvX7y
