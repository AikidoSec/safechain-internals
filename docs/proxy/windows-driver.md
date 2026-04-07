# Windows L4 Driver
Kernel-mode WFP redirect driver for SafeChain L4 proxy on Windows.

## Requirements
- Windows machine
- Windows Driver Kit environment.
- Visual Studio C++ Build Tools + Windows SDK/WDK integration.
- LLVM/Clang 17 on `PATH` (used by `bindgen` via `wdk-build`/`wdk-sys`).
- Workspace root must have `Cargo.lock` present.

## Install WDK
1. Install Visual Studio 2022 Build Tools (or Visual Studio 2022) with:
- `Desktop development with C++`
- `MSVC v143` toolchain
- `Windows 10/11 SDK`
  <https://learn.microsoft.com/en-us/windows/apps/windows-sdk/downloads> (`10.0.26100`)
2. Install the Windows Driver Kit (WDK) matching your installed Windows SDK version:
- Download from the official Microsoft WDK page and run the installer:
  <https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk> (`10.0.26100`)
3. Open a Developer PowerShell (or eWDK prompt) and verify headers exist:
- `Test-Path "C:\Program Files (x86)\Windows Kits\10\Include\<SDK_VERSION>\km\crt"`
4. If the path above is missing, repair/reinstall SDK + WDK so the same `<SDK_VERSION>` is installed for both.

## Build

```
just windows-driver-build
```
