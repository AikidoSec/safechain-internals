# Windows L4 Driver
Kernel-mode WFP redirect driver for SafeChain L4 proxy on Windows.

## Requirements
- Windows machine
- Rust toolchain (`rustup`, `cargo`).
- `cargo-wdk` (`cargo install cargo-wdk`).
- `cargo-make` (`cargo install --locked cargo-make --no-default-features --features tls-native`).
- Windows Driver Kit environment (recommended: eWDK developer prompt).
- Visual Studio C++ Build Tools + Windows SDK/WDK integration.
- LLVM/Clang 17 on `PATH` (used by `bindgen` via `wdk-build`/`wdk-sys`).
- Workspace root must have `Cargo.lock` present.

## Install WDK
1. Install Visual Studio 2022 Build Tools (or Visual Studio 2022) with:
- `Desktop development with C++`
- `MSVC v143` toolchain
- `Windows 10/11 SDK`
  <https://learn.microsoft.com/en-us/windows/apps/windows-sdk/downloads>
2. Install the Windows Driver Kit (WDK) matching your installed Windows SDK version:
- Download from the official Microsoft WDK page and run the installer:
  <https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk>
3. Open a Developer PowerShell (or eWDK prompt) and verify headers exist:
- `Test-Path "C:\Program Files (x86)\Windows Kits\10\Include\<SDK_VERSION>\km\crt"`
4. If the path above is missing, repair/reinstall SDK + WDK so the same `<SDK_VERSION>` is installed for both.

In case `wdk-sys` picks up the wrong WDK version you can set it
all manually prior to building/checking:

```ps
$env:WDKContentRoot = "C:\Program Files (x86)\Windows Kits\10\"
$env:Version_Number = "10.0.26100.0"
$env:WindowsSDKVersion = "10.0.26100.0\"
```

## Build
- `just windows-driver-build`
- `just windows-driver-build release amd64`
- `just windows-driver-build-verify`
