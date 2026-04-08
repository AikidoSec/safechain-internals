# Windows L4 Driver
Kernel-mode WFP redirect driver for SafeChain L4 proxy on Windows.

## TODO
- [x] Implement kernel classify callback for ALE connect redirection and apply remote redirect targets.
- [ ] Register/connect the driver callouts at the WFP connect-redirect layers from user mode (`Fwpm*` provider, sublayer, callouts, filters).
- [ ] Install/package the driver artifacts (`.sys`, INF, catalog/signing) in the Windows packaging flow.
- [x] Add a small user-space driver controller CLI/service for `start`, `stop`, and `update`.
- [ ] Provision the startup registry blob before driver start and keep runtime IOCTL updates in sync with persisted config.
- [ ] Prevent proxy-loop redirection for the local proxy process and redirected/proxied follow-up connections.
- [ ] Add end-to-end verification on Windows for IPv4 redirect, IPv6 redirect, unload/reload, and runtime config updates.

## Requirements
- Windows machine
- Rust tooling (as usual, see other docs)
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
