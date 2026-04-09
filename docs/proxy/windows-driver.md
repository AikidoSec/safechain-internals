# Windows L4 Driver
Kernel-mode WFP redirect driver for SafeChain L4 proxy on Windows.

## TODO
- [x] Implement kernel classify callback for ALE connect redirection and apply remote redirect targets.
- [x] Register/connect the driver callouts at the WFP connect-redirect layers from user mode (`Fwpm*` provider, sublayer, callouts, filters).
- [x] Install/package the driver artifacts for local/dev Windows usage (`.sys`, INF staging, optional catalog generation hook, install/remove scripts).
- [x] Add a small user-space driver controller CLI/service for `start`, `stop`, and `update`.
- [x] Provision the startup registry blob before driver start and keep runtime IOCTL updates in sync with persisted config.
- [x] Prevent proxy-loop redirection for the local proxy process and redirected/proxied follow-up connections.
- [ ] Add end-to-end verification on Windows for IPv4 redirect, IPv6 redirect, unload/reload, and runtime config updates.

## Production TODO
- [ ] Add production driver package signing flow (`.cat` / release-signing path).
- [ ] Decide and document the intended production signing route (attestation vs WHQL/HLK-backed path).
- [ ] Wire production-ready driver artifacts into the MSI/distribution flow.
- [ ] Add production-grade install/uninstall rollback and upgrade handling.
- [ ] Add production validation and compatibility/signing verification across supported Windows targets.

## Packaging Scope
The current packaging goal is local/development install only.

That means it is acceptable for now to:
- build and stage the driver package locally on a Windows developer machine;
- generate the final `.inf` and `.cat` locally;
- use development or test-signing flows for install/load on development systems;
- install/remove the package through local tooling such as `pnputil`.

It does not yet need to satisfy public-distribution requirements such as Microsoft dashboard signing, WHQL/HLK validation, production certificate handling, or consumer-friendly MSI-only install UX.

## Local/Dev Packaging Requirements
To complete the current TODO item for local/dev usage, the Windows packaging flow still needs to do all of the following:

1. Build and stage the driver binary.
- Produce the final driver `.sys` from [`proxy-lib-l4-windows-driver`](/C:/Users/glendc/Documents/GitHub/safechain-internals/proxy-lib-l4-windows-driver).
- Copy it into a packaging/staging directory used by the Windows installer flow.

2. Turn the INF template into a real INF.
- Convert [`safechain_lib_l4_proxy_windows_driver.inx`](/C:/Users/glendc/Documents/GitHub/safechain-internals/proxy-lib-l4-windows-driver/safechain_lib_l4_proxy_windows_driver.inx) into a concrete `.inf`.
- Ensure the file names and service/binary names match the actual staged driver artifact names.

3. Generate a catalog file.
- Run `Inf2Cat` over the staged driver package directory so the package has a `.cat`.
- This is the standard Windows tool for generating an unsigned catalog from an INF-based driver package.
- Microsoft docs: [Inf2Cat](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/inf2cat)

4. Add a development signing flow.
- For local/dev, test-signing or another development-only signing workflow is acceptable.
- The package should be signed in a way that allows it to install/load on the intended development systems.
- Microsoft docs: [Test-Signing Driver Packages](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/test-signing-driver-packages)

5. Package the driver artifacts into the Windows install flow.
- Update [`EndpointProtection.wxs`](/C:/Users/glendc/Documents/GitHub/safechain-internals/packaging/windows/EndpointProtection.wxs) so the driver package files are included:
  - `.sys`
  - generated `.inf`
  - generated `.cat`
  - and, if needed during install, the Windows driver-object helper binary

6. Add install/remove actions.
- Install the driver package during setup, most likely via `pnputil /add-driver <inf> /install`.
- Remove the driver package during uninstall.
- Microsoft docs: [PnPUtil Command Line Tool for Driver Packages](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/pnputil)

7. Verify the development flow end-to-end.
- Fresh install on a development machine.
- Upgrade/reinstall behavior.
- Uninstall/cleanup behavior.
- Confirm the driver service loads and the callout path can be exercised after install.

## Production Gap
If this later needs to become a production-distributable Windows driver package, the following work is still missing beyond the local/dev scope:

1. Production signing and Microsoft acceptance path.
- Modern 64-bit Windows production drivers generally need Microsoft-signed packages through the Hardware Dev Center process.
- This is stricter than ordinary EXE/MSI signing.
- Microsoft docs: [Driver Signing Policy](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-policy--windows-vista-and-later-), [Driver signing](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/driver-signing), [Kernel-Mode Code Signing Requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-requirements--windows-vista-and-later-)

2. Decide production submission route.
- Attestation signing may be sufficient for some scenarios.
- WHQL/HLK-backed signing may be needed if broader compatibility or certification requirements apply.
- Microsoft docs: [Release Signing](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/release-signing)

3. Production certificate and CI handling.
- EV certificate / Hardware Dev Center onboarding.
- Secure handling of release signing credentials.
- CI steps that distinguish development signing from release signing.

4. Stronger installer behavior.
- Robust rollback if package install partially fails.
- Upgrade-safe migration behavior.
- Better uninstall semantics when the driver is in use.
- Clear user/admin privilege handling and diagnostics.

5. Compliance and validation.
- Test matrix across supported Windows versions.
- HLK/compatibility validation if required by the chosen release-signing path.
- Production verification that install, boot/load, redirect behavior, and uninstall are all stable.

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

## Local/Dev Driver Package Flow

Build and stage the driver package:

```
just windows-driver-build
just windows-driver-package-stage
```

That stages the local/dev package under:

```
dist/windows-driver-package/debug
```

By default the staging script:
- copies the built `.sys`;
- renders the `.inf` from the checked-in `.inx` template;
- attempts to run `Inf2Cat` when it is available on `PATH`.

You can install/remove the staged package with:

```
just windows-driver-package-install
just windows-driver-package-remove
```

Notes:
- `pnputil` and driver install/remove operations require an elevated shell.
- `Inf2Cat` comes from the Windows Driver Kit tooling; if it is missing, staging still completes but the catalog step is skipped.
- This flow is intentionally local/dev oriented and not yet a production signing/distribution flow.
