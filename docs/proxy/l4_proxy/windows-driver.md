# Windows L4 Driver
Kernel-mode WFP redirect driver for SafeChain L4 proxy on Windows.

## TODO
- [x] Implement kernel classify callback for ALE connect redirection and apply remote redirect targets.
- [x] Register/connect the driver callouts at the WFP connect-redirect layers from user mode (`Fwpm*` provider, sublayer, callouts, filters).
- [x] Install/package the driver artifacts for local/dev Windows usage (`.sys`, INF staging, optional catalog generation hook, install/remove scripts).
- [x] Add a small user-space driver controller CLI/service for `enable`, `disable`, and `update`.
- [x] Keep the driver runtime-configurable from user space without relying on persisted proxy endpoint state across restarts.
- [x] Prevent proxy-loop redirection for the local proxy process and redirected/proxied follow-up connections.
- [ ] Add end-to-end verification on Windows for IPv4 redirect, IPv6 redirect, unload/reload, and runtime config updates.
- [ ] Ensure proxy (driver) is compatible with VPNs .. e.g. wireguard

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

> Make sure that your Windows SDK and NDK versions match!

## Local/Dev Driver Package Flow

Build and stage the driver package:

```
just windows-driver-build
just windows-driver-package-stage
```

> Normally powershell scripts (even when elavated) might not run your script.
> You can allow it for the current session using:
>
> ```ps
> Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
> ```
>
> These and other just commands provided in this repo do this for you already.

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

> Should you for some reason not be able to remove the device,
> you can do so manually using `Device Manager`,
> where you will be able to find the `Safechain L4 Proxy Driver` undewr
> System drivers...
>
> As per usual, a reboot is required after cleaning up.

As a developer the easiest to run for a new build, packe and install,
e.g. after a code change, is:

```
just windows-driver-package-install-fresh-debug
```

After that you just need to "update" the driver with the proxy address(es)
and off you go.

## Local/Dev Windows Driver Validation

After staging and installing the driver package, run:

```powershell
just windows-driver-package-verify
```

This verifies:

* the driver package is staged and present
* the driver service exists
* the driver is loaded
* the installed `.sys` file exists
* test signing mode is enabled
* the Base Filtering Engine service is running
* the driver service registry entry exists
* the WFP state contains the expected SafeChain provider, sublayer, callout, and filter GUIDs

The verification checks these WFP GUIDs:

> Truth of source for these GUIDs and other constants
> can at any time be found at `proxy-lib-nostd\src\windows\driver_protocol.rs`
>
> It's a manual task to keep them up to date in docs and powershell scripts,
> not that they should change often, if ever.

* Provider: `{6A625BB6-F310-443E-9850-280FACDC1A21}`
* Sublayer: `{D95A6EAF-3882-495F-858C-65C2CE3F6A07}`
* TCP connect redirect callout v4: `{5C6262C4-8EF6-43D8-A8F9-48636B172BB8}`
* TCP connect redirect callout v6: `{4F05F1F8-9093-44F1-A8E7-2D841A3E2E5A}`
* TCP connect redirect filter v4: `{DB5B9241-4532-4517-B0E0-6F85E4E631F8}`
* TCP connect redirect filter v6: `{4B60D58C-85FD-4FB1-8256-8C4E6053E43A}`

A successful verification means the driver is not only installed, but also visible in the WFP state with the expected registration objects.

Until you actually ran the `start` command with your ipv4/ipv6 proxy configured, you will not actually
see those GUIDs registered or even see your driver active. E.g.:

```ps
just run-windows-driver-cli start \
  --ipv4-proxy 127.0.0.1:52647
```

### Validate via Windows GUI

Use these built in Windows tools for a quick manual check:

* **System Information**: open `msinfo32`, then go to **Software Environment > System Drivers** and confirm the SafeChain driver exists and is running
* **Services**: open `services.msc` and confirm **Base Filtering Engine** is running
* **Registry Editor**: open `regedit` and inspect `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\safechain_lib_l4_proxy_windows_driver`
* **Event Viewer**: open **Windows Logs > System** and look for driver load, signature, or WFP related errors
* **WFP state dump**: run `netsh wfp show state file=%TEMP%\safechain_wfpstate.xml`, open the XML file, and search for the SafeChain GUIDs above

The PowerShell verification script is the preferred validation path because it checks the full install and WFP registration state in one pass.

### RegEdit

Run `regedit` evalated and you should also be able to find the registry key
for the safechain l4 proxy (windows) at:

```
Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SafeChainL4Proxy
```

### SysInternals Utilities

Utilities that are useful when working with windows drivers,
and other system tasks on the Windows OS.

Available at: <https://learn.microsoft.com/en-us/sysinternals/downloads/>

Useful tools in particular (run them as administrator == elevated):

- `winobj`: access and display information about driver objects (is my driver object created?).
  - You can find the driver (object) itself under `Driver`
  - The actual symbolic link through which userspace processes communicate with the driver,
    can be found under `Global??` (even Microsoft is not sure apparently... joking ofc)
- `procexp` (Process Explorer): see how your loaded system driver (`.sys`)
  is doing (filter on `safechain`)
- `dbgview` (DebugView): capture (kernel) "debug" output (see dedicated doc chapter for it below)

#### DebugView

Before you can see trace output for the windows driver via `DebugView` you will need to enable tracing
by adding a key named `Debug Print Filter` (_DWORD_ value named `DEFAULT` with as value `8`) in:

```
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager
```

Also ensure to enable debug logging using:

```ps1
bcdedit /debug on
```

You will have to restart your system for this to take effect.

Once you have that filter setup correctly you can open `DebugView`
in elevated mode, and make sure to "Capture Kernel", you can deselect
user-mode capturees (win32 and Global win32) to reduce noise.

When starting/updating/stopping the SafechainL4Proxy sys driver
you should now see these logs appear there. You can filter them if you wish using the
prefix `[safechain-l4-windows-driver]` prefix.

> NOTE: this is about the log output of the `windows driver`!!
> Not about the trace output of any userspace processes such as:
>
> - `safechain_l4_proxy_windows_driver_object` (CC CLI);
> - or `safechain_l4_proxy` (userspace MITM proxy)
>
> These are just logging to stderr/file output as per usual.

The driver, written in `Rust`, makes use of `wdk::println` for this,
which roughly translates to code similar to a C/C++ tracing code generated
in such drivers using the `kDPrint` macro.

These logs are not stored _unless_ "something" is capturing these.
The easiest to do this is through the `DebugViewer`, locally or remote.

### WinDbg

Essential on Windows is the `WinDbg` utility (which ships with the Windows SDK).
You can run it via the start menu as adminstrator by looking for `WinDbg`.
Probably it will show up as the "x64" variant.

It can be used for debug both userspace processes as well as kernel processes.

E.g. the L4 safechain (userspace) proxy can be debugged using it,
similar to how you would use `gdb` / `lldb` on unix platforms.

Some essential commands for userspace processes:

- `~`: shows information about all threads in the debugged process
  (for safechain-l4-proxy this will show mostly generic "tokio" threads given we do not give them custom names (yet))
- The "current" thread will have a subtle "dot" in front of its name, to switch thread
  use `~ns` where `n` is the number of the thread
- using `k` you can view the stack of a thread, a shortcut to see the stack for a specific thread is `~nk`
  where `n` is the number of the thread
- for breakpoints you can use `bp <symbol>` to set a breakpoint for a specific symbol, and use `bl` to list all existing breakpoints.

See the documentation of `WinDbg ` for more information on more commands and how to use it.
In most cases you will not require this, but in case the userspace proxy ever behaves very odd (e.g. feels stuck),
a tool like this can be pretty essential to narrow down the exact issue (if you can reproduce it ofc...)

It is used in similar ways for debugging a kernel driver, but in this case you will need to
run the kernel driver in a VM to which you can connect to from the host on which you'll run `WinDbg`.
This by communicating over a COM. Once you have set this up the UX is pretty similar to debugging
userspace processes.
