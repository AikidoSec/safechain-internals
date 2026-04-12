# Windows L4 Driver
Kernel-mode WFP driver for the Windows L4 proxy.

For production/release packaging and signing, see [windows-driver-prod.md](/C:/Users/glendc/Documents/GitHub/safechain-internals/docs/proxy/l4_proxy/windows-driver-prod.md).

## Scope

This document is the day-to-day developer and operator guide for the Windows driver:
- local/dev build and staging;
- fresh install;
- updating a machine that already has the driver;
- verification and debugging;
- runtime behavior and WFP terminology.

## Requirements

- Windows machine
- Rust tooling
- Visual Studio C++ Build Tools with:
  - `Desktop development with C++`
  - `MSVC v143`
  - `Windows 10/11 SDK`
- Windows Driver Kit matching the installed SDK
- LLVM/Clang 17 on `PATH`

Quick check after installing SDK + WDK:

```powershell
Test-Path "C:\Program Files (x86)\Windows Kits\10\Include\<SDK_VERSION>\km\crt"
```

## Build And Stage

Build the driver and stage a local/dev package:

```powershell
just windows-driver-build
just windows-driver-package-stage
```

That produces a staged package under:

```text
dist/windows-driver-package/debug
```

By default staging:
- copies the built `.sys`;
- renders the checked-in `.inx` template into a concrete `.inf`;
- runs `Inf2Cat` when available;
- signs the generated catalog with the configured local code-signing cert.

> Hint:
>
> If you do not yet have a cert setup for local development (of windows kernel driver),
> you can do so using a single command + a reboot:
>
> ```ps1
> just windows-install-root-crt
> ```

## Fresh Install

Use this on a machine that does not already have the current driver package installed:

```powershell
just windows-driver-package-install
```

Or, for the full clean local/dev flow:

```powershell
just windows-driver-package-install-fresh-debug
```

That recipe:
- runs the usual QA/build checks;
- disables the currently running runtime config path;
- removes the old driver package;
- rebuilds and restages the driver;
- installs the fresh package.

After install:
1. Reboot Windows.
2. Start `safechain-l4-proxy`.

Once the proxy starts, it automatically synchronizes its live IPv4 bind and optional IPv6 bind into the driver runtime config. There is no separate manual runtime-config step anymore.

In practice this means the `safechain-l4-proxy-windows-driver-object` CLI is no longer part of the normal install/start flow.
It is now mostly optional extra tooling for inspection, manual experiments, or recovery scenarios.
Day-to-day usage should generally rely on:
- the PowerShell packaging/install/update scripts for driver lifecycle;
- `safechain-l4-proxy` for runtime registration;
- the driver's own proxy-PID exit handling to clear stale runtime config.

## Update An Existing Driver

When the machine already has a driver installed and you want to replace it with a newer build:

```powershell
just windows-driver-build
just windows-driver-package-stage
just windows-driver-package-install
```

The install script is intentionally written as an install-or-update path. It uses `pnputil /add-driver ... /install`, preserves the existing service/hardware identity, and stages the updated package for activation.

After an update:
1. Reboot Windows so the new driver package is active.
2. Start `safechain-l4-proxy`.

If you want the most conservative dev update flow, use `just windows-driver-package-install-fresh-debug` instead.

Again, the driver-object CLI is typically not needed for this update path.

## Remove

To remove the currently installed local/dev driver package:

```powershell
just windows-driver-package-remove
```

If Windows keeps the device around, remove it manually via Device Manager and reboot.

## Verify

After installing or updating the driver package, run:

```powershell
just windows-driver-package-verify
```

This verifies:
- the staged package exists;
- the driver service exists;
- the driver is loaded;
- the installed `.sys` exists;
- test-signing state;
- Base Filtering Engine state;
- the service registry entry;
- the expected SafeChain WFP provider, sublayer, callout, and filter GUIDs.

The verification script checks these WFP GUIDs:

- Provider: `{6A625BB6-F310-443E-9850-280FACDC1A21}`
- Sublayer: `{D95A6EAF-3882-495F-858C-65C2CE3F6A07}`
- TCP connect redirect callout v4: `{5C6262C4-8EF6-43D8-A8F9-48636B172BB8}`
- TCP connect redirect callout v6: `{4F05F1F8-9093-44F1-A8E7-2D841A3E2E5A}`
- TCP connect redirect filter v4: `{DB5B9241-4532-4517-B0E0-6F85E4E631F8}`
- TCP connect redirect filter v6: `{4B60D58C-85FD-4FB1-8256-8C4E6053E43A}`
- UDP auth-connect block callout v4: `{87053C13-7C73-4E52-8DDD-F82B3856EF41}`
- UDP auth-connect block callout v6: `{27B8A5FA-66B5-451C-A566-B79478B52A81}`
- UDP auth-connect block filter v4: `{E4B805FC-B3AB-45E8-8F04-200DCBC00955}`
- UDP auth-connect block filter v6: `{FCBAB31F-7DFB-4128-8196-559FE0E0E8B4}`

Source of truth for these GUIDs is [driver_protocol.rs](/C:/Users/glendc/Documents/GitHub/safechain-internals/proxy-lib-nostd/src/windows/driver_protocol.rs).

## Runtime Behavior

The driver is intentionally fail-open when it cannot safely redirect TCP traffic.

Outbound TCP is permitted directly when:
- no proxy endpoint is configured for that address family;
- the destination is local/private traffic;
- the destination is TCP port `53`;
- redirect context encoding fails.

The stale-runtime-config edge case is handled separately. The driver registers a kernel process notification callback and clears any configured proxy endpoint whose tracked proxy PID exits.

Source process paths are resolved from the source PID in-kernel during classify. We do not rely on the `processPath` metadata or `ALE_APP_ID` fixed values for our current flow.

For UDP:
- the driver never redirects;
- UDP/443 is intercepted at ALE auth-connect v4/v6;
- Chromium-family browsers are blocked on UDP/443;
- everything else is passed through.

## Validate Via Windows GUI

Useful manual checks:

- `msinfo32` -> `Software Environment > System Drivers`
- `services.msc` -> confirm `Base Filtering Engine` is running
- `regedit` -> `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SafeChainL4Proxy`
- Event Viewer -> `Windows Logs > System`
- `netsh wfp show state file=%TEMP%\safechain_wfpstate.xml`

## Glossary

### `layer id`

The WFP layer id identifies the filtering stage that invoked the classify callback.

Important layers for this driver:
- `FWPS_LAYER_ALE_CONNECT_REDIRECT_V4`
- `FWPS_LAYER_ALE_CONNECT_REDIRECT_V6`
- `FWPS_LAYER_ALE_AUTH_CONNECT_V4`
- `FWPS_LAYER_ALE_AUTH_CONNECT_V6`

The connect-redirect layers are where TCP destinations can still be rewritten.

The auth-connect layers are earlier policy checkpoints. We currently use them for UDP block/pass decisions only.

### `callout`

A callout is the kernel callback implementation registered with WFP.

This driver currently registers four callouts:
- IPv4 TCP connect redirect
- IPv6 TCP connect redirect
- IPv4 UDP auth-connect block
- IPv6 UDP auth-connect block

### `filter`

A filter is the WFP rule that selects traffic and binds it to a callout at a given layer.

### `classify callback`

This is the driver function WFP invokes for matching traffic. In our code it decides:
- passthrough;
- TCP redirect to the local L4 proxy;
- UDP block.

### `redirect handle`

The redirect handle is created through `FwpsRedirectHandleCreate0` and attached to redirected TCP flows so Windows tracks the redirection correctly.

### `runtime config`

Runtime config is the in-memory driver state updated from user space through IOCTLs. Today that is mainly:
- active IPv4 proxy endpoint;
- active IPv6 proxy endpoint;
- proxy PID tracking.

It is not persisted across driver reloads. The proxy repopulates it on startup.

### `source pid`

The source pid is the process id reported for the outbound flow that triggered classification.

### `source process path`

The source process path is the executable image path resolved from that source pid during classify.

## Tools

Useful Windows tools while debugging:

- `winobj`
- `procexp`
- `dbgview`
- `WinDbg`

For registry inspection, the service key is:

```text
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
