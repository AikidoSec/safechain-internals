# Windows L4 Driver Production Release
Production/release notes for the Windows L4 driver.

This document is intentionally short. It is for colleagues preparing a signed release package, not for day-to-day driver development.

For local/dev build, install, update, validation, and glossary notes, see [windows-driver.md](/C:/Users/glendc/Documents/GitHub/safechain-internals/docs/proxy/l4_proxy/windows-driver.md).

## Release Inputs

Before cutting a release, make sure you have:
- the target release version `X.Y.Z`;
- access to the proper Aikido code-signing certificate/private key used for Windows releases;
- Windows SDK + WDK + `SignTool.exe` + `Inf2Cat.exe`;
- any required Microsoft Hardware Dev Center / attestation / WHQL access for the final production signing path.

## Versioning

Sync the repo versioned files first:

```bash
./scripts/sync-versions.sh --version X.Y.Z
```

That updates the shared version locations used by the repo, including the Windows packaging metadata that should stay aligned with the release.

## Build A Release Driver Package

Build the release driver binary and stage a release package:

```powershell
just windows-driver-build release
just windows-driver-package-stage release
```

That stages the release driver package under:

```text
dist/windows-driver-package/release
```

If you need to sign the staged catalog with the production Aikido certificate directly from this repo flow, use the staging script with the production certificate subject instead of the local test cert default:

```powershell
./packaging/windows/stage-driver-package.ps1 -Profile release -CertSubject "CN=<Aikido production cert subject>"
```

Use the current Aikido production code-signing certificate and timestamping policy for the actual release. Do not use the local test certificate flow for production packages.

If your final production flow requires Microsoft attestation or WHQL/HLK-backed signing, treat the locally staged package as the input artifact for that external signing step.

If you are also producing the outer Windows installer for the product, build it with the same release version:

```powershell
./packaging/windows/build-msi.ps1 -Version X.Y.Z -BinDir .\bin -OutputDir .\dist
```

That MSI step is separate from kernel driver package signing. The driver package still needs to be correctly signed and upgrade-tested on its own.

## Fresh Production Install

On a system without the driver already installed:

```powershell
./packaging/windows/install-driver-package.ps1 -PackageDir .\dist\windows-driver-package\release
```

Then:
1. Reboot Windows.
2. Start `safechain-l4-proxy`.

The proxy will push its live IPv4 bind and optional IPv6 bind into the driver runtime config automatically.

## Update A System With An Existing Driver

For an in-place driver package update on a system that already has the driver installed:

```powershell
./packaging/windows/install-driver-package.ps1 -PackageDir .\dist\windows-driver-package\release
```

The install script is install-or-update oriented and uses `pnputil /add-driver ... /install`. In other words, the same command is used for fresh install and update; the operational difference is only whether the machine already had a prior package.

After updating:
1. Reboot Windows so the new driver package becomes active.
2. Start `safechain-l4-proxy`.

If the driver is shipped inside the broader Windows installer, make sure the MSI upgrade path still results in the same outcome:
- new signed driver package staged;
- old package replaced cleanly;
- reboot required before activation.

## Verify The Release Package

Run:

```powershell
just windows-driver-package-verify -OutputDir .\dist\windows-driver-package\release
```

Minimum expectations before release:
- package contains `.sys`, `.inf`, and `.cat`;
- the catalog signature is valid;
- the driver installs on a clean machine;
- the driver updates cleanly on a machine with an existing driver;
- reboot activates the new package;
- `safechain-l4-proxy` repopulates runtime config after startup.

## Notes

- The source of truth for driver WFP GUIDs is [driver_protocol.rs](/C:/Users/glendc/Documents/GitHub/safechain-internals/proxy-lib-nostd/src/windows/driver_protocol.rs).
- The outer Windows product installer can be built via [build-msi.ps1](/C:/Users/glendc/Documents/GitHub/safechain-internals/packaging/windows/build-msi.ps1), but that is separate from the kernel driver package signing step.
- If the org-level production signing path changes, update this document and the packaging scripts together.
