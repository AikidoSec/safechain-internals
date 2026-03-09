# SafeChain L7 macOS Xcode Wrapper

This wrapper lets Xcode manage signing/provisioning for the L7 Rust proxy app identity (`com.aikido.endpoint.proxy.l7`) while still running the Rust binary itself.

## Requirements

- Xcode logged into an Apple account with access to team `7VPF8GD6J4`
- `xcodegen` installed

## Local flow

```bash
just macos-l7-xcodegen-generate
just macos-l7-xcodegen-build-debug
just macos-l7-xcode-verify-signing
just run-macos-l7-proxy-protected-xcode
```

`xcodebuild` uses `-allowProvisioningUpdates` in the just recipe so Xcode can resolve/update signing assets automatically.
