# Aikido Device Protection — Binary Releases

This repository exists solely to host **Aikido Device Protection** binary releases. It publishes only the installer artifacts (`.msi` for Windows and `.pkg` for macOS).

It serves as a transitional release channel until auto-updating clients migrate to the new distribution mechanism on versions **1.6.1 and later**.

## How releases work

Pushing a tag matching `v*` triggers the [Release from S3](.github/workflows/release-from-s3.yml) workflow, which:

1. Downloads `EndpointProtection.msi` and `EndpointProtection.pkg` from S3 for that tag.
2. Creates a **draft** GitHub release with both installers attached.
