# Build the SafeChain Windows L4 driver and prepare it for MSI bundling.
#
# This orchestrator script:
# 1. Ensures a self-signed code-signing cert exists in CurrentUser\My (and exports the .cer).
# 2. Installs cargo-wdk if missing.
# 3. Builds the kernel driver via `cargo wdk build`.
# 4. Stages the driver package (renders .inf, runs Inf2Cat, signs the catalog).
# 5. Copies the staged .sys/.inf/.cat plus the .cer into a flat bundle dir
#    that the MSI build (build-msi.ps1) will pick up.
#
# Production CI keeps using AzureSignTool for both binaries and catalog; this
# script is intended for the local/dev `make build-pkg-sign-local` flow.

param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("dev", "release")]
    [string]$Profile = "dev",

    [Parameter(Mandatory = $false)]
    [string]$BundleDir = ".\bin\driver",

    [Parameter(Mandatory = $false)]
    [string]$CertSubject = "CN=SafeChain Test",

    [Parameter(Mandatory = $false)]
    [string]$CertExportDir = ".\dist\windows-driver-cert",

    [Parameter(Mandatory = $false)]
    [switch]$SkipCert,

    [Parameter(Mandatory = $false)]
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"

$ProjectDir = (Get-Item (Split-Path -Parent $MyInvocation.MyCommand.Path)).Parent.Parent.FullName
$DriverDir = Join-Path $ProjectDir "proxy-lib-l4-windows-driver"
$WorkspaceCargoToml = Join-Path $ProjectDir "Cargo.toml"

$StageProfile = if ($Profile -eq "release") { "release" } else { "debug" }
$StagingDir = Join-Path $ProjectDir "dist\windows-driver-package\$StageProfile"

$CreateCertScript = Join-Path $ProjectDir "packaging\windows\create-test-cert.ps1"
$StageScript = Join-Path $ProjectDir "packaging\windows\stage-driver-package.ps1"

if (-not [System.IO.Path]::IsPathRooted($BundleDir)) {
    $BundleDir = [System.IO.Path]::GetFullPath((Join-Path (Get-Location).Path $BundleDir))
}
if (-not [System.IO.Path]::IsPathRooted($CertExportDir)) {
    $CertExportDir = [System.IO.Path]::GetFullPath((Join-Path (Get-Location).Path $CertExportDir))
}

$BundledCertFileName = "safechain-driver.cer"

Write-Host "==> Building Windows L4 driver and staging MSI bundle" -ForegroundColor Cyan
Write-Host "  cargo profile  : $Profile"
Write-Host "  stage profile  : $StageProfile"
Write-Host "  cert subject   : $CertSubject"
Write-Host "  cert export    : $CertExportDir"
Write-Host "  staging dir    : $StagingDir"
Write-Host "  bundle output  : $BundleDir"

if (-not (Test-Path $CreateCertScript)) { throw "Missing helper: $CreateCertScript" }
if (-not (Test-Path $StageScript)) { throw "Missing helper: $StageScript" }
if (-not (Test-Path $DriverDir)) { throw "Driver crate not found: $DriverDir" }
if (-not (Test-Path $WorkspaceCargoToml)) { throw "Workspace Cargo.toml not found: $WorkspaceCargoToml" }

if (-not $SkipCert) {
    Write-Host ""
    Write-Host "==> Ensuring self-signed code-signing certificate" -ForegroundColor Cyan
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $CreateCertScript `
        -CertSubject $CertSubject `
        -ExportDir $CertExportDir `
        -CurrentUserOnly
    if ($LASTEXITCODE -ne 0) { throw "create-test-cert.ps1 failed with exit code $LASTEXITCODE" }
}

if (-not $SkipBuild) {
    Write-Host ""
    Write-Host "==> Ensuring cargo-wdk is installed" -ForegroundColor Cyan
    & cargo install cargo-wdk
    if ($LASTEXITCODE -ne 0) { throw "cargo install cargo-wdk failed with exit code $LASTEXITCODE" }

    Write-Host ""
    Write-Host "==> Building driver via 'cargo wdk build --profile $Profile'" -ForegroundColor Cyan

    $versionMatch = Select-String -Path $WorkspaceCargoToml -Pattern '^\s*version = "([^"]+)"' | Select-Object -First 1
    if (-not $versionMatch) { throw "Could not determine workspace version from $WorkspaceCargoToml" }
    $env:STAMPINF_VERSION = "$($versionMatch.Matches[0].Groups[1].Value).0"
    Write-Host "  STAMPINF_VERSION=$($env:STAMPINF_VERSION)"

    Push-Location $DriverDir
    try {
        & cargo wdk build --profile $Profile
        if ($LASTEXITCODE -ne 0) { throw "cargo wdk build failed with exit code $LASTEXITCODE" }
    } finally {
        Pop-Location
    }
}

Write-Host ""
Write-Host "==> Staging driver package + signing catalog" -ForegroundColor Cyan
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $StageScript `
    -Profile $StageProfile `
    -CertSubject $CertSubject `
    -NoTimestamp
if ($LASTEXITCODE -ne 0) { throw "stage-driver-package.ps1 failed with exit code $LASTEXITCODE" }

Write-Host ""
Write-Host "==> Preparing MSI driver bundle in $BundleDir" -ForegroundColor Cyan

if (Test-Path $BundleDir) {
    Remove-Item -Path $BundleDir -Recurse -Force
}
New-Item -ItemType Directory -Path $BundleDir -Force | Out-Null

$staged = @(Get-ChildItem -Path $StagingDir -File -ErrorAction Stop)
if ($staged.Count -eq 0) { throw "No staged files found in $StagingDir" }
foreach ($file in $staged) {
    Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $BundleDir $file.Name) -Force
    Write-Host "  + $($file.Name)"
}

$sanitizedName = ($CertSubject -replace '^CN=', '') -replace '[^a-zA-Z0-9._-]', '_'
$cerSrc = Join-Path $CertExportDir "$sanitizedName.cer"
if (-not (Test-Path $cerSrc)) {
    throw "Exported .cer not found at $cerSrc. Re-run without -SkipCert."
}
$cerDst = Join-Path $BundleDir $BundledCertFileName
Copy-Item -LiteralPath $cerSrc -Destination $cerDst -Force
Write-Host "  + $BundledCertFileName"

$requiredFiles = @(
    "safechain_lib_l4_proxy_windows_driver.sys",
    "safechain_lib_l4_proxy_windows_driver.inf",
    "safechain_lib_l4_proxy_windows_driver.cat",
    $BundledCertFileName
)
foreach ($req in $requiredFiles) {
    $p = Join-Path $BundleDir $req
    if (-not (Test-Path $p)) {
        throw "Driver bundle is missing required file: $p"
    }
}

Write-Host ""
Write-Host "Driver bundle ready at $BundleDir" -ForegroundColor Green
