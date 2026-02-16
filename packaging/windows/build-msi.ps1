# Build MSI installer for SafeChain Ultimate
# Requires: WiX Toolset v4+ (dotnet tool install -g wix)

param(
    [Parameter(Mandatory=$true)]
    [string]$Version,

    [Parameter(Mandatory=$true)]
    [string]$Arch,

    [Parameter(Mandatory=$false)]
    [string]$BinDir = ".\bin",

    [Parameter(Mandatory=$false)]
    [string]$OutputDir = ".\dist"
)

$ErrorActionPreference = "Stop"

if ($Version -eq "dev" -or [string]::IsNullOrEmpty($Version)) {
    $WixVersion = "0.0.0-dev"
} else {
    $WixVersion = $Version
}

# Ensure output directory exists
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

$ProjectDir = (Get-Item (Split-Path -Parent $MyInvocation.MyCommand.Path)).Parent.Parent.FullName
$WxsFile = Join-Path $ProjectDir "packaging\windows\SafeChainUltimate.wxs"

Write-Host "Building MSI installer for Aikido SafeChain Ultimate v$Version (WiX version: $WixVersion)"
Write-Host "  Binary directory: $BinDir"
Write-Host "  Output directory: $OutputDir"
Write-Host "  Project directory: $ProjectDir"

# Verify required binaries exist
$AgentExe = Join-Path $BinDir "SafeChainUltimate.exe"
$AgentUIExe = Join-Path $BinDir "SafeChainUltimateUI.exe"
$ProxyExe = Join-Path $BinDir "SafeChainL7Proxy.exe"
$StoreTokenScript = Join-Path $ProjectDir "packaging\windows\scripts\StoreToken.ps1"

if (-not (Test-Path $AgentExe)) {
    Write-Host "Error: SafeChainUltimate.exe not found at $AgentExe" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $AgentUIExe)) {
    Write-Host "Error: SafeChainUltimateUI.exe not found at $AgentUIExe" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $ProxyExe)) {
    Write-Host "Error: SafeChainL7Proxy.exe not found at $ProxyExe" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $StoreTokenScript)) {
    Write-Host "Error: StoreToken.ps1 not found at $StoreTokenScript" -ForegroundColor Red
    exit 1
}

# Build the MSI
$OutputMsi = Join-Path $OutputDir "SafeChainUltimate.$Arch.msi"
$WixArch = if ($Arch -eq "arm64") { "arm64" } else { "x64" }

wix build $WxsFile `
    -d Version=$WixVersion `
    -d BinDir=$BinDir `
    -d ProjectDir=$ProjectDir `
    -ext WixToolset.UI.wixext `
    -ext WixToolset.Util.wixext `
    -arch $WixArch `
    -o $OutputMsi

if ($LASTEXITCODE -eq 0) {
    Write-Host "MSI built successfully: $OutputMsi" -ForegroundColor Green

    # Calculate checksum
    $hash = Get-FileHash -Path $OutputMsi -Algorithm SHA256
    Write-Host "SHA256: $($hash.Hash)"

    # Save checksum to file
    $hash.Hash | Out-File -FilePath "$OutputMsi.sha256" -NoNewline
} else {
    Write-Host "MSI build failed" -ForegroundColor Red
    exit 1
}
