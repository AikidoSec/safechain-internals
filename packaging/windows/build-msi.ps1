# Build MSI installer for Aikido Endpoint Protection
# Requires: WiX Toolset v4+ (dotnet tool install -g wix)

param(
    [Parameter(Mandatory=$true)]
    [string]$Version,

    [Parameter(Mandatory=$false)]
    [string]$BinDir = ".\bin",

    [Parameter(Mandatory=$false)]
    [string]$OutputDir = ".\dist"
)

$ErrorActionPreference = "Stop"

if ($Version -eq "dev" -or [string]::IsNullOrEmpty($Version)) {
    $WixVersion = "0.0.0"
} else {
    $WixVersion = $Version
}

# Ensure output directory exists
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

$ProjectDir = (Get-Item (Split-Path -Parent $MyInvocation.MyCommand.Path)).Parent.Parent.FullName
$WxsFile = Join-Path $ProjectDir "packaging\windows\EndpointProtection.wxs"
$CustomUIFile = Join-Path $ProjectDir "packaging\windows\WixUI_InstallDir_Custom.wxs"

Write-Host "Building MSI installer for Aikido Aikido Endpoint Protection v$Version (WiX version: $WixVersion)"
Write-Host "  Binary directory: $BinDir"
Write-Host "  Output directory: $OutputDir"
Write-Host "  Project directory: $ProjectDir"

# Verify required binaries exist
$AgentExe = Join-Path $BinDir "EndpointProtection.exe"
$AgentUIExe = Join-Path $BinDir "EndpointProtectionUI.exe"
$ProxyExe = Join-Path $BinDir "SafeChainL7Proxy.exe"
$StoreTokenScript = Join-Path $ProjectDir "packaging\windows\scripts\StoreToken.ps1"

if (-not (Test-Path $AgentExe)) {
    Write-Host "Error: EndpointProtection.exe not found at $AgentExe" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $AgentUIExe)) {
    Write-Host "Error: EndpointProtectionUI.exe not found at $AgentUIExe" -ForegroundColor Red
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
$OutputMsi = Join-Path $OutputDir "EndpointProtection.msi"

wix build $WxsFile $CustomUIFile `
    -d Version=$WixVersion `
    -d BinDir=$BinDir `
    -d ProjectDir=$ProjectDir `
    -ext WixToolset.UI.wixext `
    -ext WixToolset.Util.wixext `
    -arch x64 `
    -acceptEula wix7 `
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
