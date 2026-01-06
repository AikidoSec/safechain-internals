# Build MSI installer for Aikido Agent
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
$WxsFile = Join-Path $ProjectDir "packaging\windows\SafeChainAgent.wxs"

Write-Host "Building MSI installer for Aikido Safe Chain Agent v$Version (WiX version: $WixVersion)"
Write-Host "  Binary directory: $BinDir"
Write-Host "  Output directory: $OutputDir"
Write-Host "  Project directory: $ProjectDir"

# Verify required binaries exist
$AgentExe = Join-Path $BinDir "SafeChainAgent.exe"

if (-not (Test-Path $AgentExe)) {
    Write-Host "Error: SafeChainAgent.exe not found at $AgentExe" -ForegroundColor Red
    exit 1
}

# Build the MSI
$OutputMsi = Join-Path $OutputDir "SafeChainAgent.$Arch.msi"
$WixArch = if ($Arch -eq "arm64") { "arm64" } else { "x64" }

wix build $WxsFile `
    -d Version=$WixVersion `
    -d BinDir=$BinDir `
    -d ProjectDir=$ProjectDir `
    -ext WixToolset.UI.wixext `
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
