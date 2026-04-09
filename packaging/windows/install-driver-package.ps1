# Install the staged SafeChain Windows L4 driver package for local/dev use.

param(
    [Parameter(Mandatory = $false)]
    [string]$PackageDir
)

$ErrorActionPreference = "Stop"

function Test-IsAdministrator {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$ProjectDir = (Get-Item (Split-Path -Parent $MyInvocation.MyCommand.Path)).Parent.Parent.FullName
$PackageDir = if ($PackageDir) {
    [System.IO.Path]::GetFullPath($PackageDir)
} else {
    Join-Path $ProjectDir "dist\windows-driver-package\debug"
}

if (-not (Test-IsAdministrator)) {
    throw "This script must be run from an elevated PowerShell session."
}

if (-not (Test-Path $PackageDir)) {
    throw "Package directory not found: $PackageDir"
}

$InfPath = Join-Path $PackageDir "safechain_lib_l4_proxy_windows_driver.inf"
$SysPath = Join-Path $PackageDir "safechain_lib_l4_proxy_windows_driver.sys"
$CatPath = Join-Path $PackageDir "safechain_lib_l4_proxy_windows_driver.cat"

if (-not (Test-Path $InfPath)) {
    throw "Driver INF not found: $InfPath"
}

if (-not (Test-Path $SysPath)) {
    throw "Driver SYS not found: $SysPath"
}

if (-not (Test-Path $CatPath)) {
    Write-Warning "Driver CAT not found: $CatPath"
    Write-Warning "Install may fail if driver signing is required."
}

Write-Host "Installing driver package" -ForegroundColor Green
Write-Host "  dir: $PackageDir"
Write-Host "  inf: $InfPath"

$pnputil = Get-Command pnputil.exe -ErrorAction Stop

& $pnputil.Source /add-driver $InfPath /install
if ($LASTEXITCODE -ne 0) {
    throw "pnputil add-driver failed with exit code $LASTEXITCODE"
}

Write-Host "Driver package staged/install command completed successfully." -ForegroundColor Green