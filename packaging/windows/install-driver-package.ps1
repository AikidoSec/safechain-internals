# Install the staged SafeChain Windows L4 driver package for local/dev use.

param(
    [Parameter(Mandatory = $false)]
    [string]$PackageDir
)

$ErrorActionPreference = "Stop"

$ProjectDir = (Get-Item (Split-Path -Parent $MyInvocation.MyCommand.Path)).Parent.Parent.FullName
$PackageDir = if ($PackageDir) {
    [System.IO.Path]::GetFullPath($PackageDir)
} else {
    Join-Path $ProjectDir "dist\windows-driver-package\debug"
}

$InfPath = Join-Path $PackageDir "safechain_lib_l4_proxy_windows_driver.inf"
if (-not (Test-Path $InfPath)) {
    throw "Driver INF not found: $InfPath"
}

Write-Host "Installing driver package from $InfPath"
& pnputil.exe /add-driver $InfPath /install
if ($LASTEXITCODE -ne 0) {
    throw "pnputil add-driver failed with exit code $LASTEXITCODE"
}
