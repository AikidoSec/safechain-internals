# MSI custom-action helper: trust the bundled self-signed code-signing
# certificate and install the SafeChain Windows L4 driver package via pnputil.
#
# Invoked from EndpointProtection.wxs as a deferred (elevated) custom action.
# Expected to run on the target machine, NOT on the build host.

param(
    [Parameter(Mandatory = $true)]
    [string]$DriverDir
)

$ErrorActionPreference = "Stop"

$InfFileName = "safechain_lib_l4_proxy_windows_driver.inf"
$DriverFileName = "safechain_lib_l4_proxy_windows_driver.sys"
$CatalogFileName = "safechain_lib_l4_proxy_windows_driver.cat"
$CertFileName = "safechain-driver.cer"
$DriverHardwareId = "Root\SafeChainL4Proxy"
$DriverServiceName = "SafeChainL4Proxy"
$PnpUtilSuccess = 0
$PnpUtilNoMoreItems = 259
$PnpUtilRebootRequired = 3010
$PnpUtilRebootInitiated = 1641

function Test-IsAdministrator {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Find-DevCon {
    $kitsRoot = "C:\Program Files (x86)\Windows Kits\10\Tools"
    if (-not (Test-Path $kitsRoot)) { return $null }
    $candidates = Get-ChildItem -Path $kitsRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
        Sort-Object Name -Descending
    foreach ($candidate in $candidates) {
        $path = Join-Path $candidate.FullName "x64\devcon.exe"
        if (Test-Path $path) { return $path }
    }
    return $null
}

function Get-DriverDeviceInstanceIds {
    $output = & pnputil.exe /enum-devices /deviceids /services /format csv 2>&1
    if ($LASTEXITCODE -ne 0) { return @() }
    $text = ($output | Out-String).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) { return @() }

    $rows = $text | ConvertFrom-Csv
    return @(
        $rows |
            Where-Object {
                $hwIds = if ($_.PSObject.Properties.Name -contains 'Hardware IDs') { $_.'Hardware IDs' } else { $_.HardwareIds }
                $svc = if ($_.PSObject.Properties.Name -contains 'Service') { $_.Service } else { $null }
                ($hwIds -and $hwIds.ToString().ToLowerInvariant().Contains($DriverHardwareId.ToLowerInvariant())) -or
                ($svc -and $svc -eq $DriverServiceName)
            } |
            ForEach-Object {
                if ($_.PSObject.Properties.Name -contains 'Instance ID') { $_.'Instance ID' } else { $_.InstanceId }
            } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
}

if (-not (Test-IsAdministrator)) {
    throw "install-driver.ps1 must run elevated."
}

$DriverDir = [System.IO.Path]::GetFullPath($DriverDir.TrimEnd('"'))
if (-not (Test-Path $DriverDir)) { throw "Driver dir not found: $DriverDir" }

$InfPath = Join-Path $DriverDir $InfFileName
$SysPath = Join-Path $DriverDir $DriverFileName
$CatPath = Join-Path $DriverDir $CatalogFileName
$CerPath = Join-Path $DriverDir $CertFileName

foreach ($p in @($InfPath, $SysPath, $CerPath)) {
    if (-not (Test-Path $p)) { throw "Driver bundle missing required file: $p" }
}
if (-not (Test-Path $CatPath)) {
    Write-Warning "Driver catalog not found at $CatPath. Install may fail if driver signing is required."
}

Write-Host "Trusting bundled driver code-signing certificate ($CerPath)..."
Import-Certificate -FilePath $CerPath -CertStoreLocation "Cert:\LocalMachine\Root" -ErrorAction SilentlyContinue | Out-Null
Import-Certificate -FilePath $CerPath -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" -ErrorAction SilentlyContinue | Out-Null

Write-Host "Installing driver package via pnputil ($InfPath)..."
& pnputil.exe /add-driver $InfPath /install
$exit = $LASTEXITCODE
if (@($PnpUtilSuccess, $PnpUtilNoMoreItems, $PnpUtilRebootRequired, $PnpUtilRebootInitiated) -notcontains $exit) {
    throw "pnputil /add-driver failed with exit code $exit"
}

$instanceIds = @(Get-DriverDeviceInstanceIds)
if ($instanceIds.Count -eq 0) {
    $devconPath = Find-DevCon
    if ($devconPath) {
        Write-Host "No device instance found; creating root-enumerated devnode via devcon ($devconPath)..."
        & $devconPath install $InfPath $DriverHardwareId | Out-Null
        & pnputil.exe /scan-devices | Out-Null
        $instanceIds = @(Get-DriverDeviceInstanceIds)
    } else {
        Write-Warning "No device instance present and devcon.exe not found; driver will be activated on next reboot."
    }
}

foreach ($instanceId in $instanceIds) {
    Write-Host "Installed device instance: $instanceId"
}

if (($exit -eq $PnpUtilRebootRequired) -or ($exit -eq $PnpUtilRebootInitiated)) {
    Write-Warning "Windows reports that driver install requires a reboot to complete."
}

Write-Host "Driver install step complete."
exit 0
