# Install the staged SafeChain Windows L4 driver package for local/dev use.

param(
    [Parameter(Mandatory = $false)]
    [string]$PackageDir
)

$ErrorActionPreference = "Stop"

$DriverServiceName = "SafeChainL4Proxy"
$DriverHardwareId = "Root\SafeChainL4Proxy"
$InfFileName = "safechain_lib_l4_proxy_windows_driver.inf"
$DriverFileName = "safechain_lib_l4_proxy_windows_driver.sys"
$CatalogFileName = "safechain_lib_l4_proxy_windows_driver.cat"

function Test-IsAdministrator {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Find-DevCon {
    $kitsRoot = "C:\Program Files (x86)\Windows Kits\10\Tools"
    if (-not (Test-Path $kitsRoot)) {
        return $null
    }

    $candidates = Get-ChildItem -Path $kitsRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
        Sort-Object Name -Descending

    foreach ($candidate in $candidates) {
        $path = Join-Path $candidate.FullName "x64\devcon.exe"
        if (Test-Path $path) {
            return $path
        }
    }

    return $null
}

function Get-DeviceInstanceIds {
    param(
        [Parameter(Mandatory = $true)]
        [string]$HardwareId,

        [Parameter(Mandatory = $false)]
        [string]$ServiceName
    )

    $output = & pnputil.exe /enum-devices /class System /deviceids /services /format csv 2>&1
    if ($LASTEXITCODE -ne 0) {
        return @()
    }

    $text = ($output | Out-String).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) {
        return @()
    }

    $rows = $text | ConvertFrom-Csv
    return @(
        $rows |
            Where-Object {
                (
                    $_.'Hardware IDs' -and
                    $_.'Hardware IDs'.ToString().ToLowerInvariant().Contains($HardwareId.ToLowerInvariant())
                ) -or (
                    $ServiceName -and
                    $_.Service -and
                    $_.Service -eq $ServiceName
                )
            } |
            ForEach-Object { $_.'Instance ID' } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
}

function Test-DriverServiceInstalled {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName
    )

    $null -ne (Get-Item "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" -ErrorAction SilentlyContinue)
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

$InfPath = Join-Path $PackageDir $InfFileName
$SysPath = Join-Path $PackageDir $DriverFileName
$CatPath = Join-Path $PackageDir $CatalogFileName

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
Write-Host "  service: $DriverServiceName"
Write-Host "  hardware id: $DriverHardwareId"

$pnputil = Get-Command pnputil.exe -ErrorAction Stop

$pnputilOutput = & $pnputil.Source /add-driver $InfPath /install 2>&1
$pnputilSucceeded =
    ($LASTEXITCODE -eq 0) -or
    (
        $LASTEXITCODE -eq 259 -and
        (($pnputilOutput | Out-String) -match 'Driver package added successfully')
    )

if (-not $pnputilSucceeded) {
    throw "pnputil add-driver failed with exit code $LASTEXITCODE"
}

$deviceInstanceIds = Get-DeviceInstanceIds -HardwareId $DriverHardwareId -ServiceName $DriverServiceName
$serviceInstalled = Test-DriverServiceInstalled -ServiceName $DriverServiceName

if (($deviceInstanceIds.Count -eq 0) -and (-not $serviceInstalled)) {
    $devconPath = Find-DevCon
    if (-not $devconPath) {
        throw "No device instance exists for $DriverHardwareId and devcon.exe was not found to create one."
    }

    Write-Host "Creating root-enumerated device instance..." -ForegroundColor Green
    Write-Host "  using: $devconPath"
    $devconOutput = & $devconPath install $InfPath $DriverHardwareId 2>&1
    $devconSucceeded =
        ($LASTEXITCODE -eq 0) -or
        (($devconOutput | Out-String) -match 'Drivers installed successfully')

    if (-not $devconSucceeded) {
        throw "devcon install failed with exit code $LASTEXITCODE"
    }

    $deviceInstanceIds = Get-DeviceInstanceIds -HardwareId $DriverHardwareId -ServiceName $DriverServiceName
    $serviceInstalled = Test-DriverServiceInstalled -ServiceName $DriverServiceName
}

if (($deviceInstanceIds.Count -eq 0) -and (-not $serviceInstalled)) {
    throw "Driver package was staged, but neither a device instance nor the $DriverServiceName service was found."
}

if ($deviceInstanceIds.Count -gt 0) {
    Write-Host "Installed device instance(s):" -ForegroundColor Green
    foreach ($instanceId in $deviceInstanceIds) {
        Write-Host "  $instanceId"
    }
}

if ($serviceInstalled) {
    Write-Host "Driver service registry key detected: HKLM\\SYSTEM\\CurrentControlSet\\Services\\$DriverServiceName" -ForegroundColor Green
}

Write-Host "Driver package staged/install command completed successfully." -ForegroundColor Green
