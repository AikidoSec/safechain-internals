# Install the staged SafeChain Windows L4 driver package for local/dev use.
#
# For local development we treat driver upgrades as a reboot-bound workflow:
# 1. stage/install the package and ensure the devnode exists;
# 2. reboot Windows;
# 3. run the post-reboot configure step to point the driver at the current proxy.

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

    $output = & pnputil.exe /enum-devices /deviceids /services /format csv 2>&1
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
                $hardwareIds = if ($_.PSObject.Properties.Name -contains 'Hardware IDs') {
                    $_.'Hardware IDs'
                } else {
                    $_.HardwareIds
                }
                $service = if ($_.PSObject.Properties.Name -contains 'Service') {
                    $_.Service
                } else {
                    $null
                }

                (
                    $hardwareIds -and
                    $hardwareIds.ToString().ToLowerInvariant().Contains($HardwareId.ToLowerInvariant())
                ) -or (
                    $ServiceName -and
                    $service -and
                    $service -eq $ServiceName
                )
            } |
            ForEach-Object {
                if ($_.PSObject.Properties.Name -contains 'Instance ID') {
                    $_.'Instance ID'
                } else {
                    $_.InstanceId
                }
            } |
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

function Invoke-PnpUtil {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$Description,

        [Parameter(Mandatory = $false)]
        [int[]]$AllowedExitCodes = @($PnpUtilSuccess)
    )

    $output = & pnputil.exe @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    if ($AllowedExitCodes -notcontains $exitCode) {
        $rendered = ($output | Out-String).Trim()
        throw "$Description failed with exit code $exitCode`n$rendered"
    }

    return @{
        Output = $output
        ExitCode = $exitCode
    }
}

function Wait-ForDeviceInstanceIds {
    param(
        [Parameter(Mandatory = $true)]
        [string]$HardwareId,

        [Parameter(Mandatory = $false)]
        [string]$ServiceName,

        [Parameter(Mandatory = $false)]
        [int]$Attempts = 8,

        [Parameter(Mandatory = $false)]
        [int]$DelayMilliseconds = 250
    )

    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        $instanceIds = @(Get-DeviceInstanceIds -HardwareId $HardwareId -ServiceName $ServiceName)
        if ($instanceIds.Count -gt 0) {
            return $instanceIds
        }

        Start-Sleep -Milliseconds $DelayMilliseconds
    }

    return @()
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

$addDriver = Invoke-PnpUtil `
    -Arguments @('/add-driver', $InfPath, '/install') `
    -Description 'pnputil add-driver' `
    -AllowedExitCodes @($PnpUtilSuccess, $PnpUtilNoMoreItems, $PnpUtilRebootRequired, $PnpUtilRebootInitiated)

$deviceInstanceIds = @(Wait-ForDeviceInstanceIds -HardwareId $DriverHardwareId -ServiceName $DriverServiceName)
$serviceInstalled = Test-DriverServiceInstalled -ServiceName $DriverServiceName

if ($deviceInstanceIds.Count -eq 0) {
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

    & pnputil.exe /scan-devices | Out-Null
    $deviceInstanceIds = @(Wait-ForDeviceInstanceIds -HardwareId $DriverHardwareId -ServiceName $DriverServiceName)
    $serviceInstalled = Test-DriverServiceInstalled -ServiceName $DriverServiceName
}

if ($deviceInstanceIds.Count -eq 0) {
    if ($serviceInstalled) {
        throw "Driver service registry key exists, but no device instance was found for $DriverHardwareId after install. Refusing to continue without a real devnode."
    }

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

Write-Host "Driver package install/update staged successfully." -ForegroundColor Green
Write-Warning "A reboot is required before continuing with the post-reboot driver configure step."

if (($addDriver.ExitCode -eq $PnpUtilRebootRequired) -or ($addDriver.ExitCode -eq $PnpUtilRebootInitiated)) {
    Write-Warning "Windows explicitly reported that the package install requires a reboot."
}
