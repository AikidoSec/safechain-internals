# Verify the SafeChain Windows L4 driver install and WFP registration state.
#
# This script checks:
# - driver package presence via pnputil
# - kernel driver service presence and state
# - loaded driver presence
# - installed .sys file presence
# - test signing mode
# - Base Filtering Engine state
# - service registry key
# - WFP provider, sublayer, callouts, and filters via netsh wfp state dump
# - expected SafeChain GUIDs
#
# Usage:
#   .\packaging\windows\verify-driver-install.ps1
#   .\packaging\windows\verify-driver-install.ps1 -OutputDir .\dist\windows-driver-package\debug
#   .\packaging\windows\verify-driver-install.ps1 -KeepWfpStateXml

param(
    [Parameter(Mandatory = $false)]
    [string]$OutputDir,

    [Parameter(Mandatory = $false)]
    [string]$DriverServiceName = "SafeChainL4Proxy",

    [Parameter(Mandatory = $false)]
    [string]$DriverHardwareId = "Root\SafeChainL4Proxy",

    [Parameter(Mandatory = $false)]
    [string]$DriverFileName = "safechain_lib_l4_proxy_windows_driver.sys",

    [Parameter(Mandatory = $false)]
    [string]$InfFileName = "safechain_lib_l4_proxy_windows_driver.inf",

    [Parameter(Mandatory = $false)]
    [switch]$KeepWfpStateXml
)

$ErrorActionPreference = "Stop"

$ProjectDir = (Get-Item (Split-Path -Parent $MyInvocation.MyCommand.Path)).Parent.Parent.FullName
$OutputDir = if ($OutputDir) {
    [System.IO.Path]::GetFullPath($OutputDir)
} else {
    Join-Path $ProjectDir "dist\windows-driver-package\debug"
}

$InfPath = Join-Path $OutputDir $InfFileName
$ExpectedDriverPath = Join-Path $OutputDir $DriverFileName

$ServiceRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$DriverServiceName"
$InstalledDriverPath = Join-Path $env:WINDIR "System32\drivers\$DriverFileName"
$ServiceImagePath = $null
$ResolvedServiceDriverPath = $null

$WfpStatePath = Join-Path $env:TEMP "safechain_wfpstate.xml"

$GuidMap = [ordered]@{
    "Provider"                 = "{6A625BB6-F310-443E-9850-280FACDC1A21}"
    "Sublayer"                 = "{D95A6EAF-3882-495F-858C-65C2CE3F6A07}"
    "Callout TCP Redirect V4"  = "{5C6262C4-8EF6-43D8-A8F9-48636B172BB8}"
    "Callout TCP Redirect V6"  = "{4F05F1F8-9093-44F1-A8E7-2D841A3E2E5A}"
    "Filter TCP Redirect V4"   = "{DB5B9241-4532-4517-B0E0-6F85E4E631F8}"
    "Filter TCP Redirect V6"   = "{4B60D58C-85FD-4FB1-8256-8C4E6053E43A}"
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "== $Title ==" -ForegroundColor Cyan
}

function Write-Pass {
    param([string]$Message)
    Write-Host "[PASS] $Message" -ForegroundColor Green
}

function Write-Fail {
    param([string]$Message)
    Write-Host "[FAIL] $Message" -ForegroundColor Red
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message"
}

function Test-CommandExists {
    param([string]$Name)
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Resolve-ServiceImagePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ImagePath
    )

    $resolved = $ImagePath.Trim()

    if ($resolved -like '\SystemRoot\*') {
        return Join-Path $env:WINDIR $resolved.Substring('\SystemRoot\'.Length)
    }

    if ($resolved -like '%SystemRoot%\*') {
        return Join-Path $env:WINDIR $resolved.Substring('%SystemRoot%\'.Length)
    }

    if ($resolved -like '\??\*') {
        return $resolved.Substring('\??\'.Length)
    }

    return [Environment]::ExpandEnvironmentVariables($resolved)
}

function Get-MatchingDriverDevices {
    param(
        [Parameter(Mandatory = $true)]
        [string]$HardwareId,

        [Parameter(Mandatory = $true)]
        [string]$ServiceName
    )

    $deviceOutput = & pnputil.exe /enum-devices /class System /deviceids /services /format csv 2>&1
    if ($LASTEXITCODE -ne 0) {
        return @()
    }

    $deviceText = ($deviceOutput | Out-String).Trim()
    if ([string]::IsNullOrWhiteSpace($deviceText)) {
        return @()
    }

    $deviceRows = $deviceText | ConvertFrom-Csv
    return @(
        $deviceRows |
            Where-Object {
                (
                    $_.'Hardware IDs' -and
                    $_.'Hardware IDs'.ToString().ToLowerInvariant().Contains($HardwareId.ToLowerInvariant())
                ) -or (
                    $_.Service -and
                    $_.Service -eq $ServiceName
                )
            }
    )
}

Write-Host "SafeChain driver verification" -ForegroundColor Green
Write-Host "  ProjectDir : $ProjectDir"
Write-Host "  OutputDir  : $OutputDir"
Write-Host "  INF        : $InfPath"
Write-Host "  SYS        : $ExpectedDriverPath"
Write-Host "  Service    : $DriverServiceName"
Write-Host "  DeviceId   : $DriverHardwareId"

Write-Section "Package staging"
if (Test-Path $OutputDir) {
    Write-Pass "Package directory exists: $OutputDir"
} else {
    Write-Fail "Package directory not found: $OutputDir"
}

if (Test-Path $InfPath) {
    Write-Pass "INF exists: $InfPath"
} else {
    Write-Fail "INF not found: $InfPath"
}

if (Test-Path $ExpectedDriverPath) {
    Write-Pass "Staged SYS exists: $ExpectedDriverPath"
} else {
    Write-Fail "Staged SYS not found: $ExpectedDriverPath"
}

Write-Section "Installed driver packages"
if (Test-CommandExists "pnputil.exe") {
    $pnputilOutput = & pnputil.exe /enum-drivers 2>&1
    $safechainDriverLines = $pnputilOutput | Select-String -Pattern "safechain|$([regex]::Escape($InfFileName))"

    if ($safechainDriverLines) {
        Write-Pass "Found SafeChain related entry in pnputil output"
        $safechainDriverLines | ForEach-Object { Write-Info $_.Line }
    } else {
        Write-Warn "No SafeChain related entry found in pnputil output"
    }
} else {
    Write-Warn "pnputil.exe not found"
}

Write-Section "Driver service"
$serviceFound = $false
try {
    $service = Get-CimInstance Win32_SystemDriver | Where-Object {
        $_.Name -eq $DriverServiceName -or $_.PathName -like "*$DriverFileName*"
    } | Select-Object -First 1

    if ($service) {
        $serviceFound = $true
        Write-Pass "Driver service found"
        Write-Info "Name      : $($service.Name)"
        Write-Info "State     : $($service.State)"
        Write-Info "StartMode : $($service.StartMode)"
        Write-Info "PathName  : $($service.PathName)"
        Write-Info "Display   : $($service.DisplayName)"
    } else {
        Write-Fail "Driver service not found via Win32_SystemDriver"
    }
} catch {
    Write-Warn "Failed to query Win32_SystemDriver: $($_.Exception.Message)"
}

if (Test-CommandExists "sc.exe") {
    try {
        $scQc = & sc.exe qc $DriverServiceName 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Pass "sc qc succeeded for $DriverServiceName"
            $scQc | ForEach-Object { Write-Info $_ }
        } else {
            Write-Warn "sc qc did not find service $DriverServiceName"
        }

        $scQuery = & sc.exe query $DriverServiceName 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Pass "sc query succeeded for $DriverServiceName"
            $scQuery | ForEach-Object { Write-Info $_ }
        } else {
            Write-Warn "sc query did not find service $DriverServiceName"
        }
    } catch {
        Write-Warn "Failed to query service with sc.exe: $($_.Exception.Message)"
    }
}

try {
    $svcReg = Get-ItemProperty $ServiceRegistryPath -ErrorAction Stop
    if ($null -ne $svcReg.ImagePath) {
        $ServiceImagePath = [string]$svcReg.ImagePath
        $ResolvedServiceDriverPath = Resolve-ServiceImagePath -ImagePath $ServiceImagePath
    }
} catch {
}

Write-Section "Driver device"
if (Test-CommandExists "pnputil.exe") {
    try {
        $matchingRows = Get-MatchingDriverDevices -HardwareId $DriverHardwareId -ServiceName $DriverServiceName
        if ($matchingRows.Count -gt 0) {
            Write-Pass "Found device instance(s) for $DriverHardwareId"
            foreach ($device in $matchingRows) {
                if ($device.'Instance ID') {
                    Write-Info "Instance ID : $($device.'Instance ID')"
                }
                if ($device.'Device Description') {
                    Write-Info "Description : $($device.'Device Description')"
                } elseif ($device.Description) {
                    Write-Info "Description : $($device.Description)"
                }
                if ($device.Service) {
                    Write-Info "Service     : $($device.Service)"
                }
                if ($device.Status) {
                    Write-Info "Status      : $($device.Status)"
                }
            }
        } else {
            Write-Warn "No device instance found for $DriverHardwareId via pnputil"
        }
    } catch {
        Write-Warn "Failed to query device instance(s): $($_.Exception.Message)"
    }
} else {
    Write-Warn "pnputil.exe not found"
}

Write-Section "Loaded driver"
if (Test-CommandExists "driverquery.exe") {
    $driverQueryOutput = & driverquery.exe /v 2>&1
    $driverLines = $driverQueryOutput | Select-String -Pattern "safechain|$([regex]::Escape($DriverFileName))"
    if ($driverLines) {
        Write-Pass "Found SafeChain related line in driverquery output"
        $driverLines | ForEach-Object { Write-Info $_.Line }
    } else {
        Write-Warn "No SafeChain related line found in driverquery output"
    }
} else {
    Write-Warn "driverquery.exe not found"
}

Write-Section "Installed SYS on disk"
if (Test-Path $InstalledDriverPath) {
    Write-Pass "Installed SYS exists: $InstalledDriverPath"
    $item = Get-Item $InstalledDriverPath
    Write-Info "Length        : $($item.Length)"
    Write-Info "LastWriteTime : $($item.LastWriteTime)"
} else {
    Write-Warn "Installed SYS not found at legacy expected path: $InstalledDriverPath"
}

if ($ResolvedServiceDriverPath) {
    Write-Info "Service ImagePath : $ServiceImagePath"
    Write-Info "Resolved path     : $ResolvedServiceDriverPath"
    if (Test-Path $ResolvedServiceDriverPath) {
        Write-Pass "Service driver binary exists at resolved ImagePath"
        $item = Get-Item $ResolvedServiceDriverPath
        Write-Info "Length        : $($item.Length)"
        Write-Info "LastWriteTime : $($item.LastWriteTime)"
    } else {
        Write-Fail "Service ImagePath does not exist on disk: $ResolvedServiceDriverPath"
    }
}

Write-Section "Test signing mode"
try {
    $bcd = & bcdedit 2>&1
    $testSigningLine = $bcd | Select-String -Pattern "testsigning"
    if ($testSigningLine) {
        $lineText = ($testSigningLine | Select-Object -First 1).Line
        Write-Info $lineText
        if ($lineText -match "Yes") {
            Write-Pass "Test signing appears enabled"
        } else {
            Write-Warn "Test signing line found, but not enabled"
        }
    } else {
        Write-Warn "Could not find testsigning in bcdedit output"
    }
} catch {
    Write-Warn "Failed to query bcdedit: $($_.Exception.Message)"
}

Write-Section "Base Filtering Engine"
try {
    $bfe = Get-Service BFE -ErrorAction Stop
    Write-Info "Name      : $($bfe.Name)"
    Write-Info "Status    : $($bfe.Status)"
    Write-Info "StartType : $($bfe.StartType)"
    if ($bfe.Status -eq "Running") {
        Write-Pass "BFE is running"
    } else {
        Write-Fail "BFE is not running"
    }
} catch {
    Write-Fail "Could not query BFE service: $($_.Exception.Message)"
}

Write-Section "Service registry"
if (Test-Path $ServiceRegistryPath) {
    Write-Pass "Service registry key exists: $ServiceRegistryPath"
    try {
        $svcReg = Get-ItemProperty $ServiceRegistryPath
        foreach ($prop in @("DisplayName", "ImagePath", "Start", "Type", "ErrorControl")) {
            if ($null -ne $svcReg.$prop) {
                Write-Info "$prop : $($svcReg.$prop)"
            }
        }
    } catch {
        Write-Warn "Could not read service registry properties: $($_.Exception.Message)"
    }
} else {
    Write-Fail "Service registry key not found: $ServiceRegistryPath"
}

Write-Section "WFP state"
if (Test-CommandExists "netsh.exe") {
    try {
        & netsh.exe wfp show state file=$WfpStatePath | Out-Null
        if (Test-Path $WfpStatePath) {
            Write-Pass "WFP state exported: $WfpStatePath"
        } else {
            Write-Fail "WFP state export did not produce file: $WfpStatePath"
        }
    } catch {
        Write-Fail "Failed to export WFP state: $($_.Exception.Message)"
    }
} else {
    Write-Fail "netsh.exe not found"
}

if (Test-Path $WfpStatePath) {
    $wfpContent = Get-Content $WfpStatePath -Raw

    foreach ($entry in $GuidMap.GetEnumerator()) {
        $name = $entry.Key
        $guid = $entry.Value

        if ($wfpContent -match [regex]::Escape($guid)) {
            Write-Pass "$name GUID found in WFP state: $guid"
        } else {
            Write-Fail "$name GUID NOT found in WFP state: $guid"
        }
    }

    $safechainTextHits = Select-String -Path $WfpStatePath -Pattern "SafeChain|safechain|ProxyStartupConfigV1" -SimpleMatch
    if ($safechainTextHits) {
        Write-Pass "Found SafeChain text markers in WFP state"
        $safechainTextHits | Select-Object -First 20 | ForEach-Object {
            Write-Info ("Line {0}: {1}" -f $_.LineNumber, $_.Line.Trim())
        }
    } else {
        Write-Warn "No SafeChain text markers found in WFP state"
    }
}

Write-Section "Recent System log hints"
try {
    $events = Get-WinEvent -LogName System -MaxEvents 300 -ErrorAction Stop |
        Where-Object {
            $_.ProviderName -match "Service Control Manager|CodeIntegrity|Kernel-PnP" -or
            $_.Message -match "safechain|wfp|filter|bfe"
        } |
        Select-Object -First 20

    if ($events) {
        Write-Pass "Found potentially relevant System log entries"
        foreach ($evt in $events) {
            Write-Info ("[{0}] {1} Id={2}" -f $evt.TimeCreated, $evt.ProviderName, $evt.Id)
            Write-Info ($evt.Message -replace "\r?\n", " ")
        }
    } else {
        Write-Warn "No relevant recent System log entries found"
    }
} catch {
    Write-Warn "Failed to query System event log: $($_.Exception.Message)"
}

if ((Test-Path $WfpStatePath) -and (-not $KeepWfpStateXml)) {
    Remove-Item $WfpStatePath -Force -ErrorAction SilentlyContinue
    Write-Info "Removed temporary WFP state file: $WfpStatePath"
} elseif (Test-Path $WfpStatePath) {
    Write-Info "Kept WFP state file: $WfpStatePath"
}

Write-Host ""
Write-Host "Verification complete." -ForegroundColor Green
