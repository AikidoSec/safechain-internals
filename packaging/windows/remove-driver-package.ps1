# Remove the SafeChain Windows L4 driver package installed through pnputil.

$ErrorActionPreference = "Stop"

$DriverServiceName = "SafeChainL4Proxy"
$DriverHardwareId = "Root\SafeChainL4Proxy"
$OriginalInfName = "safechain_lib_l4_proxy_windows_driver.inf"
$StartupConfigRegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$DriverServiceName\Parameters"
$StartupConfigValueName = "ProxyStartupConfigV1"
$PnpUtilSuccess = 0
$PnpUtilRebootRequired = 3010
$PnpUtilRebootInitiated = 1641

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

Write-Host "Removing SafeChain driver package for service $DriverServiceName"

$deviceOutput = & pnputil.exe /enum-devices /deviceids /services /format csv 2>&1
if ($LASTEXITCODE -eq 0) {
    $deviceText = ($deviceOutput | Out-String).Trim()
    if (-not [string]::IsNullOrWhiteSpace($deviceText)) {
        $deviceRows = $deviceText | ConvertFrom-Csv
        $instanceIds = @(
            $deviceRows |
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
                        $hardwareIds.ToString().ToLowerInvariant().Contains($DriverHardwareId.ToLowerInvariant())
                    ) -or (
                        $service -and
                        $service -eq $DriverServiceName
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
        foreach ($instanceId in $instanceIds) {
            Write-Host "Removing device instance $instanceId"
            & pnputil.exe /remove-device $instanceId /subtree
            if ($LASTEXITCODE -ne 0) {
                $devconPath = Find-DevCon
                if (-not $devconPath) {
                    throw "pnputil remove-device failed for $instanceId with exit code $LASTEXITCODE and devcon.exe was not found for fallback removal"
                }

                Write-Warning "pnputil remove-device failed for $instanceId; falling back to devcon remove"
                & $devconPath /r remove "@$instanceId"
                if (($LASTEXITCODE -ne 0) -and ($LASTEXITCODE -ne 1)) {
                    throw "device removal failed for $instanceId via both pnputil and devcon"
                }
            }
        }
    }
}

$output = & pnputil.exe /enum-drivers
if ($LASTEXITCODE -ne 0) {
    throw "pnputil enum-drivers failed with exit code $LASTEXITCODE"
}

$publishedNames = New-Object System.Collections.Generic.List[string]
$currentPublishedName = $null
$currentOriginalName = $null

foreach ($line in $output) {
    if ($line -match 'Published Name\s*:\s*(.+)$') {
        $currentPublishedName = $Matches[1].Trim()
        continue
    }

    if ($line -match 'Original Name\s*:\s*(.+)$') {
        $currentOriginalName = $Matches[1].Trim()
        if ($currentPublishedName -and $currentOriginalName -ieq $OriginalInfName) {
            $publishedNames.Add($currentPublishedName)
        }
        continue
    }

    if ([string]::IsNullOrWhiteSpace($line)) {
        $currentPublishedName = $null
        $currentOriginalName = $null
    }
}

if ($publishedNames.Count -eq 0) {
    Write-Host "No installed driver package found for $OriginalInfName"
    exit 0
}

foreach ($publishedName in $publishedNames) {
    Write-Host "Removing driver package $publishedName"
    & pnputil.exe /delete-driver $publishedName /uninstall /force
    if (($LASTEXITCODE -ne $PnpUtilSuccess) -and ($LASTEXITCODE -ne $PnpUtilRebootRequired) -and ($LASTEXITCODE -ne $PnpUtilRebootInitiated)) {
        throw "pnputil delete-driver failed for $publishedName with exit code $LASTEXITCODE"
    }

    if (($LASTEXITCODE -eq $PnpUtilRebootRequired) -or ($LASTEXITCODE -eq $PnpUtilRebootInitiated)) {
        throw "Windows reports that driver removal requires a reboot to complete. Please reboot before reinstalling."
    }
}

if (Test-Path $StartupConfigRegistryPath) {
    Write-Host "Removing persisted startup config value $StartupConfigValueName"
    Remove-ItemProperty -Path $StartupConfigRegistryPath -Name $StartupConfigValueName -ErrorAction SilentlyContinue
}
