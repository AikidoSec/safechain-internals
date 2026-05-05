# MSI custom-action helper: remove the SafeChain Windows L4 driver package.
#
# Invoked from EndpointProtection.wxs as a deferred (elevated) custom action
# during MSI uninstall (and major upgrade). Mirrors the logic in
# packaging/windows/remove-driver-package.ps1 but is tolerant of a partially
# installed state and never throws (uninstall must be idempotent).

$ErrorActionPreference = "Continue"

$DriverServiceName = "SafeChainL4Proxy"
$DriverHardwareId = "Root\SafeChainL4Proxy"
$OriginalInfName = "safechain_lib_l4_proxy_windows_driver.inf"

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

Write-Host "Removing SafeChain L4 driver package..."

try {
    $deviceOutput = & pnputil.exe /enum-devices /deviceids /services /format csv 2>&1
    if ($LASTEXITCODE -eq 0) {
        $deviceText = ($deviceOutput | Out-String).Trim()
        if (-not [string]::IsNullOrWhiteSpace($deviceText)) {
            $deviceRows = $deviceText | ConvertFrom-Csv
            $instanceIds = @(
                $deviceRows |
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

            foreach ($instanceId in $instanceIds) {
                Write-Host "Removing device instance $instanceId"
                & pnputil.exe /remove-device $instanceId /subtree
                if ($LASTEXITCODE -ne 0) {
                    $devconPath = Find-DevCon
                    if ($devconPath) {
                        Write-Warning "pnputil remove-device failed for $instanceId; falling back to devcon"
                        & $devconPath /r remove "@$instanceId"
                    } else {
                        Write-Warning "pnputil remove-device failed for $instanceId and devcon.exe not found; continuing"
                    }
                }
            }
        }
    }
} catch {
    Write-Warning "Device-instance removal step failed: $_"
}

try {
    $output = & pnputil.exe /enum-drivers
    if ($LASTEXITCODE -eq 0) {
        $publishedNames = New-Object System.Collections.Generic.List[string]
        $currentPublished = $null
        foreach ($line in $output) {
            if ($line -match 'Published Name\s*:\s*(.+)$') {
                $currentPublished = $Matches[1].Trim()
                continue
            }
            if ($line -match 'Original Name\s*:\s*(.+)$') {
                $orig = $Matches[1].Trim()
                if ($currentPublished -and $orig -ieq $OriginalInfName) {
                    $publishedNames.Add($currentPublished)
                }
                continue
            }
            if ([string]::IsNullOrWhiteSpace($line)) {
                $currentPublished = $null
            }
        }

        foreach ($p in $publishedNames) {
            Write-Host "Removing driver package $p"
            & pnputil.exe /delete-driver $p /uninstall /force
            if ($LASTEXITCODE -ne 0) {
                Write-Warning "pnputil delete-driver failed for $p (exit $LASTEXITCODE); continuing"
            }
        }
    } else {
        Write-Warning "pnputil enum-drivers failed (exit $LASTEXITCODE); skipping driver-package removal."
    }
} catch {
    Write-Warning "Driver-package removal step failed: $_"
}

Write-Host "Driver uninstall step complete."
exit 0
