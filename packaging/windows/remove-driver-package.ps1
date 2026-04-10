# Remove the SafeChain Windows L4 driver package installed through pnputil.

$ErrorActionPreference = "Stop"

$DriverServiceName = "SafeChainL4Proxy"
$DriverHardwareId = "Root\SafeChainL4Proxy"
$OriginalInfName = "safechain_lib_l4_proxy_windows_driver.inf"

Write-Host "Removing SafeChain driver package for service $DriverServiceName"

$deviceOutput = & pnputil.exe /enum-devices /class System /deviceids /services /format csv 2>&1
if ($LASTEXITCODE -eq 0) {
    $deviceText = ($deviceOutput | Out-String).Trim()
    if (-not [string]::IsNullOrWhiteSpace($deviceText)) {
        $deviceRows = $deviceText | ConvertFrom-Csv
        $instanceIds = @(
            $deviceRows |
                Where-Object {
                    (
                        $_.'Hardware IDs' -and
                        $_.'Hardware IDs'.ToString().ToLowerInvariant().Contains($DriverHardwareId.ToLowerInvariant())
                    ) -or (
                        $_.Service -and
                        $_.Service -eq $DriverServiceName
                    )
                } |
                ForEach-Object { $_.'Instance ID' } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        )
        foreach ($instanceId in $instanceIds) {
            Write-Host "Removing device instance $instanceId"
            & pnputil.exe /remove-device $instanceId /subtree
            if ($LASTEXITCODE -ne 0) {
                throw "pnputil remove-device failed for $instanceId with exit code $LASTEXITCODE"
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
    if ($LASTEXITCODE -ne 0) {
        throw "pnputil delete-driver failed for $publishedName with exit code $LASTEXITCODE"
    }
}
