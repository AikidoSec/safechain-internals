# Remove the SafeChain Windows L4 driver package installed through pnputil.

$ErrorActionPreference = "Stop"

$OriginalInfName = "safechain_lib_l4_proxy_windows_driver.inf"

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
