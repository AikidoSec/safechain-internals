param(
    [Parameter(Mandatory = $true)]
    [string]$BindAddress,

    [Parameter(Mandatory = $false)]
    [string]$ProcessSelector
)

$ErrorActionPreference = "Stop"

function Parse-BindAddress {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    $lastColon = $Value.LastIndexOf(":")
    if ($lastColon -lt 1) {
        throw "Bind address must include a port: $Value"
    }

    $hostPart = $Value.Substring(0, $lastColon).Trim()
    $portPart = $Value.Substring($lastColon + 1).Trim()
    if ($hostPart.StartsWith("[") -and $hostPart.EndsWith("]")) {
        $hostPart = $hostPart.Substring(1, $hostPart.Length - 2)
    }

    $port = 0
    if (-not [int]::TryParse($portPart, [ref]$port)) {
        throw "Bind address port is not a valid integer: $Value"
    }

    [pscustomobject]@{
        BindHost = $hostPart
        Port = $port
    }
}

function Get-ListeningPidsForEndpoint {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BindHost,

        [Parameter(Mandatory = $true)]
        [int]$Port
    )

    $connections = @(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue)
    if ([string]::IsNullOrWhiteSpace($BindHost)) {
        return @($connections | Select-Object -ExpandProperty OwningProcess -Unique)
    }

    $normalizedHost = $BindHost.ToLowerInvariant()
    $matchingConnections = @(
        $connections | Where-Object {
            $localAddress = $_.LocalAddress.ToLowerInvariant()
            $localAddress -eq $normalizedHost -or
            $localAddress -eq "0.0.0.0" -or
            $localAddress -eq "::" -or
            $localAddress -eq "[::]"
        }
    )
    @($matchingConnections | Select-Object -ExpandProperty OwningProcess -Unique)
}

function Get-ProcessCandidates {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Selector
    )

    if ($Selector -match '^\d+$') {
        return @([int]$Selector)
    }

    $trimmedSelector = $Selector.Trim('"')
    $resolvedPath = $null
    if ([System.IO.Path]::IsPathRooted($trimmedSelector) -or $trimmedSelector.Contains("\") -or $trimmedSelector.Contains("/")) {
        try {
            $resolvedPath = [System.IO.Path]::GetFullPath($trimmedSelector)
        } catch {
            throw "Failed to normalize process path selector: $trimmedSelector"
        }

        $pathMatches = @(
            Get-CimInstance Win32_Process -ErrorAction Stop |
                Where-Object { $_.ExecutablePath -and ([string]::Equals($_.ExecutablePath, $resolvedPath, [System.StringComparison]::OrdinalIgnoreCase)) } |
                Select-Object -ExpandProperty ProcessId
        )
        return @($pathMatches | Select-Object -Unique)
    }

    $processName = [System.IO.Path]::GetFileNameWithoutExtension($trimmedSelector)
    $nameMatches = @(
        Get-Process -Name $processName -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty Id
    )
    @($nameMatches | Select-Object -Unique)
}

$endpoint = Parse-BindAddress -Value $BindAddress
$portPids = @(Get-ListeningPidsForEndpoint -BindHost $endpoint.BindHost -Port $endpoint.Port)

if (-not [string]::IsNullOrWhiteSpace($ProcessSelector)) {
    $selectorPids = @(Get-ProcessCandidates -Selector $ProcessSelector)
    if ($selectorPids.Count -eq 0) {
        throw "No running process matched selector '$ProcessSelector'"
    }

    if ($portPids.Count -gt 0) {
        $intersection = @($selectorPids | Where-Object { $portPids -contains $_ } | Select-Object -Unique)
        if ($intersection.Count -eq 1) {
            Write-Output $intersection[0]
            exit 0
        }
        if ($intersection.Count -gt 1) {
            throw "Multiple matching processes matched selector '$ProcessSelector' and listen on ${BindAddress}: $($intersection -join ', ')"
        }
    }

    if ($selectorPids.Count -eq 1) {
        Write-Output $selectorPids[0]
        exit 0
    }

    throw "Multiple running processes matched selector '$ProcessSelector': $($selectorPids -join ', ')"
}

if ($portPids.Count -eq 1) {
    Write-Output $portPids[0]
    exit 0
}

if ($portPids.Count -gt 1) {
    throw "Multiple listening processes matched ${BindAddress}: $($portPids -join ', '). Pass a process selector to disambiguate."
}

throw "No listening process was found for $BindAddress. Pass a process selector or ensure the proxy is already listening."
