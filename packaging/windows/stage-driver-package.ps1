# Stage the SafeChain Windows L4 driver package for local/dev install.
#
# This script:
# - locates the built `.sys`
# - renders the `.inx` template as `.inf`
# - copies all package files into a staging directory
# - optionally runs `Inf2Cat` when available

param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("debug", "release")]
    [string]$Profile = "debug",

    # Target architecture used for the cargo build. The product ships x64
    # only, so we default to amd64 unconditionally - this also matches how
    # build-driver.ps1 invokes `cargo wdk build --target-arch amd64`, which
    # places the .sys under target\<rust-triple>\<profile>\.
    [Parameter(Mandatory = $false)]
    [ValidateSet("amd64", "arm64")]
    [string]$TargetArch = "amd64",

    [Parameter(Mandatory = $false)]
    [string]$DriverSysPath,

    [Parameter(Mandatory = $false)]
    [string]$OutputDir,

    [Parameter(Mandatory = $false)]
    [switch]$SkipInf2Cat,

    [Parameter(Mandatory = $false)]
    [string]$CertSubject = "CN=SafeChain Test",

    [Parameter(Mandatory = $false)]
    [string]$CertStore = "My",

    [Parameter(Mandatory = $false)]
    [switch]$NoTimestamp
)

function Find-SignTool {
    $kitsRoot = "C:\Program Files (x86)\Windows Kits\10\bin"
    if (-not (Test-Path $kitsRoot)) {
        return $null
    }

    $candidates = Get-ChildItem -Path $kitsRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
        Sort-Object Name -Descending

    foreach ($candidate in $candidates) {
        foreach ($arch in @("x64", "x86")) {
            $path = Join-Path $candidate.FullName "$arch\signtool.exe"
            if (Test-Path $path) {
                return $path
            }
        }
    }

    return $null
}

function Get-SigningCertificate {
    param(
        [string]$Subject = "CN=SafeChain Test"
    )

    $cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -eq $Subject -and $_.HasPrivateKey } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1

    if ($cert) {
        return @{
            Cert = $cert
            UseMachineStore = $false
        }
    }

    $cert = Get-ChildItem Cert:\LocalMachine\My -CodeSigningCert -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -eq $Subject -and $_.HasPrivateKey } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1

    if ($cert) {
        return @{
            Cert = $cert
            UseMachineStore = $true
        }
    }

    return $null
}

function Find-Inf2Cat {
    $kitsRoot = "C:\Program Files (x86)\Windows Kits\10\bin"
    if (-not (Test-Path $kitsRoot)) {
        return $null
    }

    $candidates = Get-ChildItem -Path $kitsRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
        Sort-Object Name -Descending

    foreach ($candidate in $candidates) {
        foreach ($arch in @("x64", "x86")) {
            $path = Join-Path $candidate.FullName "$arch\Inf2Cat.exe"
            if (Test-Path $path) {
                return $path
            }
        }
    }

    return $null
}

$ErrorActionPreference = "Stop"

$ProjectDir = (Get-Item (Split-Path -Parent $MyInvocation.MyCommand.Path)).Parent.Parent.FullName
$DriverDir = Join-Path $ProjectDir "proxy-lib-l4-windows-driver"
$WorkspaceCargoToml = Join-Path $ProjectDir "Cargo.toml"
$RustTriple = switch ($TargetArch) {
    "amd64" { "x86_64-pc-windows-msvc" }
    "arm64" { "aarch64-pc-windows-msvc" }
}
$DefaultDriverSysPath = Join-Path $ProjectDir "target\$RustTriple\$Profile\safechain_lib_l4_proxy_windows_driver.sys"
$TemplatePath = Join-Path $DriverDir "safechain_lib_l4_proxy_windows_driver.inx"
$OutputDir = if ($OutputDir) {
    [System.IO.Path]::GetFullPath($OutputDir)
} else {
    Join-Path $ProjectDir "dist\windows-driver-package\$Profile-$TargetArch"
}

$Inf2CatOs = switch ($TargetArch) {
    "amd64" { "10_X64" }
    "arm64" { "10_ARM64" }
}

if (-not $DriverSysPath) {
    $DriverSysPath = $DefaultDriverSysPath
}
$DriverSysPath = [System.IO.Path]::GetFullPath($DriverSysPath)

$DriverFileName = "safechain_lib_l4_proxy_windows_driver.sys"
$InfFileName = "safechain_lib_l4_proxy_windows_driver.inf"
$CatFileName = "safechain_lib_l4_proxy_windows_driver.cat"
$DriverServiceName = "SafeChainL4Proxy"
$DriverHardwareId = "Root\SafeChainL4Proxy"
$InfPath = Join-Path $OutputDir $InfFileName
$CatPath = Join-Path $OutputDir $CatFileName

function Get-WorkspaceVersion {
    param([string]$CargoTomlPath)

    if (-not (Test-Path $CargoTomlPath)) {
        throw "Workspace Cargo.toml not found: $CargoTomlPath"
    }

    $match = Select-String -Path $CargoTomlPath -Pattern '^\s*version = "([^"]+)"' | Select-Object -First 1
    if (-not $match) {
        throw "Could not determine workspace version from $CargoTomlPath"
    }

    return $match.Matches[0].Groups[1].Value
}

# Convert a Cargo SemVer (major.minor.patch) into the four-part w.x.y.z form
# used by INF DriverVer and Windows VS_VERSIONINFO. Each component must fit in
# a u16 (0..=65535). Local dev versions (scripts\sync-versions.ps1 -Dev) emit
# 0.0.<unix-timestamp> whose patch overflows u16, so we split a wide patch into
# (high16, low16) and place those in fields 3 and 4. This keeps every dev build
# unique while still producing a valid Windows version.
#
# Layout (must match parse_version_quad in proxy-lib-l4-windows-driver/build.rs):
#   patch <= 65535 -> "<major>.<minor>.<patch>.0"
#   patch >  65535 -> "<major>.<minor>.<patch>>16.<patch & 0xFFFF>"
function Convert-CargoVersionToWindowsQuad {
    param([Parameter(Mandatory = $true)][string]$CargoVersion)

    $parts = $CargoVersion.Split('.')
    if ($parts.Count -lt 3) {
        throw "Cargo version '$CargoVersion' must have at least 3 components"
    }

    [uint16]$major = 0
    if (-not [uint16]::TryParse($parts[0], [ref]$major)) {
        throw "Cargo version '$CargoVersion' major component '$($parts[0])' does not fit in u16"
    }
    [uint16]$minor = 0
    if (-not [uint16]::TryParse($parts[1], [ref]$minor)) {
        throw "Cargo version '$CargoVersion' minor component '$($parts[1])' does not fit in u16"
    }

    [uint32]$patch = 0
    if (-not [uint32]::TryParse($parts[2], [ref]$patch)) {
        throw "Cargo version '$CargoVersion' patch component '$($parts[2])' is not a non-negative integer"
    }

    if ($patch -le 65535) {
        return "{0}.{1}.{2}.0" -f $major, $minor, $patch
    }

    $patchHi = ($patch -shr 16) -band 0xFFFF
    $patchLo = $patch -band 0xFFFF
    return "{0}.{1}.{2}.{3}" -f $major, $minor, $patchHi, $patchLo
}

if (-not (Test-Path $TemplatePath)) {
    throw "INF template not found: $TemplatePath"
}

if (-not (Test-Path $DriverSysPath)) {
    throw "Driver binary not found: $DriverSysPath"
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
Copy-Item -LiteralPath $DriverSysPath -Destination (Join-Path $OutputDir $DriverFileName) -Force

$infContents = Get-Content -LiteralPath $TemplatePath -Raw
$workspaceVersion = Get-WorkspaceVersion -CargoTomlPath $WorkspaceCargoToml
$driverVersion = Convert-CargoVersionToWindowsQuad -CargoVersion $workspaceVersion
$driverDate = Get-Date -Format 'MM/dd/yyyy'
$infContents = [Regex]::Replace(
    $infContents,
    '(?m)^DriverVer\s*=.*$',
    "DriverVer   = $driverDate,$driverVersion"
)
Set-Content -LiteralPath $InfPath -Value $infContents -Encoding ASCII

Write-Host "Staged driver package:" -ForegroundColor Green
Write-Host "  sys: $DriverSysPath"
Write-Host "  inf: $InfPath"
Write-Host "  driver date/version: $driverDate / $driverVersion"
Write-Host "  out: $OutputDir"
Write-Host "  service: $DriverServiceName"
Write-Host "  hardware id: $DriverHardwareId"

if (-not $SkipInf2Cat) {
    $inf2cat = Get-Command Inf2Cat.exe -ErrorAction SilentlyContinue
    if ($null -eq $inf2cat) {
        $inf2catPath = Find-Inf2Cat
        if ($inf2catPath) {
            $inf2cat = @{ Source = $inf2catPath }
        }
    }

    if ($null -eq $inf2cat) {
        Write-Warning "Inf2Cat.exe was not found on PATH; skipping catalog generation."
    } else {
        Write-Host "Running Inf2Cat to generate catalog..."
        Write-Host "  using: $($inf2cat.Source)"

        & $inf2cat.Source /driver:$OutputDir /os:$Inf2CatOs
        if ($LASTEXITCODE -ne 0) {
            throw "Inf2Cat failed with exit code $LASTEXITCODE"
        }

        if (-not (Test-Path $CatPath)) {
            throw "Inf2Cat completed but $CatPath was not found."
        }

        Write-Host "  cat: $CatPath"

        $signTool = Get-Command SignTool.exe -ErrorAction SilentlyContinue
        if ($null -eq $signTool) {
            $signToolPath = Find-SignTool
            if ($signToolPath) {
                $signTool = @{ Source = $signToolPath }
            }
        }

        if ($null -eq $signTool) {
            throw "SignTool.exe was not found. Install the Windows SDK / WDK, or add signtool.exe to PATH."
        }

        $signingCertInfo = Get-SigningCertificate -Subject $CertSubject
        if (-not $signingCertInfo) {
            throw "No matching code-signing certificate with private key was found in CurrentUser\My or LocalMachine\My."
        }

        $cert = $signingCertInfo.Cert

        Write-Host "Using signing certificate:" -ForegroundColor Green
        Write-Host "  Subject    : $($cert.Subject)"
        Write-Host "  Thumbprint : $($cert.Thumbprint)"
        Write-Host "  Store      : " + ($(if ($signingCertInfo.UseMachineStore) { "LocalMachine\My" } else { "CurrentUser\My" }))

        Write-Host "Signing catalog file with test certificate..."

        $signArgs = @(
            "sign",
            "/v",
            "/debug",
            "/fd", "SHA256",
            "/sha1", $cert.Thumbprint,
            "/s", "My"
        )

        if ($signingCertInfo.UseMachineStore) {
            $signArgs += "/sm"
        }

        if (-not $NoTimestamp) {
            $signArgs += @("/tr", "http://timestamp.digicert.com", "/td", "SHA256")
        }

        $signArgs += $CatPath

        Write-Host "SignTool path: $($signTool.Source)"
        Write-Host "SignTool args: $($signArgs -join ' ')"

        & $signTool.Source @signArgs
        if ($LASTEXITCODE -ne 0) {
            throw "SignTool sign failed with exit code $LASTEXITCODE"
        }

        Write-Host "Verifying catalog signature for test install policy..."
        & $signTool.Source verify /v /pa /c $CatPath (Join-Path $OutputDir $DriverFileName)
        if ($LASTEXITCODE -ne 0) {
            throw "Catalog verification failed with exit code $LASTEXITCODE"
        }
    }
}
