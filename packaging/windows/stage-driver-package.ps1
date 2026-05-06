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
    Join-Path $ProjectDir "dist\windows-driver-package\$Profile"
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
$driverVersion = "$workspaceVersion.0"
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

        & $inf2cat.Source /driver:$OutputDir /os:10_X64
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
