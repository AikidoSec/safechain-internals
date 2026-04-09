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
$DefaultDriverSysPath = Join-Path $ProjectDir "target\$Profile\safechain_lib_l4_proxy_windows_driver.sys"
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
$InfPath = Join-Path $OutputDir $InfFileName
$CatPath = Join-Path $OutputDir $CatFileName

if (-not (Test-Path $TemplatePath)) {
    throw "INF template not found: $TemplatePath"
}

if (-not (Test-Path $DriverSysPath)) {
    throw "Driver binary not found: $DriverSysPath"
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
Copy-Item -LiteralPath $DriverSysPath -Destination (Join-Path $OutputDir $DriverFileName) -Force

$infContents = Get-Content -LiteralPath $TemplatePath -Raw
Set-Content -LiteralPath $InfPath -Value $infContents -Encoding ASCII

Write-Host "Staged driver package:" -ForegroundColor Green
Write-Host "  sys: $DriverSysPath"
Write-Host "  inf: $InfPath"
Write-Host "  out: $OutputDir"

f (-not $SkipInf2Cat) {
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

        $signtool = Get-Command SignTool.exe -ErrorAction SilentlyContinue
        if ($null -eq $signtool) {
            throw "SignTool.exe was not found on PATH."
        }

        Write-Host "Signing catalog file with test certificate..."
        $signArgs = @(
            "sign",
            "/v",
            "/fd", "SHA256",
            "/s", $CertStore,
            "/n", $CertSubject
        )

        if (-not $NoTimestamp) {
            $signArgs += @("/tr", "http://timestamp.digicert.com", "/td", "SHA256")
        }

        $signArgs += $CatPath

        & $signtool.Source @signArgs
        if ($LASTEXITCODE -ne 0) {
            throw "SignTool sign failed with exit code $LASTEXITCODE"
        }

        Write-Host "Verifying catalog signature..."
        & $signtool.Source verify /v /kp /c $CatPath (Join-Path $OutputDir $DriverFileName)
        if ($LASTEXITCODE -ne 0) {
            throw "SignTool verify failed with exit code $LASTEXITCODE"
        }
    }
}s
