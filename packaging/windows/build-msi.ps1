# Build MSI installer for Aikido Endpoint Protection.
#
# Two modes:
#
# 1. CI mode (default): assumes binaries are already in $BinDir (typical
#    GitHub Actions usage where each binary is built in a separate job and
#    downloaded as an artifact). Produces an MSI WITHOUT the L4 kernel
#    driver and WITHOUT the userspace L4 proxy. This is the historical
#    behavior; the CI workflow keeps invoking this script the same way.
#
# 2. Local end-to-end mode (-Local): builds Go binaries, the UI, the L7
#    proxy, the L4 proxy and the kernel driver from source, generates a
#    self-signed code-signing certificate (if missing), signs the driver
#    catalog with it, and bundles everything into the resulting MSI. The
#    MSI's deferred custom actions then trust the bundled .cer on the
#    target machine and install the driver via pnputil.
#
# Requirements:
# - WiX Toolset v4+ (`dotnet tool install -g wix`).
# - For -Local: Rust + cargo, Go, wails3, Visual Studio C++ Build Tools,
#   Windows SDK + WDK, LLVM/Clang. See docs/proxy/l4_proxy/windows-driver.md.
#   The script auto-imports the VS Dev environment (link.exe, INCLUDE, LIB)
#   via VsDevCmd.bat, so it can be run from a plain PowerShell session.

param(
    [Parameter(Mandatory = $false)]
    [string]$Version = "dev",

    [Parameter(Mandatory = $false)]
    [string]$BinDir = ".\bin",

    [Parameter(Mandatory = $false)]
    [string]$OutputDir = ".\dist",

    [Parameter(Mandatory = $false)]
    [switch]$Local,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeDriver,

    [Parameter(Mandatory = $false)]
    [string]$CertSubject = "CN=SafeChain Test"
)

$ErrorActionPreference = "Stop"

# `-Local` and `-IncludeDriver` are equivalent: there is no realistic way to
# obtain a signed driver bundle locally without source-building, and CI never
# packages the driver. Treat either flag as "do a full source rebuild and
# include the driver".
if ($Local -or $IncludeDriver) {
    $Local = $true
    $IncludeDriver = $true
}

$ProjectDir = (Get-Item (Split-Path -Parent $MyInvocation.MyCommand.Path)).Parent.Parent.FullName
$WxsFile = Join-Path $ProjectDir "packaging\windows\EndpointProtection.wxs"
$CustomUIFile = Join-Path $ProjectDir "packaging\windows\WixUI_InstallDir_Custom.wxs"
$BuildDriverScript = Join-Path $ProjectDir "packaging\windows\build-driver.ps1"

if (-not [System.IO.Path]::IsPathRooted($BinDir)) {
    $BinDir = [System.IO.Path]::GetFullPath((Join-Path (Get-Location).Path $BinDir))
}
if (-not [System.IO.Path]::IsPathRooted($OutputDir)) {
    $OutputDir = [System.IO.Path]::GetFullPath((Join-Path (Get-Location).Path $OutputDir))
}

if ($Version -eq "dev" -or [string]::IsNullOrEmpty($Version)) {
    $WixVersion = "0.0.0"
} else {
    $WixVersion = $Version
}

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}
if (-not (Test-Path $BinDir)) {
    New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
}

Write-Host "==> Building MSI for Aikido Endpoint Protection v$Version" -ForegroundColor Cyan
Write-Host "  WiX product version : $WixVersion"
Write-Host "  Mode                : $(if ($Local) { 'LOCAL (full build)' } else { 'CI (use existing bins)' })"
Write-Host "  Include driver      : $IncludeDriver"
Write-Host "  BinDir              : $BinDir"
Write-Host "  OutputDir           : $OutputDir"
Write-Host "  ProjectDir          : $ProjectDir"

# ----------------------------------------------------------------------------
# Local-build steps (only run with -Local)
# ----------------------------------------------------------------------------

function Invoke-Tool {
    param(
        [Parameter(Mandatory = $true)] [string]$ToolDescription,
        [Parameter(Mandatory = $true)] [scriptblock]$Action
    )

    Write-Host ""
    Write-Host "==> $ToolDescription" -ForegroundColor Cyan
    & $Action
    if ($LASTEXITCODE -ne 0) {
        throw "$ToolDescription failed with exit code $LASTEXITCODE"
    }
}

function Find-Tool {
    param(
        [Parameter(Mandatory = $true)] [string]$Name,
        [Parameter(Mandatory = $false)] [string[]]$ExtraSearchDirs = @()
    )

    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    foreach ($dir in $ExtraSearchDirs) {
        if (-not $dir) { continue }
        $candidate = Join-Path $dir "$Name.exe"
        if (Test-Path $candidate) {
            $resolved = (Resolve-Path $candidate).Path
            if (-not ($env:PATH -split ';' | Where-Object { $_ -ieq $dir })) {
                $env:PATH = "$dir;$env:PATH"
            }
            return $resolved
        }
    }

    return $null
}

function Find-VsDevCmd {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswhere)) { return $null }

    $installPath = & $vswhere -latest -prerelease -products * `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -property installationPath 2>$null | Select-Object -First 1
    if (-not $installPath) { return $null }

    $vsDevCmd = Join-Path $installPath "Common7\Tools\VsDevCmd.bat"
    if (Test-Path $vsDevCmd) { return $vsDevCmd }

    return $null
}

function Get-HostArch {
    switch ($env:PROCESSOR_ARCHITECTURE) {
        "ARM64" { return "arm64" }
        "AMD64" { return "amd64" }
        "x86"   { return "x86" }
        default { return "amd64" }
    }
}

# Loads the *host* VS Dev environment (link.exe, INCLUDE, LIB matching the
# current machine's architecture). This is required so cargo's host-side
# build scripts (proc-macro2, serde_core, ...) link correctly. Cross-target
# Rust compilation is handled separately by rustc's bundled MSVC tool
# finder (find-msvc-tools), which locates the right cross linker on its own
# (e.g. HostARM64\x64\link.exe on an ARM64 host targeting x86_64).
function Import-VsDevEnv {
    param(
        [Parameter(Mandatory = $true)] [string]$VsDevCmd
    )

    $hostArch = Get-HostArch
    $envDump = & cmd.exe /c "`"$VsDevCmd`" -arch=$hostArch -host_arch=$hostArch -no_logo && set"
    if ($LASTEXITCODE -ne 0) {
        throw "VsDevCmd.bat failed (host=$hostArch target=$hostArch)"
    }
    foreach ($line in $envDump) {
        if ($line -match '^(?<n>[^=]+)=(?<v>.*)$') {
            Set-Item -Path "Env:$($Matches.n)" -Value $Matches.v
        }
    }
}

if ($Local) {
    $RustTriple = "x86_64-pc-windows-msvc"
    $GoOS = "windows"
    $GoArch = "amd64"

    $env:GOOS = $GoOS
    $env:GOARCH = $GoArch
    $env:CGO_ENABLED = "0"

    $cargoSearchDirs = @(
        (Join-Path $env:USERPROFILE ".cargo\bin"),
        $(if ($env:CARGO_HOME) { Join-Path $env:CARGO_HOME "bin" } else { $null })
    )
    $goSearchDirs = @(
        "C:\Program Files\Go\bin",
        (Join-Path $env:USERPROFILE "go\bin")
    )
    $wails3SearchDirs = @(
        (Join-Path $env:USERPROFILE "go\bin")
    )

    Write-Host ""
    Write-Host "==> Verifying local-build prerequisites" -ForegroundColor Cyan

    $cargoPath  = Find-Tool -Name "cargo"  -ExtraSearchDirs $cargoSearchDirs
    $rustupPath = Find-Tool -Name "rustup" -ExtraSearchDirs $cargoSearchDirs
    $goPath     = Find-Tool -Name "go"     -ExtraSearchDirs $goSearchDirs
    $wails3Path = Find-Tool -Name "wails3" -ExtraSearchDirs $wails3SearchDirs
    $wixPath    = Find-Tool -Name "wix"
    $vsDevCmd   = Find-VsDevCmd
    $cmakePath  = Find-Tool -Name "cmake"
    $nasmPath   = Find-Tool -Name "nasm"   -ExtraSearchDirs @(
        "C:\Program Files\NASM",
        "C:\Program Files (x86)\NASM",
        (Join-Path $env:LOCALAPPDATA "bin\NASM"),
        (Join-Path $env:LOCALAPPDATA "Programs\NASM")
    )
    $clangPath  = Find-Tool -Name "clang"  -ExtraSearchDirs @("C:\Program Files\LLVM\bin")
    $libclang   = $null
    foreach ($d in @($env:LIBCLANG_PATH, "C:\Program Files\LLVM\bin")) {
        if ($d -and (Test-Path (Join-Path $d "libclang.dll"))) { $libclang = (Join-Path $d "libclang.dll"); break }
    }

    Write-Host ("  cargo    : " + ($(if ($cargoPath)  { $cargoPath }  else { "NOT FOUND" })))
    Write-Host ("  rustup   : " + ($(if ($rustupPath) { $rustupPath } else { "NOT FOUND (will skip target add)" })))
    Write-Host ("  go       : " + ($(if ($goPath)     { $goPath }     else { "NOT FOUND" })))
    Write-Host ("  wails3   : " + ($(if ($wails3Path) { $wails3Path } else { "NOT FOUND" })))
    Write-Host ("  wix      : " + ($(if ($wixPath)    { $wixPath }    else { "NOT FOUND" })))
    Write-Host ("  VsDevCmd : " + ($(if ($vsDevCmd)   { $vsDevCmd }   else { "NOT FOUND" })))
    Write-Host ("  cmake    : " + ($(if ($cmakePath)  { $cmakePath }  else { "NOT FOUND" })))
    Write-Host ("  nasm     : " + ($(if ($nasmPath)   { $nasmPath }   else { "NOT FOUND" })))
    Write-Host ("  clang    : " + ($(if ($clangPath)  { $clangPath }  else { "NOT FOUND" })))
    Write-Host ("  libclang : " + ($(if ($libclang)   { $libclang }   else { "NOT FOUND" })))

    $vsHint = "Install VS 2022 Build Tools with the C++ workload:`n" +
              "      winget install --id Microsoft.VisualStudio.2022.BuildTools -e --override `"--quiet --wait --add Microsoft.VisualStudio.Workload.VCTools --add Microsoft.VisualStudio.Component.Windows11SDK.22621 --includeRecommended`""

    $required = @(
        @{ Tool = $cargoPath;  Hint = "Install Rust from https://rustup.rs/" },
        @{ Tool = $goPath;     Hint = "Install Go from https://go.dev/dl/" },
        @{ Tool = $wails3Path; Hint = "go install github.com/wailsapp/wails/v3/cmd/wails3@v3.0.0-alpha.78" },
        @{ Tool = $wixPath;    Hint = "dotnet tool install -g wix --version 6.0.2" },
        @{ Tool = $vsDevCmd;   Hint = $vsHint },
        @{ Tool = $cmakePath;  Hint = "winget install --id Kitware.CMake -e" },
        @{ Tool = $nasmPath;   Hint = "winget install --id NASM.NASM -e   (required by aws-lc-sys)" },
        @{ Tool = $libclang;   Hint = "winget install --id LLVM.LLVM -e   (required by bindgen / aws-lc-sys; provides libclang.dll)" }
    )
    $missing = $required | Where-Object { -not $_.Tool }
    if ($missing) {
        Write-Host ""
        Write-Host "Missing local-build prerequisites:" -ForegroundColor Red
        foreach ($m in $missing) { Write-Host "  - $($m.Hint)" -ForegroundColor Red }
        exit 1
    }

    if (-not $env:LIBCLANG_PATH) {
        $env:LIBCLANG_PATH = Split-Path $libclang -Parent
        Write-Host "  (set LIBCLANG_PATH=$env:LIBCLANG_PATH for bindgen)"
    }
    if ($nasmPath) {
        $nasmDir = Split-Path $nasmPath -Parent
        if (-not ($env:PATH -split ';' | Where-Object { $_ -ieq $nasmDir })) {
            $env:PATH = "$nasmDir;$env:PATH"
        }
    }

    $hostArch = Get-HostArch
    Invoke-Tool "Importing VS Dev environment (host=$hostArch)" {
        Import-VsDevEnv -VsDevCmd $vsDevCmd
        $linkPath = (Get-Command link.exe -ErrorAction SilentlyContinue).Source
        if (-not $linkPath) {
            throw "link.exe still not on PATH after importing VS Dev environment"
        }
        Write-Host "  link.exe : $linkPath"

        $hostMsvcDir = Split-Path $linkPath -Parent
        $hostBinDir  = Split-Path (Split-Path $hostMsvcDir -Parent) -Parent
        $expectedHost = "Host" + $hostArch
        $nativeHostBin = Get-ChildItem $hostBinDir -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -ieq $expectedHost } |
            ForEach-Object { Join-Path $_.FullName $hostArch } |
            Where-Object { Test-Path (Join-Path $_ "link.exe") } |
            Select-Object -First 1
        if (-not $nativeHostBin) {
            throw @"
Native MSVC tools for host '$hostArch' are missing.
Cargo's host-side build scripts cannot compile.
Install the matching component, e.g. on ARM64:
  winget install --id Microsoft.VisualStudio.2022.BuildTools -e --override `"--quiet --wait --add Microsoft.VisualStudio.Workload.VCTools --add Microsoft.VisualStudio.Component.VC.Tools.ARM64 --add Microsoft.VisualStudio.Component.Windows11SDK.22621 --includeRecommended`"
"@
        }
        $global:LASTEXITCODE = 0
    }

    if ($rustupPath) {
        Invoke-Tool "Ensuring Rust target $RustTriple" {
            & rustup target add $RustTriple
        }
    } else {
        Write-Host ""
        Write-Host "==> Skipping 'rustup target add $RustTriple' (rustup not found)" -ForegroundColor Yellow
        Write-Host "    Make sure the target is already installed; otherwise install rustup from https://rustup.rs/" -ForegroundColor Yellow
    }

    Invoke-Tool "Building Go daemon (cmd/daemon -> EndpointProtection.exe)" {
        Push-Location $ProjectDir
        try {
            $ldflags = "-s -w"
            $outPath = Join-Path $BinDir "EndpointProtection.exe"
            & go build -trimpath -ldflags $ldflags -o $outPath "./cmd/daemon"
        } finally {
            Pop-Location
        }
    }

    Invoke-Tool "Building Wails UI (-> EndpointProtectionUI.exe)" {
        $env:CGO_ENABLED = "1"
        Push-Location (Join-Path $ProjectDir "ui")
        try {
            & wails3 package
        } finally {
            Pop-Location
            $env:CGO_ENABLED = "0"
        }

        $uiSrc = Join-Path $ProjectDir "ui\bin\endpoint-protection-ui.exe"
        if (-not (Test-Path $uiSrc)) {
            throw "Expected UI binary not found at $uiSrc"
        }
        Copy-Item -LiteralPath $uiSrc -Destination (Join-Path $BinDir "EndpointProtectionUI.exe") -Force
    }

    Invoke-Tool "Building safechain-l7-proxy ($RustTriple)" {
        Push-Location $ProjectDir
        try {
            & cargo build --release -p safechain-l7-proxy --target $RustTriple
        } finally {
            Pop-Location
        }
        Copy-Item -LiteralPath (Join-Path $ProjectDir "target\$RustTriple\release\safechain-l7-proxy.exe") `
                  -Destination (Join-Path $BinDir "SafeChainL7Proxy.exe") -Force
    }

    Invoke-Tool "Building safechain-l4-proxy ($RustTriple)" {
        Push-Location $ProjectDir
        try {
            & cargo build --release -p safechain-l4-proxy --target $RustTriple
        } finally {
            Pop-Location
        }
        Copy-Item -LiteralPath (Join-Path $ProjectDir "target\$RustTriple\release\safechain-l4-proxy.exe") `
                  -Destination (Join-Path $BinDir "SafeChainL4Proxy.exe") -Force
    }

    Invoke-Tool "Building + staging + self-signing kernel driver" {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $BuildDriverScript `
            -Profile dev `
            -TargetArch amd64 `
            -BundleDir (Join-Path $BinDir "driver") `
            -CertSubject $CertSubject
    }
}

# ----------------------------------------------------------------------------
# Verify required artifacts exist
# ----------------------------------------------------------------------------

$AgentExe = Join-Path $BinDir "EndpointProtection.exe"
$AgentUIExe = Join-Path $BinDir "EndpointProtectionUI.exe"
$L7ProxyExe = Join-Path $BinDir "SafeChainL7Proxy.exe"
$StoreTokenScript = Join-Path $ProjectDir "packaging\windows\scripts\StoreToken.ps1"

$RequiredFiles = [System.Collections.Generic.List[hashtable]]::new()
$RequiredFiles.Add(@{ Label = "EndpointProtection.exe"; Path = $AgentExe })
$RequiredFiles.Add(@{ Label = "EndpointProtectionUI.exe"; Path = $AgentUIExe })
$RequiredFiles.Add(@{ Label = "SafeChainL7Proxy.exe"; Path = $L7ProxyExe })
$RequiredFiles.Add(@{ Label = "StoreToken.ps1"; Path = $StoreTokenScript })

if ($IncludeDriver) {
    $L4ProxyExe = Join-Path $BinDir "SafeChainL4Proxy.exe"
    $InstallDriverScript = Join-Path $ProjectDir "packaging\windows\scripts\install-driver.ps1"
    $UninstallDriverScript = Join-Path $ProjectDir "packaging\windows\scripts\uninstall-driver.ps1"
    $DriverBundleDir = Join-Path $BinDir "driver"

    $RequiredFiles.Add(@{ Label = "SafeChainL4Proxy.exe"; Path = $L4ProxyExe })
    $RequiredFiles.Add(@{ Label = "install-driver.ps1"; Path = $InstallDriverScript })
    $RequiredFiles.Add(@{ Label = "uninstall-driver.ps1"; Path = $UninstallDriverScript })

    $DriverBundleFiles = @(
        "safechain_lib_l4_proxy_windows_driver.sys",
        "safechain_lib_l4_proxy_windows_driver.inf",
        "safechain_lib_l4_proxy_windows_driver.cat",
        "safechain-driver.cer"
    )
    foreach ($file in $DriverBundleFiles) {
        $RequiredFiles.Add(@{ Label = "driver\$file"; Path = (Join-Path $DriverBundleDir $file) })
    }
}

$missing = $RequiredFiles | Where-Object { -not (Test-Path $_.Path) }
if ($missing) {
    Write-Host ""
    Write-Host "Missing required files:" -ForegroundColor Red
    foreach ($m in $missing) {
        Write-Host "  - $($m.Label): $($m.Path)" -ForegroundColor Red
    }
    if (-not $Local) {
        Write-Host ""
        Write-Host "Hint: run with -Local to build all artifacts from source." -ForegroundColor Yellow
    }
    exit 1
}

# ----------------------------------------------------------------------------
# Build the MSI
# ----------------------------------------------------------------------------

$OutputMsi = Join-Path $OutputDir "EndpointProtection.msi"
$IncludeDriverDefine = if ($IncludeDriver) { "1" } else { "0" }

Write-Host ""
Write-Host "==> Building MSI -> $OutputMsi" -ForegroundColor Cyan

& wix eula accept wix7 | Out-Null

& wix build $WxsFile $CustomUIFile `
    -d "Version=$WixVersion" `
    -d "BinDir=$BinDir" `
    -d "ProjectDir=$ProjectDir" `
    -d "IncludeDriver=$IncludeDriverDefine" `
    -ext WixToolset.UI.wixext `
    -ext WixToolset.Util.wixext `
    -arch x64 `
    -o $OutputMsi

if ($LASTEXITCODE -ne 0) {
    Write-Host "MSI build failed" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "MSI built successfully: $OutputMsi" -ForegroundColor Green

$hash = Get-FileHash -Path $OutputMsi -Algorithm SHA256
Write-Host "SHA256: $($hash.Hash)"
$hash.Hash | Out-File -FilePath "$OutputMsi.sha256" -NoNewline
