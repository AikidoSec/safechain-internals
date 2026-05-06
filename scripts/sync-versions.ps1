<#
.SYNOPSIS
  Update all version locations in the repository to a specified version.

.DESCRIPTION
  PowerShell port of scripts/sync-versions.sh. Used by
  packaging/windows/build-msi.ps1 -GenerateVersion to stamp a unique
  0.0.<unix-timestamp> version across every relevant file before a build,
  and then to restore the original version after the build completes.

  Mirrors the *.sh equivalent file-for-file so that switching between the
  macOS and Windows local builders produces consistent results.

.PARAMETER Version
  Explicit X.Y.Z release version (e.g. 1.2.5). Mutually exclusive with -Dev.

.PARAMETER Dev
  Generate a dev version as 0.0.<unix-timestamp> and apply it. Mutually
  exclusive with -Version.

.EXAMPLE
  ./scripts/sync-versions.ps1 -Version 1.2.5

.EXAMPLE
  ./scripts/sync-versions.ps1 -Dev
#>
[CmdletBinding(DefaultParameterSetName = 'Explicit')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Explicit')]
    [string]$Version,

    [Parameter(Mandatory = $true, ParameterSetName = 'Dev')]
    [switch]$Dev
)

$ErrorActionPreference = 'Stop'

if ($Dev) {
    # Match scripts/sync-versions.sh: 0.0.<seconds-since-epoch>
    $epoch = [int64]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
    $Version = "0.0.$epoch"
}

if ($Version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$') {
    throw "version must be numeric X.Y.Z, got: $Version"
}

$RepoRoot = (Get-Item (Split-Path -Parent $PSCommandPath)).Parent.FullName
$DriverDate = Get-Date -Format 'MM/dd/yyyy'

Write-Host "Syncing all versions to $Version"
Write-Host ""

# Always read/write as UTF-8 without BOM and preserve whatever line endings
# the file already contains. Get-Content -Raw + Set-Content collide with
# both BOM behaviour and CRLF rewriting on PS 5.1, so we go through
# System.IO.File for both ends.
$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)

function Update-VersionFile {
    param(
        [Parameter(Mandatory = $true)] [string]$Path,
        [Parameter(Mandatory = $true)] [object[]]$Replacements # array of @{ Pattern = '...'; Replacement = '...' }
    )

    Write-Host "  -> $Path"
    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Warning "    (file not found, skipping)"
        return
    }

    $content = [System.IO.File]::ReadAllText($Path, $Utf8NoBom)
    foreach ($r in $Replacements) {
        $content = [Regex]::Replace($content, $r.Pattern, $r.Replacement)
    }
    [System.IO.File]::WriteAllText($Path, $content, $Utf8NoBom)
}

# internal/version/version.go: Version = "..."
# Capture the optional `\r` together with the closing quote so the original
# CRLF / LF line ending is preserved verbatim through the replacement
# (otherwise CRLF files would silently be converted to LF on each sync).
Update-VersionFile (Join-Path $RepoRoot 'internal/version/version.go') @(
    @{ Pattern = '(?m)^(\s*Version\s+= ")[^"]+("\r?)$'; Replacement = "`${1}$Version`${2}" }
)

# Cargo.toml: workspace.package version (specifically the line annotated
# with "# keep in sync with GH releases" so we don't accidentally rewrite
# unrelated `version = "..."` lines for dependencies).
Update-VersionFile (Join-Path $RepoRoot 'Cargo.toml') @(
    @{ Pattern = '(?m)^(version = ")([^"]+)(".*# keep in sync with GH releases)'; Replacement = "`${1}$Version`${3}" }
)

# Cargo.lock — refresh from the (now-updated) Cargo.toml.
Write-Host "  -> $(Join-Path $RepoRoot 'Cargo.lock')"
Push-Location $RepoRoot
try {
    & cargo update --workspace
    if ($LASTEXITCODE -ne 0) {
        throw "cargo update --workspace failed with exit code $LASTEXITCODE"
    }
} finally {
    Pop-Location
}

# macOS Xcode project files (kept consistent across platforms even when
# building from Windows so that switching builders produces the same diff).
# Match `[^\r\n]+` rather than `.+` so the original line ending (CRLF on
# Windows checkout, LF on macOS) survives the replacement intact.
Update-VersionFile (Join-Path $RepoRoot 'packaging/macos/xcode/l4-proxy/Project.dist.yml') @(
    @{ Pattern = '(MARKETING_VERSION: )[^\r\n]+';        Replacement = "`${1}$Version" }
    @{ Pattern = '(CURRENT_PROJECT_VERSION: )[^\r\n]+';  Replacement = "`${1}$Version" }
)
Update-VersionFile (Join-Path $RepoRoot 'packaging/macos/xcode/l4-proxy/Project.dev.yml') @(
    @{ Pattern = '(MARKETING_VERSION: )[^\r\n]+';        Replacement = "`${1}$Version" }
    @{ Pattern = '(CURRENT_PROJECT_VERSION: )[^\r\n]+';  Replacement = "`${1}$Version" }
)
Update-VersionFile (Join-Path $RepoRoot 'packaging/macos/xcode/l7-proxy/project.yml') @(
    @{ Pattern = '(MARKETING_VERSION: )[^\r\n]+';        Replacement = "`${1}$Version" }
    @{ Pattern = '(CURRENT_PROJECT_VERSION: )[^\r\n]+';  Replacement = "`${1}$Version" }
)

# Wails / NSIS / MSIX manifests under ui/build/.
Update-VersionFile (Join-Path $RepoRoot 'ui/build/windows/msix/app_manifest.xml') @(
    @{ Pattern = '(\sVersion=")[^"]+(")'; Replacement = "`${1}$Version`${2}" }
)
Update-VersionFile (Join-Path $RepoRoot 'ui/build/config.yml') @(
    @{ Pattern = '(?m)^(  version: ")[^"]+(".*)$'; Replacement = "`${1}$Version`${2}" }
)
Update-VersionFile (Join-Path $RepoRoot 'ui/build/windows/info.json') @(
    @{ Pattern = '("file_version": ")[^"]+(")';   Replacement = "`${1}$Version`${2}" }
    @{ Pattern = '("ProductVersion": ")[^"]+(")'; Replacement = "`${1}$Version`${2}" }
)
Update-VersionFile (Join-Path $RepoRoot 'ui/build/windows/nsis/wails_tools.nsh') @(
    @{ Pattern = '(?m)^(\s*!define INFO_PRODUCTVERSION ")[^"]+("\r?)$'; Replacement = "`${1}$Version`${2}" }
)
Update-VersionFile (Join-Path $RepoRoot 'ui/build/darwin/Info.plist') @(
    @{ Pattern = '(<key>CFBundleShortVersionString</key>\s*<string>)[^<]*(</string>)'; Replacement = "`${1}$Version`${2}" }
    @{ Pattern = '(<key>CFBundleVersion</key>\s*<string>)[^<]*(</string>)';            Replacement = "`${1}$Version`${2}" }
)
Update-VersionFile (Join-Path $RepoRoot 'ui/build/darwin/Info.dev.plist') @(
    @{ Pattern = '(<key>CFBundleShortVersionString</key>\s*<string>)[^<]*(</string>)'; Replacement = "`${1}$Version`${2}" }
    @{ Pattern = '(<key>CFBundleVersion</key>\s*<string>)[^<]*(</string>)';            Replacement = "`${1}$Version`${2}" }
)
Update-VersionFile (Join-Path $RepoRoot 'ui/build/windows/wails.exe.manifest') @(
    @{ Pattern = '(name="com\.aikido[^"]*" version=")[^"]+(")'; Replacement = "`${1}$Version`${2}" }
)

# Windows L4 driver INF — DriverVer = MM/DD/YYYY,X.Y.Z.0
# `[^\r\n]*` (instead of `.*`) keeps the line ending out of the match so the
# original CRLF / LF is preserved.
Update-VersionFile (Join-Path $RepoRoot 'proxy-lib-l4-windows-driver/safechain_lib_l4_proxy_windows_driver.inx') @(
    @{ Pattern = '(?m)^DriverVer\s*=[^\r\n]*'; Replacement = "DriverVer   = $DriverDate,$Version.0" }
)

# Surface the version to GitHub Actions if invoked from CI.
if ($env:GITHUB_OUTPUT) {
    "version=$Version" | Out-File -FilePath $env:GITHUB_OUTPUT -Encoding utf8 -Append
}

Write-Host ""
Write-Host "Done. All versions set to $Version"
