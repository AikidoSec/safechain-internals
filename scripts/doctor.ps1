# Aikido Endpoint Protection -- Doctor (Windows)

$AppDir  = "C:\Program Files\AikidoSecurity\EndpointProtection"
$Healthy = "$AppDir\scripts\Healthy.ps1"
$RunDir  = "$env:ProgramData\AikidoSecurity\EndpointProtection\run"

$status = 0

function Ok($name) {
    Write-Host "  [OK]   $name" -ForegroundColor Green
}

function Fail($name, $detail = $null) {
    $msg = if ($detail) { "  [FAIL] $name -- $detail" } else { "  [FAIL] $name" }
    Write-Host $msg -ForegroundColor Red
    $script:status = 1
}

function ExpectEnv($var, $expected) {
    $actual = [System.Environment]::GetEnvironmentVariable($var, "User")
    if ($actual -eq $expected) {
        Ok $var
    } else {
        $got = if ($actual) { $actual } else { "<not set>" }
        Fail $var "expected '$expected', got '$got'"
    }
}

function IsSetEnv($var) {
    $actual = [System.Environment]::GetEnvironmentVariable($var, "User")
    if ($actual) { Ok $var } else { Fail $var "not set" }
}

function CheckGemrc {
    $gemrc = "$env:USERPROFILE\.gemrc"
    if (-not (Test-Path $gemrc)) {
        Fail "~/.gemrc" "file not found"
        return
    }
    $lines = Get-Content $gemrc
    $inBlock = $false
    $certPath = $null
    foreach ($line in $lines) {
        if ($line -match "# aikido-endpoint-ruby-gemrc-start") { $inBlock = $true }
        if ($inBlock -and $line -match "^:ssl_ca_cert:\s+(.+)") { $certPath = $Matches[1].Trim() }
        if ($line -match "# aikido-endpoint-ruby-gemrc-end") { $inBlock = $false }
    }
    if (-not $certPath) {
        Fail "~/.gemrc" "Aikido block not found or :ssl_ca_cert: missing"
        return
    }
    if (Test-Path $certPath) { Ok "~/.gemrc :ssl_ca_cert" } else { Fail "~/.gemrc :ssl_ca_cert" "cert file not found: $certPath" }
}

Write-Host "Aikido Endpoint Protection -- Doctor"
Write-Host "===================================="

Write-Host "`nInstallation"

if (Test-Path $AppDir) {
    Ok "App installed"
} else {
    Fail "App installed" "not found at $AppDir"
}

if (Test-Path $Healthy) {
    & $Healthy | Out-Null
    if ($LASTEXITCODE -eq 0) { Ok "Health check" } else { Fail "Health check" "returned exit code $LASTEXITCODE" }
} else {
    Fail "Health check" "script not found: $Healthy"
}

Write-Host "`nRun directory"

$files = @(
    "config.json",
    "endpoint-protection-combined-ca.pem",
    "endpoint-protection-git-combined-ca.pem",
    "endpoint-protection-node-original-extra-ca-certs.txt",
    "endpoint-protection-openssl-combined-ca.pem",
    "endpoint-protection-pip-combined-ca.pem",
    "endpoint-protection-pip-original-cert-path.txt",
    "endpoint-protection-proxy-ca-crt.pem",
    "endpoint-protection-ruby-combined-ca.pem"
)

foreach ($f in $files) {
    if (Test-Path "$RunDir\$f") { Ok $f } else { Fail $f "missing from $RunDir" }
}

Write-Host "`nPackage manager CA configuration"

# Node.js
ExpectEnv "NODE_EXTRA_CA_CERTS" "$RunDir\endpoint-protection-combined-ca.pem"

if (Get-Command npm -ErrorAction SilentlyContinue) {
    $npmCafile = (npm config get cafile 2>$null) -replace "`r|`n", ""
    if (-not $npmCafile -or $npmCafile -eq "null") {
        Ok "npm cafile"
    } elseif ($npmCafile -eq "$RunDir\endpoint-protection-npm-cafile.pem") {
        Ok "npm cafile"
    } else {
        Fail "npm cafile" "expected null or '$RunDir\endpoint-protection-npm-cafile.pem', got '$npmCafile'"
    }
} else {
    Write-Host "  [SKIP] npm cafile -- npm not found"
}

# Python
ExpectEnv "PIP_CERT"           "$RunDir\endpoint-protection-pip-combined-ca.pem"
ExpectEnv "REQUESTS_CA_BUNDLE" "$RunDir\endpoint-protection-pip-combined-ca.pem"
ExpectEnv "SSL_CERT_FILE"      "$RunDir\endpoint-protection-openssl-combined-ca.pem"

# Java
$javaOpts = [System.Environment]::GetEnvironmentVariable("JAVA_TOOL_OPTIONS", "User")
if ($javaOpts -and $javaOpts.Contains("-Djavax.net.ssl.trustStore=NUL") -and $javaOpts.Contains("-Djavax.net.ssl.trustStoreType=Windows-ROOT")) {
    Ok "JAVA_TOOL_OPTIONS"
} else {
    Fail "JAVA_TOOL_OPTIONS" "expected to contain '-Djavax.net.ssl.trustStore=NUL' and '-Djavax.net.ssl.trustStoreType=Windows-ROOT'"
}

# Ruby
ExpectEnv "BUNDLE_SSL_CA_CERT" "$RunDir\endpoint-protection-ruby-combined-ca.pem"
CheckGemrc

# Git (gitconfig, not an env var)
$gitCa = (git config --global http.sslCAInfo 2>$null) -replace "`r|`n", ""
$expectedGitCa = "$RunDir\endpoint-protection-git-combined-ca.pem"
if ($gitCa -eq $expectedGitCa) {
    Ok "git http.sslCAInfo"
} else {
    $got = if ($gitCa) { $gitCa } else { "<not set>" }
    Fail "git http.sslCAInfo" "expected '$expectedGitCa', got '$got'"
}

exit $status
