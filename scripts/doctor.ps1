# Aikido Endpoint Protection — Doctor (Windows)

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

function ExpectConfig($name, $actual, $expected) {
    if ($actual -eq $expected) {
        Ok $name
    } else {
        $got = if ($actual) { $actual } else { "<not set>" }
        Fail $name "expected '$expected', got '$got'"
    }
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
    if ($LASTEXITCODE -eq 0) {
        Ok "Health check"
    } else {
        Fail "Health check" "returned exit code $LASTEXITCODE"
    }
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
    if (Test-Path "$RunDir\$f") {
        Ok $f
    } else {
        Fail $f "missing from $RunDir"
    }
}

Write-Host "`nPackage manager CA configuration"

$npmCafile = (npm config get cafile 2>$null) -replace "`r|`n", ""
ExpectConfig "npm cafile" $npmCafile "$RunDir\endpoint-protection-combined-ca.pem"

$nodeExtraCa = [System.Environment]::GetEnvironmentVariable("NODE_EXTRA_CA_CERTS", "Machine")
ExpectConfig "NODE_EXTRA_CA_CERTS (Machine)" $nodeExtraCa "$RunDir\endpoint-protection-combined-ca.pem"

$pipCert = (pip config get global.cert 2>$null) -replace "`r|`n", ""
ExpectConfig "pip global.cert" $pipCert "$RunDir\endpoint-protection-pip-combined-ca.pem"

$gitCa = (git config --global http.sslCAInfo 2>$null) -replace "`r|`n", ""
ExpectConfig "git http.sslCAInfo" $gitCa "$RunDir\endpoint-protection-git-combined-ca.pem"

exit $status
