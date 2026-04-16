$ErrorActionPreference = "Stop"

$CertUrl = "http://mitm.ramaproxy.org/data/root.ca.pem"
$CertFileName = "ramaproxy-root.ca.pem"

function Test-IsAdministrator {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdministrator)) {
    throw "This script must be run from an elevated PowerShell session so it can write to the LocalMachine Root certificate store."
}

$certPath = Join-Path $env:TEMP $CertFileName

Write-Host "Downloading root certificate from $CertUrl" -ForegroundColor Green
Write-Host "  temp file: $certPath"
Invoke-WebRequest -Uri $CertUrl -OutFile $certPath

Write-Host "Importing certificate into Cert:\LocalMachine\Root" -ForegroundColor Green
Import-Certificate -FilePath $certPath -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null

Write-Host "Trusted root certificate installed successfully." -ForegroundColor Green
