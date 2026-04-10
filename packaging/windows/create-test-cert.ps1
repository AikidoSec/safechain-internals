param(
    [Parameter(Mandatory = $false)]
    [string]$CertSubject = "CN=SafeChain Test",

    [Parameter(Mandatory = $false)]
    [string]$ExportDir = ".\test-cert",

    [Parameter(Mandatory = $false)]
    [int]$ValidYears = 3,

    [Parameter(Mandatory = $false)]
    [switch]$CurrentUserOnly,

    [Parameter(Mandatory = $false)]
    [switch]$EnableBcdEdit
)

$ErrorActionPreference = "Stop"

function Test-IsAdministrator {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Ensure-Directory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Get-CertStoreBase {
    param(
        [Parameter(Mandatory = $true)]
        [bool]$UseCurrentUser
    )

    if ($UseCurrentUser) {
        return "Cert:\CurrentUser"
    }

    return "Cert:\LocalMachine"
}

function Get-OrCreate-CodeSigningCert {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Subject,

        [Parameter(Mandatory = $true)]
        [string]$MyStorePath,

        [Parameter(Mandatory = $true)]
        [int]$Years
    )

    $existing = Get-ChildItem -Path $MyStorePath -CodeSigningCert -ErrorAction SilentlyContinue |
        Where-Object { $_.Subject -eq $Subject } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1

    if ($existing) {
        Write-Host "Using existing certificate" -ForegroundColor Green
        Write-Host "  Subject    : $($existing.Subject)"
        Write-Host "  Thumbprint : $($existing.Thumbprint)"
        Write-Host "  Expires    : $($existing.NotAfter)"
        return $existing
    }

    Write-Host "Creating new self signed code signing certificate" -ForegroundColor Green

    $cert = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $Subject `
        -CertStoreLocation $MyStorePath `
        -HashAlgorithm "SHA256" `
        -KeyAlgorithm "RSA" `
        -KeyLength 2048 `
        -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" `
        -KeyExportPolicy Exportable `
        -NotAfter (Get-Date).AddYears($Years)

    Write-Host "Created certificate"
    Write-Host "  Subject    : $($cert.Subject)"
    Write-Host "  Thumbprint : $($cert.Thumbprint)"
    Write-Host "  Expires    : $($cert.NotAfter)"

    return $cert
}

function Export-PublicCertificateFile {
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    Export-Certificate -Cert $Certificate -FilePath $OutputPath -Force | Out-Null
    Write-Host "Exported public certificate to: $OutputPath" -ForegroundColor Green
}

function Install-CertificateIntoStore {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CertFilePath,

        [Parameter(Mandatory = $true)]
        [string]$StorePath
    )

    $alreadyInstalled = Get-ChildItem -Path $StorePath -ErrorAction SilentlyContinue |
        Where-Object {
            try {
                $_.Thumbprint -eq $script:CertThumbprint
            } catch {
                $false
            }
        } |
        Select-Object -First 1

    if ($alreadyInstalled) {
        Write-Host "Certificate already present in $StorePath" -ForegroundColor Yellow
        return
    }

    Import-Certificate -FilePath $CertFilePath -CertStoreLocation $StorePath | Out-Null
    Write-Host "Installed certificate into: $StorePath" -ForegroundColor Green
}

function Enable-TestSigning {
    Write-Host "Enabling Windows test signing mode" -ForegroundColor Green
    & bcdedit /set testsigning on

    if ($LASTEXITCODE -ne 0) {
        throw "bcdedit failed with exit code $LASTEXITCODE"
    }

    Write-Host "Test signing mode enabled. Reboot is required for it to take effect." -ForegroundColor Yellow
}

$useCurrentUser = [bool]$CurrentUserOnly
$needsAdmin = (-not $useCurrentUser) -or ($EnableBcdEdit)

if ($needsAdmin -and -not (Test-IsAdministrator)) {
    throw "This script must be run as Administrator unless you use -CurrentUserOnly without -EnableBcdEdit."
}

$storeBase = Get-CertStoreBase -UseCurrentUser $useCurrentUser
$myStore = Join-Path $storeBase "My"
$rootStore = Join-Path $storeBase "Root"
$trustedPublisherStore = Join-Path $storeBase "TrustedPublisher"

$ExportDir = [System.IO.Path]::GetFullPath($ExportDir)
Ensure-Directory -Path $ExportDir

$cert = Get-OrCreate-CodeSigningCert -Subject $CertSubject -MyStorePath $myStore -Years $ValidYears
$script:CertThumbprint = $cert.Thumbprint

$sanitizedName = ($CertSubject -replace '^CN=', '') -replace '[^a-zA-Z0-9._-]', '_'
$cerPath = Join-Path $ExportDir "$sanitizedName.cer"

Export-PublicCertificateFile -Certificate $cert -OutputPath $cerPath

Install-CertificateIntoStore -CertFilePath $cerPath -StorePath $rootStore
Install-CertificateIntoStore -CertFilePath $cerPath -StorePath $trustedPublisherStore

if ($EnableBcdEdit) {
    Enable-TestSigning
}

Write-Host ""
Write-Host "Done." -ForegroundColor Green
Write-Host "Certificate subject : $($cert.Subject)"
Write-Host "Thumbprint          : $($cert.Thumbprint)"
Write-Host "Public cert file    : $cerPath"
Write-Host "My store            : $myStore"
Write-Host "Root store          : $rootStore"
Write-Host "TrustedPublisher    : $trustedPublisherStore"

if ($EnableBcdEdit) {
    Write-Host ""
    Write-Host "Next step: reboot the machine before testing the driver." -ForegroundColor Yellow
}