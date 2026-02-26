param(
    [Parameter(Mandatory=$true)]
    [string]$Token
)

$dir = Join-Path $env:ProgramData "AikidoSecurity\SafeChainUltimate\run"
if (-not (Test-Path $dir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}

$tokenFile = Join-Path $dir ".token"
[System.IO.File]::WriteAllText($tokenFile, $Token)
