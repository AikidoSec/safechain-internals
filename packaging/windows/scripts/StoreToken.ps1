param(
    [Parameter(Mandatory=$true)]
    [string]$Token
)

$dir = Join-Path $env:ProgramData "AikidoSecurity\SafeChainUltimate\run"
if (-not (Test-Path $dir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}

$configFile = Join-Path $dir "config.json"
$json = '{"token":"' + $Token + '"}'
[System.IO.File]::WriteAllText($configFile, $json)
