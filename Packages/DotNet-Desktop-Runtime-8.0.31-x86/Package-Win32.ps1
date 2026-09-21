[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$IntuneWinAppUtilPath,

    [Parameter(Mandatory)]
    [string]$OutputFolder
)

$ErrorActionPreference = 'Stop'
$installer = Join-Path $PSScriptRoot 'windowsdesktop-runtime-8.0.31-win-x86.exe'

if (-not (Test-Path -LiteralPath $IntuneWinAppUtilPath)) {
    throw "IntuneWinAppUtil.exe was not found: $IntuneWinAppUtilPath"
}
if (-not (Test-Path -LiteralPath $installer)) {
    throw 'The Desktop Runtime installer is missing. Run Download-DesktopRuntime.ps1 first.'
}

New-Item -Path $OutputFolder -ItemType Directory -Force | Out-Null
& $IntuneWinAppUtilPath -c $PSScriptRoot -s 'Install.ps1' -o $OutputFolder -q
if ($LASTEXITCODE -ne 0) { throw "IntuneWinAppUtil failed with exit code $LASTEXITCODE." }

Write-Host "Package created in: $OutputFolder" -ForegroundColor Green

