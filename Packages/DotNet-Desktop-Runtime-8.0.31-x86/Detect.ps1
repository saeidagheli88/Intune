$ErrorActionPreference = 'SilentlyContinue'
$TargetVersion = [version]'8.0.31'
$dotnetX86 = Join-Path ${env:ProgramFiles(x86)} 'dotnet\dotnet.exe'

if (-not (Test-Path -LiteralPath $dotnetX86)) { exit 1 }

$inventory = @(& $dotnetX86 --list-runtimes 2>$null)
if ($LASTEXITCODE -ne 0) { exit 1 }

$desktopVersions = @($inventory | ForEach-Object {
    if ($_ -match '^Microsoft\.WindowsDesktop\.App\s+(8\.0\.\d+)\s') { [version]$Matches[1] }
})
$baseVersions = @($inventory | ForEach-Object {
    if ($_ -match '^Microsoft\.NETCore\.App\s+(8\.0\.\d+)\s') { [version]$Matches[1] }
})

$targetDesktopInstalled = $TargetVersion -in $desktopVersions
$targetBaseInstalled = $TargetVersion -in $baseVersions
$olderDesktop = @($desktopVersions | Where-Object { $_ -lt $TargetVersion })
$olderBase = @($baseVersions | Where-Object { $_ -lt $TargetVersion })

if ($targetDesktopInstalled -and $targetBaseInstalled -and $olderDesktop.Count -eq 0 -and $olderBase.Count -eq 0) {
    Write-Output '.NET Desktop Runtime 8.0.31 x86 and .NET Runtime 8.0.31 x86 are installed; older 8.0.x x86 runtimes are absent.'
    exit 0
}

exit 1

