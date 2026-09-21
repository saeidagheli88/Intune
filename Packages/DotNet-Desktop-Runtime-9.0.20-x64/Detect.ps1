$ErrorActionPreference = 'SilentlyContinue'
$TargetVersion = [version]'9.0.20'
$dotnetX64 = Join-Path $env:SystemDrive 'Program Files\dotnet\dotnet.exe'

if (-not (Test-Path -LiteralPath $dotnetX64)) { exit 1 }

$inventory = @(& $dotnetX64 --list-runtimes 2>$null)
if ($LASTEXITCODE -ne 0) { exit 1 }

$desktopVersions = @($inventory | ForEach-Object {
    if ($_ -match '^Microsoft\.WindowsDesktop\.App\s+(9\.0\.\d+)\s') { [version]$Matches[1] }
})
$baseVersions = @($inventory | ForEach-Object {
    if ($_ -match '^Microsoft\.NETCore\.App\s+(9\.0\.\d+)\s') { [version]$Matches[1] }
})

$targetDesktopInstalled = $TargetVersion -in $desktopVersions
$targetBaseInstalled = $TargetVersion -in $baseVersions
$olderDesktop = @($desktopVersions | Where-Object { $_ -lt $TargetVersion })
$olderBase = @($baseVersions | Where-Object { $_ -lt $TargetVersion })

if ($targetDesktopInstalled -and $targetBaseInstalled -and $olderDesktop.Count -eq 0 -and $olderBase.Count -eq 0) {
    Write-Output '.NET Desktop Runtime 9.0.20 x64 and .NET Runtime 9.0.20 x64 are installed; older 9.0.x x64 runtimes are absent.'
    exit 0
}

exit 1

