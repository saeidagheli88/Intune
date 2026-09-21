$TargetVersion = [version]'9.0.20'
$dotnetX64 = Join-Path $env:SystemDrive 'Program Files\dotnet\dotnet.exe'

Write-Host 'Microsoft .NET Desktop Runtime 9.0.20 x64 compliance test'
Write-Host '----------------------------------------------------------'

if (-not (Test-Path -LiteralPath $dotnetX64)) {
    Write-Host "FAIL: x64 dotnet host was not found at $dotnetX64" -ForegroundColor Red
    exit 1
}

$inventory = @(& $dotnetX64 --list-runtimes)
$inventory | ForEach-Object { Write-Host $_ }

$desktopVersions = @($inventory | ForEach-Object {
    if ($_ -match '^Microsoft\.WindowsDesktop\.App\s+(9\.0\.\d+)\s') { [version]$Matches[1] }
})
$baseVersions = @($inventory | ForEach-Object {
    if ($_ -match '^Microsoft\.NETCore\.App\s+(9\.0\.\d+)\s') { [version]$Matches[1] }
})

$problems = @()
if ($TargetVersion -notin $desktopVersions) { $problems += 'Microsoft.WindowsDesktop.App 9.0.20 x64 is missing.' }
if ($TargetVersion -notin $baseVersions) { $problems += 'Microsoft.NETCore.App 9.0.20 x64 is missing.' }

$olderDesktop = @($desktopVersions | Where-Object { $_ -lt $TargetVersion })
$olderBase = @($baseVersions | Where-Object { $_ -lt $TargetVersion })
if ($olderDesktop.Count -gt 0) { $problems += "Older Desktop Runtime versions remain: $($olderDesktop -join ', ')" }
if ($olderBase.Count -gt 0) { $problems += "Older base Runtime versions remain: $($olderBase -join ', ')" }

if ($problems.Count -gt 0) {
    Write-Host ''
    $problems | ForEach-Object { Write-Host "FAIL: $_" -ForegroundColor Red }
    exit 1
}

Write-Host ''
Write-Host 'PASS: Required x64 Desktop/Base Runtime 9.0.20 are installed and older 9.0.x x64 patches are absent.' -ForegroundColor Green
exit 0

