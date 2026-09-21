$TargetVersion = [version]'8.0.31'
$dotnetX86 = Join-Path ${env:ProgramFiles(x86)} 'dotnet\dotnet.exe'

Write-Host 'Microsoft .NET Desktop Runtime 8.0.31 x86 compliance test'
Write-Host '----------------------------------------------------------'

if (-not (Test-Path -LiteralPath $dotnetX86)) {
    Write-Host "FAIL: x86 dotnet host was not found at $dotnetX86" -ForegroundColor Red
    exit 1
}

$inventory = @(& $dotnetX86 --list-runtimes)
$inventory | ForEach-Object { Write-Host $_ }

$desktopVersions = @($inventory | ForEach-Object {
    if ($_ -match '^Microsoft\.WindowsDesktop\.App\s+(8\.0\.\d+)\s') { [version]$Matches[1] }
})
$baseVersions = @($inventory | ForEach-Object {
    if ($_ -match '^Microsoft\.NETCore\.App\s+(8\.0\.\d+)\s') { [version]$Matches[1] }
})

$problems = @()
if ($TargetVersion -notin $desktopVersions) { $problems += 'Microsoft.WindowsDesktop.App 8.0.31 x86 is missing.' }
if ($TargetVersion -notin $baseVersions) { $problems += 'Microsoft.NETCore.App 8.0.31 x86 is missing.' }

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
Write-Host 'PASS: Required x86 Desktop/Base Runtime 8.0.31 are installed and older 8.0.x x86 patches are absent.' -ForegroundColor Green
exit 0

