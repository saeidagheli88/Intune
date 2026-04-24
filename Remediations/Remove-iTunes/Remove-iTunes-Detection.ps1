$AppGuid = "{9D0D2A8B-7E7B-4D88-8D50-24286ED6A5EB}"
$UninstallKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$AppGuid"
$UninstallKeyWow6432 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$AppGuid"
$AppPath = "C:\Program Files\iTunes\iTunes.exe"

if ((Test-Path $UninstallKey) -or (Test-Path $UninstallKeyWow6432) -or (Test-Path $AppPath)) {
    Write-Output "iTunes detected"
    exit 1
} else {
    Write-Output "iTunes not detected"
    exit 0
}
