# Remove iTunes via Intune
$AppGuid = "{9D0D2A8B-7E7B-4D88-8D50-24286ED6A5EB}"
$UninstallKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$AppGuid"
$UninstallKeyWow6432 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$AppGuid"
$AppPath = "C:\Program Files\iTunes\iTunes.exe"
$AppFolder = "C:\Program Files\iTunes"

function Stop-AppProcesses {
    $processNames = @("iTunes","iTunesHelper","AppleMobileDeviceService")
    foreach ($proc in $processNames) {
        Get-Process -Name $proc -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
}

function Run-UninstallString {
    param([string]$UninstallString)
    if ($UninstallString -match "msiexec") {
        if ($UninstallString -match "/I") {
            $UninstallString = $UninstallString -replace "/I", "/X"
        }
        $UninstallString += " /qn /norestart"
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c $UninstallString" -Wait -NoNewWindow
    }
}

Stop-AppProcesses

if (Test-Path $UninstallKey) {
    $UninstallString = (Get-ItemProperty $UninstallKey).UninstallString
    Run-UninstallString $UninstallString
} elseif (Test-Path $UninstallKeyWow6432) {
    $UninstallString = (Get-ItemProperty $UninstallKeyWow6432).UninstallString
    Run-UninstallString $UninstallString
}

Start-Process "msiexec.exe" -ArgumentList "/x $AppGuid /qn /norestart" -Wait

if (Test-Path $AppFolder) {
    Remove-Item $AppFolder -Recurse -Force -ErrorAction SilentlyContinue
}

Remove-Item $UninstallKey -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $UninstallKeyWow6432 -Recurse -Force -ErrorAction SilentlyContinue
