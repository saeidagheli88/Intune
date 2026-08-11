<#
.SYNOPSIS
    Detects if any version of Crestron AirMedia is installed on this device.

.DESCRIPTION
    Intune Remediation DETECTION script.
    Checks HKLM, all user registry hives (active + inactive), and file paths.
    Uses already-mounted HKU hives for logged-in users (avoids access errors).
    Logs to C:\Windows\Temp -- always writable by SYSTEM.

    Exit 1 = app found  -> trigger remediation.
    Exit 0 = clean      -> no action.

.NOTES
    Intune: Run as SYSTEM | 64-bit PowerShell | No signature check
#>

$AppFilter = "*AirMedia*"

# Use C:\Windows\Temp -- always accessible by SYSTEM, no permission issues
$LogFile = "C:\Windows\Temp\Detect-CrestronAirMedia_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param([string]$Msg, [string]$Level = "INFO")
    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Msg"
    try { Add-Content -Path $LogFile -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue } catch { }
}

Write-Log "=== AirMedia Detection Started | $env:COMPUTERNAME ==="

$found   = $false
$details = [System.Collections.Generic.List[string]]::new()

function Search-RegPaths {
    param([string[]]$Paths, [string]$Scope)
    foreach ($p in $Paths) {
        try {
            $hits = Get-ItemProperty -Path $p -ErrorAction Stop |
                    Where-Object { $_.DisplayName -like $AppFilter }
            foreach ($h in $hits) {
                $script:found = $true
                $msg = "[$Scope] $($h.DisplayName) v$($h.DisplayVersion)"
                Write-Log $msg -Level "WARN"
                $script:details.Add($msg)
            }
        } catch { }
    }
}

# -- 1. HKLM (machine-wide) ----------------------------------------------------
Search-RegPaths -Scope "HKLM" -Paths @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

# -- 2. All user profiles ------------------------------------------------------
$profiles = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" `
                -ErrorAction SilentlyContinue |
            Where-Object { $_.ProfileImagePath -match "\\Users\\" }

# SIDs already loaded in HKU (users currently logged in -- do NOT re-load their hives)
$loadedSIDs = (Get-ChildItem "Registry::HKEY_USERS" -ErrorAction SilentlyContinue).PSChildName

foreach ($profile in $profiles) {
    $sid   = $profile.PSChildName
    $uPath = $profile.ProfileImagePath

    if ($loadedSIDs -contains $sid) {
        # Hive already mounted -- read directly, no reg load
        Write-Log "Active hive: $uPath ($sid)"
        Search-RegPaths -Scope "HKCU:$uPath" -Paths @(
            "Registry::HKEY_USERS\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "Registry::HKEY_USERS\$sid\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
    } else {
        # Hive not loaded -- mount temporarily
        $hivePath = "$uPath\NTUSER.DAT"
        if (-not (Test-Path $hivePath -ErrorAction SilentlyContinue)) { continue }

        $tempKey = "TempHive_$($sid -replace '[^a-zA-Z0-9]','')"
        try {
            & reg load "HKU\$tempKey" $hivePath 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) { Write-Log "Cannot load hive for $uPath" -Level "WARN"; continue }
            Write-Log "Offline hive: $uPath"
            Search-RegPaths -Scope "HKCU:$uPath" -Paths @(
                "Registry::HKEY_USERS\$tempKey\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
                "Registry::HKEY_USERS\$tempKey\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
            )
        } finally {
            [GC]::Collect(); Start-Sleep -Milliseconds 300
            & reg unload "HKU\$tempKey" 2>&1 | Out-Null
        }
    }
}

# -- 3. File-system fallback ---------------------------------------------------
foreach ($p in @(
    "$env:ProgramFiles\Crestron\AirMedia",
    "${env:ProgramFiles(x86)}\Crestron\AirMedia"
)) {
    if (Test-Path $p -ErrorAction SilentlyContinue) {
        $script:found = $true
        $msg = "[FileSystem] $p"
        Write-Log $msg -Level "WARN"
        $details.Add($msg)
    }
}

# -- Result --------------------------------------------------------------------
if ($found) {
    $summary = $details -join " | "
    Write-Log "RESULT: DETECTED -- $summary" -Level "WARN"
    Write-Host "Crestron AirMedia detected: $summary"
    exit 1
} else {
    Write-Log "RESULT: Not found."
    Write-Host "Crestron AirMedia not found."
    exit 0
}
