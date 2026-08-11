<#
.SYNOPSIS
    Silently uninstalls ALL versions of Crestron AirMedia from any install scope.

.DESCRIPTION
    Intune Remediation REMEDIATION script.
    Searches HKLM, all user registry hives (active and inactive), and file paths.
    Uses already-mounted HKU hives for logged-in users (avoids access errors).
    Logs to C:\Windows\Temp -- always writable by SYSTEM.

    Removes EVERY scope/version seen in inventory: the HKLM Machine-Wide
    Installer (MSI) and all per-user 3.x/4.x/5.x copies (HKCU/EXE).

    Hardening:
      * Stops any running AirMedia process first (prevents msiexec 1603).
      * Prefers QuietUninstallString, falls back to UninstallString.
      * Retries msiexec on 1618 (another install in progress).
      * Win32_Product fallback when msiexec /x fails (e.g. 1612 source missing).
      * Bounds every uninstall with a timeout so the script can't hang.
      * Treats 0/1605/1614/1641/3010 as success.
      * Cleans legacy + modern (Crestron Electronics, Inc) folders & shortcuts.
      * ALWAYS writes a final summary line so Intune never gets empty output.

.NOTES
    Intune: Run as SYSTEM | 64-bit PowerShell | No signature check
#>

$AppFilter      = "*AirMedia*"
$LogFile        = "C:\Windows\Temp\Remediate-CrestronAirMedia_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$ProcTimeoutSec = 300   # max seconds to wait for any single uninstall
$MsiSuccess     = @(0, 1605, 1614, 1641, 3010)   # 1605/1614 = not installed, 1641/3010 = reboot

function Write-Log {
    param([string]$Msg, [string]$Level = "INFO")
    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Msg"
    try { Add-Content -Path $LogFile -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue } catch { }
    Write-Output $line
}

# Stop anything that would lock the MSI during uninstall.
function Stop-AirMediaProcesses {
    $names = @("AirMedia", "Crestron*AirMedia*", "AirMediaDesktop", "Crestron.AirMedia")
    foreach ($n in $names) {
        Get-Process -Name $n -ErrorAction SilentlyContinue | ForEach-Object {
            try { $_ | Stop-Process -Force -ErrorAction Stop; Write-Log "Stopped process: $($_.ProcessName) (PID $($_.Id))" }
            catch { Write-Log "Could not stop $($_.ProcessName): $_" -Level "WARN" }
        }
    }
}

# Run a process with a hard timeout. Returns the exit code, or -1 on timeout.
function Invoke-Process {
    param([string]$FilePath, [string]$Arguments)
    $p = Start-Process -FilePath $FilePath -ArgumentList $Arguments -PassThru -NoNewWindow
    if (-not $p.WaitForExit($ProcTimeoutSec * 1000)) {
        try { $p.Kill() } catch { }
        Write-Log "Timed out after $ProcTimeoutSec s: $FilePath $Arguments" -Level "WARN"
        return -1
    }
    return $p.ExitCode
}

# Last-resort MSI removal via the installer database, by product name.
# Used only when msiexec /x by GUID fails (e.g. mangled UninstallString).
function Invoke-Win32ProductFallback {
    param([string]$Name)
    try {
        $prod = Get-CimInstance -ClassName Win32_Product `
                    -Filter "Name LIKE '%AirMedia%'" -ErrorAction Stop |
                Where-Object { $_.Name -eq $Name -or $_.Name -like $AppFilter }
        if (-not $prod) { Write-Log "Win32_Product fallback: no matching MSI product." -Level "WARN"; return $false }
        $ok = $true
        foreach ($pr in $prod) {
            Write-Log "Win32_Product fallback uninstalling: $($pr.Name) ($($pr.IdentifyingNumber))"
            $r = Invoke-CimMethod -InputObject $pr -MethodName Uninstall -ErrorAction SilentlyContinue
            Write-Log "Win32_Product Uninstall returned: $($r.ReturnValue)"
            if ($r.ReturnValue -ne 0) { $ok = $false }
        }
        return $ok
    } catch {
        Write-Log "Win32_Product fallback error: $_" -Level "WARN"
        return $false
    }
}

function Invoke-Uninstall {
    param([string]$Name, [string]$UninstallString, [string]$QuietUninstallString, [string]$Source)
    Write-Log "Uninstalling [$Source] $Name"

    Stop-AirMediaProcesses

    # -- MSI path (most reliable; works by product code) -----------------------
    $cmd = if ($QuietUninstallString) { $QuietUninstallString } else { $UninstallString }
    if (-not $cmd) { Write-Log "No UninstallString -- skipped." -Level "WARN"; return $false }

    if ($cmd -match "msiexec|(\{[0-9A-Fa-f\-]{36}\})") {
        $guid = [regex]::Match($cmd, '\{[0-9A-Fa-f\-]{36}\}').Value
        if ($guid) {
            $msiArgs = "/x $guid /qn /norestart REBOOT=ReallySuppress"
            for ($try = 1; $try -le 3; $try++) {
                $code = Invoke-Process -FilePath "msiexec.exe" -Arguments $msiArgs
                Write-Log "msiexec /x $guid -> exit $code (attempt $try)"
                if ($code -in $MsiSuccess) { return $true }
                if ($code -eq 1618) {                 # another install running -- wait & retry
                    Write-Log "1618 (install busy). Waiting 30s before retry." -Level "WARN"
                    Start-Sleep -Seconds 30
                    continue
                }
                break   # any other code: don't keep hammering
            }
            # msiexec /x failed (e.g. 1612 cached source missing) -- try the installer DB.
            Write-Log "msiexec /x did not succeed; trying Win32_Product fallback." -Level "WARN"
            return (Invoke-Win32ProductFallback -Name $Name)
        }
    }

    # -- EXE path --------------------------------------------------------------
    if ($cmd -match '^"(.+?)"(.*)') {
        $exe = $Matches[1]; $a = $Matches[2].Trim()
    } else {
        $parts = $cmd -split ' ', 2
        $exe = $parts[0]; $a = if ($parts.Count -gt 1) { $parts[1] } else { "" }
    }
    if (-not $QuietUninstallString) {   # only force silent flags if we had to use UninstallString
        foreach ($f in @("/S", "/silent", "/quiet", "/norestart")) {
            if ($a -notmatch [regex]::Escape($f)) { $a += " $f" }
        }
    }
    Write-Log "EXE: `"$exe`" $($a.Trim())"
    $code = Invoke-Process -FilePath $exe -Arguments $a.Trim()
    Write-Log "EXE exit: $code"
    return ($code -in @(0, 3010, 1641))
}

$processed      = @{}
$overallSuccess = $true
$actedCount     = 0

function Remove-FromRegPaths {
    param([string[]]$Paths, [string]$Scope)
    foreach ($p in $Paths) {
        try {
            $hits = Get-ItemProperty -Path $p -ErrorAction Stop |
                    Where-Object { $_.DisplayName -like $AppFilter }
            foreach ($h in $hits) {
                $key = "$($h.DisplayName)|$($h.DisplayVersion)"
                if ($script:processed[$key]) { Write-Log "Already handled: $key -- skip."; continue }
                $script:processed[$key] = $true
                $script:actedCount++
                $ok = Invoke-Uninstall -Name $h.DisplayName `
                                       -UninstallString $h.UninstallString `
                                       -QuietUninstallString $h.QuietUninstallString `
                                       -Source $Scope
                if (-not $ok) { $script:overallSuccess = $false }
            }
        } catch { }
    }
}

Write-Log "=== AirMedia Remediation Started | $env:COMPUTERNAME ==="

# -- 1. HKLM ------------------------------------------------------------------
Remove-FromRegPaths -Scope "HKLM" -Paths @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

# -- 2. All user profiles ------------------------------------------------------
$profiles = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" `
                -ErrorAction SilentlyContinue |
            Where-Object { $_.ProfileImagePath -match "\\Users\\" }

$loadedSIDs = (Get-ChildItem "Registry::HKEY_USERS" -ErrorAction SilentlyContinue).PSChildName

foreach ($profile in $profiles) {
    $sid   = $profile.PSChildName
    $uPath = $profile.ProfileImagePath

    if ($loadedSIDs -contains $sid) {
        Write-Log "Active hive: $uPath"
        Remove-FromRegPaths -Scope "HKCU:$uPath" -Paths @(
            "Registry::HKEY_USERS\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "Registry::HKEY_USERS\$sid\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
    } else {
        $hivePath = "$uPath\NTUSER.DAT"
        if (-not (Test-Path $hivePath -ErrorAction SilentlyContinue)) { continue }

        $tempKey = "TempHive_$($sid -replace '[^a-zA-Z0-9]','')"
        try {
            & reg load "HKU\$tempKey" $hivePath 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) { Write-Log "Cannot load hive for $uPath" -Level "WARN"; continue }
            Write-Log "Offline hive: $uPath"
            Remove-FromRegPaths -Scope "HKCU:$uPath" -Paths @(
                "Registry::HKEY_USERS\$tempKey\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
                "Registry::HKEY_USERS\$tempKey\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
            )
        } finally {
            [GC]::Collect(); Start-Sleep -Milliseconds 300
            & reg unload "HKU\$tempKey" 2>&1 | Out-Null
        }
    }
}

# -- 3. Remove leftover folders & shortcuts ------------------------------------
# Covers legacy ("Crestron\AirMedia") and modern 5.x ("Crestron Electronics, Inc\AirMedia") layouts.
$folders = @(
    "$env:ProgramFiles\Crestron\AirMedia",
    "${env:ProgramFiles(x86)}\Crestron\AirMedia",
    "$env:ProgramFiles\Crestron Electronics, Inc\AirMedia",
    "${env:ProgramFiles(x86)}\Crestron Electronics, Inc\AirMedia",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Crestron AirMedia"
)
foreach ($profile in $profiles) {
    $base = $profile.ProfileImagePath
    $folders += @(
        "$base\AppData\Local\Programs\Crestron\AirMedia",
        "$base\AppData\Local\Programs\Crestron Electronics, Inc\AirMedia",
        "$base\AppData\Local\Crestron\AirMedia",
        "$base\AppData\Roaming\Crestron\AirMedia",
        "$base\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Crestron AirMedia"
    )
}
foreach ($f in $folders) {
    if (Test-Path $f -ErrorAction SilentlyContinue) {
        try { Remove-Item $f -Recurse -Force -ErrorAction Stop; Write-Log "Removed: $f" }
        catch { Write-Log "Cannot remove $f : $_" -Level "WARN" }
    }
}

# -- 4. Verify HKLM clean -----------------------------------------------------
Write-Log "--- Verification ---"
$remain = @()
foreach ($p in @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)) {
    $remain += Get-ItemProperty -Path $p -ErrorAction SilentlyContinue |
               Where-Object { $_.DisplayName -like $AppFilter }
}

if ($remain) {
    Write-Log "$($remain.Count) HKLM entry still present." -Level "WARN"
    $overallSuccess = $false
} else {
    Write-Log "HKLM clear."
}

# Guaranteed final output line (so Intune never records empty output).
$summary = "Done. Entries acted on: $actedCount. Success: $overallSuccess."
Write-Log "=== $summary ==="
Write-Output $summary

if ($overallSuccess) { exit 0 } else { exit 1 }
