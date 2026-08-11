<#
.SYNOPSIS
    Removes ALL Brave Browser installs from a Windows device -- management
    decision is FULL REMOVAL (no Brave install is allowed to remain). Pairs
    with Detect-Brave.ps1 (keep the CONFIG block identical in both).

.DESCRIPTION
    Intune Remediation REMEDIATION script.

    WHAT IT DOES:
      1. Stops every running Brave process (brave.exe, BraveUpdate.exe, crash
         handlers, plus anything executing out of a BraveSoftware folder,
         which catches elevation_service.exe) so uninstalls/deletes cannot hang.
      2. For MACHINE-WIDE installs, first tries the official Chromium-style
         uninstaller (Brave-Browser\Application\<ver>\Installer\setup.exe
         --uninstall --system-level --force-uninstall). This is best-effort:
         success code 19 (UNINSTALL_SUCCESSFUL) or 0 is logged, anything else
         is tolerated because the brute-force passes below guarantee the end
         state either way.
      3. Removes every machine-wide Brave ARP entry that survives (both
         registry views): MSI-coded entries via msiexec (0/1605/3010/1641
         convention); everything else brute-force key deletion. Never uses
         Win32_Product.
      4. Stops and deletes Brave services (Brave Update's 'brave'/'bravem',
         BraveElevationService, Brave VPN services -- matched by BINARY PATH
         containing \BraveSoftware\, never by name alone) and unregisters the
         BraveSoftwareUpdate* scheduled tasks so nothing can reinstall it.
      5. Deletes the machine-wide BraveSoftware folders. A locked file is
         queued for delete-on-reboot via PendingFileRenameOperations
         (MoveFileEx), which detection already treats as compliant.
      6. Sweeps EVERY user profile (loaded HKU hives in place; logged-off
         NTUSER.DAT hives 'reg load'ed and ALWAYS unloaded in finally):
           - deletes Brave per-user Uninstall keys (per-user installs cannot
             run their uninstaller reliably from SYSTEM -- brute-force is the
             reliable path and matches the folder deletion),
           - deletes Brave Run values,
           - deletes AppData\Local\BraveSoftware (app + browser profile data
             -- full removal per management decision),
           - deletes BraveSoftware / BraveHTML registry leftovers and Classes
             keys, and Brave shortcuts (Desktop / Start Menu / Startup).
      7. Removes machine-level leftovers: HKLM Run values (both views),
         HKLM\SOFTWARE\BraveSoftware vendor keys, BraveHTML/Brave* Classes
         keys, Start Menu and Public Desktop shortcuts.
      8. Removes any Brave MSIX/Store package for all users + deprovisions.
      9. VERIFY pass using the IDENTICAL classification rules as
         Detect-Brave.ps1 (ARP entries + binary-gated folders with the
         pending-delete guard + Appx). Any residual -> exit 1, so Intune shows
         the device honestly as "not fixed" instead of flapping.

    IDEMPOTENT: second run finds nothing -> no-op exit 0.

    EXIT CODES:
        exit 0 = success or no-op (including "done, reboot pending").
        exit 1 = at least one action FAILED / residual Brave remains.

    OUTPUT: diagnostics to Write-Host (transcript only); exactly ONE
    Write-Output summary line at the end (<2048 chars).

.NOTES
    Author : Endpoint Engineering (Monster Energy)
    Target : Windows PowerShell 5.1, SYSTEM context
    Intune : Run using logged-on credentials = No (SYSTEM)
             Run script in 64-bit PowerShell = Yes (REQUIRED)
             Enforce script signature check  = No
#>

#--------------------------------------------------------------------------------
# 0. 64-bit self-relaunch guard (guarded on a real $PSCommandPath).
#--------------------------------------------------------------------------------
if (($env:PROCESSOR_ARCHITEW6432 -eq 'AMD64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') -and
    -not [Environment]::Is64BitProcess) {
    $sysnative = Join-Path $env:WINDIR 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if ((-not [string]::IsNullOrWhiteSpace($PSCommandPath)) -and
        (Test-Path -LiteralPath $PSCommandPath) -and
        (Test-Path -LiteralPath $sysnative)) {
        & $sysnative -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath @args
        exit $LASTEXITCODE
    }
}

$ErrorActionPreference = 'Stop'

#--------------------------------------------------------------------------------
# CONFIG -- keep IDENTICAL in Detect-Brave.ps1 / Remediate-Brave.ps1
#--------------------------------------------------------------------------------
$BraveStrongName  = '(?i)^\s*brave\b'
$BraveLooseName   = '(?i)\bbrave\b'
$BraveBinaryNames = @('brave.exe','BraveUpdate.exe')
$MachineDirs = @(
    (Join-Path $env:ProgramFiles 'BraveSoftware')
)
if (${env:ProgramFiles(x86)}) {
    $MachineDirs += (Join-Path ${env:ProgramFiles(x86)} 'BraveSoftware')
}
$UserAppDirRel = @('AppData\Local\BraveSoftware')

function Test-IsBrave {
    param([string]$Name, [string]$Publisher)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    if ($Name -match $BraveStrongName) { return $true }
    return (($Publisher -match '(?i)brave') -and ($Name -match $BraveLooseName))
}

function Test-IsBraveAppx {
    param([string]$Name, [string]$Publisher)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    if ($Publisher -match '(?i)CN=Microsoft') { return $false }
    return ($Name -match '(?i)brave')
}

#--------------------------------------------------------------------------------
# Remediation-only config (NOT part of the shared classifier).
#--------------------------------------------------------------------------------
# Per-profile USER-DATA folders: cleaned opportunistically, never a finding.
$UserDataDirRel = @('AppData\Roaming\BraveSoftware')
# Leftover vendor registry keys (relative to SOFTWARE), machine and per-user.
$RegLeftoverNames = @('BraveSoftware')
# Classes/protocol-handler keys (BraveHTML, BraveFile, BraveB64..., brave: ...).
$BraveClassesKeyRegex = '(?i)^brave'
# Processes to stop by name before touching anything (names without .exe).
$BraveProcesses = @('brave','BraveUpdate','BraveCrashHandler','BraveCrashHandler64')
# Path-based process kill: catches elevation_service.exe etc. (generic names).
$BraveProcPathRegex = '(?i)\\BraveSoftware\\'
# Services are matched by BINARY PATH (never name alone -- 'brave'/'bravem'
# are short names, but the path check is what makes deletion safe).
$BraveServicePathRegex = '(?i)bravesoftware'
# Scheduled tasks created by Brave Update.
$BraveTaskNameRegex = '(?i)^BraveSoftware'
# Regex for Run values / shortcuts that belong to Brave.
$BravePathRegex = '(?i)brave'

#--------------------------------------------------------------------------------
# 1. Durable logging.
#--------------------------------------------------------------------------------
$LogDir = Join-Path $env:ProgramData 'Monster\Logs'
if (-not (Test-Path -LiteralPath $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}
$LogFile = Join-Path $LogDir ("Remediate-Brave_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
try { Start-Transcript -Path $LogFile -Append -ErrorAction SilentlyContinue | Out-Null } catch { }

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    Write-Host ("[{0:yyyy-MM-dd HH:mm:ss}] [{1}] {2}" -f (Get-Date), $Level, $Msg)
}

$actions       = [System.Collections.Generic.List[string]]::new()
$failures      = [System.Collections.Generic.List[string]]::new()
$rebootPending = $false

#--------------------------------------------------------------------------------
# Shared helpers (same field-proven patterns as the 7-Zip / Adobe / Webex pairs).
#--------------------------------------------------------------------------------
function Get-ActiveUserSid {
    $sids = New-Object System.Collections.Generic.HashSet[string]
    try {
        Get-CimInstance -ClassName Win32_LoggedOnUser -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $acct = $_.Antecedent
                $nt   = New-Object System.Security.Principal.NTAccount($acct.Domain, $acct.Name)
                $sid  = $nt.Translate([System.Security.Principal.SecurityIdentifier]).Value
                if ($sid) { [void]$sids.Add($sid) }
            } catch { }
        }
    } catch { }
    return $sids
}

function Invoke-RegUnload {
    param([string]$Sid)
    if ([string]::IsNullOrWhiteSpace($Sid) -or ($Sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$')) {
        Write-Log "Invoke-RegUnload: refusing malformed SID '$Sid'." 'WARN'; return $false
    }
    $doUnload = {
        $prevEAP = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try   { $null = (& reg.exe unload "HKU\$Sid" 2>&1) }
        finally { $ErrorActionPreference = $prevEAP }
        return $LASTEXITCODE
    }
    [gc]::Collect()
    if ((& $doUnload) -ne 0) {
        Start-Sleep -Milliseconds 250
        [gc]::Collect(); [gc]::WaitForPendingFinalizers()
        if ((& $doUnload) -ne 0) {
            Write-Log "FAILED to unload HKU\$Sid (hive left mounted - may block that user's logon)." 'ERROR'
            return $false
        }
    }
    return $true
}

# Queue a locked file for delete-on-reboot via MoveFileEx(...,NULL,
# MOVEFILE_DELAY_UNTIL_REBOOT). Detection treats queued paths as compliant.
$moveFileEx = @'
using System;
using System.Runtime.InteropServices;
public static class Native {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
}
'@
try { Add-Type -TypeDefinition $moveFileEx -ErrorAction SilentlyContinue } catch { }
function Register-DeleteOnReboot {
    param([string]$Path)
    try {
        if ([Native]::MoveFileEx($Path, $null, 4)) {   # 4 = MOVEFILE_DELAY_UNTIL_REBOOT
            $script:rebootPending = $true
            Write-Log "Queued for delete-on-reboot: $Path" 'WARN'
            return $true
        }
    } catch { }
    Write-Log "Could not queue delete-on-reboot for: $Path" 'ERROR'
    return $false
}

# MSI uninstall with the exit-code convention: 0/1605 ok, 3010/1641 ok+reboot.
# (Brave ships its own Omaha installer, but an MSI-coded entry is handled
# properly should one ever appear, e.g. an enterprise MSI wrapper.)
function Uninstall-Msi {
    param([string]$ProductCode, [string]$Name)
    Write-Log "Uninstalling '$Name' ($ProductCode) via msiexec..."
    $msiLog = Join-Path $LogDir ("MsiUninstall-Brave_{0}_{1:yyyyMMdd_HHmmss}.log" -f ($ProductCode -replace '[{}]',''), (Get-Date))
    $p = Start-Process -FilePath "$env:WINDIR\System32\msiexec.exe" `
             -ArgumentList "/x $ProductCode /qn /norestart REBOOT=ReallySuppress /l*v `"$msiLog`"" `
             -Wait -PassThru
    switch ($p.ExitCode) {
        0     { Write-Log "Uninstalled '$Name'."; return $true }
        1605  { Write-Log "'$Name' was already gone (1605)."; return $true }
        3010  { Write-Log "Uninstalled '$Name' (3010: reboot pending)." 'WARN'; $script:rebootPending = $true; return $true }
        1641  { Write-Log "Uninstalled '$Name' (1641: reboot initiated by installer suppressed)." 'WARN'; $script:rebootPending = $true; return $true }
        default {
            Write-Log "msiexec /x '$Name' failed with exit code $($p.ExitCode) (log: $msiLog)." 'ERROR'
            return $false
        }
    }
}

# Best-effort official Chromium-style uninstall for MACHINE-WIDE installs.
# Success (19/0) removes ARP keys, shortcuts and Application dir cleanly; any
# other outcome is tolerated -- the brute-force passes below guarantee the
# end state regardless.
function Invoke-BraveSetupUninstall {
    param([string]$VendorRoot)   # e.g. C:\Program Files\BraveSoftware
    $ran = $false
    try {
        $setups = Get-ChildItem -Path (Join-Path $VendorRoot 'Brave-Browser\Application\*\Installer\setup.exe') `
                      -ErrorAction SilentlyContinue | Sort-Object FullName -Descending
        foreach ($setup in @($setups)) {
            $ran = $true
            Write-Log "Running official uninstaller: $($setup.FullName) --uninstall --system-level --force-uninstall"
            try {
                $p = Start-Process -FilePath $setup.FullName `
                         -ArgumentList '--uninstall --system-level --force-uninstall' `
                         -Wait -PassThru
                if ($p.ExitCode -in 0, 19) {
                    Write-Log "Official uninstaller finished (exit $($p.ExitCode) = success)."
                    $script:actions.Add("ran official Brave uninstaller ($VendorRoot)")
                } else {
                    Write-Log "Official uninstaller exit $($p.ExitCode) (tolerated; brute-force follows)." 'WARN'
                }
            } catch {
                Write-Log "Official uninstaller error ($($setup.FullName)): $($_.Exception.Message) (tolerated)." 'WARN'
            }
            break   # newest version's setup.exe is enough
        }
    } catch { Write-Log "Uninstaller lookup error ($VendorRoot): $($_.Exception.Message)" 'WARN' }
    return $ran
}

# Delete a folder; locked files get queued for delete-on-reboot. Returns $true
# when the folder is gone OR every remaining file is queued.
function Remove-FolderOrQueue {
    param([string]$Dir, [string]$Label)
    if (-not (Test-Path -LiteralPath $Dir)) { return $true }
    try {
        Remove-Item -LiteralPath $Dir -Recurse -Force -ErrorAction Stop
        Write-Log "Removed folder: $Dir"
        $script:actions.Add("removed $Label")
        return $true
    } catch {
        Write-Log "Folder locked ($Dir): $($_.Exception.Message). Queuing remaining files for delete-on-reboot." 'WARN'
    }
    $allQueued = $true
    try {
        Get-ChildItem -LiteralPath $Dir -Recurse -Force -File -ErrorAction SilentlyContinue | ForEach-Object {
            try { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop }
            catch { if (-not (Register-DeleteOnReboot -Path $_.FullName)) { $allQueued = $false } }
        }
        Get-ChildItem -LiteralPath $Dir -Recurse -Force -Directory -ErrorAction SilentlyContinue |
            Sort-Object { $_.FullName.Length } -Descending | ForEach-Object {
                try { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue } catch { }
                if (Test-Path -LiteralPath $_.FullName) { [void](Register-DeleteOnReboot -Path $_.FullName) }
            }
        try { Remove-Item -LiteralPath $Dir -Force -ErrorAction SilentlyContinue } catch { }
        if (Test-Path -LiteralPath $Dir) { [void](Register-DeleteOnReboot -Path $Dir) }
    } catch {
        Write-Log "Queue pass error ($Dir): $($_.Exception.Message)" 'WARN'
        $allQueued = $false
    }
    if ($allQueued) {
        $script:actions.Add("queued delete-on-reboot: $Label")
        return $true
    }
    $script:failures.Add("could not remove or queue: $Dir")
    return $false
}

# Remove Brave-referencing values from a Run key (HKLM views and HKU).
function Remove-BraveRunValues {
    param([Microsoft.Win32.RegistryKey]$RunKey, [string]$Scope)
    if (-not $RunKey) { return }
    foreach ($valName in @($RunKey.GetValueNames())) {
        try {
            $data = [string]$RunKey.GetValue($valName)
            if (($valName -match $BravePathRegex) -or ($data -match $BravePathRegex)) {
                $RunKey.DeleteValue($valName)
                Write-Log "Removed Run value '$valName' ($Scope)."
                $script:actions.Add("removed Run value $valName [$Scope]")
            }
        } catch { Write-Log "Run value removal error ('$valName', $Scope): $($_.Exception.Message)" 'WARN' }
    }
}

# Delete leftover vendor keys (BraveSoftware) under an opened writable SOFTWARE
# key, plus Brave Classes keys (BraveHTML, brave: ...) under an opened writable
# Classes key. Cleanup only -- never detection findings.
function Remove-BraveLeftoverKeys {
    param([Microsoft.Win32.RegistryKey]$SoftwareKey, [string]$Scope)
    if (-not $SoftwareKey) { return }
    foreach ($leftover in $RegLeftoverNames) {
        try {
            $probe = $SoftwareKey.OpenSubKey($leftover)
            if ($probe) {
                $probe.Close()
                $SoftwareKey.DeleteSubKeyTree($leftover, $false)
                Write-Log "Removed leftover key $Scope\SOFTWARE\$leftover."
                $script:actions.Add("removed key SOFTWARE\$leftover [$Scope]")
            }
        } catch { Write-Log "Leftover key removal error ($Scope\SOFTWARE\$leftover): $($_.Exception.Message)" 'WARN' }
    }
}
function Remove-BraveClassesKeys {
    param([Microsoft.Win32.RegistryKey]$ClassesKey, [string]$Scope)
    if (-not $ClassesKey) { return }
    $removed = 0
    foreach ($keyName in @($ClassesKey.GetSubKeyNames())) {
        if ($keyName -match $BraveClassesKeyRegex) {
            try {
                $ClassesKey.DeleteSubKeyTree($keyName, $false)
                Write-Log "Removed Classes key '$keyName' ($Scope)."
                $removed++
            } catch { Write-Log "Classes key removal error ('$keyName', $Scope): $($_.Exception.Message)" 'WARN' }
        }
    }
    if ($removed -gt 0) { $script:actions.Add("removed $removed Classes key(s) [$Scope]") }
}

# Delete Brave shortcuts (.lnk/.url) under a folder, recursively.
function Remove-BraveShortcuts {
    param([string]$Folder, [string]$Scope)
    if ([string]::IsNullOrWhiteSpace($Folder) -or -not (Test-Path -LiteralPath $Folder)) { return }
    try {
        Get-ChildItem -LiteralPath $Folder -Recurse -Force -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in '.lnk','.url' -and $_.BaseName -match $BravePathRegex } |
            ForEach-Object {
                try {
                    Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop
                    Write-Log "Removed shortcut: $($_.FullName)"
                } catch { Write-Log "Shortcut removal error ($($_.FullName)): $($_.Exception.Message)" 'WARN' }
            }
        Get-ChildItem -LiteralPath $Folder -Recurse -Force -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match $BravePathRegex } |
            Sort-Object { $_.FullName.Length } -Descending | ForEach-Object {
                if (-not (Get-ChildItem -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue)) {
                    try { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue } catch { }
                }
            }
    } catch { Write-Log "Shortcut sweep error ($Folder, $Scope): $($_.Exception.Message)" 'WARN' }
}

Write-Log "=== Brave removal remediation started on $env:COMPUTERNAME (64-bit host: $([Environment]::Is64BitProcess)) ==="

try {
    $sidPattern = 'S-1-5-21-\d+-\d+-\d+-\d+$'
    $hklmViews  = @([Microsoft.Win32.RegistryView]::Registry64,
                    [Microsoft.Win32.RegistryView]::Registry32)

    #----------------------------------------------------------------------------
    # Pre-pass: clean orphaned HKU mounts from a prior crashed run.
    #----------------------------------------------------------------------------
    $activeSids = Get-ActiveUserSid
    $loadedSids = (Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
                   Where-Object { $_.PSChildName -match $sidPattern }).PSChildName
    foreach ($lsid in @($loadedSids)) {
        if ([string]::IsNullOrWhiteSpace($lsid)) { continue }
        if (-not $activeSids.Contains($lsid)) {
            try {
                Write-Log "Orphaned HKU mount detected for $lsid. Attempting cleanup." 'WARN'
                if (Invoke-RegUnload -Sid $lsid) { Write-Log "Unloaded orphaned hive HKU\$lsid." }
            } catch { Write-Log "Orphan cleanup error for $lsid (continuing): $($_.Exception.Message)" 'WARN' }
        }
    }
    $loadedSids = (Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
                   Where-Object { $_.PSChildName -match $sidPattern }).PSChildName

    #----------------------------------------------------------------------------
    # 2. Stop every Brave process (user sessions included) so nothing blocks.
    #    Named processes first, then a PATH-based pass for generic names
    #    (elevation_service.exe etc.).
    #----------------------------------------------------------------------------
    foreach ($procName in $BraveProcesses) {
        try {
            $procs = Get-Process -Name $procName -ErrorAction SilentlyContinue
            if ($procs) {
                $procs | Stop-Process -Force -ErrorAction SilentlyContinue
                Write-Log "Stopped running process(es): $procName"
            }
        } catch { Write-Log "Could not stop $procName : $($_.Exception.Message)" 'WARN' }
    }
    try {
        Get-Process -ErrorAction SilentlyContinue | Where-Object {
            $_.Path -and ($_.Path -match $BraveProcPathRegex)
        } | ForEach-Object {
            try {
                Write-Log "Stopping process by path: $($_.ProcessName) ($($_.Path))"
                $_ | Stop-Process -Force -ErrorAction SilentlyContinue
            } catch { }
        }
    } catch { Write-Log "Path-based process sweep error: $($_.Exception.Message)" 'WARN' }

    #----------------------------------------------------------------------------
    # 3. Best-effort official uninstall for machine-wide installs, THEN sweep
    #    the surviving machine ARP entries (both views): MSI -> msiexec;
    #    non-MSI -> brute-force key deletion (folders handled in step 5).
    #----------------------------------------------------------------------------
    foreach ($dir in ($MachineDirs | Select-Object -Unique)) {
        if (Test-Path -LiteralPath $dir) { [void](Invoke-BraveSetupUninstall -VendorRoot $dir) }
    }

    $machineEntries = [System.Collections.Generic.List[object]]::new()
    foreach ($view in $hklmViews) {
        $base = $null
        try {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                        [Microsoft.Win32.RegistryHive]::LocalMachine, $view)
            $uninstall = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
            if ($uninstall) {
                foreach ($subName in $uninstall.GetSubKeyNames()) {
                    $sub = $uninstall.OpenSubKey($subName)
                    if (-not $sub) { continue }
                    $name = [string]$sub.GetValue('DisplayName')
                    $pub  = [string]$sub.GetValue('Publisher')
                    $ver  = [string]$sub.GetValue('DisplayVersion')
                    $ustr = [string]$sub.GetValue('UninstallString')
                    if (Test-IsBrave -Name $name -Publisher $pub) {
                        $machineEntries.Add([pscustomobject]@{
                            Key = $subName; Name = $name; Version = $ver
                            UninstallString = $ustr; View = $view
                        })
                    }
                    $sub.Close()
                }
                $uninstall.Close()
            }
        } catch {
            Write-Log "HKLM $view scan error: $($_.Exception.Message)" 'WARN'
        } finally {
            if ($base) { $base.Close() }
        }
    }

    $seenCodes = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($app in $machineEntries) {
        $label = "$($app.Name) v$($app.Version)"
        $code  = $null
        if ($app.Key -match '^\{[0-9A-Fa-f-]{36}\}$') { $code = $app.Key }
        elseif ($app.UninstallString -match '(?i)msiexec.*(\{[0-9A-Fa-f-]{36}\})') { $code = $Matches[1] }

        if ($code) {
            if ($seenCodes.Add($code)) {
                if (Uninstall-Msi -ProductCode $code -Name $label) { $actions.Add("uninstalled $label") }
                else { $failures.Add("uninstall failed: $label ($code)") }
            }
            # If the ARP key survived the MSI pass (orphaned registration),
            # delete the key directly -- same flap protection as the Webex pair.
            $base = $null
            try {
                $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                            [Microsoft.Win32.RegistryHive]::LocalMachine, $app.View)
                $uninstall = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', $true)
                if ($uninstall) {
                    $probe = $uninstall.OpenSubKey($app.Key)
                    if ($probe) {
                        $probe.Close()
                        $uninstall.DeleteSubKeyTree($app.Key, $false)
                        Write-Log "ARP key '$($app.Key)' [$($app.View)] survived the MSI uninstall; removed it directly." 'WARN'
                        $actions.Add("removed orphaned ARP key $label [$($app.View)]")
                    }
                    $uninstall.Close()
                }
            } catch {
                Write-Log "Orphaned ARP key removal failed ('$($app.Key)', $($app.View)): $($_.Exception.Message)" 'ERROR'
                $failures.Add("orphaned ARP key removal failed: $label")
            } finally {
                if ($base) { $base.Close() }
            }
        } else {
            # Non-MSI registration (the normal Brave case when the official
            # uninstaller didn't take it) -- remove the ARP key here and let
            # the folder pass (step 5) take the files.
            Write-Log "Non-MSI machine entry '$label' [$($app.View)] -> removing ARP key '$($app.Key)' (files handled by folder pass)." 'WARN'
            $base = $null
            try {
                $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                            [Microsoft.Win32.RegistryHive]::LocalMachine, $app.View)
                $uninstall = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', $true)
                if ($uninstall) {
                    $uninstall.DeleteSubKeyTree($app.Key, $false)
                    $uninstall.Close()
                    $actions.Add("removed ARP key $label")
                }
            } catch {
                Write-Log "ARP key removal failed ('$($app.Key)'): $($_.Exception.Message)" 'ERROR'
                $failures.Add("ARP key removal failed: $label")
            } finally {
                if ($base) { $base.Close() }
            }
        }
    }
    if ($machineEntries.Count -eq 0) { Write-Log 'No machine-wide Brave ARP entries found (after official uninstall pass).' }

    #----------------------------------------------------------------------------
    # 4. Brave services and scheduled tasks (Brave Update would otherwise
    #    reinstall the browser). Services matched by binary PATH, never name.
    #----------------------------------------------------------------------------
    try {
        Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue |
            Where-Object { $_.PathName -and ($_.PathName -match $BraveServicePathRegex) } |
            ForEach-Object {
                $svcName = $_.Name
                Write-Log "Brave service '$svcName' present (state $($_.State)); stopping and deleting." 'WARN'
                try { Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue } catch { }
                $prevEAP = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
                try   { $null = (& sc.exe delete $svcName 2>&1) }
                finally { $ErrorActionPreference = $prevEAP }
                if ($LASTEXITCODE -eq 0) { $actions.Add("deleted service $svcName") }
                else { Write-Log "sc.exe delete $svcName exit $LASTEXITCODE (may already be marked for deletion)." 'WARN' }
            }
    } catch { Write-Log "Service cleanup error: $($_.Exception.Message)" 'WARN' }

    if (Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue) {
        try {
            Get-ScheduledTask -ErrorAction SilentlyContinue |
                Where-Object { $_.TaskName -match $BraveTaskNameRegex } |
                ForEach-Object {
                    try {
                        Unregister-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -Confirm:$false -ErrorAction Stop
                        Write-Log "Unregistered scheduled task: $($_.TaskPath)$($_.TaskName)"
                        $actions.Add("removed scheduled task $($_.TaskName)")
                    } catch { Write-Log "Scheduled task removal error ($($_.TaskName)): $($_.Exception.Message)" 'WARN' }
                }
        } catch { Write-Log "Scheduled task sweep error: $($_.Exception.Message)" 'WARN' }
    }

    #----------------------------------------------------------------------------
    # 5. Machine-wide folders (the whole BraveSoftware vendor dir).
    #----------------------------------------------------------------------------
    foreach ($dir in ($MachineDirs | Select-Object -Unique)) {
        if (Test-Path -LiteralPath $dir) {
            [void](Remove-FolderOrQueue -Dir $dir -Label "folder $dir")
        }
    }

    #----------------------------------------------------------------------------
    # 6. Machine-level leftovers: HKLM Run values, vendor keys, Brave* Classes
    #    keys, common Start Menu / Public Desktop shortcuts.
    #----------------------------------------------------------------------------
    foreach ($view in $hklmViews) {
        $base = $null
        try {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                        [Microsoft.Win32.RegistryHive]::LocalMachine, $view)
            $run = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Run', $true)
            if ($run) { Remove-BraveRunValues -RunKey $run -Scope "HKLM $view"; $run.Close() }
            $sw = $base.OpenSubKey('SOFTWARE', $true)
            if ($sw) { Remove-BraveLeftoverKeys -SoftwareKey $sw -Scope "HKLM $view"; $sw.Close() }
            $classes = $base.OpenSubKey('SOFTWARE\Classes', $true)
            if ($classes) { Remove-BraveClassesKeys -ClassesKey $classes -Scope "HKLM $view"; $classes.Close() }
            # Browser registration leftovers (Default Programs / StartMenuInternet).
            foreach ($regPath in @('SOFTWARE\Clients\StartMenuInternet',
                                   'SOFTWARE\RegisteredApplications')) {
                try {
                    if ($regPath -eq 'SOFTWARE\Clients\StartMenuInternet') {
                        $smi = $base.OpenSubKey($regPath, $true)
                        if ($smi) {
                            foreach ($kn in @($smi.GetSubKeyNames())) {
                                if ($kn -match '(?i)^brave') {
                                    $smi.DeleteSubKeyTree($kn, $false)
                                    Write-Log "Removed StartMenuInternet key '$kn' [HKLM $view]."
                                    $actions.Add("removed StartMenuInternet $kn [$view]")
                                }
                            }
                            $smi.Close()
                        }
                    } else {
                        $ra = $base.OpenSubKey($regPath, $true)
                        if ($ra) {
                            foreach ($vn in @($ra.GetValueNames())) {
                                if ($vn -match '(?i)^brave') {
                                    $ra.DeleteValue($vn)
                                    Write-Log "Removed RegisteredApplications value '$vn' [HKLM $view]."
                                    $actions.Add("removed RegisteredApplications $vn [$view]")
                                }
                            }
                            $ra.Close()
                        }
                    }
                } catch { Write-Log "Browser registration cleanup error ($regPath, $view): $($_.Exception.Message)" 'WARN' }
            }
        } catch { Write-Log "HKLM leftover sweep error ($view): $($_.Exception.Message)" 'WARN' }
        finally { if ($base) { $base.Close() } }
    }

    Remove-BraveShortcuts -Folder (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs') -Scope 'AllUsers StartMenu'
    Remove-BraveShortcuts -Folder (Join-Path $env:PUBLIC 'Desktop') -Scope 'Public Desktop'

    #----------------------------------------------------------------------------
    # 7. Per-user sweep: uninstall keys, Run values, app + data folders,
    #    shortcuts -- for EVERY real profile (offline hives loaded/unloaded).
    #----------------------------------------------------------------------------
    $profiles = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' `
                    -ErrorAction SilentlyContinue |
                Where-Object { $_.PSChildName -match $sidPattern }

    function Remove-UserBraveRegistry {
        param([string]$HiveRoot, [string]$Scope)   # HiveRoot e.g. HKEY_USERS\<SID>
        foreach ($node in @('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                             'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
            $path = "Registry::$HiveRoot\$node"
            try {
                if (-not (Test-Path -LiteralPath $path)) { continue }
                Get-ChildItem -LiteralPath $path -ErrorAction SilentlyContinue | ForEach-Object {
                    $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
                    if ($p -and (Test-IsBrave -Name ([string]$p.DisplayName) -Publisher ([string]$p.Publisher))) {
                        try {
                            Remove-Item -LiteralPath $_.PSPath -Recurse -Force -ErrorAction Stop
                            Write-Log "Removed per-user uninstall key: $($p.DisplayName) [$Scope]"
                            $script:actions.Add("removed user ARP $($p.DisplayName) [$Scope]")
                        } catch {
                            Write-Log "Per-user key removal failed ($($p.DisplayName), $Scope): $($_.Exception.Message)" 'ERROR'
                            $script:failures.Add("user ARP removal failed: $($p.DisplayName) [$Scope]")
                        }
                    }
                }
            } catch { Write-Log "User key sweep error ($path): $($_.Exception.Message)" 'WARN' }
        }
        # Per-user Run values + leftover vendor keys + user Classes keys.
        try {
            $relRoot = ($HiveRoot -replace '^HKEY_USERS\\','')
            $users   = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users,
                           [Microsoft.Win32.RegistryView]::Default)
            $run = $users.OpenSubKey("$relRoot\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", $true)
            if ($run) { Remove-BraveRunValues -RunKey $run -Scope $Scope; $run.Close() }
            $sw = $users.OpenSubKey("$relRoot\SOFTWARE", $true)
            if ($sw) { Remove-BraveLeftoverKeys -SoftwareKey $sw -Scope $Scope; $sw.Close() }
            $classes = $users.OpenSubKey("$relRoot\SOFTWARE\Classes", $true)
            if ($classes) { Remove-BraveClassesKeys -ClassesKey $classes -Scope "$Scope Classes"; $classes.Close() }
            $users.Close()
        } catch { Write-Log "User registry leftover sweep error ($Scope): $($_.Exception.Message)" 'WARN' }
    }

    foreach ($prof in $profiles) {
        $sid      = $prof.PSChildName
        $profPath = $prof.ProfileImagePath
        $didLoad  = $false
        $hiveRoot = "HKEY_USERS\$sid"
        try {
            #--- registry (load offline hive if needed) ---
            $hiveAvailable = $true
            if ($loadedSids -notcontains $sid) {
                if ($sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { Write-Log "Skipping malformed SID '$sid'." 'WARN'; continue }
                if ([string]::IsNullOrWhiteSpace($profPath)) { Write-Log "Empty ProfileImagePath for $sid." 'WARN'; continue }
                $ntuser = Join-Path $profPath 'NTUSER.DAT'
                if (Test-Path -LiteralPath $ntuser) {
                    $prevEAP = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
                    try   { $null = (& reg.exe load "HKU\$sid" $ntuser 2>&1) }
                    finally { $ErrorActionPreference = $prevEAP }
                    if ($LASTEXITCODE -eq 0) { $didLoad = $true; Write-Log "Loaded offline hive: $profPath" }
                    else { Write-Log "Could not load hive for $profPath (files will still be cleaned)." 'WARN'; $hiveAvailable = $false }
                } else { $hiveAvailable = $false }
            }
            if ($hiveAvailable) {
                Remove-UserBraveRegistry -HiveRoot $hiveRoot -Scope "HKU:$sid"
            }

            #--- file system (works even when the hive could not be loaded) ---
            if (-not [string]::IsNullOrWhiteSpace($profPath) -and (Test-Path -LiteralPath $profPath)) {
                foreach ($rel in $UserAppDirRel) {
                    $dir = Join-Path $profPath $rel
                    if (Test-Path -LiteralPath $dir) {
                        [void](Remove-FolderOrQueue -Dir $dir -Label "user folder $dir")
                    }
                }
                foreach ($rel in $UserDataDirRel) {
                    $dir = Join-Path $profPath $rel
                    if (Test-Path -LiteralPath $dir) {
                        try {
                            Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction Stop
                            Write-Log "Removed user-data folder: $dir"
                        } catch { Write-Log "User-data folder not fully removed ($dir): $($_.Exception.Message). Not a failure (never a finding)." 'WARN' }
                    }
                }
                Remove-BraveShortcuts -Folder (Join-Path $profPath 'Desktop') -Scope "Desktop:$sid"
                Remove-BraveShortcuts -Folder (Join-Path $profPath 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs') -Scope "StartMenu:$sid"
            }
        } catch {
            Write-Log "Per-user sweep error ($sid): $($_.Exception.Message)" 'WARN'
        } finally {
            if ($didLoad) {
                [void](Invoke-RegUnload -Sid $sid)
            }
        }
    }

    #----------------------------------------------------------------------------
    # 7b. MSIX/Store Brave packages. Removed for all users + deprovisioned.
    #----------------------------------------------------------------------------
    if (Get-Command -Name Get-AppxPackage -ErrorAction SilentlyContinue) {
        try {
            $pkgs = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue |
                    Where-Object { Test-IsBraveAppx -Name $_.Name -Publisher $_.Publisher }
            foreach ($pkg in @($pkgs)) {
                try {
                    Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
                    Write-Log "Removed Appx: $($pkg.PackageFullName)"
                    $actions.Add("removed Appx $($pkg.Name)")
                } catch {
                    Write-Log "Remove-AppxPackage failed ($($pkg.PackageFullName)): $($_.Exception.Message)" 'ERROR'
                    $failures.Add("Appx removal failed: $($pkg.Name)")
                }
            }
        } catch { Write-Log "Appx enumeration error: $($_.Exception.Message)" 'WARN' }
    }
    if (Get-Command -Name Get-AppxProvisionedPackage -ErrorAction SilentlyContinue) {
        try {
            Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -match '(?i)brave' -and
                               $_.DisplayName -notmatch '(?i)^Microsoft' } |
                ForEach-Object {
                    try {
                        Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName -ErrorAction Stop | Out-Null
                        Write-Log "Deprovisioned: $($_.PackageName)"
                        $actions.Add("deprovisioned $($_.DisplayName)")
                    } catch {
                        Write-Log "Deprovision failed ($($_.PackageName)): $($_.Exception.Message)" 'ERROR'
                        $failures.Add("deprovision failed: $($_.DisplayName)")
                    }
                }
        } catch { Write-Log "Provisioned enumeration error: $($_.Exception.Message)" 'WARN' }
    }

    #----------------------------------------------------------------------------
    # 8. VERIFY -- identical classification rules as Detect-Brave.ps1 (ARP both
    #    HKLM views + per-user keys of LOADED hives + binary-gated folders with
    #    the pending-delete guard + Appx). Residual -> failure, so detection
    #    and remediation can never disagree ("Recurred" flap protection).
    #    Offline hives are NOT reloaded here: their keys were just removed
    #    above and reloading every hive twice per run doubles the riskiest
    #    operation.
    #----------------------------------------------------------------------------
    function Get-PendingDeleteSet {
        $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        try {
            $pfro = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
                        -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
            foreach ($raw in @($pfro)) {
                if ([string]::IsNullOrWhiteSpace($raw)) { continue }
                $p = $raw.TrimStart('!')
                if ($p.StartsWith('\??\')) { $p = $p.Substring(4) }
                if (-not [string]::IsNullOrWhiteSpace($p)) { [void]$set.Add($p.TrimEnd('\')) }
            }
        } catch { }
        return $set
    }
    $pendingDelete = Get-PendingDeleteSet
    $binarySet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($b in $BraveBinaryNames) { [void]$binarySet.Add($b) }

    $residual = [System.Collections.Generic.List[string]]::new()

    foreach ($view in $hklmViews) {
        $base = $null
        try {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                        [Microsoft.Win32.RegistryHive]::LocalMachine, $view)
            $uninstall = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
            if ($uninstall) {
                foreach ($subName in $uninstall.GetSubKeyNames()) {
                    $sub = $uninstall.OpenSubKey($subName)
                    if (-not $sub) { continue }
                    $name = [string]$sub.GetValue('DisplayName')
                    $pub  = [string]$sub.GetValue('Publisher')
                    if (Test-IsBrave -Name $name -Publisher $pub) {
                        $residual.Add("HKLM ${view}: $name")
                    }
                    $sub.Close()
                }
                $uninstall.Close()
            }
        } catch { } finally { if ($base) { $base.Close() } }
    }

    $loadedNow = (Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
                  Where-Object { $_.PSChildName -match $sidPattern }).PSChildName
    foreach ($sid in @($loadedNow)) {
        foreach ($node in @('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                             'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
            $path = "Registry::HKEY_USERS\$sid\$node"
            try {
                if (-not (Test-Path -LiteralPath $path)) { continue }
                Get-ChildItem -LiteralPath $path -ErrorAction SilentlyContinue | ForEach-Object {
                    $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
                    if ($p -and (Test-IsBrave -Name ([string]$p.DisplayName) -Publisher ([string]$p.Publisher))) {
                        $residual.Add("HKU ${sid}: $($p.DisplayName)")
                    }
                }
            } catch { }
        }
    }

    function Test-LiveBraveBinary {
        param([string]$Dir)
        if (-not (Test-Path -LiteralPath $Dir)) { return $false }
        try {
            $hit = Get-ChildItem -LiteralPath $Dir -Recurse -Force -File -ErrorAction SilentlyContinue |
                   Where-Object { $binarySet.Contains($_.Name) -and
                                  -not $pendingDelete.Contains($_.FullName.TrimEnd('\')) } |
                   Select-Object -First 1
            return [bool]$hit
        } catch { return $false }
    }
    foreach ($dir in ($MachineDirs | Select-Object -Unique)) {
        if (Test-LiveBraveBinary -Dir $dir) { $residual.Add("folder: $dir") }
    }
    foreach ($prof in $profiles) {
        $profPath = $prof.ProfileImagePath
        if ([string]::IsNullOrWhiteSpace($profPath)) { continue }
        foreach ($rel in $UserAppDirRel) {
            $dir = Join-Path $profPath $rel
            if (Test-LiveBraveBinary -Dir $dir) { $residual.Add("user folder: $dir") }
        }
    }

    if (Get-Command -Name Get-AppxPackage -ErrorAction SilentlyContinue) {
        try {
            Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue |
                Where-Object { Test-IsBraveAppx -Name $_.Name -Publisher $_.Publisher } |
                ForEach-Object { $residual.Add("Appx: $($_.PackageFullName)") }
        } catch { }
    }

    foreach ($r in ($residual | Select-Object -Unique)) {
        Write-Log "VERIFY residual: $r" 'ERROR'
        $failures.Add("residual: $r")
    }
    if ($residual.Count -eq 0) { Write-Log 'VERIFY: no residual Brave found.' }

    #----------------------------------------------------------------------------
    # 9. Result. Exactly ONE Write-Output. Reboot-pending is SUCCESS.
    #----------------------------------------------------------------------------
    $summaryBits = [System.Collections.Generic.List[string]]::new()
    if ($actions.Count)  { $summaryBits.Add("Actions: " + ($actions -join '; ')) }
    if ($rebootPending)  { $summaryBits.Add('REBOOT PENDING to finish cleanup') }
    if ($failures.Count) { $summaryBits.Add("FAILURES: " + ($failures -join '; ')) }
    if ($summaryBits.Count -eq 0) { $summaryBits.Add('Nothing to do (already clean)') }
    $summary = $summaryBits -join ' | '
    if ($summary.Length -gt 1800) { $summary = $summary.Substring(0, 1800) + ' ...(truncated)' }

    if ($failures.Count -gt 0) {
        Write-Log "RESULT: Brave removal completed WITH FAILURES." 'ERROR'
        try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
        Write-Output "Brave removal incomplete: $summary"
        exit 1
    } else {
        Write-Log 'RESULT: Brave removal completed successfully.'
        try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
        Write-Output "Brave removal OK: $summary"
        exit 0
    }
}
catch {
    Write-Log "FATAL remediation error: $($_.Exception.Message)" 'ERROR'
    try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
    Write-Output "Brave remediation error: $($_.Exception.Message)"
    exit 1
}
