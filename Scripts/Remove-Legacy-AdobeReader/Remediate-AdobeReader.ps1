<#
.SYNOPSIS
    Removes LEGACY / duplicate Adobe Reader installs and re-enables the Adobe
    auto-updater, so the ONE version that stays is the unified 64-bit Adobe
    Acrobat Reader ({AC76BA86-1033-FFFF-7760-BC15014EA700}) deployed by the
    Intune Win32 app.

.DESCRIPTION
    Intune Remediation REMEDIATION script. Pairs with Detect-AdobeReader.ps1
    (keep the CONFIG block identical in both).

    WHAT IT DOES:
      1. Uninstalls every LEGACY Reader found in the HKLM Uninstall keys (both
         registry views): all {AC76BA86-7AD7-...} product codes (the 32-bit
         Reader 9.x/X/XI/DC family) plus name-matched 'Adobe Reader'/'Adobe
         Acrobat Reader' entries that are NOT the unified 64-bit product.
         MSI entries go through msiexec /x <code> /qn /norestart; running
         AcroRd32 processes are stopped first so the uninstall cannot hang on
         a files-in-use prompt. Exit 0/1605 = success, 3010/1641 = success with
         reboot pending ("reboot required" is SUCCESS, not failure -- same
         convention as the 7-Zip pair). Never uses Win32_Product.
      2. Deletes leftover legacy install folders once their MSI is gone; a
         locked file is queued for delete-on-reboot via PendingFileRenameOperations
         (MoveFileEx), which the detection script already treats as compliant.
      3. Re-enables the Adobe ARM auto-updater when it was actively disabled:
         sets service 'AdobeARMservice' back to Automatic and starts it, and
         flips FeatureLockDown bUpdater=0 -> 1 wherever set. (Service missing
         entirely is left to the Win32 app reinstall.)
      4. Best effort, non-blocking: if the unified Reader is below baseline,
         kicks the 'Adobe Acrobat Update Task' scheduled task so Adobe's
         updater starts catching the device up. We do NOT wait for it --
         upgrades are owned by the Win32 app's version-based detection rule.
      5. OPTIONAL (off by default, flag must match the detect script): removes
         the MSIX 'AdobeAcrobatReaderCoreApp' Store package for all users and
         deprovisions it so new profiles don't get it back.

    WHAT IT NEVER TOUCHES: the unified 64-bit Reader itself, paid Acrobat
    Standard/Pro, and (unless the flag is on) the Store CoreApp.

    IDEMPOTENT: second run finds nothing legacy, updater already enabled ->
    no-op exit 0.

    EXIT CODES:
        exit 0 = success or no-op (including "done, reboot pending").
        exit 1 = at least one action FAILED (residual legacy install remains).

    OUTPUT: diagnostics to Write-Host (transcript only); exactly ONE
    Write-Output summary line at the end.

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
# CONFIG -- keep these IDENTICAL in Detect-AdobeReader.ps1 / Remediate-AdobeReader.ps1
#--------------------------------------------------------------------------------
$BaselineVersion    = [version]'26.1.21662'
$Unified64Code      = '{AC76BA86-1033-FFFF-7760-BC15014EA700}'
$Unified64Exe       = Join-Path $env:ProgramFiles 'Adobe\Acrobat DC\Acrobat\Acrobat.exe'
$HandleStoreCoreApp = $false

#--------------------------------------------------------------------------------
# 1. Durable logging.
#--------------------------------------------------------------------------------
$LogDir = Join-Path $env:ProgramData 'Monster\Logs'
if (-not (Test-Path -LiteralPath $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}
$LogFile = Join-Path $LogDir ("Remediate-AdobeReader_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
try { Start-Transcript -Path $LogFile -Append -ErrorAction SilentlyContinue | Out-Null } catch { }

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    Write-Host ("[{0:yyyy-MM-dd HH:mm:ss}] [{1}] {2}" -f (Get-Date), $Level, $Msg)
}

$actions       = [System.Collections.Generic.List[string]]::new()
$failures      = [System.Collections.Generic.List[string]]::new()
$rebootPending = $false

# Same tight classifier as the detect script.
function Test-IsLegacyReader {
    param([string]$Code, [string]$Name, [string]$Publisher)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    if ($Code -eq $Unified64Code) { return $false }
    if ($Publisher -notlike 'Adobe*') { return $false }
    if ($Name -match '64-bit') { return $false }
    if ($Code -match '^\{AC76BA86-7AD7-') { return $true }
    return ($Name -match '^Adobe (Acrobat )?Reader\b')
}

# Queue a locked file/folder entry for delete-on-reboot via MoveFileEx(...,NULL,
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
function Uninstall-Msi {
    param([string]$ProductCode, [string]$Name)
    Write-Log "Uninstalling '$Name' ($ProductCode) via msiexec..."
    $msiLog = Join-Path $LogDir ("MsiUninstall-AdobeReader_{0}_{1:yyyyMMdd_HHmmss}.log" -f ($ProductCode -replace '[{}]',''), (Get-Date))
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

Write-Log "=== Adobe Reader cleanup remediation started on $env:COMPUTERNAME (64-bit host: $([Environment]::Is64BitProcess)) ==="

try {
    #----------------------------------------------------------------------------
    # 2. Stop legacy Reader processes so uninstall/folder cleanup cannot block.
    #    AcroRd32 is ONLY the legacy 32-bit binary; the unified Reader runs
    #    Acrobat.exe, which we deliberately leave alone.
    #----------------------------------------------------------------------------
    foreach ($procName in @('AcroRd32', 'ReaderCEF', 'RdrCEF')) {
        try {
            $procs = Get-Process -Name $procName -ErrorAction SilentlyContinue
            if ($procs) {
                $procs | Stop-Process -Force -ErrorAction SilentlyContinue
                Write-Log "Stopped running process(es): $procName"
            }
        } catch { Write-Log "Could not stop $procName : $($_.Exception.Message)" 'WARN' }
    }

    #----------------------------------------------------------------------------
    # 3. Enumerate & uninstall legacy ARP entries (both registry views).
    #----------------------------------------------------------------------------
    $legacy = [System.Collections.Generic.List[object]]::new()
    $hklmViews = @([Microsoft.Win32.RegistryView]::Registry64,
                   [Microsoft.Win32.RegistryView]::Registry32)
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
                    if (Test-IsLegacyReader -Code $subName -Name $name -Publisher $pub) {
                        $legacy.Add([pscustomobject]@{
                            Code = $subName; Name = $name; Version = $ver
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

    # Same product code can appear in both views; uninstall each code once.
    $legacy = @($legacy | Sort-Object Code -Unique)
    if ($legacy.Count -eq 0) {
        Write-Log 'No legacy Reader ARP entries found.'
    }
    foreach ($app in $legacy) {
        if ($app.Code -match '^\{[0-9A-Fa-f-]{36}\}$') {
            if (Uninstall-Msi -ProductCode $app.Code -Name "$($app.Name) v$($app.Version)") {
                $actions.Add("uninstalled $($app.Name) v$($app.Version)")
            } else {
                $failures.Add("uninstall failed: $($app.Name) v$($app.Version) ($($app.Code))")
            }
        } elseif ($app.UninstallString -match '(?i)msiexec.*(\{[0-9A-Fa-f-]{36}\})') {
            $code = $Matches[1]
            if (Uninstall-Msi -ProductCode $code -Name "$($app.Name) v$($app.Version)") {
                $actions.Add("uninstalled $($app.Name) v$($app.Version)")
            } else {
                $failures.Add("uninstall failed: $($app.Name) v$($app.Version) ($code)")
            }
        } else {
            # Old Reader is always MSI; a non-MSI match here is unexpected -- log
            # it as a failure so it surfaces, rather than running an arbitrary
            # vendor UninstallString silently as SYSTEM.
            $failures.Add("non-MSI legacy entry, manual review: $($app.Name) [$($app.UninstallString)]")
            Write-Log "Non-MSI legacy entry left for manual review: $($app.Name) [$($app.UninstallString)]" 'ERROR'
        }
    }

    #----------------------------------------------------------------------------
    # 4. Leftover legacy folders. Only after the MSI pass; locked leftovers are
    #    queued for delete-on-reboot (detection treats that as compliant).
    #----------------------------------------------------------------------------
    $legacyDirs = @()
    if (${env:ProgramFiles(x86)}) {
        $legacyDirs += (Join-Path ${env:ProgramFiles(x86)} 'Adobe\Acrobat Reader DC')
        try {
            $legacyDirs += Get-ChildItem -Path (Join-Path ${env:ProgramFiles(x86)} 'Adobe') `
                               -Directory -Filter 'Reader*' -ErrorAction SilentlyContinue |
                           Select-Object -ExpandProperty FullName
        } catch { }
    }
    foreach ($dir in ($legacyDirs | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $dir)) { continue }
        # Only clean folders that still hold the LEGACY binary; anything else in
        # an 'Adobe' folder is not ours to delete.
        $bin = Join-Path $dir 'Reader\AcroRd32.exe'
        if (-not (Test-Path -LiteralPath $bin)) { continue }
        try {
            Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction Stop
            Write-Log "Removed leftover folder: $dir"
            $actions.Add("removed folder $dir")
        } catch {
            Write-Log "Folder locked ($dir): $($_.Exception.Message). Queuing binary for delete-on-reboot." 'WARN'
            if (Register-DeleteOnReboot -Path $bin) {
                $actions.Add("queued delete-on-reboot: $bin")
            } else {
                $failures.Add("could not remove or queue: $bin")
            }
        }
    }

    #----------------------------------------------------------------------------
    # 5. Re-enable the Adobe updater (only relevant if the unified Reader is on).
    #----------------------------------------------------------------------------
    $unifiedPresent = (Test-Path -LiteralPath $Unified64Exe)
    if ($unifiedPresent) {
        try {
            $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='AdobeARMservice'" -ErrorAction SilentlyContinue
            if ($svc) {
                if ($svc.StartMode -eq 'Disabled') {
                    Set-Service -Name 'AdobeARMservice' -StartupType Automatic
                    Write-Log 'AdobeARMservice startup set Disabled -> Automatic.'
                    $actions.Add('re-enabled AdobeARMservice')
                }
                if ((Get-Service -Name 'AdobeARMservice').Status -ne 'Running') {
                    try { Start-Service -Name 'AdobeARMservice'; Write-Log 'AdobeARMservice started.' }
                    catch { Write-Log "AdobeARMservice would not start: $($_.Exception.Message)" 'WARN' }
                }
            } else {
                Write-Log "AdobeARMservice not present; the Win32 app reinstall restores it. Skipping." 'WARN'
            }
        } catch { Write-Log "Service remediation error: $($_.Exception.Message)" 'WARN' }

        # bUpdater=0 -> 1 in every location it is set (both views, both products).
        foreach ($polKey in @('SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown',
                              'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown')) {
            foreach ($view in $hklmViews) {
                $base = $null
                try {
                    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                                [Microsoft.Win32.RegistryHive]::LocalMachine, $view)
                    $k = $base.OpenSubKey($polKey, $true)
                    if ($k) {
                        $v = $k.GetValue('bUpdater', $null)
                        if ($v -is [int] -and $v -eq 0) {
                            $k.SetValue('bUpdater', 1, [Microsoft.Win32.RegistryValueKind]::DWord)
                            Write-Log "bUpdater 0 -> 1 in HKLM($view)\$polKey."
                            $actions.Add("bUpdater=1 [$view]")
                        }
                        $k.Close()
                    }
                } catch { Write-Log "Policy fix error ($polKey/$view): $($_.Exception.Message)" 'WARN' }
                finally { if ($base) { $base.Close() } }
            }
        }

        #------------------------------------------------------------------------
        # 6. Below baseline? Kick Adobe's update task -- fire and forget. The
        #    Win32 app's version-based detection rule owns the actual upgrade.
        #------------------------------------------------------------------------
        try {
            $fv = [version](Get-Item -LiteralPath $Unified64Exe).VersionInfo.FileVersion.Split(' ')[0]
            if ($fv -lt $BaselineVersion) {
                Write-Log "Unified Reader v$fv < baseline $BaselineVersion; triggering 'Adobe Acrobat Update Task' (non-blocking)." 'WARN'
                $task = Get-ScheduledTask -TaskName 'Adobe Acrobat Update Task' -ErrorAction SilentlyContinue
                if ($task) {
                    Start-ScheduledTask -TaskName 'Adobe Acrobat Update Task'
                    $actions.Add('triggered Adobe update task')
                } else {
                    Write-Log "'Adobe Acrobat Update Task' not found; Win32 app / ARM service will handle the upgrade." 'WARN'
                }
            }
        } catch { Write-Log "Update-task trigger error: $($_.Exception.Message)" 'WARN' }
    } else {
        Write-Log 'Unified 64-bit Reader not installed; updater steps skipped (Win32 app installs it).'
    }

    #----------------------------------------------------------------------------
    # 7. OPTIONAL MSIX Store CoreApp removal (flag must match the detect script).
    #----------------------------------------------------------------------------
    if ($HandleStoreCoreApp) {
        $appxCmd = Get-Command -Name Get-AppxPackage -ErrorAction SilentlyContinue
        if ($appxCmd) {
            try {
                $pkgs = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -like '*AcrobatReaderCoreApp*' -and $_.Publisher -like '*Adobe Inc*' }
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
        try {
            Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -like '*AcrobatReaderCoreApp*' } |
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
    # 8. Result. Exactly ONE Write-Output. Reboot-pending is SUCCESS.
    #----------------------------------------------------------------------------
    $summaryBits = [System.Collections.Generic.List[string]]::new()
    if ($actions.Count)  { $summaryBits.Add("Actions: " + ($actions -join '; ')) }
    if ($rebootPending)  { $summaryBits.Add('REBOOT PENDING to finish cleanup') }
    if ($failures.Count) { $summaryBits.Add("FAILURES: " + ($failures -join '; ')) }
    if ($summaryBits.Count -eq 0) { $summaryBits.Add('Nothing to do (already clean)') }
    $summary = $summaryBits -join ' | '
    if ($summary.Length -gt 1800) { $summary = $summary.Substring(0, 1800) + ' ...(truncated)' }

    if ($failures.Count -gt 0) {
        Write-Log "RESULT: remediation completed WITH FAILURES." 'ERROR'
        try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
        Write-Output "Adobe Reader cleanup incomplete: $summary"
        exit 1
    } else {
        Write-Log 'RESULT: remediation completed successfully.'
        try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
        Write-Output "Adobe Reader cleanup OK: $summary"
        exit 0
    }
}
catch {
    Write-Log "FATAL remediation error: $($_.Exception.Message)" 'ERROR'
    try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
    Write-Output "Adobe Reader remediation error: $($_.Exception.Message)"
    exit 1
}
