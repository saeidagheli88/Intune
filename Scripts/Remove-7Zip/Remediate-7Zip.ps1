<#
.SYNOPSIS
    Completely removes ALL 7-Zip installations (publisher Igor Pavlov) and cleans
    leftovers across every install scope and installer family.

.DESCRIPTION
    Intune Remediation REMEDIATION script.

    Handles, in order:
      1. Stop running 7-Zip processes (7zFM, 7zG, 7z) -- ONLY after at least one
         removable 7-Zip artifact is confirmed, and ONLY processes whose image
         path is inside a 7-Zip install folder, logging each PID/path killed.
      2. MSI builds  -- "7-Zip <ver> (x64 edition)". Parse the product-code GUID
         from the registry UninstallString and run
            msiexec.exe /x {GUID} /qn /norestart REBOOT=ReallySuppress
         Success = exit 0 / 1605 / 1641 / 3010.
      3. NSIS EXE builds -- "7-Zip <ver> (x64)". Run "<dir>\Uninstall.exe" /S
         (capital S). NSIS self-relaunches from %TEMP% and Start-Process -Wait can
         return early, so we poll, and we base SUCCESS on the originating ARP/
         Uninstall registry key disappearing (a lingering binary alone is not a
         hard failure if the registry entry is gone).
      4. Per-user installs -- iterate every loaded HKU hive AND temporarily load
         logged-off NTUSER.DAT hives. For per-user entries we delete the ARP key
         and install folder DIRECTLY from the correct HKU\<SID> hive rather than
         relying on a user's own uninstaller (which, run as SYSTEM, would target
         SYSTEM's HKCU, not the target user's hive).
      5. MSIX / Appx -- Remove-AppxPackage -AllUsers / Remove-AppxProvisionedPackage
         -Online, but ONLY for a TIGHT, publisher/family-gated match (never the
         over-broad '*7*zip*'). 7-Zip is normally Win32, so by default this matches
         nothing and cannot remove an unrelated Store app.
      6. Leftover cleanup (ONLY after uninstall): allow-listed install folders,
         Start Menu shortcut folders, and stray HKLM/HKCU\Software\7-Zip keys.

    SAFETY:
      * Every Remove-Item is guarded by Test-Path AND a leaf allow-list ("the leaf
        must literally be '7-Zip'"), so a blank/malformed path can never delete a
        parent like C:\Program Files. Paths are env/profile-derived, never C:\.
      * Idempotent: existence checks everywhere; a second run on a clean device is
        a no-op -> exit 0.
      * Every hive we load is ALWAYS unloaded in finally, with GC first AND a
        retry + ERROR log + failCount bump if the unload still fails (a stuck hive
        can block that user's logon). Orphaned mounts from a prior crashed run are
        detected and cleaned up at startup.
      * Win32_Product is never used (it would reconfigure every MSI on the box).

    BITNESS: self-relaunches via %WINDIR%\Sysnative when started 32-bit on 64-bit
    Windows -- GUARDED so it only fires when $PSCommandPath is a real existing file
    (never '-File ""'). Independently reads HKLM Uninstall through both
    RegistryView::Registry64 and Registry32. *** Deploy with "Run script in 64-bit
    PowerShell = Yes" (HARD requirement): it makes the relaunch dead code and is
    the only configuration in which the Appx cmdlets are guaranteed to work. ***

    VERSION: v2.4 (2026-07-21). Fixes the fleet crash "You cannot call a method on a
    null-valued expression" (seen in BOTH detection and remediation): PowerShell
    unrolls an EMPTY collection returned from a function to $null, so when the CIM
    Win32_LoggedOnUser query returned nothing (or timed out), Get-ActiveUserSid's
    empty HashSet arrived as $null and $activeSids.Contains() threw. Fixed with
    'return ,$sids' (comma prevents unrolling; empirically reproduced + verified)
    plus defensive re-wrapping at the call sites. Same fix applied to detection's
    Get-PendingDeleteSet.

    VERSION: v2.3 (2026-07-14). Changes vs v2.2, after a fleet-wide export showed two remaining script issues:
       * NULL ProfileImagePath: a few ProfileList entries have no ImagePath; Join-Path
         $null threw ("Cannot bind argument to parameter 'Path'..."/"method on a null-
         valued expression") -> detection errors + fatal remediations. Now filtered
         out where $profiles is built (both scripts).
       * TIMEOUTS: the remaining UNBOUNDED external calls -- Get-CimInstance
         Win32_LoggedOnUser and reg.exe load/unload -- could hang past Intune's 30-min
         limit (v2.2 only bounded msiexec/NSIS). CIM now uses -OperationTimeoutSec 60,
         and reg.exe load/unload run through the bounded Wait-ProcessWithTimeout (60s).
         (Send a timed-out device's C:\ProgramData\Monster\Logs\Remove-7Zip_*.log to
         confirm the hang point if any device still times out.)

    VERSION: v2.2 (2026-07-02). Changes vs v2.1, after a CSV export revealed THREE
    distinct failure modes beyond the locked DLL:
       * ORPHANED MSI ARP KEY (signature "Failed: 0. Residual: reg:7-Zip ... (x64
         edition)"): an OK/1605 msiexec code no longer counts as done unless the
         originating Uninstall key is actually gone -- the MSI branch now removes the
         orphaned key (mirrors the NSIS branch) so verification can't loop on it.
       * TIMEOUT (Intune kills scripts at 30 min): the NSIS uninstaller and msiexec
         now run under a BOUNDED Wait-ProcessWithTimeout (kills a hung child), the
         NSIS poll cap dropped 90s->30s, and a 25-min internal deadline makes the run
         exit 1 (retry next cycle) before Intune force-kills it.
       * reg.exe stderr ("ERROR: Invalid key name.") no longer terminates the run:
         native reg.exe calls run with EAP='Continue' + 2>&1 and SIDs are validated
         (this also fixes the detection-side crash in Detect-7Zip.ps1).

    VERSION: v2.1 (2026-06-30). Changes vs v1, after the first pilot showed "Failed"
    on devices where the MSI uninstalled cleanly but C:\Program Files\7-Zip\7z.dll
    was locked by explorer.exe (the 7-Zip shell-extension), so the folder could not
    be deleted and verification wrongly reported a HARD residual:
       * Locked leftovers are now scheduled for delete-on-reboot (MoveFileEx) and
         treated as SUCCESS + reboot-pending, NOT a failure.
       * msiexec /x now RETRIES only genuinely transient codes (1618 = another
         install already in progress, 1601, 1622) up to 3x with a 10s wait. 1603 is
         no longer retried (rarely transient; the in-use case is covered by the
         delete-on-reboot path) -- keeps the run inside the Intune time budget.
       * MSI exit codes 3010/1641 now raise the reboot-pending flag.
       * REPARSE-SAFE deletion (v2.1): folder cleanup never traverses INTO a
         junction/symlink (a reparse child is unlinked, never followed), and the
         delete-on-reboot primitive refuses any path that does not canonically sit
         under the allow-listed 7-Zip root -- closing a SYSTEM-context over-delete
         escape via a junction planted in the user-writable per-user install dir.
       * Companion fix in Detect-7Zip.ps1 (v2.1): a binary already queued in
         PendingFileRenameOperations is NOT reported as a finding, so a device that
         has scheduled the locked DLL stops flapping detect->remediate before reboot.

    EXIT CODES:
        exit 0 = removal succeeded (incl. "done, reboot required" for locked files).
        exit 1 = at least one removal genuinely failed or 7-Zip still installed.

    OUTPUT: diagnostics go to Write-Host (transcript only). Exactly ONE Write-Output
    runs -- the final summary line Intune captures as STDOUT.

.NOTES
    Author : Endpoint Engineering (Monster Energy)
    Target : Windows PowerShell 5.1, SYSTEM context
    Intune : Run using logged-on credentials = No (SYSTEM)
             Run script in 64-bit PowerShell = Yes (REQUIRED)
             Enforce script signature check  = No
    Per-user caveat: a truly per-user MSIX for a LOGGED-OFF user may not be
    removable from SYSTEM; pair this with a user-context Remediation if your fleet
    has per-user MSIX 7-Zip (rare). Per-user Win32 (NSIS/MSI) installs ARE handled
    here via the HKU hive sweep + direct registry/folder removal.
#>

#--------------------------------------------------------------------------------
# 0. 64-bit self-relaunch guard (see Detect-7Zip.ps1 for rationale).
#    GUARDED: only relaunch with -File when $PSCommandPath is a real existing file.
#    Otherwise fall through to the dual-RegistryView reads (host-bitness-independent).
#    Note: in a 32-bit host the Appx cmdlets may be unavailable; that is logged at
#    the Appx phase and is the only capability lost in the no-Sysnative edge case.
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
    # Fall through (32-bit host): registry/file/msiexec work fine; Appx may not.
}

$ErrorActionPreference = 'Stop'

# v2.2: Intune runs Remediation scripts via the management extension, which KILLS a
# script after 30 minutes (docs: "PowerShell scripts time out after 30 minutes").
# A killed run reports "Timed out" (seen on a device whose NSIS uninstaller hung).
# We set an internal deadline WELL under that so the script exits cleanly (exit 1 ->
# retried next cycle) before Intune force-kills it mid-write. Combined with the
# bounded per-child waits below, no single hung child can run the clock out.
$script:Deadline = [DateTime]::UtcNow.AddSeconds(1500)   # 25 min; < Intune's 30 min
function Test-PastDeadline { return ([DateTime]::UtcNow -ge $script:Deadline) }

#--------------------------------------------------------------------------------
# 1. Durable logging under %ProgramData%\Monster\Logs (writable by SYSTEM).
#--------------------------------------------------------------------------------
$LogDir = Join-Path $env:ProgramData 'Monster\Logs'
if (-not (Test-Path -LiteralPath $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}
$LogFile = Join-Path $LogDir ("Remove-7Zip_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
try { Start-Transcript -Path $LogFile -Append -ErrorAction SilentlyContinue | Out-Null } catch { }

# Write-Host so log lines hit the transcript but NOT Intune's captured STDOUT
# success stream; one Write-Output at the end is the captured summary line.
function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    Write-Host ("[{0:yyyy-MM-dd HH:mm:ss}] [{1}] {2}" -f (Get-Date), $Level, $Msg)
}

# --- v2 helpers: delete-on-reboot for locked files + msiexec retry -------------
# MoveFileEx lets us schedule a LOCKED file (classically 7z.dll loaded into
# explorer.exe as the 7-Zip shell extension) for deletion on the next reboot --
# the same mechanism Windows Installer uses for in-use files. Loaded once and
# guarded so a re-run in the same host doesn't throw 'type already exists'.
if (-not ('Win32.NativeMethods' -as [type])) {
    Add-Type -Namespace Win32 -Name NativeMethods -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true, CharSet=System.Runtime.InteropServices.CharSet.Unicode)]
public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);

[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true, CharSet=System.Runtime.InteropServices.CharSet.Unicode)]
public static extern System.IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode, System.IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, System.IntPtr hTemplateFile);

[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true, CharSet=System.Runtime.InteropServices.CharSet.Unicode)]
public static extern uint GetFinalPathNameByHandleW(System.IntPtr hFile, System.Text.StringBuilder lpszFilePath, uint cchFilePath, uint dwFlags);

[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true)]
public static extern bool CloseHandle(System.IntPtr hObject);
'@
}
$MOVEFILE_DELAY_UNTIL_REBOOT = 0x4

# Lexical full-path canonicalization (resolves . / .. / trailing separators). Does
# NOT follow reparse points -- intentional: combined with never traversing INTO a
# junction during enumeration, lexical containment == physical containment.
function Get-CanonicalPath {
    param([string]$P)
    if ([string]::IsNullOrWhiteSpace($P)) { return $null }
    try { return ([IO.Path]::GetFullPath($P)).TrimEnd([IO.Path]::DirectorySeparatorChar) } catch { return $null }
}

# Resolve a path to its REAL on-disk target with all junctions/symlinks FOLLOWED,
# via a kernel handle (GetFinalPathNameByHandleW). This is what makes containment
# checks TOCTOU-resistant: [IO.Path]::GetFullPath is lexical only, so a junction can
# spoof a path that lexically sits under the 7-Zip root but physically points into
# e.g. System32. Opening with FILE_READ_ATTRIBUTES + full sharing succeeds even on
# files locked/in-use (e.g. 7z.dll mapped by explorer.exe). Returns $null if the
# target cannot be resolved (caller then falls back to a lexical check).
function Resolve-FinalPath {
    param([string]$Path)
    $FILE_READ_ATTRIBUTES       = 0x80
    $FILE_SHARE_ALL             = 0x7          # READ|WRITE|DELETE
    $OPEN_EXISTING              = 3
    $FILE_FLAG_BACKUP_SEMANTICS = 0x02000000   # required to open a directory handle
    $h = [IntPtr](-1)
    try {
        $h = [Win32.NativeMethods]::CreateFileW($Path, $FILE_READ_ATTRIBUTES, $FILE_SHARE_ALL,
                 [IntPtr]::Zero, $OPEN_EXISTING, $FILE_FLAG_BACKUP_SEMANTICS, [IntPtr]::Zero)
        if ($h.ToInt64() -eq -1 -or $h.ToInt64() -eq 0) { return $null }
        $sb  = New-Object System.Text.StringBuilder 32768
        $len = [Win32.NativeMethods]::GetFinalPathNameByHandleW($h, $sb, [uint32]$sb.Capacity, 0)
        if ($len -eq 0 -or $len -ge $sb.Capacity) { return $null }
        $res = $sb.ToString()
        if     ($res.StartsWith('\\?\UNC\')) { $res = '\\' + $res.Substring(8) }
        elseif ($res.StartsWith('\\?\'))     { $res = $res.Substring(4) }
        return $res.TrimEnd([IO.Path]::DirectorySeparatorChar)
    } catch {
        return $null
    } finally {
        if ($h.ToInt64() -ne -1 -and $h.ToInt64() -ne 0) { [void][Win32.NativeMethods]::CloseHandle($h) }
    }
}

# $true only if $Path's target is $Root or physically under it. Prefers the REAL
# reparse-resolved target (defeats a junction that lexically appears in-tree); if
# the real target cannot be resolved it falls back to the LEXICAL check (no worse
# than a pure-lexical guard, so a transient resolve failure never blocks a genuine
# in-tree removal). $RootReal may be $null when the root itself was unresolvable.
function Test-Contained {
    param([string]$Path, [string]$RootReal, [string]$RootCanon)
    $sep  = [IO.Path]::DirectorySeparatorChar
    $real = Resolve-FinalPath $Path
    if ($real -and $RootReal) {
        return ($real.Equals($RootReal, [System.StringComparison]::OrdinalIgnoreCase) -or
                $real.StartsWith("$RootReal$sep", [System.StringComparison]::OrdinalIgnoreCase))
    }
    $canon = Get-CanonicalPath $Path
    if (-not $canon -or -not $RootCanon) { return $false }
    return ($canon.Equals($RootCanon, [System.StringComparison]::OrdinalIgnoreCase) -or
            $canon.StartsWith("$RootCanon$sep", [System.StringComparison]::OrdinalIgnoreCase))
}

# Schedule a single path for deletion on next reboot via MoveFileEx. HARD-GUARDED:
# rejects empty/relative paths and ANY path whose REAL resolved target is not on or
# under the root, so this SYSTEM-context reboot-delete primitive can never be pointed
# outside the 7-Zip folder even via a junction/symlink. Sets $script:rebootPending.
function Add-DelayedDelete {
    param([string]$Path, [string]$RootReal, [string]$RootCanon)
    if ([string]::IsNullOrWhiteSpace($Path)) { Write-Log "Add-DelayedDelete: empty path rejected." 'WARN'; return $false }
    if (-not [IO.Path]::IsPathRooted($Path)) { Write-Log "Add-DelayedDelete: non-rooted path rejected: $Path" 'WARN'; return $false }
    if (-not (Test-Contained -Path $Path -RootReal $RootReal -RootCanon $RootCanon)) {
        Write-Log "Add-DelayedDelete: REFUSED path whose target is not under the 7-Zip root: $Path" 'ERROR'
        return $false
    }
    try {
        $scheduled = [Win32.NativeMethods]::MoveFileEx($Path, $null, $MOVEFILE_DELAY_UNTIL_REBOOT)
        if ($scheduled) {
            Write-Log "Scheduled for delete-on-reboot: $Path"
            $script:rebootPending = $true
            return $true
        }
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Log "MoveFileEx failed to schedule '$Path' (Win32 error $err)." 'WARN'
        return $false
    } catch {
        Write-Log "Add-DelayedDelete threw for '$Path': $($_.Exception.Message)" 'WARN'
        return $false
    }
}

# Reparse- and TOCTOU-SAFE recursive removal of a guarded folder's contents. It:
#   * NEVER descends into a directory junction/symlink -- a reparse child is unlinked
#     (link only), never followed;
#   * RE-VERIFIES each directory is still a real, non-reparse dir AT ENUMERATION TIME
#     (closes the race where an attacker swaps a real dir for a junction after it was
#     first classified -- the reviewer's remaining TOCTOU finding); and
#   * before deleting OR reboot-scheduling any file, confirms the file's REAL target
#     is physically under the root (a junctioned parent can otherwise spoof an
#     in-tree .FullName). Locked in-tree files are scheduled for delete-on-reboot.
# Returns $true if every item was removed or safely handled.
function Remove-TreeReparseSafe {
    param([string]$Root)
    $rootCanon = Get-CanonicalPath $Root
    $rootReal  = Resolve-FinalPath $Root
    if (-not $rootCanon -and -not $rootReal) { return $false }
    $ok = $true
    $stack = New-Object 'System.Collections.Generic.Stack[string]'
    $stack.Push($Root)
    $realDirs = New-Object 'System.Collections.Generic.List[string]'
    while ($stack.Count -gt 0) {
        $cur = $stack.Pop()
        # Enumeration-time re-check (TOCTOU fix): $cur must STILL be a real,
        # non-reparse directory whose real target is in-tree. If it was swapped for a
        # junction/symlink since we queued it, unlink it (link only) and do not walk.
        $curItem = Get-Item -LiteralPath $cur -Force -ErrorAction SilentlyContinue
        if (-not $curItem -or -not $curItem.PSIsContainer) { continue }
        if (($curItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            try { [IO.Directory]::Delete($cur, $false); Write-Log "Removed reparse point (link only): $cur" }
            catch { Write-Log "Could not unlink reparse dir '$cur': $($_.Exception.Message)" 'WARN'; $ok = $false }
            continue
        }
        if (-not (Test-Contained -Path $cur -RootReal $rootReal -RootCanon $rootCanon)) {
            Write-Log "REFUSED to enumerate dir whose real target is outside the 7-Zip root: $cur" 'ERROR'; $ok = $false; continue
        }
        $realDirs.Add($cur)
        foreach ($it in @(Get-ChildItem -LiteralPath $cur -Force -ErrorAction SilentlyContinue)) {
            if (($it.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                # Remove ONLY the link, never its target's contents.
                try {
                    if ($it.PSIsContainer) { [IO.Directory]::Delete($it.FullName, $false) }
                    else { [IO.File]::Delete($it.FullName) }
                    Write-Log "Removed reparse point (link only): $($it.FullName)"
                } catch {
                    Write-Log "Could not remove reparse point '$($it.FullName)': $($_.Exception.Message)" 'WARN'
                    $ok = $false
                }
                continue
            }
            if ($it.PSIsContainer) {
                $stack.Push($it.FullName)
            } else {
                # Real file: confirm its resolved target is in-tree BEFORE deleting or
                # scheduling (defends against a junctioned parent spoofing .FullName).
                if (-not (Test-Contained -Path $it.FullName -RootReal $rootReal -RootCanon $rootCanon)) {
                    Write-Log "REFUSED file whose real target is outside the 7-Zip root: $($it.FullName)" 'ERROR'; $ok = $false; continue
                }
                try { Remove-Item -LiteralPath $it.FullName -Force -ErrorAction Stop }
                catch { if (-not (Add-DelayedDelete -Path $it.FullName -RootReal $rootReal -RootCanon $rootCanon)) { $ok = $false } }
            }
        }
    }
    # Remove the now-empty REAL directories, deepest first (by path-segment depth).
    foreach ($d in ($realDirs | Sort-Object { ($_ -split '\\').Count } -Descending)) {
        if (Test-Path -LiteralPath $d) {
            try { Remove-Item -LiteralPath $d -Force -ErrorAction Stop }
            catch { if (-not (Add-DelayedDelete -Path $d -RootReal $rootReal -RootCanon $rootCanon)) { $ok = $false } }
        }
    }
    return $ok
}

# Run 'msiexec /x {GUID}' silently, RETRYING transient failures with a wait between
# attempts: 1618 = another install already in progress (very common when Intune is
# concurrently installing/updating apps), 1603 = fatal/often in-use, 1601/1622 =
# service/config issues. Returns the FINAL exit code. Success codes and any
# non-retryable failure return immediately (we never mask a genuine failure).
function Invoke-MsiUninstall {
    param([string]$Guid)
    $okCodes     = @(0, 1605, 1641, 3010)   # ok / not-installed / reboot-initiated / reboot-pending
    # Retry ONLY genuinely transient codes: 1618 = another install in progress
    # (common when Intune installs concurrently), 1601 = service unavailable, 1622 =
    # log-open error. 1603 is intentionally NOT retried -- it is rarely transient,
    # and the in-use-file case it usually represents is already covered by the
    # delete-on-reboot path, so retrying just burns the Intune time budget.
    $retryCodes  = @(1618, 1601, 1622)
    $maxAttempts = 3
    $code = -1
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        if (Test-PastDeadline) { Write-Log 'Deadline reached; not starting further msiexec attempts.' 'WARN'; break }
        # v2.2: bounded wait (90s) instead of unbounded -Wait, so a wedged Windows
        # Installer service can never hang the whole remediation past Intune's limit.
        $code = Wait-ProcessWithTimeout -FilePath 'msiexec.exe' `
                    -Arguments "/x $Guid /qn /norestart REBOOT=ReallySuppress" -TimeoutSec 90
        if ($null -eq $code) { $code = -1 }   # killed/overran = non-success (fail safe)
        Write-Log "msiexec /x $Guid (attempt $attempt/$maxAttempts) -> exit $code"
        if ($okCodes -contains $code)       { return $code }
        if ($retryCodes -notcontains $code) { return $code }   # hard, non-retryable failure
        if ($attempt -lt $maxAttempts) {
            Write-Log "Transient msiexec code $code -- waiting 5s before retry." 'WARN'
            Start-Sleep -Seconds 5
        }
    }
    return $code
}

# v2.2: Bounded child-process wait. Starts the process, waits at most $TimeoutSec,
# then Kill()s it if it overran -- defeats a hung NSIS uninstaller UI in session 0
# or a wedged msiexec (the observed "Timed out" cause). Returns the exit code, or
# $null if it had to be killed / failed to start (caller treats $null as failure).
function Wait-ProcessWithTimeout {
    # $Arguments is untyped so callers may pass either a single string (msiexec, which
    # parses its own command line) or a string[]. CAUTION: Start-Process -ArgumentList
    # does NOT auto-quote array elements -- it joins them with spaces -- so any element
    # that may contain spaces (file paths) must be pre-quoted by the caller.
    param([string]$FilePath, $Arguments, [int]$TimeoutSec = 60)
    $p = $null
    try {
        $p = Start-Process -FilePath $FilePath -ArgumentList $Arguments -PassThru -WindowStyle Hidden -ErrorAction Stop
        if (-not $p) { return $null }
        if ($p.WaitForExit($TimeoutSec * 1000)) {
            try { return [int]$p.ExitCode } catch { return $null }
        }
        Write-Log "Child '$FilePath' exceeded ${TimeoutSec}s -- killing PID $($p.Id)." 'WARN'
        try { $p.Kill() } catch { }
        try { [void]$p.WaitForExit(5000) } catch { }
        return $null
    } catch {
        Write-Log "Wait-ProcessWithTimeout failed for '$FilePath': $($_.Exception.Message)" 'WARN'
        return $null
    } finally {
        if ($p) { try { $p.Dispose() } catch { } }
    }
}
# -------------------------------------------------------------------------------

# Running tallies for the final summary.
$successCount = 0
$failCount    = 0
# v2: reboot-pending flag (set when MSI returns 3010/1641, or when a locked
# leftover is scheduled for delete-on-reboot) and the set of install folders whose
# only remaining contents are scheduled for reboot deletion -- those are treated as
# SUCCESS+reboot-pending in verification, never as a hard residual.
$script:rebootPending  = $false
$script:pendingFolders = New-Object 'System.Collections.Generic.HashSet[string]'
# Dedup guard. Key INCLUDES Scope (review fix) so the same DisplayName|Version
# installed per-user by two DIFFERENT users is NOT collapsed -- only a genuine
# duplicate within the SAME scope (e.g. the same machine-wide entry surfacing in
# both the 64- and 32-bit views) is deduped.
$processed    = @{}

function Test-Is7Zip {
    param($Entry)
    if (-not $Entry) { return $false }
    $name = [string]$Entry.DisplayName
    $pub  = [string]$Entry.Publisher
    if ([string]::IsNullOrWhiteSpace($name)) { return $false }
    return ($name -like '7-Zip*' -or $pub -eq 'Igor Pavlov')
}

# TIGHT MSIX/Appx match (review fix). By default $KnownAppxFamilies is empty, so
# this matches NOTHING unless you confirm a real 7-Zip package family. Used
# IDENTICALLY in removal, fallback and verification so the phases cannot diverge.
$script:KnownAppxFamilies = @()   # e.g. @('NikolayRaspopov.7-Zip_xxxxxxxxxxxxx')
function Test-Is7ZipAppx {
    param($Pkg)
    if (-not $Pkg) { return $false }
    $name = [string]$Pkg.Name
    $pub  = [string]$Pkg.Publisher
    $fam  = [string]$Pkg.PackageFamilyName
    if ($script:KnownAppxFamilies -contains $fam) { return $true }
    return (($name -like '7-Zip*' -or $name -like '*SevenZip*') -and ($pub -like '*Igor Pavlov*'))
}

# Canonical {8-4-4-4-12} product-code GUID pattern (review fix -- layout-anchored).
$script:GuidAnchored   = '^\{[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}$'
$script:GuidUnanchored = '\{[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}'

# Active logon SIDs (so orphaned HKU mounts aren't mistaken for "logged on").
function Get-ActiveUserSid {
    $sids = New-Object System.Collections.Generic.HashSet[string]
    try {
        Get-CimInstance -ClassName Win32_LoggedOnUser -OperationTimeoutSec 60 -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $acct = $_.Antecedent
                $nt   = New-Object System.Security.Principal.NTAccount($acct.Domain, $acct.Name)
                $sid  = $nt.Translate([System.Security.Principal.SecurityIdentifier]).Value
                if ($sid) { [void]$sids.Add($sid) }
            } catch { }
        }
    } catch { }
    # v2.4: the comma is load-bearing. PowerShell enumerates a returned collection:
    # an EMPTY HashSet unrolls to $null (then $activeSids.Contains() throws "You
    # cannot call a method on a null-valued expression" -- the fleet crash), and a
    # 1-item set unrolls to a bare STRING whose .Contains() does substring matching.
    # ',$sids' wraps it so the HashSet itself always reaches the caller.
    return ,$sids
}

# Verified hive unload with one retry. Returns $true on success, $false otherwise.
# v2.3: run reg.exe via the BOUNDED helper. This (a) caps a hung 'reg unload' on a
# corrupt/locked hive at 60s so it can't run past Intune's 30-min limit (a leading
# timeout suspect), and (b) as a Start-Process child its stderr ("ERROR: Invalid key
# name.") never becomes a terminating NativeCommandError under EAP=Stop -- keeping the
# v2.2 crash fix. GC first to release our own hive handles so the unload can succeed.
function Invoke-RegUnload {
    param([string]$Sid)
    if ([string]::IsNullOrWhiteSpace($Sid) -or ($Sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$')) {
        Write-Log "Invoke-RegUnload: refusing malformed SID '$Sid'." 'WARN'; return $false
    }
    [gc]::Collect()
    $rc = Wait-ProcessWithTimeout -FilePath 'reg.exe' -Arguments @('unload', "HKU\$Sid") -TimeoutSec 60
    if ($rc -ne 0) {
        Start-Sleep -Milliseconds 250
        [gc]::Collect(); [gc]::WaitForPendingFinalizers()
        $rc = Wait-ProcessWithTimeout -FilePath 'reg.exe' -Arguments @('unload', "HKU\$Sid") -TimeoutSec 60
        if ($rc -ne 0) {
            Write-Log "FAILED to unload HKU\$Sid (rc=$rc; hive left mounted - may block that user's logon)." 'ERROR'
            return $false
        }
    }
    return $true
}

# Deletes the specific ARP/Uninstall subkey that produced an entry. Guarded so it
# can ONLY ever target a key directly beneath an Uninstall node whose leaf equals
# the enumerated KeyName (prevents touching anything unexpected).
function Remove-UninstallKey {
    param(
        [string]$HiveRoot,   # e.g. 'HKEY_LOCAL_MACHINE' or 'HKEY_USERS\<SID>'
        [string]$View,       # 'Registry64' | 'Registry32' | '' (for HKU)
        [string]$KeyName
    )
    if ([string]::IsNullOrWhiteSpace($KeyName)) { return }
    if ($View -eq 'Registry32') {
        $node = 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    } else {
        $node = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    }
    # For HKU we try both native and WOW6432Node locations.
    $candidatePaths = @()
    if ($HiveRoot -like 'HKEY_USERS*') {
        $candidatePaths += "Registry::$HiveRoot\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$KeyName"
        $candidatePaths += "Registry::$HiveRoot\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$KeyName"
    } else {
        $candidatePaths += "Registry::$HiveRoot\$node\$KeyName"
    }
    foreach ($kp in $candidatePaths) {
        if (Test-Path -LiteralPath $kp) {
            # Safety: leaf of the key path must equal the KeyName we enumerated.
            if ((Split-Path -Leaf $kp) -ne $KeyName) { continue }
            try {
                Remove-Item -LiteralPath $kp -Recurse -Force -ErrorAction Stop
                Write-Log "Removed leftover Uninstall key: $kp"
            } catch {
                Write-Log "Could not remove Uninstall key '$kp': $($_.Exception.Message)" 'WARN'
            }
        }
    }
}

# Checks whether an ARP entry still exists (used to confirm NSIS removal).
function Test-UninstallKey {
    param([string]$HiveRoot, [string]$View, [string]$KeyName)
    if ([string]::IsNullOrWhiteSpace($KeyName)) { return $false }
    if ($HiveRoot -like 'HKEY_USERS*') {
        foreach ($n in @('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                         'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
            if (Test-Path -LiteralPath "Registry::$HiveRoot\$n\$KeyName") { return $true }
        }
        return $false
    }
    # Machine-wide: check the matching view via OpenBaseKey.
    $rv = if ($View -eq 'Registry32') { [Microsoft.Win32.RegistryView]::Registry32 }
          else { [Microsoft.Win32.RegistryView]::Registry64 }
    $base = $null
    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $rv)
        $k = $base.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$KeyName")
        if ($k) { $k.Close(); return $true }
        return $false
    } catch { return $false } finally { if ($base) { $base.Close() } }
}

#--------------------------------------------------------------------------------
# Uninstall one ARP entry. Branches MSI vs NSIS by the documented discriminators.
# Returns $true on success.
#--------------------------------------------------------------------------------
function Invoke-7ZipUninstall {
    param(
        [string]$DisplayName,
        [string]$DisplayVersion,
        [string]$UninstallString,
        [string]$QuietUninstallString,
        [object]$WindowsInstaller,   # DWORD 1 for MSI
        [string]$KeyName,            # subkey name (GUID for MSI, "7-Zip" for NSIS)
        [string]$Scope,              # e.g. 'HKLM Registry64' or 'HKU:<SID>'
        [string]$HiveRoot,           # 'HKEY_LOCAL_MACHINE' or 'HKEY_USERS\<SID>'
        [string]$View                # 'Registry64' | 'Registry32' | ''
    )

    # Dedup key INCLUDES Scope so distinct users are not collapsed (review fix).
    $dedupKey = "$Scope|$DisplayName|$DisplayVersion"
    if ($processed[$dedupKey]) { Write-Log "Already handled '$dedupKey' -- skipping."; return $true }
    $processed[$dedupKey] = $true

    Write-Log "Uninstalling [$Scope] $DisplayName v$DisplayVersion"

    if ([string]::IsNullOrWhiteSpace($UninstallString) -and
        [string]::IsNullOrWhiteSpace($QuietUninstallString)) {
        Write-Log "No UninstallString for '$DisplayName' -- nothing to invoke." 'WARN'
        return $false
    }

    # ---- Decide installer family ----
    $isMsi = ($WindowsInstaller -eq 1) -or
             ($UninstallString -match '(?i)msiexec') -or
             ($KeyName -match $script:GuidAnchored)

    try {
        if ($isMsi) {
            # Pull the {GUID} from whichever string carries it.
            $guidMatch = [regex]::Match("$UninstallString $QuietUninstallString", $script:GuidUnanchored)
            if (-not $guidMatch.Success) {
                Write-Log "MSI entry but no well-formed GUID found -- skipping." 'WARN'
                return $false
            }
            $guid = $guidMatch.Value
            Write-Log "MSI uninstall: msiexec /x $guid /qn /norestart REBOOT=ReallySuppress (with retry)"
            $code = Invoke-MsiUninstall -Guid $guid
            # 0 = ok, 1605 = not installed, 1641 = success+reboot initiated,
            # 3010 = success+reboot pending. 1641/3010 mean a reboot is needed to
            # finish (e.g. in-use files the MSI scheduled for deletion).
            if ($code -in @(1641, 3010)) { $script:rebootPending = $true }
            if ($code -notin @(0, 1605, 1641, 3010)) {
                Write-Log "msiexec returned non-success code $code for $guid." 'WARN'
                return $false
            }
            # v2.2 fix (observed: "Failed: 0. Residual: reg:7-Zip 24.09 (x64 edition)").
            # An OK code -- especially 1605 (ERROR_UNKNOWN_PRODUCT: the parsed GUID is
            # a stale/superseded/wrong-view product code that msiexec can't act on),
            # or a GUID/view mismatch -- does NOT guarantee the ARP key that SEEDED
            # this entry is gone. If it lingers, verification 8a re-finds it by
            # DisplayName -> residual with Failed=0, looping forever. Mirror the NSIS
            # branch: remove the orphaned ARP key from the CORRECT hive/view and only
            # report success once it is actually gone.
            if (Test-UninstallKey -HiveRoot $HiveRoot -View $View -KeyName $KeyName) {
                Write-Log "msiexec returned $code but ARP key '$KeyName' still present -- removing orphaned key." 'WARN'
                Remove-UninstallKey -HiveRoot $HiveRoot -View $View -KeyName $KeyName
                if (Test-UninstallKey -HiveRoot $HiveRoot -View $View -KeyName $KeyName) {
                    Write-Log "Orphaned MSI ARP key '$KeyName' still present after cleanup attempt." 'WARN'
                    return $false
                }
                Write-Log "Orphaned MSI ARP key '$KeyName' removed."
            }
            return $true
        }
        else {
            # ---- NSIS EXE: prefer QuietUninstallString, else UninstallString + /S
            #      Renamed $args -> $uninstArgs (review fix: avoid the automatic var).
            $exe         = $null
            $uninstArgs  = $null
            if (-not [string]::IsNullOrWhiteSpace($QuietUninstallString)) {
                if ($QuietUninstallString -match '^\s*"([^"]+)"\s*(.*)$') {
                    # Quoted path (7-Zip's own form) -- safe to split here.
                    $exe = $Matches[1]; $uninstArgs = $Matches[2].Trim()
                }
                else {
                    # UNquoted QuietUninstallString. Naive whitespace-split breaks a
                    # path that itself contains spaces (review fix). Only treat the
                    # tail as args if it begins with a switch token (/ or -); strip
                    # KNOWN trailing switches off the end and treat the remainder as
                    # the exe path. Otherwise treat the whole string as the exe path.
                    $qus = $QuietUninstallString.Trim()
                    $m = [regex]::Match($qus, '^(?<exe>.+?\.exe)(?<rest>\s+[/-].*)?$', 'IgnoreCase')
                    if ($m.Success) {
                        $exe        = $m.Groups['exe'].Value.Trim().Trim('"')
                        $uninstArgs = $m.Groups['rest'].Value.Trim()
                    } else {
                        # No recognizable .exe; fall back to UninstallString.
                        $exe        = $UninstallString.Trim().Trim('"')
                        $uninstArgs = '/S'
                    }
                }
            }
            else {
                $exe        = $UninstallString.Trim().Trim('"')
                $uninstArgs = '/S'   # NSIS silent switch is uppercase, case-sensitive.
            }
            if ($uninstArgs -notmatch '/S') { $uninstArgs = ("$uninstArgs /S").Trim() }

            if (-not (Test-Path -LiteralPath $exe)) {
                # The binary is gone. This is only truly "already uninstalled" if
                # the originating ARP key is ALSO gone -- otherwise we have an
                # orphaned key that would loop forever (review fix). Remove the key
                # and report success only after it is gone.
                Write-Log "NSIS uninstaller not found at '$exe'. Removing orphaned ARP key if present." 'WARN'
                Remove-UninstallKey -HiveRoot $HiveRoot -View $View -KeyName $KeyName
                if (Test-UninstallKey -HiveRoot $HiveRoot -View $View -KeyName $KeyName) {
                    Write-Log "Orphaned ARP key still present after cleanup attempt." 'WARN'
                    return $false
                }
                return $true
            }

            $installDir = Split-Path -Parent $exe
            Write-Log "NSIS uninstall: `"$exe`" $uninstArgs  (dir: $installDir)"
            # v2.2: BOUNDED wait (60s) instead of unbounded -Wait. An NSIS Uninstall.exe
            # that shows any UI in session 0 (mis-detected /S, an "in use" page, a modal)
            # would otherwise hang forever and get the whole run "Timed out" by Intune.
            [void](Wait-ProcessWithTimeout -FilePath $exe -Arguments $uninstArgs -TimeoutSec 60)

            # NSIS self-relaunches from %TEMP% and can return early; poll for the File
            # Manager / install dir to vanish (cap 30s, and bail on the global deadline).
            # On timeout, fall back to the ARP key: if the registry entry is gone, treat
            # as success even if a file lingers (avoids a perpetual exit-1 loop).
            $marker  = Join-Path $installDir '7zFM.exe'
            $waited   = 0
            while ((Test-Path -LiteralPath $marker) -and $waited -lt 30 -and -not (Test-PastDeadline)) {
                Start-Sleep -Seconds 3; $waited += 3
            }

            $keyGone = -not (Test-UninstallKey -HiveRoot $HiveRoot -View $View -KeyName $KeyName)
            if (-not (Test-Path -LiteralPath $marker)) {
                Write-Log "NSIS uninstall confirmed (7zFM.exe gone after ${waited}s)."
                if (-not $keyGone) { Remove-UninstallKey -HiveRoot $HiveRoot -View $View -KeyName $KeyName }
                return $true
            }
            if ($keyGone) {
                Write-Log "7zFM.exe lingering after ${waited}s but ARP key is gone -- treating as success." 'WARN'
                return $true
            }
            Write-Log "7zFM.exe AND ARP key still present after ${waited}s wait." 'WARN'
            return $false
        }
    }
    catch {
        Write-Log "Uninstall threw for '$DisplayName': $($_.Exception.Message)" 'ERROR'
        return $false
    }
}

# Wrapper that updates the success/fail tallies.
function Invoke-EntryRemoval {
    param([hashtable]$E)
    $ok = Invoke-7ZipUninstall @E
    if ($ok) { $script:successCount++ } else { $script:failCount++ }
}

# Per-user / machine install folder that holds a 7-Zip binary (used for both the
# kill-decision and verification). Mirrors detection's binary check.
$binaryNames = @('7z.exe', '7zFM.exe', '7zG.exe', '7z.dll')
function Test-FolderHas7ZipBinary {
    param([string]$Dir)
    if ([string]::IsNullOrWhiteSpace($Dir)) { return $false }
    if (-not (Test-Path -LiteralPath $Dir)) { return $false }
    foreach ($b in $binaryNames) {
        if (Test-Path -LiteralPath (Join-Path $Dir $b)) { return $true }
    }
    return $false
}

Write-Log "=== 7-Zip Removal started on $env:COMPUTERNAME (64-bit host: $([Environment]::Is64BitProcess)) ==="

try {
    #----------------------------------------------------------------------------
    # 2. Profile / SID enumeration + orphaned-mount cleanup (shared by later steps).
    #----------------------------------------------------------------------------
    $sidPattern = 'S-1-5-21-\d+-\d+-\d+-\d+$'
    # v2.3: exclude ProfileList entries with a null/empty ProfileImagePath -- Join-Path
    # $null later threw "Cannot bind argument to parameter 'Path' because it is null",
    # which under the top-level catch became a FATAL remediation error (exit 1) on a
    # few fleet devices.
    $profiles = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' `
                    -ErrorAction SilentlyContinue |
                Where-Object { $_.PSChildName -match $sidPattern -and -not [string]::IsNullOrWhiteSpace($_.ProfileImagePath) }
    $activeSids = Get-ActiveUserSid
    # v2.4 defense-in-depth: never let a null/degenerate return reach .Contains().
    if ($null -eq $activeSids -or $activeSids -isnot [System.Collections.Generic.HashSet[string]]) {
        $tmp = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($s in @($activeSids)) { if ($s) { [void]$tmp.Add([string]$s) } }
        $activeSids = $tmp
    }
    $loadedSids = (Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
                   Where-Object { $_.PSChildName -match $sidPattern }).PSChildName
    foreach ($lsid in @($loadedSids)) {
        if ([string]::IsNullOrWhiteSpace($lsid)) { continue }
        if (-not $activeSids.Contains($lsid)) {
            try {
                Write-Log "Orphaned HKU mount detected for $lsid (no active session). Attempting cleanup." 'WARN'
                if (Invoke-RegUnload -Sid $lsid) { Write-Log "Unloaded orphaned hive HKU\$lsid." }
            } catch {
                Write-Log "Orphan cleanup error for $lsid (continuing): $($_.Exception.Message)" 'WARN'
            }
        }
    }
    $loadedSids = (Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
                   Where-Object { $_.PSChildName -match $sidPattern }).PSChildName

    #----------------------------------------------------------------------------
    # 3. HKLM machine-wide entries -- explicit 64-bit AND 32-bit views.
    #    Collect first (so we don't enumerate a hive we're mutating), then act.
    #----------------------------------------------------------------------------
    $hklmEntries = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($viewObj in @([Microsoft.Win32.RegistryView]::Registry64,
                           [Microsoft.Win32.RegistryView]::Registry32)) {
        $base = $null
        try {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                        [Microsoft.Win32.RegistryHive]::LocalMachine, $viewObj)
            $uninstall = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
            if ($uninstall) {
                foreach ($subName in $uninstall.GetSubKeyNames()) {
                    $sub = $uninstall.OpenSubKey($subName)
                    if (-not $sub) { continue }
                    $entry = [pscustomobject]@{
                        DisplayName    = $sub.GetValue('DisplayName')
                        DisplayVersion = $sub.GetValue('DisplayVersion')
                        Publisher      = $sub.GetValue('Publisher')
                    }
                    if (Test-Is7Zip $entry) {
                        $hklmEntries.Add(@{
                            DisplayName          = [string]$entry.DisplayName
                            DisplayVersion       = [string]$entry.DisplayVersion
                            UninstallString      = [string]$sub.GetValue('UninstallString')
                            QuietUninstallString = [string]$sub.GetValue('QuietUninstallString')
                            WindowsInstaller     = $sub.GetValue('WindowsInstaller')
                            KeyName              = $subName
                            Scope                = "HKLM $viewObj"
                            HiveRoot             = 'HKEY_LOCAL_MACHINE'
                            View                 = "$viewObj"
                        })
                    }
                    $sub.Close()
                }
                $uninstall.Close()
            }
        } catch {
            Write-Log "HKLM $viewObj enumeration error: $($_.Exception.Message)" 'WARN'
        } finally {
            if ($base) { $base.Close() }
        }
    }

    #----------------------------------------------------------------------------
    # 3b. Decide whether anything is removable, so we only kill processes if so.
    #     We also peek per-user + folders here to make the kill decision sound.
    #----------------------------------------------------------------------------
    $anyArtifact = ($hklmEntries.Count -gt 0)
    $folderTargets = [System.Collections.Generic.List[string]]::new()
    $folderTargets.Add((Join-Path $env:ProgramFiles '7-Zip'))
    if (${env:ProgramFiles(x86)}) { $folderTargets.Add((Join-Path ${env:ProgramFiles(x86)} '7-Zip')) }
    foreach ($prof in $profiles) {
        $folderTargets.Add((Join-Path $prof.ProfileImagePath 'AppData\Local\Programs\7-Zip'))
    }
    foreach ($f in ($folderTargets | Select-Object -Unique)) {
        if (Test-FolderHas7ZipBinary -Dir $f) { $anyArtifact = $true; break }
    }

    #----------------------------------------------------------------------------
    # 4. Stop running 7-Zip processes -- ONLY if there is something to remove, and
    #    ONLY processes whose image path is inside a known 7-Zip folder. Log each.
    #    (review fix: no unconditional kill; audit PID/path; avoid unrelated 7z.exe)
    #----------------------------------------------------------------------------
    if ($anyArtifact) {
        foreach ($pName in @('7zFM', '7zG', '7z')) {
            Get-Process -Name $pName -ErrorAction SilentlyContinue | ForEach-Object {
                $procPath = $null
                try { $procPath = $_.Path } catch { }
                $installScoped = $false
                if ($procPath) {
                    foreach ($f in ($folderTargets | Select-Object -Unique)) {
                        if ($procPath -like (Join-Path $f '*')) { $installScoped = $true; break }
                    }
                }
                # If we cannot resolve the path (access denied on a SYSTEM read of
                # another session's process) fall back to name-based kill, which is
                # safe because these names are 7-Zip-specific.
                if ($installScoped -or -not $procPath) {
                    Write-Log "Stopping $($_.ProcessName) PID $($_.Id) Path '$procPath'"
                    Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
                } else {
                    Write-Log "Skipping non-7-Zip-path process $($_.ProcessName) PID $($_.Id) Path '$procPath'" 'WARN'
                }
            }
        }
    } else {
        Write-Log "No removable 7-Zip artifact found before process scan -- not killing any processes."
    }

    foreach ($e in $hklmEntries) { if (Test-PastDeadline) { break }; Invoke-EntryRemoval $e }

    #----------------------------------------------------------------------------
    # 5. Per-user entries across all profiles (loaded + temporarily loaded).
    #----------------------------------------------------------------------------
    foreach ($prof in $profiles) {
        if (Test-PastDeadline) { Write-Log 'Deadline reached; skipping remaining profiles.' 'WARN'; break }
        $sid      = $prof.PSChildName
        $profPath = $prof.ProfileImagePath
        $hiveRoot = "HKEY_USERS\$sid"
        $didLoad  = $false
        try {
            if ($loadedSids -notcontains $sid) {
                if ($sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { Write-Log "Skipping malformed SID '$sid'." 'WARN'; continue }
                if ([string]::IsNullOrWhiteSpace($profPath)) { Write-Log "Empty ProfileImagePath for $sid." 'WARN'; continue }
                $ntuser = Join-Path $profPath 'NTUSER.DAT'
                if (-not (Test-Path -LiteralPath $ntuser)) { continue }
                # v2.3: bounded reg load (60s) via Start-Process -- caps a hang on a
                # corrupt/locked NTUSER.DAT and avoids native-stderr termination.
                # NOTE: Start-Process -ArgumentList does NOT auto-quote array elements,
                # so the NTUSER.DAT path must be quoted explicitly or a profile path
                # containing a space (C:\Users\John Doe) splits into two arguments and
                # the load fails -- silently skipping that user's 7-Zip removal.
                $rc = Wait-ProcessWithTimeout -FilePath 'reg.exe' -Arguments @('load', "HKU\$sid", ('"{0}"' -f $ntuser)) -TimeoutSec 60
                if ($rc -ne 0) { Write-Log "Could not load hive for $profPath (rc=$rc)" 'WARN'; continue }
                $didLoad = $true
                Write-Log "Loaded offline hive: $profPath"
            }

            # 5a. Per-user uninstall entries. We pass HiveRoot/View so that, after
            #     a successful or binary-missing uninstall, the originating ARP key
            #     is removed from the CORRECT HKU\<SID> hive (not SYSTEM's HKCU).
            foreach ($node in @('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                                 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
                $path = "Registry::$hiveRoot\$node"
                if (-not (Test-Path -LiteralPath $path)) { continue }
                $userEntries = Get-ChildItem -LiteralPath $path -ErrorAction SilentlyContinue | ForEach-Object {
                    $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
                    if (Test-Is7Zip $p) {
                        @{
                            DisplayName          = [string]$p.DisplayName
                            DisplayVersion       = [string]$p.DisplayVersion
                            UninstallString      = [string]$p.UninstallString
                            QuietUninstallString = [string]$p.QuietUninstallString
                            WindowsInstaller     = $p.WindowsInstaller
                            KeyName              = $_.PSChildName
                            Scope                = "HKU:$sid"
                            HiveRoot             = $hiveRoot
                            View                 = ''
                        }
                    }
                }
                foreach ($e in $userEntries) { if ($e) { Invoke-EntryRemoval $e } }
            }

            # 5b. Stray per-user settings key HKCU\Software\7-Zip (correct hive).
            $userSoftware7z = "Registry::$hiveRoot\Software\7-Zip"
            if (Test-Path -LiteralPath $userSoftware7z) {
                Remove-Item -LiteralPath $userSoftware7z -Recurse -Force -ErrorAction SilentlyContinue
                Write-Log "Removed per-user reg key: HKU\$sid\Software\7-Zip"
            }
        }
        catch {
            Write-Log "Per-user processing error ($sid): $($_.Exception.Message)" 'WARN'
        }
        finally {
            if ($didLoad) {
                # Verified unload + retry; count a stuck hive as a failure so the
                # run reports incomplete rather than a false success (review fix).
                if (-not (Invoke-RegUnload -Sid $sid)) { $script:failCount++ }
            }
        }
    }

    #----------------------------------------------------------------------------
    # 6. MSIX / Appx removal. TIGHT filter (publisher/family-gated). Distinguishes
    #    "cmdlet unavailable" from "package gone" so verification stays sound.
    #----------------------------------------------------------------------------
    $appxAvailable = [bool](Get-Command -Name Get-AppxPackage -ErrorAction SilentlyContinue)
    if (-not $appxAvailable) {
        Write-Log "Get-AppxPackage unavailable in this host (possibly 32-bit/SYSTEM). MSIX removal NOT attempted; MSIX state cannot be verified." 'WARN'
    } else {
        try {
            $appx = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue |
                    Where-Object { Test-Is7ZipAppx $_ }
            foreach ($pkg in $appx) {
                try {
                    Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
                    Write-Log "Removed Appx (all users): $($pkg.PackageFullName)"
                    $successCount++
                } catch {
                    Write-Log "Remove-AppxPackage -AllUsers failed ($($pkg.PackageFullName)): $($_.Exception.Message). Trying per-user." 'WARN'
                    $anyFail = $false
                    foreach ($u in $pkg.PackageUserInformation) {
                        if ($u.InstallState -eq 'Installed') {
                            try { Remove-AppxPackage -Package $pkg.PackageFullName -User $u.UserSecurityId.Sid -ErrorAction Stop }
                            catch { $anyFail = $true; Write-Log "  per-user remove failed for $($u.UserSecurityId.Sid): $($_.Exception.Message). A user-context Remediation may be required." 'WARN' }
                        }
                    }
                    if ($anyFail) { $failCount++ } else { $successCount++ }
                }
            }
        } catch { Write-Log "Appx removal phase error: $($_.Exception.Message)" 'WARN' }
    }

    # Provisioned-package removal goes through DISM and is reliable from SYSTEM.
    $provAvailable = [bool](Get-Command -Name Get-AppxProvisionedPackage -ErrorAction SilentlyContinue)
    if (-not $provAvailable) {
        Write-Log "Get-AppxProvisionedPackage unavailable in this host. Provisioned MSIX state NOT verified." 'WARN'
    } else {
        try {
            $prov = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
                    Where-Object { $_.DisplayName -like '7-Zip*' -or $_.DisplayName -like '*SevenZip*' }
            foreach ($pp in $prov) {
                try {
                    Remove-AppxProvisionedPackage -Online -PackageName $pp.PackageName -ErrorAction Stop | Out-Null
                    Write-Log "Deprovisioned: $($pp.PackageName)"
                    $successCount++
                } catch {
                    Write-Log "Remove-AppxProvisionedPackage failed ($($pp.PackageName)): $($_.Exception.Message)" 'WARN'
                    $failCount++
                }
            }
        } catch { Write-Log "Deprovision phase error: $($_.Exception.Message)" 'WARN' }
    }

    #----------------------------------------------------------------------------
    # 7. Leftover cleanup -- ONLY after uninstall. Each delete is guarded so it
    #    can NEVER touch anything but a folder/key whose leaf is exactly '7-Zip'.
    #----------------------------------------------------------------------------
    function Remove-7ZipFolder {
        param([string]$Path)
        if ([string]::IsNullOrWhiteSpace($Path)) { return }
        if (-not (Test-Path -LiteralPath $Path)) { return }
        if ((Split-Path -Leaf $Path) -ne '7-Zip') {
            Write-Log "Refusing to delete non-allowlisted path: $Path" 'WARN'; return
        }
        # If the folder ITSELF is a reparse point (junction/symlink), remove only the
        # link -- never recurse into / delete the target it points at (review fix).
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        if ($item -and (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            try { [IO.Directory]::Delete($Path, $false); Write-Log "Removed reparse point (link only): $Path" }
            catch { Write-Log "Could not remove reparse point '$Path': $($_.Exception.Message)" 'ERROR' }
            return
        }
        # Reparse-safe removal. Files locked in-use (classically 7z.dll loaded into
        # explorer.exe as the shell-extension) are scheduled for delete-on-reboot;
        # a folder left with only reboot-scheduled items is recorded in
        # $pendingFolders so verification treats it as reboot-pending (exit 0) rather
        # than a hard "Failed" -- exactly how Windows Installer handles in-use files.
        $ok = Remove-TreeReparseSafe -Root $Path
        if (-not $ok) {
            Write-Log "Folder '$Path' could not be fully removed or scheduled." 'ERROR'
        } elseif (Test-Path -LiteralPath $Path) {
            [void]$script:pendingFolders.Add($Path)
            Write-Log "Folder '$Path' will be removed on next reboot." 'WARN'
        } else {
            Write-Log "Removed folder: $Path"
        }
    }

    # 7a. Install folders (machine-wide + per-user). ($folderTargets built earlier.)
    foreach ($f in ($folderTargets | Select-Object -Unique)) { Remove-7ZipFolder -Path $f }

    # 7b. Start Menu shortcut folders (all-users + per-user). Leaf is '7-Zip'.
    $startMenuTargets = [System.Collections.Generic.List[string]]::new()
    $startMenuTargets.Add((Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\7-Zip'))
    foreach ($prof in $profiles) {
        $startMenuTargets.Add((Join-Path $prof.ProfileImagePath 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\7-Zip'))
    }
    foreach ($s in ($startMenuTargets | Select-Object -Unique)) { Remove-7ZipFolder -Path $s }

    # 7c. Stray machine-wide settings keys (HKCU per-user keys handled in 5b).
    foreach ($k in @('HKLM:\SOFTWARE\7-Zip', 'HKLM:\SOFTWARE\WOW6432Node\7-Zip')) {
        if (Test-Path -LiteralPath $k) {
            Remove-Item -LiteralPath $k -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log "Removed reg key: $k"
        }
    }

    #----------------------------------------------------------------------------
    # 8. Verify nothing remains. Re-scan HKLM (both views) + machine/per-user
    #    folders (binary present) + per-user HKU Uninstall keys + Appx (only when
    #    the cmdlet is actually available -- review fix). Must mirror detection.
    #----------------------------------------------------------------------------
    $residual = [System.Collections.Generic.List[string]]::new()

    # 8a. HKLM both views.
    foreach ($viewObj in @([Microsoft.Win32.RegistryView]::Registry64,
                           [Microsoft.Win32.RegistryView]::Registry32)) {
        $base = $null
        try {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                        [Microsoft.Win32.RegistryHive]::LocalMachine, $viewObj)
            $uninstall = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
            if ($uninstall) {
                foreach ($subName in $uninstall.GetSubKeyNames()) {
                    $sub = $uninstall.OpenSubKey($subName); if (-not $sub) { continue }
                    $e = [pscustomobject]@{ DisplayName = $sub.GetValue('DisplayName'); Publisher = $sub.GetValue('Publisher') }
                    if (Test-Is7Zip $e) { $residual.Add("reg:$($e.DisplayName)") }
                    $sub.Close()
                }
                $uninstall.Close()
            }
        } catch { } finally { if ($base) { $base.Close() } }
    }

    # 8b. Per-user HKU Uninstall keys (loaded SIDs -- includes any we just left
    #     loaded for active users). Mirrors detection coverage (review fix).
    $loadedSidsVerify = (Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
                         Where-Object { $_.PSChildName -match $sidPattern }).PSChildName
    foreach ($vsid in @($loadedSidsVerify)) {
        foreach ($node in @('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                             'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
            $vp = "Registry::HKEY_USERS\$vsid\$node"
            if (-not (Test-Path -LiteralPath $vp)) { continue }
            Get-ChildItem -LiteralPath $vp -ErrorAction SilentlyContinue | ForEach-Object {
                $pp = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
                if (Test-Is7Zip $pp) { $residual.Add("hku:$vsid`:$($pp.DisplayName)") }
            }
        }
    }

    # 8c. Folders (machine + per-user) -- only count a folder with a 7-Zip binary,
    #     so a stubborn EMPTY leftover dir never produces a perpetual exit 1. A
    #     folder whose only remaining content is LOCKED and already scheduled for
    #     delete-on-reboot ($pendingFolders) is NOT a hard residual -- it is counted
    #     as reboot-pending instead (v2 fix for the locked 7z.dll false "Failed").
    foreach ($dir in ($folderTargets | Select-Object -Unique)) {
        if (Test-FolderHas7ZipBinary -Dir $dir) {
            if ($script:pendingFolders.Contains($dir)) {
                Write-Log "Residual binary in '$dir' is scheduled for delete-on-reboot (reboot pending)." 'WARN'
                $script:rebootPending = $true
            } else {
                $residual.Add("dir:$dir")
            }
        }
    }

    # 8d. Appx -- ONLY if the cmdlet is available; otherwise we cannot verify and
    #     must not claim clean off a failed cmdlet (review fix).
    if ($appxAvailable) {
        try {
            Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue |
                Where-Object { Test-Is7ZipAppx $_ } |
                ForEach-Object { $residual.Add("appx:$($_.PackageFullName)") }
        } catch { Write-Log "Appx verification re-scan error: $($_.Exception.Message)" 'WARN' }
    }

    #----------------------------------------------------------------------------
    # 9. Final summary + exit code.
    #----------------------------------------------------------------------------
    # v2.2: if we blew the internal deadline mid-run, report incomplete (exit 1) so
    # Intune retries next cycle -- rather than being force-killed as "Timed out".
    if (Test-PastDeadline) {
        Write-Log 'Deadline reached mid-run; reporting incomplete so Intune retries next cycle.' 'WARN'
        try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
        Write-Output "7-Zip removal hit time budget; will retry next cycle. Uninstalled so far: $successCount."
        exit 1
    }

    Write-Log "Removals OK: $successCount | Failed: $failCount | Residual(hard): $($residual.Count) | RebootPending: $($script:rebootPending)"

    if ($residual.Count -eq 0 -and $failCount -eq 0) {
        if ($script:rebootPending) {
            # Everything is uninstalled; the only remaining items are locked files
            # (or MSI in-use files) scheduled to delete on the next reboot. This is a
            # SUCCESS, not a failure -- exit 0 so Intune reports remediated. The
            # device may keep DETECTING 7-Zip until it reboots; that self-resolves
            # once the scheduled deletes run, so it is not a perpetual "Failed".
            Write-Log '=== 7-Zip removed; REBOOT REQUIRED to delete locked leftovers. ===' 'INFO'
            try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
            Write-Output "7-Zip removed; reboot required to delete locked files. Uninstalled: $successCount."
            exit 0
        }
        Write-Log '=== 7-Zip fully removed. ===' 'INFO'
        try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
        Write-Output "7-Zip removed. Uninstalled: $successCount."
        exit 0
    } else {
        $resSummary = ($residual | Select-Object -First 20) -join ', '
        Write-Log "=== 7-Zip removal INCOMPLETE. Failed: $failCount. Residual: $resSummary ===" 'ERROR'
        try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
        Write-Output "7-Zip removal incomplete. Failed: $failCount. Residual: $resSummary"
        exit 1
    }
}
catch {
    Write-Log "FATAL remediation error: $($_.Exception.Message)" 'ERROR'
    try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
    Write-Output "7-Zip remediation error: $($_.Exception.Message)"
    exit 1
}