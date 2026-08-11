<#
.SYNOPSIS
    Detects ANY 7-Zip installation (publisher Igor Pavlov) on a Windows device.

.DESCRIPTION
    Intune Remediation DETECTION script (READ-ONLY).

    Scans every place a 7-Zip install can register itself:
      1. HKLM Uninstall keys in BOTH the 64-bit (native) and 32-bit (WOW6432Node)
         registry views.
      2. Every real user profile via HKEY_USERS: loaded SIDs are read in place;
         logged-off NTUSER.DAT hives are temporarily 'reg load'ed and ALWAYS
         unloaded (with retry) in finally.
      3. Default install folders (Program Files / Program Files (x86) / per-user)
         -- but a folder is only treated as a finding when it actually contains a
         7-Zip BINARY (7z.exe / 7zFM.exe / 7zG.exe / 7z.dll). An empty leftover
         "7-Zip" directory is NOT a finding, so it can never trigger a perpetual
         detect->remediate loop (the remediation may not be able to delete a dir
         held open by another process, and we must not loop forever on that).
      4. MSIX / Appx packages. 7-Zip is virtually never shipped as a Store/MSIX
         package (the only Store listing is an UNOFFICIAL third-party port whose
         publisher is NOT Igor Pavlov). To avoid false positives we gate on a
         TIGHT filter (Name -like '7-Zip*'/'*SevenZip*' AND Publisher contains
         'Igor Pavlov', OR an explicit confirmed PackageFamilyName allow-list).

    BITNESS HANDLING (why this matters):
      Intune Platform Scripts and Remediations can run in a 32-bit PowerShell host.
      A 32-bit process is WOW64-redirected, so 'HKLM:\SOFTWARE\...' actually reads
      Wow6432Node and CANNOT see the native 64-bit Uninstall keys where the
      64-bit 7-Zip MSI/EXE register. To stay correct regardless of how the admin
      configured the policy this script does BOTH of the following:
        (a) If launched in a 32-bit host on 64-bit Windows it re-launches itself
            through the %WINDIR%\Sysnative alias so the rest runs 64-bit (also
            best for the Appx cmdlets). The relaunch is GUARDED: it only fires
            when $PSCommandPath is a real, existing file -- never '-File ""'.
        (b) Even so, it reads the Uninstall keys via [Microsoft.Win32.RegistryView]
            for BOTH Registry64 and Registry32 explicitly, so a single view never
            hides an entry. This is belt-and-suspenders by design.

      *** DEPLOY WITH "Run script in 64-bit PowerShell = Yes" ***  When that flag
      is Yes the host is already 64-bit, the relaunch is dead code, and the Appx
      cmdlets behave correctly. Treat that flag as a HARD requirement, not a nicety.

    EXIT CODES (Intune Remediation convention -- the OPPOSITE of a Win32 detection
    rule):
        exit 1 = at least one 7-Zip artifact found   -> triggers remediation.
        exit 0 = clean                               -> no action.
    Any error during detection also exits 1 so the issue is remediated rather than
    silently treated as compliant.

    OUTPUT: All diagnostic logging goes to Write-Host (captured by the transcript,
    NOT by Intune's STDOUT/success-stream capture). Exactly ONE Write-Output call
    runs -- the final concise summary line -- so Intune's captured STDOUT is a
    single line well under the 2048-char cap. Verbose detail lives in the
    transcript under C:\ProgramData\Monster\Logs.

.NOTES
    Author : Endpoint Engineering (Monster Energy)
    Target : Windows PowerShell 5.1, SYSTEM context
    Intune : Run using logged-on credentials = No (SYSTEM)
             Run script in 64-bit PowerShell = Yes (REQUIRED)
             Enforce script signature check  = No
    Read-only: this script does not modify hive CONTENTS. The transient reg-load /
               reg-unload of an offline hive is the only side effect; it is always
               reversed (with retry), and orphaned mounts from a prior crashed run
               are detected and cleaned up at startup.
#>

#--------------------------------------------------------------------------------
# 0. 64-bit self-relaunch guard.
#    PROCESSOR_ARCHITEW6432 is only present inside a 32-bit (WOW64) process on a
#    64-bit OS. If we are 32-bit on 64-bit Windows, re-launch via Sysnative so the
#    rest of the script -- and the Appx cmdlets -- run in a real 64-bit host.
#
#    GUARD (review fix): only relaunch with -File when $PSCommandPath is a real,
#    existing path. If the script was started via -Command / STDIN / dot-source
#    (e.g. an ad-hoc 'psexec -i -s' test), $PSCommandPath is empty and '-File ""'
#    would fail the child to start, returning a garbage exit code that flips the
#    detection result. In that case we DO NOT relaunch and fall through to the
#    explicit dual-RegistryView reads, which are host-bitness-independent.
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
    # Fall through: rely on the explicit RegistryView reads below (both 64- and
    # 32-bit views). Note: in a 32-bit host the Appx cmdlets may be unavailable;
    # that limitation is logged where the Appx scan runs.
}

$ErrorActionPreference = 'Stop'

#--------------------------------------------------------------------------------
# 1. Durable logging. SYSTEM can always write under %ProgramData%; never use
#    %TEMP%/%LOCALAPPDATA% in SYSTEM context (they resolve to the SYSTEM profile).
#--------------------------------------------------------------------------------
$LogDir = Join-Path $env:ProgramData 'Monster\Logs'
if (-not (Test-Path -LiteralPath $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}
$LogFile = Join-Path $LogDir ("Detect-7Zip_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
try { Start-Transcript -Path $LogFile -Append -ErrorAction SilentlyContinue | Out-Null } catch { }

# Write-Log uses Write-Host (review fix). Under an active transcript, Write-Host
# output IS written to the transcript file, but it is NOT placed on the success
# (output) stream that Intune captures as STDOUT. That keeps Intune's captured
# STDOUT to the single Write-Output summary line at the end (well under 2048 chars).
function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    Write-Host ("[{0:yyyy-MM-dd HH:mm:ss}] [{1}] {2}" -f (Get-Date), $Level, $Msg)
}

# Match rule: DisplayName begins with "7-Zip" OR publisher is Igor Pavlov.
# (Publisher is the secondary catch for the MSI/winget variant. We deliberately
#  do NOT match on a bare '7' or 'zip' anywhere, to avoid hitting unrelated apps.)
function Test-Is7Zip {
    param($Entry)
    if (-not $Entry) { return $false }
    $name = [string]$Entry.DisplayName
    $pub  = [string]$Entry.Publisher
    if ([string]::IsNullOrWhiteSpace($name)) { return $false }
    return ($name -like '7-Zip*' -or $pub -eq 'Igor Pavlov')
}

# Tight MSIX/Appx match (review fix -- replaces the over-broad '*7*zip*'):
#  - Name is an explicit 7-Zip identity AND publisher contains 'Igor Pavlov', OR
#  - the PackageFamilyName is on a confirmed allow-list (empty by default).
# 7-Zip is normally Win32, so by default this matches NOTHING and cannot produce
# a false positive that would deprovision/remove an unrelated Store app. Populate
# $script:KnownAppxFamilies only with package families you have CONFIRMED on your
# fleet.
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

# Tracks unique findings (and prevents duplicate noise in the summary).
$found   = $false
$details = [System.Collections.Generic.List[string]]::new()
function Add-Finding {
    param([string]$Text)
    $script:found = $true
    if (-not $script:details.Contains($Text)) { $script:details.Add($Text) }
    Write-Log $Text 'WARN'
}

# Returns the SIDs that map to an ACTIVE/loaded logon session, so a leftover
# orphaned HKU mount from a previously crashed run is NOT mistaken for "logged on".
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

# Best-effort unload of an offline hive with one retry (review fix). Logs ERROR
# if the hive cannot be released so the leftover mount is visible in the log.
function Invoke-RegUnload {
    param([string]$Sid)
    # v2.2 (root cause of the "ERROR: Invalid key name." detection crash): reg.exe
    # writes that to STDERR for a bad/absent SID, and under $ErrorActionPreference=
    # 'Stop' Windows PowerShell 5.1 turns native stderr into a TERMINATING error even
    # with *> $null. So validate the SID and run reg.exe with EAP temporarily
    # 'Continue', capturing stderr via 2>&1, so it can never terminate the script.
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

Write-Log "=== 7-Zip Detection started on $env:COMPUTERNAME (64-bit host: $([Environment]::Is64BitProcess)) ==="

try {
    #----------------------------------------------------------------------------
    # Pre-pass: detect & clean orphaned HKU mounts from a prior crashed run.
    # An orphan is a loaded SID that is NOT an active logon session AND whose hive
    # we can successfully unload. We only touch SIDs we can unload; an active
    # user's hive will (correctly) refuse to unload and is left untouched.
    #----------------------------------------------------------------------------
    $sidPattern = 'S-1-5-21-\d+-\d+-\d+-\d+$'
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
    # Refresh the loaded-SID list after orphan cleanup.
    $loadedSids = (Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
                   Where-Object { $_.PSChildName -match $sidPattern }).PSChildName

    #----------------------------------------------------------------------------
    # 2. HKLM Uninstall keys -- explicit 64-bit AND 32-bit views via RegistryView.
    #    Reading both views guarantees we see MSI "(x64 edition)", NSIS "(x64)",
    #    and any 32-bit build regardless of the host's own bitness/redirection.
    #----------------------------------------------------------------------------
    $hklmViews = @(
        [Microsoft.Win32.RegistryView]::Registry64,
        [Microsoft.Win32.RegistryView]::Registry32
    )
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
                    $entry = [pscustomobject]@{
                        DisplayName    = $sub.GetValue('DisplayName')
                        DisplayVersion = $sub.GetValue('DisplayVersion')
                        Publisher      = $sub.GetValue('Publisher')
                    }
                    if (Test-Is7Zip $entry) {
                        Add-Finding ("[HKLM {0}] {1} v{2}" -f $view, $entry.DisplayName, $entry.DisplayVersion)
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

    #----------------------------------------------------------------------------
    # 3. Per-user Uninstall keys: every real user profile.
    #    Running as SYSTEM, our own HKCU is the SYSTEM profile, so we walk
    #    HKEY_USERS. Loaded SIDs are read in place; logged-off profiles get their
    #    NTUSER.DAT loaded temporarily and ALWAYS unloaded (with retry) in finally.
    #----------------------------------------------------------------------------
    # v2.3: exclude ProfileList entries with a null/empty ProfileImagePath -- at fleet
    # scale a handful exist and Join-Path $null later threw "Cannot bind argument to
    # parameter 'Path' because it is null" / "method on a null-valued expression",
    # crashing detection (which then falsely 'treats as found').
    $profiles = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' `
                    -ErrorAction SilentlyContinue |
                Where-Object { $_.PSChildName -match $sidPattern -and -not [string]::IsNullOrWhiteSpace($_.ProfileImagePath) }

    function Search-UserUninstall {
        param([string]$HiveRoot, [string]$Scope)   # HiveRoot e.g. HKEY_USERS\<SID>
        foreach ($node in @('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                             'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
            $path = "Registry::$HiveRoot\$node"
            # v2.2: per-node try/catch so a single malformed key can't abort detection.
            try {
                if (-not (Test-Path -LiteralPath $path)) { continue }
                Get-ChildItem -LiteralPath $path -ErrorAction SilentlyContinue | ForEach-Object {
                    $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
                    if (Test-Is7Zip $p) {
                        Add-Finding ("[{0}] {1} v{2}" -f $Scope, $p.DisplayName, $p.DisplayVersion)
                    }
                }
            } catch { Write-Log "User key read error ($path): $($_.Exception.Message)" 'WARN' }
        }
    }

    foreach ($prof in $profiles) {
        $sid       = $prof.PSChildName
        $profPath  = $prof.ProfileImagePath
        $didLoad   = $false
        $hiveRoot  = "HKEY_USERS\$sid"
        try {
            if ($loadedSids -notcontains $sid) {
                if ($sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { Write-Log "Skipping malformed SID '$sid'." 'WARN'; continue }
                if ([string]::IsNullOrWhiteSpace($profPath)) { Write-Log "Empty ProfileImagePath for $sid." 'WARN'; continue }
                $ntuser = Join-Path $profPath 'NTUSER.DAT'
                if (-not (Test-Path -LiteralPath $ntuser)) { continue }
                # v2.2: reg.exe stderr must not terminate under $ErrorActionPreference='Stop'.
                $prevEAP = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
                try   { $null = (& reg.exe load "HKU\$sid" $ntuser 2>&1) }
                finally { $ErrorActionPreference = $prevEAP }
                if ($LASTEXITCODE -ne 0) { Write-Log "Could not load hive for $profPath" 'WARN'; continue }
                $didLoad = $true
                Write-Log "Loaded offline hive: $profPath"
            }
            Search-UserUninstall -HiveRoot $hiveRoot -Scope "HKU:$sid"
        } catch {
            Write-Log "User hive scan error ($sid): $($_.Exception.Message)" 'WARN'
        } finally {
            if ($didLoad) {
                # Release PowerShell's registry handles BEFORE unloading (GC inside
                # Invoke-RegUnload), or the unload fails 'in use' and could block
                # that user's next logon. Unload is verified + retried.
                [void](Invoke-RegUnload -Sid $sid)
            }
        }
    }

    #----------------------------------------------------------------------------
    # 4. File-system check. Machine-wide x64/ARM64 -> Program Files; x86 ->
    #    Program Files (x86); per-user -> %LOCALAPPDATA%\Programs\7-Zip.
    #
    #    LOOP-SAFETY (review fix): a folder is a finding ONLY if it contains an
    #    actual 7-Zip binary. A bare empty leftover "7-Zip" directory is NOT a
    #    finding -- otherwise a directory the remediation cannot delete (held open
    #    by another process) would keep the device perpetually non-compliant.
    #----------------------------------------------------------------------------
    $binaryNames = @('7z.exe', '7zFM.exe', '7zG.exe', '7z.dll')

    # FLAP-SAFETY (review fix): a binary that the remediation has ALREADY queued for
    # delete-on-reboot lives in HKLM\...\Session Manager\PendingFileRenameOperations
    # but is still physically on disk until the device reboots. If we counted it as a
    # finding, detection would keep firing (exit 1) every cycle and re-trigger the
    # remediation forever on a device that simply hasn't rebooted yet. So we read the
    # pending-delete queue once and treat any queued 7-Zip binary as NOT a finding.
    function Get-PendingDeleteSet {
        $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        try {
            $pfro = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
                        -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
            foreach ($raw in @($pfro)) {
                if ([string]::IsNullOrWhiteSpace($raw)) { continue }   # target entries are empty
                $p = $raw.TrimStart('!')                               # strip optional '!' prefix
                if ($p.StartsWith('\??\')) { $p = $p.Substring(4) }    # strip the NT path prefix
                if (-not [string]::IsNullOrWhiteSpace($p)) { [void]$set.Add($p.TrimEnd('\')) }
            }
        } catch { }
        # v2.4: comma prevents an empty set unrolling to $null (see Get-ActiveUserSid).
        return ,$set
    }
    $script:PendingDelete = Get-PendingDeleteSet
    if ($null -eq $script:PendingDelete) {
        $script:PendingDelete = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    }

    function Test-FolderHas7ZipBinary {
        param([string]$Dir)
        if ([string]::IsNullOrWhiteSpace($Dir)) { return $false }
        if (-not (Test-Path -LiteralPath $Dir)) { return $false }
        foreach ($b in $binaryNames) {
            $full = Join-Path $Dir $b
            if (Test-Path -LiteralPath $full) {
                if ($script:PendingDelete.Contains($full.TrimEnd('\'))) {
                    Write-Log "Binary '$full' is queued for delete-on-reboot; not counting as a finding."
                    continue
                }
                return $true
            }
        }
        return $false
    }

    $folderCandidates = @(
        (Join-Path $env:ProgramFiles '7-Zip')
    )
    if (${env:ProgramFiles(x86)}) {
        $folderCandidates += (Join-Path ${env:ProgramFiles(x86)} '7-Zip')
    }
    foreach ($prof in $profiles) {
        $folderCandidates += (Join-Path $prof.ProfileImagePath 'AppData\Local\Programs\7-Zip')
    }
    foreach ($dir in ($folderCandidates | Select-Object -Unique)) {
        if (Test-FolderHas7ZipBinary -Dir $dir) {
            Add-Finding "[FileSystem] $dir"
        }
    }

    #----------------------------------------------------------------------------
    # 5. MSIX / Appx. 7-Zip is normally Win32, so absence is the common case.
    #    We treat Appx-cmdlet UNAVAILABILITY distinctly from "no package found":
    #      - cmdlet present, no match  -> clean (no finding).
    #      - cmdlet present, match     -> finding (only via the TIGHT filter).
    #      - cmdlet missing/throws     -> log a clear note; do NOT manufacture a
    #        false positive, but DO note we could not verify (e.g. 32-bit host).
    #    Because 7-Zip is never an official Store app and the filter is tight, this
    #    can neither miss a real Igor-Pavlov package nor remove an unrelated one.
    #----------------------------------------------------------------------------
    $appxCmd = Get-Command -Name Get-AppxPackage -ErrorAction SilentlyContinue
    if (-not $appxCmd) {
        Write-Log "Get-AppxPackage unavailable in this host (possibly 32-bit/SYSTEM). MSIX state NOT verified." 'WARN'
    } else {
        try {
            Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue |
                Where-Object { Test-Is7ZipAppx $_ } |
                ForEach-Object { Add-Finding "[Appx] $($_.PackageFullName)" }
        } catch { Write-Log "Get-AppxPackage check error (MSIX state not verified): $($_.Exception.Message)" 'WARN' }
    }

    # Provisioned packages are queried via DISM under the hood and are reliable
    # from SYSTEM in a 64-bit host. Tight name match (no publisher field exposed).
    $provCmd = Get-Command -Name Get-AppxProvisionedPackage -ErrorAction SilentlyContinue
    if ($provCmd) {
        try {
            Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -like '7-Zip*' -or $_.DisplayName -like '*SevenZip*' } |
                ForEach-Object { Add-Finding "[Provisioned] $($_.PackageName)" }
        } catch { Write-Log "Get-AppxProvisionedPackage check error: $($_.Exception.Message)" 'WARN' }
    } else {
        Write-Log "Get-AppxProvisionedPackage unavailable in this host. Provisioned MSIX state NOT verified." 'WARN'
    }

    #----------------------------------------------------------------------------
    # 6. Result. Exactly ONE Write-Output (the captured STDOUT line). Keep < 2048.
    #----------------------------------------------------------------------------
    if ($found) {
        $summary = ($details -join ' | ')
        if ($summary.Length -gt 1800) { $summary = $summary.Substring(0, 1800) + ' ...(truncated)' }
        Write-Log "RESULT: 7-Zip DETECTED ($($details.Count) artifact(s))" 'WARN'
        try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
        Write-Output "7-Zip detected: $summary"
        exit 1
    } else {
        Write-Log 'RESULT: No 7-Zip artifacts found. Device is clean.'
        try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
        Write-Output 'No 7-Zip found.'
        exit 0
    }
}
catch {
    # Unexpected failure -> exit 1 so the issue is remediated, never silently
    # treated as compliant.
    Write-Log "FATAL detection error: $($_.Exception.Message)" 'ERROR'
    try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
    Write-Output "7-Zip detection error (treating as found): $($_.Exception.Message)"
    exit 1
}