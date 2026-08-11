<#
.SYNOPSIS
    Detects ANY Google Drive desktop client install on a Windows device --
    management decision is FULL REMOVAL (no Google Drive client is allowed to
    remain). Pairs with Remediate-GoogleDrive.ps1 (keep the CONFIG block
    identical in both).

.DESCRIPTION
    Intune Remediation DETECTION script (READ-ONLY).

    SCOPE -- every Google Drive DESKTOP CLIENT counts as a finding:
      - Google Drive for desktop (a.k.a. Drive File Stream / DriveFS):
        machine-wide install in Program Files\Google\Drive File Stream with an
        HKLM uninstall key ("Google Drive", GUID key, NON-MSI).
      - Legacy "Backup and Sync from Google" / old "Google Drive" sync client
        in Program Files\Google\Drive (googledrivesync.exe).
      - Any MSIX/Store wrapper package (rare), any user or provisioned.

    EXPLICITLY OUT OF SCOPE (never a finding, never touched by remediation):
      - Google Chrome and the SHARED Google Update machinery (gupdate/gupdatem
        services, GoogleUpdateTaskMachine* scheduled tasks, Google\Update
        folder). Chrome depends on them. Only Drive-specific artifacts are in
        scope, and machine folders are the Drive-specific SUBFOLDERS of the
        Google vendor dir -- never the vendor dir itself.
      - The user's cloud files. DriveFS is a streaming client; its local
        content cache (AppData\Local\Google\DriveFS) is cleaned by remediation
        but the files live in the cloud.

    WHAT COUNTS AS A FINDING (exit 1):
      1. Any HKLM Uninstall entry (BOTH 64-bit and 32-bit registry views)
         classified as Google Drive by Test-IsGoogleDrive.
      2. Any per-user (HKU) Uninstall entry classified as Google Drive --
         every real profile is swept; logged-off NTUSER.DAT hives are
         temporarily 'reg load'ed and ALWAYS unloaded in finally.
      3. A Drive BINARY (GoogleDriveFS.exe / googledrivesync.exe) still on
         disk in the known machine or per-profile folders. Folder-only
         leftovers (no binary) are NOT findings, and a binary already queued
         in PendingFileRenameOperations (delete-on-reboot) is NOT a finding --
         loop-safety, same convention as the 7-Zip/Adobe/Webex/Brave pairs.
      4. Any Google Drive MSIX package (any user or provisioned).

    NOT findings (remediation cleans them opportunistically, but they must not
    flap detection): the DriveFS cache folder, shortcuts, Run values,
    GoogleDriveFS Classes keys, leftover Google\DriveFS vendor keys.

    CLASSIFIER SAFETY: the strong regex anchors on names STARTING with
    'Google Drive' / 'Drive File Stream' / 'Backup and Sync'; the loose regex
    requires a Google publisher AND the word 'drive' in the name -- 'Google
    Chrome', 'Google Update Helper' and 'Microsoft OneDrive' can never match.

    EXIT CODES (Intune Remediation convention):
        exit 1 = finding(s) -> triggers remediation. Errors also exit 1.
        exit 0 = clean.

    OUTPUT: diagnostics go to Write-Host (transcript only). Exactly ONE
    Write-Output at the end is the single STDOUT line Intune captures (<2048).

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
    # Fall through: the explicit dual-RegistryView reads below are bitness-safe.
}

$ErrorActionPreference = 'Stop'

#--------------------------------------------------------------------------------
# CONFIG -- keep IDENTICAL in Detect-GoogleDrive.ps1 / Remediate-GoogleDrive.ps1
#--------------------------------------------------------------------------------
# Strong name match: DisplayName starting with 'Google Drive' (also matches
# the older 'Google Drive File Stream'), 'Drive File Stream', or the legacy
# 'Backup and Sync'. Enough on its own (publisher may be blank on HKU keys).
$GDriveStrongName  = '(?i)^\s*(google\s*drive|drive\s+file\s+stream|backup\s+and\s+sync)'
# Loose match: the word 'drive' in the name, but ONLY with a Google publisher.
# (Word boundary means 'OneDrive' can never match; publisher gate means no
# non-Google 'drive' product can match.)
$GDriveLooseName   = '(?i)\bdrive\b'
# Binaries that gate a folder finding (folder-only leftovers are not findings).
$GDriveBinaryNames = @('GoogleDriveFS.exe','googledrivesync.exe')
# Machine-wide install folders. Drive-specific SUBFOLDERS only -- NEVER the
# Google vendor root (Chrome and the shared Google Update live there).
$MachineDirs = @(
    (Join-Path $env:ProgramFiles 'Google\Drive File Stream'),
    (Join-Path $env:ProgramFiles 'Google\Drive')
)
if (${env:ProgramFiles(x86)}) {
    $MachineDirs += (Join-Path ${env:ProgramFiles(x86)} 'Google\Drive File Stream')
    $MachineDirs += (Join-Path ${env:ProgramFiles(x86)} 'Google\Drive')
}
# Per-profile APP folders (findings only when a Drive binary is inside; the
# normal content here is the DriveFS cache, which is data -- cleaned by
# remediation but never a finding).
$UserAppDirRel = @('AppData\Local\Google\DriveFS')

function Test-IsGoogleDrive {
    param([string]$Name, [string]$Publisher)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    if ($Name -match $GDriveStrongName) { return $true }
    return (($Publisher -match '(?i)google') -and ($Name -match $GDriveLooseName))
}

# MSIX/Store packages: Drive-named, never Microsoft-published.
function Test-IsGoogleDriveAppx {
    param([string]$Name, [string]$Publisher)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    if ($Publisher -match '(?i)CN=Microsoft') { return $false }
    return ($Name -match '(?i)googledrive|drivefs')
}

#--------------------------------------------------------------------------------
# 1. Durable logging under %ProgramData% (SYSTEM-safe; never %TEMP% as SYSTEM).
#--------------------------------------------------------------------------------
$LogDir = Join-Path $env:ProgramData 'Monster\Logs'
if (-not (Test-Path -LiteralPath $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}
$LogFile = Join-Path $LogDir ("Detect-GoogleDrive_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
try { Start-Transcript -Path $LogFile -Append -ErrorAction SilentlyContinue | Out-Null } catch { }

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    Write-Host ("[{0:yyyy-MM-dd HH:mm:ss}] [{1}] {2}" -f (Get-Date), $Level, $Msg)
}

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

# Best-effort unload of an offline hive with one retry. reg.exe stderr must not
# terminate under $ErrorActionPreference='Stop' (field-proven trap), so EAP is
# set to 'Continue' locally around the native call.
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

Write-Log "=== Google Drive removal detection started on $env:COMPUTERNAME (64-bit host: $([Environment]::Is64BitProcess)) ==="

try {
    #----------------------------------------------------------------------------
    # Pre-pass: detect & clean orphaned HKU mounts from a prior crashed run.
    #----------------------------------------------------------------------------
    $sidPattern = 'S-1-5-21-\d+-\d+-\d+-\d+$'
    $activeSids = Get-ActiveUserSid
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
    # 2. HKLM Uninstall keys -- explicit 64-bit AND 32-bit views.
    #----------------------------------------------------------------------------
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
                    $ver  = [string]$sub.GetValue('DisplayVersion')
                    $pub  = [string]$sub.GetValue('Publisher')
                    if (Test-IsGoogleDrive -Name $name -Publisher $pub) {
                        Add-Finding ("[HKLM {0}] {1} v{2} ({3})" -f $view, $name, $ver, $subName)
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
    # 3. Per-user Uninstall keys: every real user profile. Running as SYSTEM,
    #    our own HKCU is the SYSTEM profile, so we walk HKEY_USERS. Loaded SIDs
    #    are read in place; logged-off profiles get their NTUSER.DAT loaded
    #    temporarily and ALWAYS unloaded (with retry) in finally.
    #----------------------------------------------------------------------------
    $profiles = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' `
                    -ErrorAction SilentlyContinue |
                Where-Object { $_.PSChildName -match $sidPattern }

    function Search-UserUninstall {
        param([string]$HiveRoot, [string]$Scope)   # HiveRoot e.g. HKEY_USERS\<SID>
        foreach ($node in @('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                             'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
            $path = "Registry::$HiveRoot\$node"
            try {
                if (-not (Test-Path -LiteralPath $path)) { continue }
                Get-ChildItem -LiteralPath $path -ErrorAction SilentlyContinue | ForEach-Object {
                    $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
                    if ($p -and (Test-IsGoogleDrive -Name ([string]$p.DisplayName) -Publisher ([string]$p.Publisher))) {
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
                [void](Invoke-RegUnload -Sid $sid)
            }
        }
    }

    #----------------------------------------------------------------------------
    # 4. File-system check: machine folders + per-profile app folders.
    #    Binary-gated (a folder with no Drive binary is NOT a finding) and
    #    pending-delete-guarded (a binary queued for delete-on-reboot is NOT a
    #    finding) -- both are loop/flap-safety, same as the other pairs.
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
    foreach ($b in $GDriveBinaryNames) { [void]$binarySet.Add($b) }

    # Returns Drive binaries under $Dir that are NOT queued for delete-on-reboot.
    function Get-LiveDriveBinary {
        param([string]$Dir)
        $live = @()
        if (-not (Test-Path -LiteralPath $Dir)) { return $live }
        try {
            Get-ChildItem -LiteralPath $Dir -Recurse -Force -File -ErrorAction SilentlyContinue |
                Where-Object { $binarySet.Contains($_.Name) } | ForEach-Object {
                    if ($pendingDelete.Contains($_.FullName.TrimEnd('\'))) {
                        Write-Log "Binary '$($_.FullName)' is queued for delete-on-reboot; not a finding."
                    } else {
                        $live += $_.FullName
                    }
                }
        } catch { Write-Log "Folder scan error ($Dir): $($_.Exception.Message)" 'WARN' }
        return $live
    }

    foreach ($dir in ($MachineDirs | Select-Object -Unique)) {
        $bins = @(Get-LiveDriveBinary -Dir $dir)
        if ($bins.Count -gt 0) {
            Add-Finding ("[FileSystem] {0} ({1} Drive binaries, e.g. {2})" -f $dir, $bins.Count, (Split-Path $bins[0] -Leaf))
        }
    }
    foreach ($prof in $profiles) {
        $profPath = $prof.ProfileImagePath
        if ([string]::IsNullOrWhiteSpace($profPath)) { continue }
        foreach ($rel in $UserAppDirRel) {
            $dir  = Join-Path $profPath $rel
            $bins = @(Get-LiveDriveBinary -Dir $dir)
            if ($bins.Count -gt 0) {
                Add-Finding ("[FileSystem user] {0} ({1} Drive binaries)" -f $dir, $bins.Count)
            }
        }
    }

    #----------------------------------------------------------------------------
    # 4b. MSIX/Store Google Drive packages (rare), any user + provisioned.
    #----------------------------------------------------------------------------
    if (Get-Command -Name Get-AppxPackage -ErrorAction SilentlyContinue) {
        try {
            Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue |
                Where-Object { Test-IsGoogleDriveAppx -Name $_.Name -Publisher $_.Publisher } |
                ForEach-Object { Add-Finding "[Appx] $($_.PackageFullName)" }
        } catch { Write-Log "Get-AppxPackage error (MSIX not verified): $($_.Exception.Message)" 'WARN' }
    } else {
        Write-Log 'Get-AppxPackage unavailable in this host. MSIX state NOT verified.' 'WARN'
    }
    if (Get-Command -Name Get-AppxProvisionedPackage -ErrorAction SilentlyContinue) {
        try {
            Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -match '(?i)googledrive|drivefs' -and
                               $_.DisplayName -notmatch '(?i)^Microsoft' } |
                ForEach-Object { Add-Finding "[Provisioned] $($_.PackageName)" }
        } catch { Write-Log "Get-AppxProvisionedPackage error: $($_.Exception.Message)" 'WARN' }
    }

    #----------------------------------------------------------------------------
    # 5. Result. Exactly ONE Write-Output.
    #----------------------------------------------------------------------------
    if ($found) {
        $summary = ($details -join ' | ')
        if ($summary.Length -gt 1800) { $summary = $summary.Substring(0, 1800) + ' ...(truncated)' }
        Write-Log "RESULT: Google Drive removal NEEDED ($($details.Count) finding(s))" 'WARN'
        try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
        Write-Output "Google Drive removal needed: $summary"
        exit 1
    } else {
        Write-Log 'RESULT: no Google Drive client found. Device is clean.'
        try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
        Write-Output 'Google Drive clean: no Google Drive desktop client found (machine or per-user).'
        exit 0
    }
}
catch {
    Write-Log "FATAL detection error: $($_.Exception.Message)" 'ERROR'
    try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
    Write-Output "Google Drive detection error (treating as found): $($_.Exception.Message)"
    exit 1
}
