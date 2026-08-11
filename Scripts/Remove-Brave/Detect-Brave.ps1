<#
.SYNOPSIS
    Detects ANY Brave Browser install on a Windows device -- management
    decision is FULL REMOVAL (no Brave install is allowed to remain). Pairs
    with Remediate-Brave.ps1 (keep the CONFIG block identical in both).

.DESCRIPTION
    Intune Remediation DETECTION script (READ-ONLY).

    SCOPE -- everything Brave counts as a finding, machine-wide AND per-user:
      - Brave (release), Brave Beta, Brave Nightly. Machine-wide installs live
        in Program Files\BraveSoftware\Brave-Browser\Application with an HKLM
        uninstall key; per-user installs live in
        <profile>\AppData\Local\BraveSoftware\Brave-Browser with an HKU key.
      - Brave Update (Omaha fork) in Program Files (x86)\BraveSoftware\Update
        -- its BraveUpdate.exe binary gates a folder finding too, since a
        surviving updater can put the browser back.

    WHAT COUNTS AS A FINDING (exit 1):
      1. Any HKLM Uninstall entry (BOTH 64-bit and 32-bit registry views)
         classified as Brave by Test-IsBrave.
      2. Any per-user (HKU) Uninstall entry classified as Brave -- every real
         profile is swept; logged-off NTUSER.DAT hives are temporarily
         'reg load'ed and ALWAYS unloaded in finally.
      3. A Brave BINARY (brave.exe / BraveUpdate.exe) still on disk in the
         known machine or per-profile install folders. Folder-only leftovers
         (no binary) are NOT findings, and a binary already queued in
         PendingFileRenameOperations (delete-on-reboot) is NOT a finding --
         loop-safety, same convention as the 7-Zip/Adobe/Webex pairs.
      4. Any Brave MSIX package (Store wrapper, if present for any user or
         provisioned).

    NOT findings (remediation cleans them opportunistically, but they must not
    flap detection): browser profile data (User Data), shortcuts, Run values,
    BraveHTML Classes keys, leftover services/scheduled tasks.

    CLASSIFIER SAFETY: the strong regex anchors the word 'brave' at the START
    of the DisplayName ('Brave', 'Brave Beta', ...); the loose regex requires a
    Brave Software publisher. Appx matching excludes Microsoft publishers.

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
# CONFIG -- keep IDENTICAL in Detect-Brave.ps1 / Remediate-Brave.ps1
#--------------------------------------------------------------------------------
# Strong name match: DisplayName starting with 'Brave' (Brave / Brave Beta /
# Brave Nightly). Enough on its own (publisher may be blank on HKU keys).
$BraveStrongName  = '(?i)^\s*brave\b'
# Loose match: 'brave' anywhere in the name, but ONLY with a Brave publisher.
$BraveLooseName   = '(?i)\bbrave\b'
# Binaries that gate a folder finding (folder-only leftovers are not findings).
# BraveUpdate.exe counts: a surviving updater can reinstall the browser.
$BraveBinaryNames = @('brave.exe','BraveUpdate.exe')
# Machine-wide install folders (the whole BraveSoftware vendor dir is
# wholly Brave-owned: Brave-Browser, Update, temp).
$MachineDirs = @(
    (Join-Path $env:ProgramFiles 'BraveSoftware')
)
if (${env:ProgramFiles(x86)}) {
    $MachineDirs += (Join-Path ${env:ProgramFiles(x86)} 'BraveSoftware')
}
# Per-profile APP folders (findings when a binary is inside). Also holds the
# browser profile (User Data) -- data-only leftovers are cleaned by
# remediation but never flap detection (binary-gated).
$UserAppDirRel = @('AppData\Local\BraveSoftware')

function Test-IsBrave {
    param([string]$Name, [string]$Publisher)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    if ($Name -match $BraveStrongName) { return $true }
    return (($Publisher -match '(?i)brave') -and ($Name -match $BraveLooseName))
}

# MSIX/Store packages: name containing 'brave', never Microsoft-published.
function Test-IsBraveAppx {
    param([string]$Name, [string]$Publisher)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    if ($Publisher -match '(?i)CN=Microsoft') { return $false }
    return ($Name -match '(?i)brave')
}

#--------------------------------------------------------------------------------
# 1. Durable logging under %ProgramData% (SYSTEM-safe; never %TEMP% as SYSTEM).
#--------------------------------------------------------------------------------
$LogDir = Join-Path $env:ProgramData 'Monster\Logs'
if (-not (Test-Path -LiteralPath $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}
$LogFile = Join-Path $LogDir ("Detect-Brave_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
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

Write-Log "=== Brave removal detection started on $env:COMPUTERNAME (64-bit host: $([Environment]::Is64BitProcess)) ==="

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
                    if (Test-IsBrave -Name $name -Publisher $pub) {
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
                    if ($p -and (Test-IsBrave -Name ([string]$p.DisplayName) -Publisher ([string]$p.Publisher))) {
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
    #    Binary-gated (a folder with no Brave binary is NOT a finding) and
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
    foreach ($b in $BraveBinaryNames) { [void]$binarySet.Add($b) }

    # Returns Brave binaries under $Dir that are NOT queued for delete-on-reboot.
    function Get-LiveBraveBinary {
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
        $bins = @(Get-LiveBraveBinary -Dir $dir)
        if ($bins.Count -gt 0) {
            Add-Finding ("[FileSystem] {0} ({1} Brave binaries, e.g. {2})" -f $dir, $bins.Count, (Split-Path $bins[0] -Leaf))
        }
    }
    foreach ($prof in $profiles) {
        $profPath = $prof.ProfileImagePath
        if ([string]::IsNullOrWhiteSpace($profPath)) { continue }
        foreach ($rel in $UserAppDirRel) {
            $dir  = Join-Path $profPath $rel
            $bins = @(Get-LiveBraveBinary -Dir $dir)
            if ($bins.Count -gt 0) {
                Add-Finding ("[FileSystem user] {0} ({1} Brave binaries)" -f $dir, $bins.Count)
            }
        }
    }

    #----------------------------------------------------------------------------
    # 4b. MSIX/Store Brave packages (Store wrapper), any user + provisioned.
    #----------------------------------------------------------------------------
    if (Get-Command -Name Get-AppxPackage -ErrorAction SilentlyContinue) {
        try {
            Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue |
                Where-Object { Test-IsBraveAppx -Name $_.Name -Publisher $_.Publisher } |
                ForEach-Object { Add-Finding "[Appx] $($_.PackageFullName)" }
        } catch { Write-Log "Get-AppxPackage error (MSIX not verified): $($_.Exception.Message)" 'WARN' }
    } else {
        Write-Log 'Get-AppxPackage unavailable in this host. MSIX state NOT verified.' 'WARN'
    }
    if (Get-Command -Name Get-AppxProvisionedPackage -ErrorAction SilentlyContinue) {
        try {
            Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -match '(?i)brave' -and
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
        Write-Log "RESULT: Brave removal NEEDED ($($details.Count) finding(s))" 'WARN'
        try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
        Write-Output "Brave removal needed: $summary"
        exit 1
    } else {
        Write-Log 'RESULT: no Brave products found. Device is clean.'
        try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
        Write-Output 'Brave clean: no Brave Browser installs found (machine or per-user).'
        exit 0
    }
}
catch {
    Write-Log "FATAL detection error: $($_.Exception.Message)" 'ERROR'
    try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
    Write-Output "Brave detection error (treating as found): $($_.Exception.Message)"
    exit 1
}
