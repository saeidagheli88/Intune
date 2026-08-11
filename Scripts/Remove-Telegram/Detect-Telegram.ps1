<#
.SYNOPSIS
    Detects ANY Telegram client on a Windows device -- management decision is
    FULL REMOVAL (no Telegram client is allowed to remain). Pairs with
    Remediate-Telegram.ps1 (keep the CONFIG block identical in both).

.DESCRIPTION
    Intune Remediation DETECTION script (READ-ONLY).

    SCOPE -- everything Telegram counts as a finding, machine-wide AND per-user:
      - Telegram Desktop (Inno Setup installer). Default install is PER-USER in
        <profile>\AppData\Roaming\Telegram Desktop with an HKU uninstall key;
        elevated installs land machine-wide in Program Files\Telegram Desktop
        with an HKLM uninstall key.
      - Telegram Desktop from the Microsoft Store (MSIX package
        TelegramMessengerLLP.TelegramDesktop), any user + provisioned copies.

    WHAT COUNTS AS A FINDING (exit 1):
      1. Any HKLM Uninstall entry (BOTH 64-bit and 32-bit registry views)
         classified as Telegram by Test-IsTelegram.
      2. Any per-user (HKU) Uninstall entry classified as Telegram -- every
         real profile is swept; logged-off NTUSER.DAT hives are temporarily
         'reg load'ed and ALWAYS unloaded in finally.
      3. A Telegram BINARY (Telegram.exe) still on disk in the known machine
         or per-profile install folders. Folder-only leftovers (no binary)
         are NOT findings, and a binary already queued in
         PendingFileRenameOperations (delete-on-reboot) is NOT a finding --
         loop-safety, same convention as the 7-Zip/Adobe/Webex pairs.
      4. Any Telegram MSIX package (installed for any user, or provisioned).

    NOT findings (remediation cleans them opportunistically, but they must not
    flap detection): user data (tdata lives inside the install folder),
    shortcuts, Run values, tg:// protocol Classes keys.

    KNOWN LIMITATION: PORTABLE copies (a bare Telegram.exe unzipped into
    Downloads/Desktop/etc.) are not chased -- sweeping entire profiles for
    arbitrary exes is too slow/invasive for a recurring detection. Known
    install locations only.

    CLASSIFIER SAFETY: name regex is anchored on the word 'telegram'; nothing
    in the standard Monster software catalog matches it.

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
# CONFIG -- keep IDENTICAL in Detect-Telegram.ps1 / Remediate-Telegram.ps1
#--------------------------------------------------------------------------------
# Strong name match: enough on its own (publisher may be blank on HKU keys).
$TelegramStrongName  = '(?i)^\s*telegram\b'
# Loose match: 'telegram' anywhere in the name, but ONLY with a Telegram publisher.
$TelegramLooseName   = '(?i)\btelegram\b'
# Binaries that gate a folder finding (folder-only leftovers are not findings).
$TelegramBinaryNames = @('Telegram.exe')
# Machine-wide install folders (all wholly Telegram-owned).
$MachineDirs = @(
    (Join-Path $env:ProgramFiles 'Telegram Desktop')
)
if (${env:ProgramFiles(x86)}) {
    $MachineDirs += (Join-Path ${env:ProgramFiles(x86)} 'Telegram Desktop')
}
# Per-profile APP folders (findings when a binary is inside). Roaming is the
# Telegram Desktop DEFAULT per-user install location (unusual, but real).
$UserAppDirRel = @('AppData\Roaming\Telegram Desktop',
                   'AppData\Local\Telegram Desktop',
                   'AppData\Local\Programs\Telegram Desktop')

function Test-IsTelegram {
    param([string]$Name, [string]$Publisher)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    if ($Name -match $TelegramStrongName) { return $true }
    return (($Publisher -match '(?i)telegram') -and ($Name -match $TelegramLooseName))
}

# MSIX/Store packages: package NAME containing 'telegram' (the official package
# is TelegramMessengerLLP.TelegramDesktop -- the vendor is in the name itself).
# Publisher on Store packages is a raw CN/GUID string, so it is NOT required;
# a Microsoft publisher is explicitly excluded as a safety net.
function Test-IsTelegramAppx {
    param([string]$Name, [string]$Publisher)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    if ($Publisher -match '(?i)CN=Microsoft') { return $false }
    return ($Name -match '(?i)telegram')
}

#--------------------------------------------------------------------------------
# 1. Durable logging under %ProgramData% (SYSTEM-safe; never %TEMP% as SYSTEM).
#--------------------------------------------------------------------------------
$LogDir = Join-Path $env:ProgramData 'Monster\Logs'
if (-not (Test-Path -LiteralPath $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}
$LogFile = Join-Path $LogDir ("Detect-Telegram_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
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

Write-Log "=== Telegram removal detection started on $env:COMPUTERNAME (64-bit host: $([Environment]::Is64BitProcess)) ==="

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
                    if (Test-IsTelegram -Name $name -Publisher $pub) {
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
                    if ($p -and (Test-IsTelegram -Name ([string]$p.DisplayName) -Publisher ([string]$p.Publisher))) {
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
    #    Binary-gated (a folder with no Telegram binary is NOT a finding) and
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
    foreach ($b in $TelegramBinaryNames) { [void]$binarySet.Add($b) }

    # Returns Telegram binaries under $Dir that are NOT queued for delete-on-reboot.
    function Get-LiveTelegramBinary {
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
        $bins = @(Get-LiveTelegramBinary -Dir $dir)
        if ($bins.Count -gt 0) {
            Add-Finding ("[FileSystem] {0} ({1} Telegram binaries, e.g. {2})" -f $dir, $bins.Count, (Split-Path $bins[0] -Leaf))
        }
    }
    foreach ($prof in $profiles) {
        $profPath = $prof.ProfileImagePath
        if ([string]::IsNullOrWhiteSpace($profPath)) { continue }
        foreach ($rel in $UserAppDirRel) {
            $dir  = Join-Path $profPath $rel
            $bins = @(Get-LiveTelegramBinary -Dir $dir)
            if ($bins.Count -gt 0) {
                Add-Finding ("[FileSystem user] {0} ({1} Telegram binaries)" -f $dir, $bins.Count)
            }
        }
    }

    #----------------------------------------------------------------------------
    # 4b. MSIX/Store Telegram packages, any user + provisioned copies that
    #     would come back on new profiles.
    #----------------------------------------------------------------------------
    if (Get-Command -Name Get-AppxPackage -ErrorAction SilentlyContinue) {
        try {
            Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue |
                Where-Object { Test-IsTelegramAppx -Name $_.Name -Publisher $_.Publisher } |
                ForEach-Object { Add-Finding "[Appx] $($_.PackageFullName)" }
        } catch { Write-Log "Get-AppxPackage error (MSIX not verified): $($_.Exception.Message)" 'WARN' }
    } else {
        Write-Log 'Get-AppxPackage unavailable in this host. MSIX state NOT verified.' 'WARN'
    }
    if (Get-Command -Name Get-AppxProvisionedPackage -ErrorAction SilentlyContinue) {
        try {
            Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -match '(?i)telegram' -and
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
        Write-Log "RESULT: Telegram removal NEEDED ($($details.Count) finding(s))" 'WARN'
        try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
        Write-Output "Telegram removal needed: $summary"
        exit 1
    } else {
        Write-Log 'RESULT: no Telegram products found. Device is clean.'
        try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
        Write-Output 'Telegram clean: no Telegram clients installed (machine, per-user, or Store).'
        exit 0
    }
}
catch {
    Write-Log "FATAL detection error: $($_.Exception.Message)" 'ERROR'
    try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
    Write-Output "Telegram detection error (treating as found): $($_.Exception.Message)"
    exit 1
}
