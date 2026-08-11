<#
.SYNOPSIS
    Detects OUTDATED Python that should be updated/removed, and whether the
    managed standard (python.org Python 3.14.6 machine-wide) is missing.

.DESCRIPTION
    Intune Remediation DETECTION script (READ-ONLY).

    GOAL: bring every device to a current, supported CPython and clear out the
    legacy/insecure versions -- WITHOUT disturbing data-science distributions or
    the user-managed Python tooling. Modelled on the Detect-7Zip.ps1 conventions
    (SYSTEM context, 64-bit relaunch guard, HKLM both-views + HKU per-user sweep,
    MSIX scan, durable transcript, single STDOUT summary line, idempotent gate).

    WHAT IS MANAGED (these drive the remediation gate):
      1. python.org TRADITIONAL installers -- the ARP "bundle" whose DisplayName is
         exactly  "Python X.Y.Z (64-bit|32-bit|arm64)"  and Publisher is
         "Python Software Foundation". FINDING when its version < target (3.14.6).
      2. Microsoft STORE runtimes -- MSIX packages named
         "PythonSoftwareFoundation.Python.3.NN". FINDING when NN < 14 (older than
         the target minor line).
      3. STANDARD-MISSING -- when install is enabled and, after we mentally remove
         the old ones, the device would have NO current Python at all. FINDING so
         the remediation installs the machine-wide standard.

    WHAT IS LEFT ALONE (flagged in the log for inventory, never a gate finding):
      * Anaconda / Miniconda (Publisher "Anaconda, Inc." or name contains
        Anaconda/Miniconda) -- removing these destroys users' conda environments.
      * PythonManager (Store app "PythonSoftwareFoundation.PythonManager") and the
        runtimes IT manages (DisplayName "Python X.Y.Z" WITHOUT a "(bitness)" suffix
        / DisplayVersion like "3.14-64") -- these self-update via PythonManager.
      * "Python Launcher" (py.exe) -- shared launcher, refreshed by the new install.
      * Legacy IDE tooling ("Python Tools for Visual Studio", "Python Editor").

    VERSION PARSING (important): the python.org ARP DisplayVersion is NOT the
    semantic version -- "3.14.150.0" is really 3.14.0 and "3.13.5150.0" is 3.13.5
    (third field = patch*1000 + 150). We therefore ALWAYS parse major.minor.patch
    from the DisplayName ("Python 3.14.0 (64-bit)"), never from DisplayVersion.

    BITNESS: like the 7-Zip pair, re-launches via %WINDIR%\Sysnative when started
    32-bit on 64-bit Windows (GUARDED on a real $PSCommandPath), and independently
    reads HKLM Uninstall through both Registry64 and Registry32. *** Deploy with
    "Run script in 64-bit PowerShell = Yes" *** so the Appx cmdlets work.

    EXIT CODES (Intune Remediation convention):
        exit 1 = at least one outdated Python found, OR the standard is missing
                 -> triggers remediation.
        exit 0 = compliant (only current/allowed Python present) -> no action.
    Any unexpected error also exits 1 so the device is remediated, not silently
    treated as compliant.

    OUTPUT: diagnostics go to Write-Host (transcript only, under
    C:\ProgramData\Monster\Logs). Exactly ONE Write-Output line is the STDOUT
    summary Intune captures (kept < 2048 chars).

.NOTES
    Author : Endpoint Engineering (Monster Energy)
    Target : Windows PowerShell 5.1, SYSTEM context
    Intune : Run using logged-on credentials = No (SYSTEM)
             Run script in 64-bit PowerShell = Yes (REQUIRED)
             Enforce script signature check  = No
    Read-only: transiently 'reg load's logged-off NTUSER.DAT hives and ALWAYS
               unloads them (with retry); orphaned mounts from a prior crash are
               cleaned at startup. No hive CONTENTS are modified.
#>

#--------------------------------------------------------------------------------
# 0. 64-bit self-relaunch guard (see Detect-7Zip.ps1 for full rationale).
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
    # Fall through: explicit dual-RegistryView reads below are host-bitness-safe.
}

$ErrorActionPreference = 'Stop'

#================================================================================
# CONFIG -- keep IN SYNC with Remediate-Python.ps1.
#================================================================================
# The managed standard. To move to a new patch later, change these three numbers
# in BOTH scripts (and the URL/hash block in the remediation).
$TargetVersion   = [version]'3.14.6'   # python.org bundles below this are "old".
$StoreTargetLine = [version]'3.14'     # Store runtimes below this minor are "old".

# When $true the device is non-compliant if it has NO current Python at all and
# the remediation will install the machine-wide standard. Set $false for a pure
# "remove old versions only" policy (you then deploy 3.14.6 as a separate app).
$InstallStandardPython = $true

#--------------------------------------------------------------------------------
# 1. Durable logging under %ProgramData%\Monster\Logs (writable by SYSTEM).
#--------------------------------------------------------------------------------
$LogDir = Join-Path $env:ProgramData 'Monster\Logs'
if (-not (Test-Path -LiteralPath $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}
$LogFile = Join-Path $LogDir ("Detect-Python_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
try { Start-Transcript -Path $LogFile -Append -ErrorAction SilentlyContinue | Out-Null } catch { }

# Write-Host -> transcript only (NOT Intune's captured STDOUT success stream).
function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    Write-Host ("[{0:yyyy-MM-dd HH:mm:ss}] [{1}] {2}" -f (Get-Date), $Level, $Msg)
}

#--------------------------------------------------------------------------------
# Classification helpers (mirrored EXACTLY in Remediate-Python.ps1).
#--------------------------------------------------------------------------------
$script:OrgPublisher = 'Python Software Foundation'

# Parse semantic major.minor.patch from a DisplayName like "Python 3.14.0 (64-bit)"
# or "Python 3.13.5 Core Interpreter (64-bit)". Returns [version] or $null.
function Get-PyNameVersion {
    param([string]$DisplayName)
    if ([string]::IsNullOrWhiteSpace($DisplayName)) { return $null }
    $m = [regex]::Match($DisplayName, 'Python\s+(\d+)\.(\d+)\.(\d+)')
    if (-not $m.Success) { return $null }
    try { return [version]("{0}.{1}.{2}" -f $m.Groups[1].Value, $m.Groups[2].Value, $m.Groups[3].Value) }
    catch { return $null }
}

# A traditional python.org ARP BUNDLE: Publisher is PSF AND the DisplayName ends
# with a bitness suffix "(64-bit)"/"(32-bit)"/"(arm64)". This deliberately EXCLUDES
# "Python Launcher", PythonManager runtimes ("Python 3.14.3" with no suffix), and
# Anaconda's "Python 3.6.5 (Anaconda3 ... 64-bit)" (different publisher).
function Test-IsOrgBundle {
    param($Entry)
    if (-not $Entry) { return $false }
    $name = [string]$Entry.DisplayName
    $pub  = [string]$Entry.Publisher
    if ($pub -ne $script:OrgPublisher) { return $false }
    return ($name -match '^Python\s+\d+\.\d+\.\d+\s+\((?:64-bit|32-bit|arm64)\)$')
}

# Orphaned python.org COMPONENT MSI (e.g. "Python 3.13.5 Core Interpreter (64-bit)",
# "... Standard Library ...", "... Executables ..."). PSF publisher, an MSI
# (WindowsInstaller=1), DisplayName carries a "Python X.Y.Z". Used only as a
# fallback sweep for components a removed bundle left behind.
function Test-IsOrgComponentMsi {
    param($Entry)
    if (-not $Entry) { return $false }
    $name = [string]$Entry.DisplayName
    $pub  = [string]$Entry.Publisher
    if ($pub -ne $script:OrgPublisher) { return $false }
    if ([string]::IsNullOrWhiteSpace($name)) { return $false }
    if ($name -eq 'Python Launcher') { return $false }
    if ($Entry.WindowsInstaller -ne 1) { return $false }
    return ($name -match '^Python\s+\d+\.\d+\.\d+' -and $name -match '\((?:64-bit|32-bit|arm64)\)')
}

# Anaconda / Miniconda -- inventory only, NEVER removed.
function Test-IsConda {
    param($Entry)
    if (-not $Entry) { return $false }
    $name = [string]$Entry.DisplayName
    $pub  = [string]$Entry.Publisher
    return ($pub -like '*Anaconda*' -or $name -like '*Anaconda*' -or $name -like '*Miniconda*')
}

# A Store runtime package name "PythonSoftwareFoundation.Python.3.NN". Returns the
# minor [version] (e.g. 3.13) or $null. PythonManager is intentionally NOT matched.
function Get-StoreRuntimeLine {
    param([string]$PkgName)
    if ([string]::IsNullOrWhiteSpace($PkgName)) { return $null }
    $m = [regex]::Match($PkgName, '^PythonSoftwareFoundation\.Python\.(\d+)\.(\d+)$')
    if (-not $m.Success) { return $null }
    try { return [version]("{0}.{1}" -f $m.Groups[1].Value, $m.Groups[2].Value) } catch { return $null }
}

#--------------------------------------------------------------------------------
# HKU helpers (identical pattern to the 7-Zip scripts).
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
    [gc]::Collect(); [gc]::WaitForPendingFinalizers()
    & reg.exe unload "HKU\$Sid" *> $null
    if ($LASTEXITCODE -ne 0) {
        Start-Sleep -Milliseconds 500
        [gc]::Collect(); [gc]::WaitForPendingFinalizers()
        & reg.exe unload "HKU\$Sid" *> $null
        if ($LASTEXITCODE -ne 0) {
            Write-Log "FAILED to unload HKU\$Sid (hive left mounted - may block that user's logon)." 'ERROR'
            return $false
        }
    }
    return $true
}

# Loaded HKU SIDs via .NET. The provider form (Get-ChildItem 'Registry::HKEY_USERS')
# can throw a TERMINATING "Invalid key name" on a corrupt child key that
# -ErrorAction SilentlyContinue does NOT suppress -- that abort was crashing the
# whole run on some AAD-joined devices. GetSubKeyNames() is fault-tolerant here.
function Get-LoadedUserSid {
    param([string]$Pattern)
    $out = New-Object System.Collections.Generic.List[string]
    try {
        $u = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users, [Microsoft.Win32.RegistryView]::Default)
        try { foreach ($n in $u.GetSubKeyNames()) { if ($n -match $Pattern) { [void]$out.Add($n) } } }
        finally { $u.Close() }
    } catch { Write-Log "HKU enumeration error (ignored): $($_.Exception.Message)" 'WARN' }
    return $out
}

# Findings tally (drive the gate) and inventory (log only).
$oldFindings    = [System.Collections.Generic.List[string]]::new()   # gate
$inventory      = [System.Collections.Generic.List[string]]::new()   # log only
$currentPresent = $false                                             # any usable Python?

function Add-Old {
    param([string]$Text)
    if (-not $script:oldFindings.Contains($Text)) { $script:oldFindings.Add($Text) }
    Write-Log "OUTDATED: $Text" 'WARN'
}
function Add-Inv {
    param([string]$Text)
    if (-not $script:inventory.Contains($Text)) { $script:inventory.Add($Text) }
    Write-Log "KEEP/INVENTORY: $Text"
}

# Evaluate one ARP entry (from HKLM or HKU). Classifies into old / current / inventory.
function Measure-ArpEntry {
    param($Entry, [string]$Scope)
    $name = [string]$Entry.DisplayName
    if ([string]::IsNullOrWhiteSpace($name)) { return }

    if (Test-IsConda $Entry)       { Add-Inv ("[{0}] (conda, left alone) {1}" -f $Scope, $name); $script:currentPresent = $true; return }
    if ($name -eq 'Python Launcher') { Add-Inv ("[{0}] Python Launcher (left alone)" -f $Scope); return }

    $isUserScope = ($Scope -like 'HKU:*')

    if (Test-IsOrgBundle $Entry) {
        $ver = Get-PyNameVersion $name
        if ($ver -and $ver -lt $TargetVersion) {
            # Per-user (HKU) installs are removed by the USER-CONTEXT companion, not
            # this SYSTEM pair (SYSTEM cannot cleanly uninstall a per-user MSI). Log
            # them but do NOT gate on them here, or the SYSTEM policy would flap.
            if ($isUserScope) { Add-Inv ("[{0}] old per-user python.org (user-context policy handles) {1}" -f $Scope, $name) }
            else              { Add-Old ("[{0}] {1}" -f $Scope, $name) }
        } else {
            Add-Inv ("[{0}] current python.org {1}" -f $Scope, $name)
            $script:currentPresent = $true
        }
        return
    }

    # Orphaned python.org COMPONENT MSI (bundle already gone) e.g. "Python 3.12.0
    # Standard Library (64-bit)". Gate on machine-wide (HKLM) ones so remediation
    # force-cleans them; per-user ones go to the companion. NEVER gate on the target
    # minor line (3.14.x shares its folder with 3.14.6).
    if (Test-IsOrgComponentMsi $Entry) {
        $ver = Get-PyNameVersion $name
        $isTargetLine = ($ver -and $ver.Major -eq $TargetVersion.Major -and $ver.Minor -eq $TargetVersion.Minor)
        if ($ver -and $ver -lt $TargetVersion -and -not $isTargetLine) {
            if ($isUserScope) { Add-Inv ("[{0}] old per-user component (user-context policy handles) {1}" -f $Scope, $name) }
            else              { Add-Old ("[{0}] {1} (orphaned component)" -f $Scope, $name) }
        }
        return
    }

    # PythonManager-managed runtime: PSF publisher, "Python X.Y.Z" with NO bitness
    # suffix (DisplayVersion often "3.14-64"). Left to PythonManager; counts as a
    # usable Python when >= target minor line.
    if (([string]$Entry.Publisher) -eq $script:OrgPublisher -and $name -match '^Python\s+\d+\.\d+\.\d+$') {
        $ver = Get-PyNameVersion $name
        Add-Inv ("[{0}] PythonManager runtime (left alone) {1}" -f $Scope, $name)
        if ($ver -and $ver.Major -gt 3) { $script:currentPresent = $true }
        elseif ($ver -and $ver.Major -eq $StoreTargetLine.Major -and $ver.Minor -ge $StoreTargetLine.Minor) { $script:currentPresent = $true }
        return
    }

    # Legacy IDE tooling / anything else Python-ish -- inventory only.
    if ($name -like 'Python Tools*' -or $name -eq 'Python Editor') {
        Add-Inv ("[{0}] legacy IDE tool (left alone) {1}" -f $Scope, $name)
    }
}

Write-Log "=== Python Detection started on $env:COMPUTERNAME (64-bit host: $([Environment]::Is64BitProcess)) | target $TargetVersion | install=$InstallStandardPython ==="

try {
    $sidPattern = 'S-1-5-21-\d+-\d+-\d+-\d+$'

    #----------------------------------------------------------------------------
    # Pre-pass: clean orphaned HKU mounts from a prior crashed run. Wrapped so a
    # single bad key can never abort detection (previously surfaced as the
    # "Invalid key name" fatal on some devices).
    #----------------------------------------------------------------------------
    try {
        $activeSids = Get-ActiveUserSid
        foreach ($lsid in (Get-LoadedUserSid -Pattern $sidPattern)) {
            if (-not $activeSids.Contains($lsid)) {
                Write-Log "Orphaned HKU mount detected for $lsid (no active session). Cleaning." 'WARN'
                if (Invoke-RegUnload -Sid $lsid) { Write-Log "Unloaded orphaned hive HKU\$lsid." }
            }
        }
    } catch { Write-Log "Pre-pass orphan cleanup error (ignored): $($_.Exception.Message)" 'WARN' }
    $loadedSids = Get-LoadedUserSid -Pattern $sidPattern

    #----------------------------------------------------------------------------
    # 2. HKLM Uninstall keys -- explicit 64-bit AND 32-bit views.
    #----------------------------------------------------------------------------
    foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64,
                        [Microsoft.Win32.RegistryView]::Registry32)) {
        $base = $null
        try {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
            $uninstall = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
            if ($uninstall) {
                foreach ($subName in $uninstall.GetSubKeyNames()) {
                    $sub = $uninstall.OpenSubKey($subName); if (-not $sub) { continue }
                    $entry = [pscustomobject]@{
                        DisplayName      = $sub.GetValue('DisplayName')
                        DisplayVersion   = $sub.GetValue('DisplayVersion')
                        Publisher        = $sub.GetValue('Publisher')
                        WindowsInstaller = $sub.GetValue('WindowsInstaller')
                    }
                    Measure-ArpEntry -Entry $entry -Scope "HKLM $view"
                    $sub.Close()
                }
                $uninstall.Close()
            }
        } catch {
            Write-Log "HKLM $view scan error: $($_.Exception.Message)" 'WARN'
        } finally { if ($base) { $base.Close() } }
    }

    #----------------------------------------------------------------------------
    # 3. Per-user Uninstall keys across every profile (loaded + temporarily loaded).
    #    Catches per-user python.org installs AND PythonManager runtimes.
    #----------------------------------------------------------------------------
    $profiles = @()
    try {
        $profiles = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' `
                        -ErrorAction SilentlyContinue |
                    Where-Object { $_.PSChildName -match $sidPattern }
    } catch { Write-Log "ProfileList enumeration error (ignored): $($_.Exception.Message)" 'WARN' }

    function Search-UserUninstall {
        param([string]$HiveRoot, [string]$Scope)
        foreach ($node in @('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                             'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
            $path = "Registry::$HiveRoot\$node"
            if (-not (Test-Path -LiteralPath $path)) { continue }
            Get-ChildItem -LiteralPath $path -ErrorAction SilentlyContinue | ForEach-Object {
                $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
                Measure-ArpEntry -Entry $p -Scope $Scope
            }
        }
    }

    foreach ($prof in $profiles) {
        $sid      = $prof.PSChildName
        $profPath = $prof.ProfileImagePath
        $didLoad  = $false
        $hiveRoot = "HKEY_USERS\$sid"
        try {
            if ($loadedSids -notcontains $sid) {
                $ntuser = Join-Path $profPath 'NTUSER.DAT'
                if (-not (Test-Path -LiteralPath $ntuser)) { continue }
                & reg.exe load "HKU\$sid" $ntuser *> $null
                if ($LASTEXITCODE -ne 0) { Write-Log "Could not load hive for $profPath" 'WARN'; continue }
                $didLoad = $true
                Write-Log "Loaded offline hive: $profPath"
            }
            Search-UserUninstall -HiveRoot $hiveRoot -Scope "HKU:$sid"
        } catch {
            Write-Log "User hive scan error ($sid): $($_.Exception.Message)" 'WARN'
        } finally {
            if ($didLoad) { [void](Invoke-RegUnload -Sid $sid) }
        }
    }

    #----------------------------------------------------------------------------
    # 4. MSIX / Appx. Store runtimes "PythonSoftwareFoundation.Python.3.NN" with
    #    NN < target minor are old; PythonManager is kept (counts as usable Python).
    #----------------------------------------------------------------------------
    $appxCmd = Get-Command -Name Get-AppxPackage -ErrorAction SilentlyContinue
    if (-not $appxCmd) {
        Write-Log "Get-AppxPackage unavailable in this host (possibly 32-bit/SYSTEM). Store state NOT verified." 'WARN'
    } else {
        try {
            Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -like 'PythonSoftwareFoundation.*' } |
                ForEach-Object {
                    $nm = [string]$_.Name
                    if ($nm -eq 'PythonSoftwareFoundation.PythonManager') {
                        Add-Inv "[Store] PythonManager (kept) $($_.PackageFullName)"
                        $script:currentPresent = $true
                        return
                    }
                    $line = Get-StoreRuntimeLine $nm
                    if ($line) {
                        if ($line -lt $StoreTargetLine) {
                            Add-Old "[Store] $($_.PackageFullName)"
                        } else {
                            Add-Inv "[Store] current runtime (kept) $($_.PackageFullName)"
                            $script:currentPresent = $true
                        }
                    }
                }
        } catch { Write-Log "Get-AppxPackage scan error: $($_.Exception.Message)" 'WARN' }
    }

    #----------------------------------------------------------------------------
    # 5. Decide the gate.
    #----------------------------------------------------------------------------
    $needInstall = $false
    if ($InstallStandardPython -and -not $currentPresent) {
        $needInstall = $true
        Add-Old "[Standard] No current Python present -> machine-wide $TargetVersion will be installed"
    }

    $reasons = [System.Collections.Generic.List[string]]::new()
    if ($oldFindings.Count -gt 0) { $reasons.Add("$($oldFindings.Count) outdated/standard finding(s)") }

    if ($oldFindings.Count -gt 0 -or $needInstall) {
        $summary = ($oldFindings -join ' | ')
        if ($summary.Length -gt 1800) { $summary = $summary.Substring(0, 1800) + ' ...(truncated)' }
        Write-Log "RESULT: NON-COMPLIANT ($($oldFindings.Count) item(s); currentPython=$currentPresent)" 'WARN'
        try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
        Write-Output "Python update needed: $summary"
        exit 1
    } else {
        Write-Log "RESULT: COMPLIANT. Only current/allowed Python present. Inventory items: $($inventory.Count)."
        try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
        Write-Output "Python compliant (target $TargetVersion). No outdated versions."
        exit 0
    }
}
catch {
    Write-Log "FATAL detection error: $($_.Exception.Message)" 'ERROR'
    try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
    Write-Output "Python detection error (treating as needed): $($_.Exception.Message)"
    exit 1
}
