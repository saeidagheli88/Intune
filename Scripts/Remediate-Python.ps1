<#
.SYNOPSIS
    Updates devices to the managed standard Python (python.org 3.14.6, machine-wide)
    and removes OUTDATED Python -- without touching Anaconda/Miniconda, PythonManager,
    or the user-managed runtimes/launcher.

.DESCRIPTION
    Intune Remediation REMEDIATION script. Companion to Detect-Python.ps1; uses the
    same classification so the two cannot diverge. Modelled on Remediate-7Zip.ps1.

    Handles, in order:
      1. python.org TRADITIONAL bundles ("Python X.Y.Z (64-bit)") older than the
         target. These are WiX "burn" bundles, NOT plain MSIs: uninstall via the
         registry QuietUninstallString (which already carries "/uninstall /quiet"),
         else UninstallString + " /uninstall /quiet /norestart". Success is
         confirmed by the originating ARP/bundle key disappearing.
      2. Per-user python.org bundles -- every loaded HKU hive AND temporarily loaded
         logged-off NTUSER.DAT hives, removed from the CORRECT HKU\<SID> hive.
      3. Orphaned python.org COMPONENT MSIs left behind by a half-removed bundle --
         msiexec /x {GUID} /qn /norestart, gated to PSF publisher + version < target.
      4. Microsoft STORE runtimes "PythonSoftwareFoundation.Python.3.NN" (NN < 14)
         via Remove-AppxPackage -AllUsers (per-user fallback). PythonManager is KEPT.
      5. INSTALL the machine-wide standard (3.14.6) IF enabled AND the device has no
         current Python left. The official installer is downloaded, verified by
         SHA-256 (if pinned) AND Authenticode (signer "Python Software Foundation"),
         then run silently for all users.

    LEFT ALONE (never removed -- see Detect-Python.ps1):
      Anaconda/Miniconda, PythonManager + its runtimes, "Python Launcher", and
      legacy IDE tooling. The new install refreshes the shared launcher in place.

    PROCESSES: this script does NOT kill running python.exe -- that would disrupt
    users' scripts/services. The python.org un/installers do not require it. If an
    uninstall fails because files are in use, it is reported and retried next cycle.

    SAFETY / IDEMPOTENCY:
      * Every delete is existence-checked; a second run on a compliant device is a
        no-op -> exit 0. Win32_Product is never used.
      * Every loaded hive is ALWAYS unloaded in finally (GC + retry + ERROR log);
        orphaned mounts from a prior crash are cleaned at startup.
      * Version is parsed from the DisplayName ("Python 3.14.0 (64-bit)"), never the
        4-part DisplayVersion ("3.14.150.0" actually means 3.14.0).

    BITNESS: self-relaunches via %WINDIR%\Sysnative when started 32-bit on 64-bit
    Windows (GUARDED on a real $PSCommandPath); reads HKLM via both RegistryView
    Registry64/Registry32. *** Deploy with "Run script in 64-bit PowerShell = Yes". ***

    EXIT CODES:
        exit 0 = remediation succeeded / nothing left to do (device compliant).
        exit 1 = a removal/install failed or outdated Python still present.

    OUTPUT: diagnostics -> Write-Host (transcript). Exactly ONE Write-Output is the
    STDOUT summary Intune captures.

.NOTES
    Author : Endpoint Engineering (Monster Energy)
    Target : Windows PowerShell 5.1, SYSTEM context
    Intune : Run using logged-on credentials = No (SYSTEM)
             Run script in 64-bit PowerShell = Yes (REQUIRED)
             Enforce script signature check  = No
    NETWORK: installing the standard requires the device to reach
    https://www.python.org/ftp/python/... If your fleet has no SYSTEM-context
    internet egress, set $InstallStandardPython = $false here AND in detection and
    deploy 3.14.6 as a separate Intune Win32/Store app (this pair then only removes
    old versions). See DEPLOYMENT.md.
#>

#--------------------------------------------------------------------------------
# 0. 64-bit self-relaunch guard.
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

#================================================================================
# CONFIG -- keep IN SYNC with Detect-Python.ps1.
#================================================================================
$TargetVersion   = [version]'3.14.6'
$StoreTargetLine = [version]'3.14'
$InstallStandardPython = $false   # 3.14.6 is delivered by the Win32 app; this pair is remove-only.

# Official installer download. To move to a new patch: bump $TargetVersion above,
# update the URLs, and replace the SHA-256 from
# https://www.python.org/downloads/release/python-3XYZ/  (leave a hash '' to skip
# the pin and rely on Authenticode alone). Authenticode is ALWAYS verified.
$DownloadConfig = @{
    amd64 = @{
        Url    = 'https://www.python.org/ftp/python/3.14.6/python-3.14.6-amd64.exe'
        Sha256 = '14b3e9a710a3fcf0bd9b55ab6b60412bd91227563f813fc49040cabc0209e0bd'
    }
    arm64 = @{
        Url    = 'https://www.python.org/ftp/python/3.14.6/python-3.14.6-arm64.exe'
        Sha256 = '517412448c44f0583c994723640e208ca82723e340b0cb6a667696ba2eea63fc'
    }
}
# Machine-wide silent install. PrependPath puts python/py on PATH for all users.
$InstallArgs = '/quiet InstallAllUsers=1 PrependPath=1 Include_launcher=1 InstallLauncherAllUsers=1 Include_test=0 AssociateFiles=1 Shortcuts=1 Include_pip=1 CompileAll=1'

# This SYSTEM pair owns MACHINE-WIDE (HKLM) + Store(all-users) Python only. Per-user
# ("install for just me", HKU) installs cannot be cleanly removed by SYSTEM, so they
# are delegated to the USER-CONTEXT companion (Detect/Remediate-Python-User.ps1).
# Leave $false unless you have no user-context policy and want a best-effort attempt.
$HandlePerUserFromSystem = $false

# When msiexec cannot remove an ORPHANED component MSI (bundle gone -> cached source
# missing), force-remove that version's install folder + ARP keys under strict
# guards. This is what clears the "Failed: N / Residual: ...component..." devices.
$ForceCleanOrphans = $true

#--------------------------------------------------------------------------------
# 1. Durable logging under %ProgramData%\Monster\Logs.
#--------------------------------------------------------------------------------
$LogDir = Join-Path $env:ProgramData 'Monster\Logs'
if (-not (Test-Path -LiteralPath $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}
$LogFile = Join-Path $LogDir ("Remediate-Python_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
try { Start-Transcript -Path $LogFile -Append -ErrorAction SilentlyContinue | Out-Null } catch { }

function Write-Log {
    param([string]$Msg, [string]$Level = 'INFO')
    Write-Host ("[{0:yyyy-MM-dd HH:mm:ss}] [{1}] {2}" -f (Get-Date), $Level, $Msg)
}

$successCount = 0
$failCount    = 0
$processed    = @{}

#--------------------------------------------------------------------------------
# Classification helpers (MIRROR Detect-Python.ps1 exactly).
#--------------------------------------------------------------------------------
$script:OrgPublisher   = 'Python Software Foundation'
$script:GuidUnanchored = '\{[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}'

function Get-PyNameVersion {
    param([string]$DisplayName)
    if ([string]::IsNullOrWhiteSpace($DisplayName)) { return $null }
    $m = [regex]::Match($DisplayName, 'Python\s+(\d+)\.(\d+)\.(\d+)')
    if (-not $m.Success) { return $null }
    try { return [version]("{0}.{1}.{2}" -f $m.Groups[1].Value, $m.Groups[2].Value, $m.Groups[3].Value) }
    catch { return $null }
}
function Test-IsOrgBundle {
    param($Entry)
    if (-not $Entry) { return $false }
    $name = [string]$Entry.DisplayName
    if (([string]$Entry.Publisher) -ne $script:OrgPublisher) { return $false }
    return ($name -match '^Python\s+\d+\.\d+\.\d+\s+\((?:64-bit|32-bit|arm64)\)$')
}
function Test-IsOrgComponentMsi {
    param($Entry)
    if (-not $Entry) { return $false }
    $name = [string]$Entry.DisplayName
    if (([string]$Entry.Publisher) -ne $script:OrgPublisher) { return $false }
    if ([string]::IsNullOrWhiteSpace($name)) { return $false }
    if ($name -eq 'Python Launcher') { return $false }
    if ($Entry.WindowsInstaller -ne 1) { return $false }
    return ($name -match '^Python\s+\d+\.\d+\.\d+' -and $name -match '\((?:64-bit|32-bit|arm64)\)')
}
function Test-IsConda {
    param($Entry)
    if (-not $Entry) { return $false }
    $name = [string]$Entry.DisplayName
    return ((([string]$Entry.Publisher) -like '*Anaconda*') -or $name -like '*Anaconda*' -or $name -like '*Miniconda*')
}
function Get-StoreRuntimeLine {
    param([string]$PkgName)
    if ([string]::IsNullOrWhiteSpace($PkgName)) { return $null }
    $m = [regex]::Match($PkgName, '^PythonSoftwareFoundation\.Python\.(\d+)\.(\d+)$')
    if (-not $m.Success) { return $null }
    try { return [version]("{0}.{1}" -f $m.Groups[1].Value, $m.Groups[2].Value) } catch { return $null }
}

#--------------------------------------------------------------------------------
# HKU helpers (identical to the 7-Zip scripts).
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
# Run reg.exe with EAP temporarily 'Continue' -- under 'Stop', PS 5.1 turns
# reg.exe's redirected stderr into a TERMINATING NativeCommandError (fatal
# "ERROR: Invalid key name." / "ERROR: The parameter is incorrect." in the field).
function Invoke-RegExe {
    param([string[]]$RegArgs)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & reg.exe @RegArgs 2>&1 | Out-Null; return $LASTEXITCODE }
    catch { return 1 }
    finally { $ErrorActionPreference = $prev }
}

function Invoke-RegUnload {
    param([string]$Sid)
    [gc]::Collect(); [gc]::WaitForPendingFinalizers()
    if ((Invoke-RegExe @('unload', "HKU\$Sid")) -ne 0) {
        Start-Sleep -Milliseconds 500
        [gc]::Collect(); [gc]::WaitForPendingFinalizers()
        if ((Invoke-RegExe @('unload', "HKU\$Sid")) -ne 0) {
            Write-Log "FAILED to unload HKU\$Sid (hive left mounted - may block that user's logon)." 'ERROR'
            return $false
        }
    }
    return $true
}

# Loaded HKU SIDs via .NET (provider enumeration can throw a terminating
# "Invalid key name" on a corrupt child key that -EA cannot suppress).
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

# Does an ARP/bundle key still exist? Confirms a successful uninstall.
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
# Uninstall one OUTDATED python.org bundle (burn) or component MSI. Returns $true
# on success (confirmed by the originating ARP key being gone).
#--------------------------------------------------------------------------------
function Invoke-PythonUninstall {
    param(
        [string]$DisplayName, [string]$UninstallString, [string]$QuietUninstallString,
        [object]$WindowsInstaller, [string]$KeyName, [string]$Scope,
        [string]$HiveRoot, [string]$View, [bool]$IsComponentMsi
    )
    $dedupKey = "$Scope|$DisplayName|$KeyName"
    if ($processed[$dedupKey]) { Write-Log "Already handled '$dedupKey' -- skipping."; return $true }
    $processed[$dedupKey] = $true

    Write-Log "Removing [$Scope] $DisplayName"

    try {
        # ---- Component MSI (orphan fallback) -> msiexec /x {GUID} ----
        if ($IsComponentMsi -or ($WindowsInstaller -eq 1 -and $KeyName -match $script:GuidUnanchored)) {
            $guidMatch = [regex]::Match("$KeyName $UninstallString $QuietUninstallString", $script:GuidUnanchored)
            if (-not $guidMatch.Success) { Write-Log "MSI entry but no GUID found -- skipping." 'WARN'; return $false }
            $guid = $guidMatch.Value
            Write-Log "MSI uninstall: msiexec /x $guid /qn /norestart REBOOT=ReallySuppress"
            $p = Start-Process -FilePath 'msiexec.exe' `
                    -ArgumentList "/x $guid /qn /norestart REBOOT=ReallySuppress" `
                    -Wait -PassThru -WindowStyle Hidden
            Write-Log "msiexec exit code: $($p.ExitCode)"
            return ($p.ExitCode -in @(0, 1605, 1641, 3010))
        }

        # ---- python.org burn BUNDLE ----
        $exe = $null; $bargs = $null
        if (-not [string]::IsNullOrWhiteSpace($QuietUninstallString)) {
            # QuietUninstallString already includes "/uninstall /quiet". Parse exe + args.
            if ($QuietUninstallString -match '^\s*"([^"]+)"\s*(.*)$') {
                $exe = $Matches[1]; $bargs = $Matches[2].Trim()
            } else {
                $m = [regex]::Match($QuietUninstallString.Trim(), '^(?<exe>.+?\.exe)(?<rest>\s+.*)?$', 'IgnoreCase')
                if ($m.Success) { $exe = $m.Groups['exe'].Value.Trim().Trim('"'); $bargs = $m.Groups['rest'].Value.Trim() }
            }
        }
        if ([string]::IsNullOrWhiteSpace($exe)) {
            # Fall back to UninstallString + explicit silent switches.
            if ([string]::IsNullOrWhiteSpace($UninstallString)) {
                Write-Log "No usable Uninstall string for '$DisplayName'." 'WARN'; return $false
            }
            if ($UninstallString -match '^\s*"([^"]+)"\s*(.*)$') {
                $exe = $Matches[1]; $bargs = $Matches[2].Trim()
            } else {
                $exe = $UninstallString.Trim().Trim('"'); $bargs = ''
            }
        }
        # Ensure the silent uninstall switches are present (burn engine).
        if ($bargs -notmatch '(?i)/uninstall') { $bargs = ("$bargs /uninstall").Trim() }
        if ($bargs -notmatch '(?i)/quiet')     { $bargs = ("$bargs /quiet").Trim() }
        if ($bargs -notmatch '(?i)/norestart') { $bargs = ("$bargs /norestart").Trim() }

        if (-not (Test-Path -LiteralPath $exe)) {
            # Cached installer gone. Only "already removed" if the ARP key is ALSO
            # gone; otherwise it is an orphan key that would loop. Report accordingly.
            Write-Log "Bundle uninstaller not found at '$exe'." 'WARN'
            if (Test-UninstallKey -HiveRoot $HiveRoot -View $View -KeyName $KeyName) {
                Write-Log "Orphan ARP key '$KeyName' present but uninstaller missing -- cannot remove cleanly." 'WARN'
                return $false
            }
            return $true
        }

        Write-Log "Bundle uninstall: `"$exe`" $bargs"
        $p = Start-Process -FilePath $exe -ArgumentList $bargs -Wait -PassThru -WindowStyle Hidden
        Write-Log "Bundle exit code: $($p.ExitCode)"
        # burn: 0 ok, 3010/1641 reboot, 1605 not installed.
        $okCode = ($p.ExitCode -in @(0, 1605, 1641, 3010))

        # Authoritative success = ARP key gone (poll briefly; burn can return early).
        $waited = 0
        while ((Test-UninstallKey -HiveRoot $HiveRoot -View $View -KeyName $KeyName) -and $waited -lt 60) {
            Start-Sleep -Seconds 3; $waited += 3
        }
        if (-not (Test-UninstallKey -HiveRoot $HiveRoot -View $View -KeyName $KeyName)) {
            Write-Log "Uninstall confirmed ($DisplayName, ARP key gone after ${waited}s)."
            return $true
        }
        # Exit code looked OK but the ARP key lingers (burn can return before it
        # finishes). Report failure so this device is retried next cycle rather than
        # falsely marked done; if it had truly finished the key would be gone.
        Write-Log "ARP key '$KeyName' still present after ${waited}s (exit $($p.ExitCode); okCode=$okCode)." 'WARN'
        return $false
    }
    catch {
        Write-Log "Uninstall threw for '$DisplayName': $($_.Exception.Message)" 'ERROR'
        return $false
    }
}

function Invoke-EntryRemoval {
    param([hashtable]$E)
    $ok = Invoke-PythonUninstall @E
    if ($ok) { $script:successCount++ } else { $script:failCount++ }
}

#--------------------------------------------------------------------------------
# Install the machine-wide standard. Download -> verify (SHA256 + Authenticode)
# -> silent install -> confirm. Returns $true on confirmed install.
#--------------------------------------------------------------------------------
function Install-StandardPython {
    $arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') { 'arm64' } else { 'amd64' }
    $cfg  = $DownloadConfig[$arch]
    if (-not $cfg) { Write-Log "No download config for arch '$arch'." 'ERROR'; return $false }

    $dlDir = Join-Path $env:ProgramData 'Monster\PythonInstaller'
    if (-not (Test-Path -LiteralPath $dlDir)) { New-Item -ItemType Directory -Path $dlDir -Force | Out-Null }
    $file = Join-Path $dlDir (Split-Path -Leaf $cfg.Url)

    try {
        Write-Log "Downloading standard Python ($arch): $($cfg.Url)"
        try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $cfg.Url -OutFile $file -UseBasicParsing -ErrorAction Stop
    } catch {
        Write-Log "Download failed: $($_.Exception.Message)" 'ERROR'; return $false
    }
    if (-not (Test-Path -LiteralPath $file)) { Write-Log "Installer not present after download." 'ERROR'; return $false }

    # SHA-256 pin (skipped only if the config hash is intentionally blank).
    if (-not [string]::IsNullOrWhiteSpace($cfg.Sha256)) {
        $actual = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
        if ($actual -ne $cfg.Sha256.ToUpper() -and $actual -ne $cfg.Sha256) {
            Write-Log "SHA-256 MISMATCH. Expected $($cfg.Sha256), got $actual. Aborting install." 'ERROR'
            Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
            return $false
        }
        Write-Log "SHA-256 verified."
    } else {
        Write-Log "No SHA-256 pin configured; relying on Authenticode only." 'WARN'
    }

    # Authenticode: must be a valid signature from the Python Software Foundation.
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $file
        $signer = [string]$sig.SignerCertificate.Subject
        if ($sig.Status -ne 'Valid' -or $signer -notlike '*Python Software Foundation*') {
            Write-Log "Authenticode check FAILED (Status=$($sig.Status); Signer='$signer'). Aborting install." 'ERROR'
            Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
            return $false
        }
        Write-Log "Authenticode verified (signer: $signer)."
    } catch {
        Write-Log "Authenticode verification error: $($_.Exception.Message). Aborting install." 'ERROR'
        Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
        return $false
    }

    try {
        Write-Log "Installing: `"$file`" $InstallArgs"
        $p = Start-Process -FilePath $file -ArgumentList $InstallArgs -Wait -PassThru -WindowStyle Hidden
        Write-Log "Installer exit code: $($p.ExitCode)"
        $ok = ($p.ExitCode -in @(0, 1641, 3010))
        if (-not $ok) { Write-Log "Installer returned non-success exit $($p.ExitCode)." 'ERROR' }
        return $ok
    } catch {
        Write-Log "Install threw: $($_.Exception.Message)" 'ERROR'; return $false
    } finally {
        Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
    }
}

# Scan HKLM (both views) for a python.org bundle >= target. Used to confirm the
# standard is present (before deciding to install, and to verify afterwards).
function Test-CurrentOrgBundlePresent {
    foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64,
                        [Microsoft.Win32.RegistryView]::Registry32)) {
        $base = $null
        try {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
            $u = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
            if ($u) {
                foreach ($sn in $u.GetSubKeyNames()) {
                    $s = $u.OpenSubKey($sn); if (-not $s) { continue }
                    $e = [pscustomobject]@{ DisplayName=$s.GetValue('DisplayName'); Publisher=$s.GetValue('Publisher') }
                    $s.Close()
                    if (Test-IsOrgBundle $e) {
                        $v = Get-PyNameVersion ([string]$e.DisplayName)
                        if ($v -and $v -ge $TargetVersion) { $u.Close(); return $true }
                    }
                }
                $u.Close()
            }
        } catch { } finally { if ($base) { $base.Close() } }
    }
    return $false
}

#--------------------------------------------------------------------------------
# Force-clean OLD machine-wide python.org that msiexec could NOT remove -- the
# classic orphaned-component case (bundle gone -> cached MSI source gone ->
# msiexec /x fails with a source-unavailable code). Deletes the version line's
# install folder + its ARP keys (HKLM, both views) under STRICT guards:
#   * only entries our own classifier flags as old python.org bundle/component,
#   * folder leaf MUST match ^Python\d{2,3}(-32)?$,
#   * NEVER the target minor line (3.14.x shares its folder with the kept 3.14.6).
# Per-user (HKU) is out of scope here -- the user-context companion handles it.
# Returns @{Cleaned=..; Failed=..}. Runs AFTER msiexec attempts, so it only ever
# touches what msiexec left behind.
function Invoke-OrphanForceClean {
    $cleaned = 0; $failed = 0
    $leafOk       = '^Python\d{2,3}(-32)?$'
    $targetTag    = ('Python{0}{1}' -f $TargetVersion.Major, $TargetVersion.Minor)   # e.g. Python314
    $verSet       = New-Object System.Collections.Generic.HashSet[string]           # minor lines cleaned, e.g. '3.12'
    foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64,
                        [Microsoft.Win32.RegistryView]::Registry32)) {
        $base = $null
        try {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
            $u = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', $true)  # writable
            if (-not $u) { continue }
            $folders = New-Object System.Collections.Generic.HashSet[string]
            $keys    = New-Object System.Collections.Generic.List[string]
            foreach ($sn in $u.GetSubKeyNames()) {
                $s = $u.OpenSubKey($sn); if (-not $s) { continue }
                $e = [pscustomobject]@{
                    DisplayName      = $s.GetValue('DisplayName')
                    Publisher        = $s.GetValue('Publisher')
                    WindowsInstaller = $s.GetValue('WindowsInstaller')
                    InstallLocation  = $s.GetValue('InstallLocation')
                }
                $s.Close()
                if (Test-IsConda $e) { continue }
                $v = Get-PyNameVersion ([string]$e.DisplayName)
                if (-not $v) { continue }
                $isOld = (((Test-IsOrgBundle $e) -or (Test-IsOrgComponentMsi $e)) -and ($v -lt $TargetVersion))
                if (-not $isOld) { continue }
                # Protect the target minor line (its folder holds the kept 3.14.6).
                if ($v.Major -eq $TargetVersion.Major -and $v.Minor -eq $TargetVersion.Minor) { continue }
                [void]$keys.Add($sn)
                [void]$verSet.Add(("{0}.{1}" -f $v.Major, $v.Minor))
                $tag = ('Python{0}{1}' -f $v.Major, $v.Minor)
                $cands = @(
                    (Join-Path $env:ProgramFiles $tag),
                    (Join-Path $env:ProgramFiles "$tag-32")
                )
                if (${env:ProgramFiles(x86)}) {
                    $cands += (Join-Path ${env:ProgramFiles(x86)} "$tag-32")
                    $cands += (Join-Path ${env:ProgramFiles(x86)} $tag)
                }
                $il = [string]$e.InstallLocation
                if (-not [string]::IsNullOrWhiteSpace($il)) { $cands += $il.TrimEnd('\') }
                foreach ($c in $cands) { if ($c) { [void]$folders.Add($c) } }
            }

            foreach ($f in $folders) {
                if ([string]::IsNullOrWhiteSpace($f) -or -not (Test-Path -LiteralPath $f)) { continue }
                $leaf = Split-Path -Leaf $f
                if ($leaf -notmatch $leafOk)      { Write-Log "Force-clean SKIP (leaf not allow-listed): $f" 'WARN'; continue }
                if ($leaf -match "^$targetTag(-32)?$") { continue }   # never the kept 3.14 folder
                try { Remove-Item -LiteralPath $f -Recurse -Force -ErrorAction Stop; Write-Log "Force-removed folder: $f"; $cleaned++ }
                catch { Write-Log "Force-remove folder failed ($f): $($_.Exception.Message)" 'WARN'; $failed++ }
            }

            # Re-validate each key against our classifier immediately before deleting.
            foreach ($kn in $keys) {
                try {
                    $chk = $u.OpenSubKey($kn); if (-not $chk) { continue }
                    $ee = [pscustomobject]@{ DisplayName=$chk.GetValue('DisplayName'); Publisher=$chk.GetValue('Publisher'); WindowsInstaller=$chk.GetValue('WindowsInstaller') }
                    $chk.Close()
                    if (-not (Test-IsConda $ee) -and ((Test-IsOrgBundle $ee) -or (Test-IsOrgComponentMsi $ee))) {
                        $u.DeleteSubKeyTree($kn, $false)
                        Write-Log "Force-removed ARP key: [$view] $kn ($($ee.DisplayName))"
                    }
                } catch { Write-Log "Force-remove ARP key failed ($kn): $($_.Exception.Message)" 'WARN' }
            }
            $u.Close()
        } catch { Write-Log "Orphan force-clean error ($view): $($_.Exception.Message)" 'WARN' }
        finally { if ($base) { $base.Close() } }
    }

    # All-users Start Menu groups for the removed lines ("Python 3.X" under
    # ProgramData). Only .lnk files whose target no longer exists are deleted --
    # users otherwise hit "Problem with Shortcut" on dead pythonw.exe links -- and
    # the group folder itself only when left empty. The target line is never touched.
    $shell = $null
    try { $shell = New-Object -ComObject WScript.Shell } catch { }
    foreach ($mm in $verSet) {
        if ($mm -eq ("{0}.{1}" -f $TargetVersion.Major, $TargetVersion.Minor)) { continue }
        $grp = Join-Path $env:ProgramData ("Microsoft\Windows\Start Menu\Programs\Python " + $mm)
        if (-not (Test-Path -LiteralPath $grp)) { continue }
        Get-ChildItem -LiteralPath $grp -Filter '*.lnk' -ErrorAction SilentlyContinue | ForEach-Object {
            $target = $null
            if ($shell) { try { $target = $shell.CreateShortcut($_.FullName).TargetPath } catch { } }
            if (-not [string]::IsNullOrWhiteSpace($target) -and -not (Test-Path -LiteralPath $target)) {
                try { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop; Write-Log "Removed broken Start Menu shortcut: $($_.FullName) -> $target"; $cleaned++ }
                catch { Write-Log "Could not remove shortcut $($_.FullName): $($_.Exception.Message)" 'WARN' }
            }
        }
        try {
            if (-not (Get-ChildItem -LiteralPath $grp -ErrorAction SilentlyContinue)) {
                Remove-Item -LiteralPath $grp -Force -ErrorAction Stop
                Write-Log "Removed empty Start Menu group: $grp"
            }
        } catch { }
    }

    return @{ Cleaned = $cleaned; Failed = $failed }
}

Write-Log "=== Python Remediation started on $env:COMPUTERNAME (64-bit host: $([Environment]::Is64BitProcess)) | target $TargetVersion | install=$InstallStandardPython ==="

try {
    $sidPattern = 'S-1-5-21-\d+-\d+-\d+-\d+$'
    $installFailed = $false
    $profiles = @()
    try {
        $profiles = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' `
                        -ErrorAction SilentlyContinue |
                    Where-Object { $_.PSChildName -match $sidPattern }
    } catch { Write-Log "ProfileList enumeration error (ignored): $($_.Exception.Message)" 'WARN' }
    try {
        $activeSids = Get-ActiveUserSid
        foreach ($lsid in (Get-LoadedUserSid -Pattern $sidPattern)) {
            if (-not $activeSids.Contains($lsid)) {
                Write-Log "Orphaned HKU mount detected for $lsid. Cleaning." 'WARN'
                if (Invoke-RegUnload -Sid $lsid) { Write-Log "Unloaded orphaned hive HKU\$lsid." }
            }
        }
    } catch { Write-Log "Pre-pass orphan cleanup error (ignored): $($_.Exception.Message)" 'WARN' }
    $loadedSids = Get-LoadedUserSid -Pattern $sidPattern

    #----------------------------------------------------------------------------
    # 2. Collect HKLM old bundles + old component MSIs (both views) BEFORE acting.
    #----------------------------------------------------------------------------
    $hklmEntries = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($viewObj in @([Microsoft.Win32.RegistryView]::Registry64,
                           [Microsoft.Win32.RegistryView]::Registry32)) {
        $base = $null
        try {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $viewObj)
            $uninstall = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
            if ($uninstall) {
                foreach ($subName in $uninstall.GetSubKeyNames()) {
                    $sub = $uninstall.OpenSubKey($subName); if (-not $sub) { continue }
                    $entry = [pscustomobject]@{
                        DisplayName          = $sub.GetValue('DisplayName')
                        Publisher            = $sub.GetValue('Publisher')
                        WindowsInstaller     = $sub.GetValue('WindowsInstaller')
                        UninstallString      = [string]$sub.GetValue('UninstallString')
                        QuietUninstallString = [string]$sub.GetValue('QuietUninstallString')
                    }
                    $sub.Close()

                    if (Test-IsConda $entry) { continue }     # never touch conda
                    $ver = Get-PyNameVersion ([string]$entry.DisplayName)

                    $isOldBundle    = (Test-IsOrgBundle $entry)       -and $ver -and ($ver -lt $TargetVersion)
                    $isOldComponent = (Test-IsOrgComponentMsi $entry) -and $ver -and ($ver -lt $TargetVersion)
                    if ($isOldBundle -or $isOldComponent) {
                        $hklmEntries.Add(@{
                            DisplayName          = [string]$entry.DisplayName
                            UninstallString      = [string]$entry.UninstallString
                            QuietUninstallString = [string]$entry.QuietUninstallString
                            WindowsInstaller     = $entry.WindowsInstaller
                            KeyName              = $subName
                            Scope                = "HKLM $viewObj"
                            HiveRoot             = 'HKEY_LOCAL_MACHINE'
                            View                 = "$viewObj"
                            IsComponentMsi       = [bool]$isOldComponent
                        })
                    }
                }
                $uninstall.Close()
            }
        } catch {
            Write-Log "HKLM $viewObj enumeration error: $($_.Exception.Message)" 'WARN'
        } finally { if ($base) { $base.Close() } }
    }

    # Remove HKLM bundles first, then components last (components depend on the
    # bundle being gone; sort so non-component bundles run before component MSIs).
    foreach ($e in ($hklmEntries | Sort-Object { [bool]$_.IsComponentMsi })) { Invoke-EntryRemoval $e }

    #----------------------------------------------------------------------------
    # 3. Per-user python.org bundles across all profiles (loaded + temporarily).
    #    DELEGATED to the user-context companion by default -- SYSTEM cannot cleanly
    #    uninstall a per-user MSI. Enable $HandlePerUserFromSystem for a best-effort
    #    attempt only if you have no user-context policy.
    #----------------------------------------------------------------------------
    if (-not $HandlePerUserFromSystem) {
        Write-Log "Per-user (HKU) removal delegated to the user-context companion (Remediate-Python-User.ps1); skipping from SYSTEM."
    }
    foreach ($prof in $(if ($HandlePerUserFromSystem) { $profiles } else { @() })) {
        $sid      = $prof.PSChildName
        $profPath = $prof.ProfileImagePath
        $hiveRoot = "HKEY_USERS\$sid"
        $didLoad  = $false
        try {
            if ($loadedSids -notcontains $sid) {
                $ntuser = Join-Path $profPath 'NTUSER.DAT'
                if (-not (Test-Path -LiteralPath $ntuser)) { continue }
                if ((Invoke-RegExe @('load', "HKU\$sid", $ntuser)) -ne 0) { Write-Log "Could not load hive for $profPath" 'WARN'; continue }
                $didLoad = $true
                Write-Log "Loaded offline hive: $profPath"
            }
            foreach ($node in @('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                                 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
                $path = "Registry::$hiveRoot\$node"
                if (-not (Test-Path -LiteralPath $path)) { continue }
                $userEntries = Get-ChildItem -LiteralPath $path -ErrorAction SilentlyContinue | ForEach-Object {
                    $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
                    if ($p -and -not (Test-IsConda $p)) {
                        $v = Get-PyNameVersion ([string]$p.DisplayName)
                        $oldB = (Test-IsOrgBundle $p)       -and $v -and ($v -lt $TargetVersion)
                        $oldC = (Test-IsOrgComponentMsi $p) -and $v -and ($v -lt $TargetVersion)
                        if ($oldB -or $oldC) {
                            @{
                                DisplayName          = [string]$p.DisplayName
                                UninstallString      = [string]$p.UninstallString
                                QuietUninstallString = [string]$p.QuietUninstallString
                                WindowsInstaller     = $p.WindowsInstaller
                                KeyName              = $_.PSChildName
                                Scope                = "HKU:$sid"
                                HiveRoot             = $hiveRoot
                                View                 = ''
                                IsComponentMsi       = [bool]$oldC
                            }
                        }
                    }
                }
                foreach ($e in $userEntries) { if ($e) { Invoke-EntryRemoval $e } }
            }
        } catch {
            Write-Log "Per-user processing error ($sid): $($_.Exception.Message)" 'WARN'
        } finally {
            if ($didLoad) { if (-not (Invoke-RegUnload -Sid $sid)) { $script:failCount++ } }
        }
    }

    #----------------------------------------------------------------------------
    # 4. Microsoft Store runtimes (NN < target minor). PythonManager is KEPT.
    #----------------------------------------------------------------------------
    $appxAvailable = [bool](Get-Command -Name Get-AppxPackage -ErrorAction SilentlyContinue)
    if (-not $appxAvailable) {
        Write-Log "Get-AppxPackage unavailable (possibly 32-bit/SYSTEM). Store removal NOT attempted; state not verified." 'WARN'
    } else {
        try {
            $old = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object {
                $_.Name -ne 'PythonSoftwareFoundation.PythonManager' -and
                (($l = Get-StoreRuntimeLine ([string]$_.Name)) -and $l -lt $StoreTargetLine)
            }
            foreach ($pkg in $old) {
                try {
                    Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
                    Write-Log "Removed Store runtime (all users): $($pkg.PackageFullName)"
                    $successCount++
                } catch {
                    Write-Log "Remove -AllUsers failed ($($pkg.PackageFullName)): $($_.Exception.Message). Trying per-user." 'WARN'
                    $anyFail = $false
                    foreach ($u in $pkg.PackageUserInformation) {
                        if ($u.InstallState -eq 'Installed') {
                            try { Remove-AppxPackage -Package $pkg.PackageFullName -User $u.UserSecurityId.Sid -ErrorAction Stop }
                            catch { $anyFail = $true; Write-Log "  per-user remove failed for $($u.UserSecurityId.Sid): $($_.Exception.Message). A user-context remediation may be required." 'WARN' }
                        }
                    }
                    if ($anyFail) { $failCount++ } else { $successCount++ }
                }
            }
        } catch { Write-Log "Store removal phase error: $($_.Exception.Message)" 'WARN' }
    }

    #----------------------------------------------------------------------------
    # 5. Install the standard IF enabled AND no current Python remains.
    #    "Current Python" = python.org bundle >= target, OR a kept Store runtime /
    #    PythonManager, OR Anaconda/Miniconda. We re-scan live state post-cleanup.
    #----------------------------------------------------------------------------
    if ($InstallStandardPython) {
        $havePython = Test-CurrentOrgBundlePresent
        if (-not $havePython -and $appxAvailable) {
            try {
                $havePython = [bool](Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object {
                    $_.Name -eq 'PythonSoftwareFoundation.PythonManager' -or
                    (($l = Get-StoreRuntimeLine ([string]$_.Name)) -and $l -ge $StoreTargetLine)
                })
            } catch { }
        }
        if (-not $havePython) {
            # Conda check across HKLM/HKU so we don't install over a data-science box.
            $condaPresent = $false
            foreach ($viewObj in @([Microsoft.Win32.RegistryView]::Registry64,[Microsoft.Win32.RegistryView]::Registry32)) {
                $base=$null
                try {
                    $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$viewObj)
                    $u=$base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
                    if ($u) { foreach ($sn in $u.GetSubKeyNames()) { $s=$u.OpenSubKey($sn); if(-not $s){continue}
                        $e=[pscustomobject]@{DisplayName=$s.GetValue('DisplayName');Publisher=$s.GetValue('Publisher')}; $s.Close()
                        if (Test-IsConda $e){$condaPresent=$true;break} }; $u.Close() }
                } catch { } finally { if ($base){$base.Close()} }
                if ($condaPresent) { break }
            }
            if ($condaPresent) {
                Write-Log "No CPython standard, but Anaconda/Miniconda present -- NOT installing python.org over a conda box."
            } else {
                Write-Log "No current Python after cleanup -> installing machine-wide standard $TargetVersion."
                if (Install-StandardPython) {
                    if (Test-CurrentOrgBundlePresent) { Write-Log "Standard $TargetVersion install confirmed."; $successCount++ }
                    else { Write-Log "Installer reported success but bundle >= target not found." 'ERROR'; $installFailed = $true }
                } else { $installFailed = $true }
            }
        } else {
            Write-Log "A current Python is already present -- no install needed."
        }
    } else {
        Write-Log "InstallStandardPython = false -- remove-only mode; not installing."
    }

    #----------------------------------------------------------------------------
    # 5b. Force-clean machine-wide orphans that msiexec could not remove (guarded).
    #----------------------------------------------------------------------------
    if ($ForceCleanOrphans) {
        $fc = Invoke-OrphanForceClean
        if ($fc.Cleaned -gt 0) { Write-Log "Orphan force-clean removed $($fc.Cleaned) item(s)."; $successCount += $fc.Cleaned }
        if ($fc.Failed  -gt 0) { Write-Log "Orphan force-clean could not remove $($fc.Failed) folder(s) (locked/in use)." 'WARN' }
    }

    #----------------------------------------------------------------------------
    # 6. Verify: no OUTDATED python.org bundles/components (HKLM) and no old Store
    #    runtimes remain. (Per-user residue mirrors detection's coverage loosely.)
    #----------------------------------------------------------------------------
    $residual = [System.Collections.Generic.List[string]]::new()
    foreach ($viewObj in @([Microsoft.Win32.RegistryView]::Registry64,[Microsoft.Win32.RegistryView]::Registry32)) {
        $base=$null
        try {
            $base=[Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$viewObj)
            $u=$base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
            if ($u) { foreach ($sn in $u.GetSubKeyNames()) { $s=$u.OpenSubKey($sn); if(-not $s){continue}
                $e=[pscustomobject]@{DisplayName=$s.GetValue('DisplayName');Publisher=$s.GetValue('Publisher');WindowsInstaller=$s.GetValue('WindowsInstaller')}
                $s.Close()
                if (-not (Test-IsConda $e)) {
                    $v=Get-PyNameVersion ([string]$e.DisplayName)
                    # Exclude same-minor-line components (3.14.x) -- they share the
                    # kept 3.14.6 folder and are intentionally not force-cleaned, so
                    # they must not count as residual (would falsely flap "incomplete").
                    $isTargetLineComp = ((Test-IsOrgComponentMsi $e) -and $v -and $v.Major -eq $TargetVersion.Major -and $v.Minor -eq $TargetVersion.Minor)
                    if (((Test-IsOrgBundle $e) -or (Test-IsOrgComponentMsi $e)) -and $v -and ($v -lt $TargetVersion) -and -not $isTargetLineComp) {
                        $residual.Add("reg:$($e.DisplayName)")
                    }
                } } ; $u.Close() }
        } catch { } finally { if ($base){$base.Close()} }
    }
    if ($appxAvailable) {
        try {
            Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object {
                $_.Name -ne 'PythonSoftwareFoundation.PythonManager' -and
                (($l = Get-StoreRuntimeLine ([string]$_.Name)) -and $l -lt $StoreTargetLine)
            } | ForEach-Object { $residual.Add("store:$($_.PackageFullName)") }
        } catch { Write-Log "Store verification re-scan error: $($_.Exception.Message)" 'WARN' }
    }

    #----------------------------------------------------------------------------
    # 7. Final summary + exit code.
    #----------------------------------------------------------------------------
    # Authoritative gate: no OUTDATED machine-wide (HKLM) python.org or old Store
    # runtime remains, AND the standard install (if attempted) succeeded. $failCount
    # is informational only -- an msiexec failure that force-clean then resolved must
    # NOT keep the device perpetually "incomplete" (that was the flapping bug).
    Write-Log "Actions OK: $successCount | transient fails: $failCount | installFailed: $installFailed | Residual (HKLM/Store): $($residual.Count)"
    if ($residual.Count -eq 0 -and -not $installFailed) {
        Write-Log "=== Python remediation complete. Machine-wide standardized on $TargetVersion. (Per-user handled by companion.) ==="
        try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
        Write-Output "Python remediated. Actions: $successCount. Target $TargetVersion."
        exit 0
    } else {
        $resSummary = ($residual | Select-Object -First 20) -join ', '
        if ($installFailed -and $residual.Count -eq 0) { $resSummary = "standard $TargetVersion install failed (see log)" }
        Write-Log "=== Python remediation INCOMPLETE. installFailed=$installFailed. Residual: $resSummary ===" 'ERROR'
        try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
        Write-Output "Python remediation incomplete. Residual: $resSummary"
        exit 1
    }
}
catch {
    Write-Log "FATAL remediation error: $($_.Exception.Message)" 'ERROR'
    try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
    Write-Output "Python remediation error: $($_.Exception.Message)"
    exit 1
}
