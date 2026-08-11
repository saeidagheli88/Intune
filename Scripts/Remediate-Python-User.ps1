<#
.SYNOPSIS
    USER-CONTEXT removal of OUTDATED per-user Python (python.org "install for just
    me"). Companion to the SYSTEM pair.

.DESCRIPTION
    Intune Remediation REMEDIATION script -- RUNS AS THE LOGGED-ON USER
    ("Run this script using the logged-on credentials = Yes").

    For the CURRENT user only, removes python.org installs older than 3.14.6:
      1. Bundles "Python X.Y.Z (64-bit)" -> run the entry's QuietUninstallString
         (already "/uninstall /quiet"), else UninstallString + silent switches.
         Because this runs AS the user, the per-user MSI uninstall works normally.
      2. Orphaned component MSIs -> msiexec /x {GUID} /qn (user context).
      3. Force-clean fallback -> delete the version's per-user install folder
         (%LOCALAPPDATA%\Programs\Python\PythonXY) and its HKCU ARP keys, under
         strict guards (leaf must match ^Python\d{2,3}(-32)?$; never the target
         3.14 line, which shares its folder with the kept 3.14.6).

    LEFT ALONE: Anaconda/Miniconda, PythonManager runtimes, the py.exe launcher.
    Store MSIX runtimes are handled by the SYSTEM pair (Remove-AppxPackage
    -AllUsers), so they are not touched here.

    Idempotent: a second run on a clean profile is a no-op -> exit 0.

    EXIT CODES:  exit 0 = clean / removed.  exit 1 = something still outdated.

.NOTES
    Author : Endpoint Engineering (Monster Energy)
    Target : Windows PowerShell 5.1, USER context
    Intune : Run using logged-on credentials = Yes ; 64-bit PowerShell = Yes ;
             Enforce signature check = No.
    Logs   : %LOCALAPPDATA%\Monster\Logs.
#>

$ErrorActionPreference = 'Stop'

$TargetVersion   = [version]'3.14.6'
$script:OrgPublisher = 'Python Software Foundation'
$script:GuidUnanchored = '\{[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}'

$LogDir = Join-Path $env:LOCALAPPDATA 'Monster\Logs'
try { if (-not (Test-Path -LiteralPath $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null } } catch { $LogDir = $env:TEMP }
$LogFile = Join-Path $LogDir ("Remediate-PythonUser_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
try { Start-Transcript -Path $LogFile -Append -ErrorAction SilentlyContinue | Out-Null } catch { }
function Write-Log { param([string]$Msg,[string]$Level='INFO') Write-Host ("[{0:yyyy-MM-dd HH:mm:ss}] [{1}] {2}" -f (Get-Date),$Level,$Msg) }

function Get-PyNameVersion {
    param([string]$DisplayName)
    if ([string]::IsNullOrWhiteSpace($DisplayName)) { return $null }
    $m = [regex]::Match($DisplayName, 'Python\s+(\d+)\.(\d+)\.(\d+)')
    if (-not $m.Success) { return $null }
    try { return [version]("{0}.{1}.{2}" -f $m.Groups[1].Value,$m.Groups[2].Value,$m.Groups[3].Value) } catch { return $null }
}
function Test-IsOrgBundle {
    param($Entry)
    if (-not $Entry) { return $false }
    if (([string]$Entry.Publisher) -ne $script:OrgPublisher) { return $false }
    return (([string]$Entry.DisplayName) -match '^Python\s+\d+\.\d+\.\d+\s+\((?:64-bit|32-bit|arm64)\)$')
}
function Test-IsOrgComponentMsi {
    param($Entry)
    if (-not $Entry) { return $false }
    $name=[string]$Entry.DisplayName
    if (([string]$Entry.Publisher) -ne $script:OrgPublisher) { return $false }
    if ([string]::IsNullOrWhiteSpace($name) -or $name -eq 'Python Launcher') { return $false }
    if ($Entry.WindowsInstaller -ne 1) { return $false }
    return ($name -match '^Python\s+\d+\.\d+\.\d+' -and $name -match '\((?:64-bit|32-bit|arm64)\)')
}
function Test-IsConda {
    param($Entry)
    if (-not $Entry) { return $false }
    $name=[string]$Entry.DisplayName
    return ((([string]$Entry.Publisher) -like '*Anaconda*') -or $name -like '*Anaconda*' -or $name -like '*Miniconda*')
}

$successCount = 0
$uninstallPaths = @('HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                    'HKCU:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall')

# Does this user have a CURRENT per-user bundle (>= target)? Decides whether the
# target minor line's folder (PythonXY is shared across patches) may be removed.
function Test-UserCurrentBundlePresent {
    foreach ($path in $uninstallPaths) {
        if (-not (Test-Path -LiteralPath $path)) { continue }
        foreach ($k in @(Get-ChildItem -LiteralPath $path -ErrorAction SilentlyContinue)) {
            $p = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue
            if ($p -and (Test-IsOrgBundle $p)) {
                $v = Get-PyNameVersion ([string]$p.DisplayName)
                if ($v -and $v -ge $TargetVersion) { return $true }
            }
        }
    }
    return $false
}

# Uninstall one old per-user entry (bundle burn or component MSI), as the user.
function Invoke-UserUninstall {
    param($P)
    $name = [string]$P.DisplayName
    $qus  = [string]$P.QuietUninstallString
    $us   = [string]$P.UninstallString
    $wi   = $P.WindowsInstaller
    $key  = $P.PSChildName
    try {
        if ($wi -eq 1 -or $key -match $script:GuidUnanchored) {
            $g = [regex]::Match("$key $us $qus", $script:GuidUnanchored)
            if (-not $g.Success) { Write-Log "MSI but no GUID for '$name'." 'WARN'; return $false }
            Write-Log "MSI uninstall (user): msiexec /x $($g.Value) /qn /norestart"
            $p = Start-Process msiexec.exe -ArgumentList "/x $($g.Value) /qn /norestart REBOOT=ReallySuppress" -Wait -PassThru -WindowStyle Hidden
            Write-Log "msiexec exit: $($p.ExitCode)"
            return ($p.ExitCode -in @(0,1605,1641,3010))
        }
        $exe=$null; $bargs=$null
        $src = if (-not [string]::IsNullOrWhiteSpace($qus)) { $qus } else { $us }
        if ([string]::IsNullOrWhiteSpace($src)) { Write-Log "No uninstall string for '$name'." 'WARN'; return $false }
        if ($src -match '^\s*"([^"]+)"\s*(.*)$') { $exe=$Matches[1]; $bargs=$Matches[2].Trim() }
        else { $m=[regex]::Match($src.Trim(),'^(?<exe>.+?\.exe)(?<rest>\s+.*)?$','IgnoreCase'); if ($m.Success){$exe=$m.Groups['exe'].Value.Trim().Trim('"');$bargs=$m.Groups['rest'].Value.Trim()} }
        if ([string]::IsNullOrWhiteSpace($exe)) { Write-Log "Could not parse uninstaller for '$name'." 'WARN'; return $false }
        foreach ($sw in '/uninstall','/quiet','/norestart') { if ($bargs -notmatch [regex]::Escape($sw)) { $bargs = ("$bargs $sw").Trim() } }
        if (-not (Test-Path -LiteralPath $exe)) { Write-Log "Uninstaller missing at '$exe' -- will force-clean." 'WARN'; return $false }
        Write-Log "Bundle uninstall (user): `"$exe`" $bargs"
        $p = Start-Process -FilePath $exe -ArgumentList $bargs -Wait -PassThru -WindowStyle Hidden
        Write-Log "Bundle exit: $($p.ExitCode)"
        return ($p.ExitCode -in @(0,1605,1641,3010))
    } catch { Write-Log "Uninstall threw for '$name': $($_.Exception.Message)" 'ERROR'; return $false }
}

# Force-clean the user's per-user Python folder + HKCU ARP key for an old version.
function Invoke-UserForceClean {
    param([version]$Ver, [string]$KeyPath, [string]$InstallLocation)
    if (-not $Ver) { return }
    # Target minor line (3.14.x < 3.14.6): the PythonXY folder is SHARED across
    # patches. If this user ALSO has a current bundle (>= target) the folder holds
    # it -- remove only the stale ARP key. With no current per-user bundle, the old
    # 3.14.x owns the folder and is safe to remove entirely. (Previously we skipped
    # 3.14.x here unconditionally, which left detection re-flagging it forever.)
    $sameLine = ($Ver.Major -eq $TargetVersion.Major -and $Ver.Minor -eq $TargetVersion.Minor)
    if ($sameLine -and $script:UserHasCurrentBundle) {
        if ($KeyPath -and (Test-Path -LiteralPath $KeyPath)) {
            try { Remove-Item -LiteralPath $KeyPath -Recurse -Force -ErrorAction Stop; Write-Log "Force-removed stale HKCU key (folder kept for current bundle): $KeyPath" }
            catch { Write-Log "Force-remove HKCU key failed ($KeyPath): $($_.Exception.Message)" 'WARN' }
        }
        return
    }
    $tag = ('Python{0}{1}' -f $Ver.Major, $Ver.Minor)
    $cands = @(
        (Join-Path $env:LOCALAPPDATA "Programs\Python\$tag"),
        (Join-Path $env:LOCALAPPDATA "Programs\Python\$tag-32")
    )
    if (-not [string]::IsNullOrWhiteSpace($InstallLocation)) { $cands += $InstallLocation.TrimEnd('\') }
    foreach ($f in ($cands | Select-Object -Unique)) {
        if ([string]::IsNullOrWhiteSpace($f) -or -not (Test-Path -LiteralPath $f)) { continue }
        $leaf = Split-Path -Leaf $f
        if ($leaf -notmatch '^Python\d{2,3}(-32)?$') { Write-Log "Force-clean SKIP (leaf): $f" 'WARN'; continue }
        try { Remove-Item -LiteralPath $f -Recurse -Force -ErrorAction Stop; Write-Log "Force-removed folder: $f"; $script:successCount++ }
        catch { Write-Log "Force-remove folder failed ($f): $($_.Exception.Message)" 'WARN' }
    }
    if ($KeyPath -and (Test-Path -LiteralPath $KeyPath)) {
        try { Remove-Item -LiteralPath $KeyPath -Recurse -Force -ErrorAction Stop; Write-Log "Force-removed HKCU key: $KeyPath" }
        catch { Write-Log "Force-remove HKCU key failed ($KeyPath): $($_.Exception.Message)" 'WARN' }
    }
}

# Sweep now-BROKEN shortcuts left behind by a removed version: the Start Menu
# group "Python 3.X" and any Desktop .lnk. A shortcut is deleted ONLY when its
# target path points INSIDE one of the removed install roots AND the target no
# longer exists -- a working shortcut (or one aimed anywhere else) is never touched.
# (Uninstallers miss user-created Desktop shortcuts, and force-cleaned installs
# never ran an uninstaller at all -- users then hit "Problem with Shortcut".)
function Remove-BrokenPythonShortcuts {
    param([version]$Ver, [string[]]$RemovedRoots)
    if (-not $Ver) { return }
    $shell = $null
    try { $shell = New-Object -ComObject WScript.Shell } catch { }
    $mm = "{0}.{1}" -f $Ver.Major, $Ver.Minor
    $startGroup = Join-Path $env:APPDATA ("Microsoft\Windows\Start Menu\Programs\Python " + $mm)
    $desktop = $null
    try { $desktop = [Environment]::GetFolderPath('Desktop') } catch { }
    foreach ($dir in @($startGroup, $desktop)) {
        if ([string]::IsNullOrWhiteSpace($dir) -or -not (Test-Path -LiteralPath $dir)) { continue }
        Get-ChildItem -LiteralPath $dir -Filter '*.lnk' -ErrorAction SilentlyContinue | ForEach-Object {
            $target = $null
            if ($shell) { try { $target = $shell.CreateShortcut($_.FullName).TargetPath } catch { } }
            if ([string]::IsNullOrWhiteSpace($target)) { return }
            $inRemoved = $false
            foreach ($root in $RemovedRoots) {
                if (-not [string]::IsNullOrWhiteSpace($root) -and
                    $target.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) { $inRemoved = $true; break }
            }
            if ($inRemoved -and -not (Test-Path -LiteralPath $target)) {
                try { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop; Write-Log "Removed broken shortcut: $($_.FullName) -> $target" }
                catch { Write-Log "Could not remove shortcut $($_.FullName): $($_.Exception.Message)" 'WARN' }
            }
        }
    }
    # Drop the version's Start Menu group folder once it is empty.
    try {
        if ((Test-Path -LiteralPath $startGroup) -and -not (Get-ChildItem -LiteralPath $startGroup -ErrorAction SilentlyContinue)) {
            Remove-Item -LiteralPath $startGroup -Force -ErrorAction Stop
            Write-Log "Removed empty Start Menu group: $startGroup"
        }
    } catch { }
}

Write-Log "=== Per-user Python remediation started for $env:USERNAME (target $TargetVersion) ==="
try {
    # Collect old entries first (so we don't enumerate a key we're deleting).
    $targets = [System.Collections.Generic.List[object]]::new()
    foreach ($path in $uninstallPaths) {
        if (-not (Test-Path -LiteralPath $path)) { continue }
        Get-ChildItem -LiteralPath $path -ErrorAction SilentlyContinue | ForEach-Object {
            $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
            if (-not $p -or (Test-IsConda $p)) { return }
            $v = Get-PyNameVersion ([string]$p.DisplayName)
            $isTargetLine = ($v -and $v.Major -eq $TargetVersion.Major -and $v.Minor -eq $TargetVersion.Minor)
            $oldB = (Test-IsOrgBundle $p)       -and $v -and ($v -lt $TargetVersion)
            $oldC = (Test-IsOrgComponentMsi $p) -and $v -and ($v -lt $TargetVersion) -and -not $isTargetLine
            if ($oldB -or $oldC) { $targets.Add($p) }
        }
    }
    Write-Log "Found $($targets.Count) outdated per-user item(s)."
    $script:UserHasCurrentBundle = Test-UserCurrentBundlePresent
    Write-Log "Current per-user bundle (>= $TargetVersion) present: $script:UserHasCurrentBundle"

    # Bundles first (their uninstall removes their own components), components after.
    foreach ($p in ($targets | Sort-Object { [bool](Test-IsOrgComponentMsi $_) })) {
        [void](Invoke-UserUninstall $p)
        $v = Get-PyNameVersion ([string]$p.DisplayName)
        # AUTHORITATIVE: did the ARP key actually disappear? An ORPHANED entry (real
        # product/cache already gone) makes the uninstaller return success / 1605
        # "not installed" without removing the leftover key -- so we must verify and
        # force-clean regardless of the exit code, or it lingers as residual forever.
        if (Test-Path -LiteralPath $p.PSPath) {
            Invoke-UserForceClean -Ver $v -KeyPath $p.PSPath -InstallLocation ([string]$p.InstallLocation)
        }
        if (-not (Test-Path -LiteralPath $p.PSPath)) { $script:successCount++ }
        # Clean up shortcuts that died with this version (skip the target line when a
        # current bundle keeps that folder alive).
        if ($v -and -not (($v.Major -eq $TargetVersion.Major -and $v.Minor -eq $TargetVersion.Minor) -and $script:UserHasCurrentBundle)) {
            $tag = ('Python{0}{1}' -f $v.Major, $v.Minor)
            $roots = @((Join-Path $env:LOCALAPPDATA "Programs\Python\$tag"),
                       (Join-Path $env:LOCALAPPDATA "Programs\Python\$tag-32"))
            if (-not [string]::IsNullOrWhiteSpace([string]$p.InstallLocation)) { $roots += ([string]$p.InstallLocation).TrimEnd('\') }
            Remove-BrokenPythonShortcuts -Ver $v -RemovedRoots $roots
        }
    }

    # Verify: re-scan HKCU for remaining outdated python.org (excl. target 3.14 line).
    $residual = [System.Collections.Generic.List[string]]::new()
    foreach ($path in $uninstallPaths) {
        if (-not (Test-Path -LiteralPath $path)) { continue }
        Get-ChildItem -LiteralPath $path -ErrorAction SilentlyContinue | ForEach-Object {
            $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
            if (-not $p -or (Test-IsConda $p)) { return }
            $v = Get-PyNameVersion ([string]$p.DisplayName)
            $isTargetLine = ($v -and $v.Major -eq $TargetVersion.Major -and $v.Minor -eq $TargetVersion.Minor)
            # MUST mirror detection: old BUNDLES always count (incl. 3.14.x < target --
            # the earlier exclusion here made remediation exit 0 while detection kept
            # flagging them: the "Recurred" flap). Components skip the target line only.
            $oldB = (Test-IsOrgBundle $p)       -and $v -and ($v -lt $TargetVersion)
            $oldC = (Test-IsOrgComponentMsi $p) -and $v -and ($v -lt $TargetVersion) -and -not $isTargetLine
            if ($oldB -or $oldC) {
                $residual.Add([string]$p.DisplayName)
            }
        }
    }

    if ($residual.Count -eq 0) {
        Write-Log "=== Per-user Python clean. Actions: $successCount. ==="
        try { Stop-Transcript -EA SilentlyContinue | Out-Null } catch { }
        Write-Output "Per-user Python remediated. Actions: $successCount."
        exit 0
    }
    $rs = (($residual | Select-Object -Unique) | Select-Object -First 20) -join ', '
    Write-Log "=== Per-user remediation INCOMPLETE. Residual: $rs ===" 'ERROR'
    try { Stop-Transcript -EA SilentlyContinue | Out-Null } catch { }
    Write-Output "Per-user Python remediation incomplete. Residual: $rs"
    exit 1
}
catch {
    Write-Log "FATAL remediation error: $($_.Exception.Message)" 'ERROR'
    try { Stop-Transcript -EA SilentlyContinue | Out-Null } catch { }
    Write-Output "Per-user Python remediation error: $($_.Exception.Message)"
    exit 1
}
