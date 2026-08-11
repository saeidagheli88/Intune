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
    if ($Ver.Major -eq $TargetVersion.Major -and $Ver.Minor -eq $TargetVersion.Minor) { return }  # protect 3.14 folder
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

    # Bundles first (their uninstall removes their own components), components after.
    foreach ($p in ($targets | Sort-Object { [bool](Test-IsOrgComponentMsi $_) })) {
        [void](Invoke-UserUninstall $p)
        # AUTHORITATIVE: did the ARP key actually disappear? An ORPHANED entry (real
        # product/cache already gone) makes the uninstaller return success / 1605
        # "not installed" without removing the leftover key -- so we must verify and
        # force-clean regardless of the exit code, or it lingers as residual forever.
        if (Test-Path -LiteralPath $p.PSPath) {
            $v = Get-PyNameVersion ([string]$p.DisplayName)
            Invoke-UserForceClean -Ver $v -KeyPath $p.PSPath -InstallLocation ([string]$p.InstallLocation)
        }
        if (-not (Test-Path -LiteralPath $p.PSPath)) { $script:successCount++ }
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
            if (((Test-IsOrgBundle $p) -or (Test-IsOrgComponentMsi $p)) -and $v -and ($v -lt $TargetVersion) -and -not $isTargetLine) {
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
