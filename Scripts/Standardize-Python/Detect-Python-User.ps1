<#
.SYNOPSIS
    USER-CONTEXT detection for OUTDATED per-user Python (python.org "install for
    just me"). Companion to the SYSTEM pair, which cannot remove per-user MSIs.

.DESCRIPTION
    Intune Remediation DETECTION script -- RUNS AS THE LOGGED-ON USER
    ("Run this script using the logged-on credentials = Yes").

    Scans the CURRENT user's HKCU Uninstall keys (native + WOW6432Node) for
    python.org installs older than the target (3.14.6):
      * bundles  "Python X.Y.Z (64-bit)"            -> finding when < target
      * orphaned "Python X.Y.Z <component> (64-bit)" -> finding when < target
        (excluding the target minor line 3.14.x, which shares the kept folder)
    Anaconda/Miniconda, PythonManager runtimes, and the launcher are LEFT ALONE.

    WHY A SEPARATE USER-CONTEXT POLICY: a per-user MSI is registered in the user's
    own Windows Installer context; a SYSTEM-context script cannot uninstall it
    cleanly. Running as the user, the product's own QuietUninstallString / msiexec
    works normally. The SYSTEM pair handles machine-wide + Store + installing the
    standard; this pair only clears the user's per-user leftovers.

    Version is parsed from the DisplayName (the 4-part DisplayVersion is not
    semantic: "3.14.150.0" = 3.14.0).

    EXIT CODES:  exit 1 = outdated per-user Python found -> remediate.  exit 0 = clean.
    Errors exit 1 (remediate). Exactly one Write-Output = the STDOUT summary.

.NOTES
    Author : Endpoint Engineering (Monster Energy)
    Target : Windows PowerShell 5.1, USER context
    Intune : Run using logged-on credentials = Yes ; 64-bit PowerShell = Yes ;
             Enforce signature check = No.
    Logs   : %LOCALAPPDATA%\Monster\Logs (SYSTEM's ProgramData path may not be
             writable by a standard user).
#>

$ErrorActionPreference = 'Stop'

$TargetVersion   = [version]'3.14.6'
$StoreTargetLine = [version]'3.14'
$script:OrgPublisher = 'Python Software Foundation'

$LogDir = Join-Path $env:LOCALAPPDATA 'Monster\Logs'
try { if (-not (Test-Path -LiteralPath $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null } } catch { $LogDir = $env:TEMP }
$LogFile = Join-Path $LogDir ("Detect-PythonUser_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
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

$findings = [System.Collections.Generic.List[string]]::new()

Write-Log "=== Per-user Python detection started for $env:USERNAME (target $TargetVersion) ==="
try {
    foreach ($path in @('HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                        'HKCU:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
        if (-not (Test-Path -LiteralPath $path)) { continue }
        try {
            Get-ChildItem -LiteralPath $path -ErrorAction SilentlyContinue | ForEach-Object {
                $p = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
                if (-not $p -or [string]::IsNullOrWhiteSpace([string]$p.DisplayName)) { return }
                if (Test-IsConda $p) { Write-Log "Leave (conda): $($p.DisplayName)"; return }
                $v = Get-PyNameVersion ([string]$p.DisplayName)
                $isTargetLine = ($v -and $v.Major -eq $TargetVersion.Major -and $v.Minor -eq $TargetVersion.Minor)
                if ((Test-IsOrgBundle $p) -and $v -and $v -lt $TargetVersion) {
                    $findings.Add("$($p.DisplayName)") ; Write-Log "OUTDATED per-user bundle: $($p.DisplayName)" 'WARN'
                }
                elseif ((Test-IsOrgComponentMsi $p) -and $v -and $v -lt $TargetVersion -and -not $isTargetLine) {
                    $findings.Add("$($p.DisplayName)") ; Write-Log "OUTDATED per-user component: $($p.DisplayName)" 'WARN'
                }
            }
        } catch { Write-Log "Scan error at ${path}: $($_.Exception.Message)" 'WARN' }
    }

    if ($findings.Count -gt 0) {
        $summary = (($findings | Select-Object -Unique) -join ' | ')
        if ($summary.Length -gt 1800) { $summary = $summary.Substring(0,1800) + ' ...(truncated)' }
        Write-Log "RESULT: $($findings.Count) outdated per-user item(s)." 'WARN'
        try { Stop-Transcript -EA SilentlyContinue | Out-Null } catch { }
        Write-Output "Per-user Python update needed: $summary"
        exit 1
    }
    Write-Log "RESULT: no outdated per-user Python."
    try { Stop-Transcript -EA SilentlyContinue | Out-Null } catch { }
    Write-Output "Per-user Python compliant (target $TargetVersion)."
    exit 0
}
catch {
    Write-Log "FATAL detection error: $($_.Exception.Message)" 'ERROR'
    try { Stop-Transcript -EA SilentlyContinue | Out-Null } catch { }
    Write-Output "Per-user Python detection error (treating as needed): $($_.Exception.Message)"
    exit 1
}
