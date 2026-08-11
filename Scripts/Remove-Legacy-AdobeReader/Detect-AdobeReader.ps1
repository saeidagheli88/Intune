<#
.SYNOPSIS
    Detects LEGACY / duplicate Adobe Reader installs and an unhealthy Adobe
    auto-updater on a Windows device. The ONE version allowed to stay is the
    unified 64-bit Adobe Acrobat Reader (MSI product code
    {AC76BA86-1033-FFFF-7760-BC15014EA700}) deployed by the Intune Win32 app.

.DESCRIPTION
    Intune Remediation DETECTION script (READ-ONLY).

    DIVISION OF LABOR (by design -- do not blur it):
      - The Intune Win32 app "Adobe Acrobat Reader DC (64-bit)" (version-based
        detection rule: Acrobat.exe file version >= baseline, Required assignment)
        is what INSTALLS and UPGRADES the unified 64-bit Reader. This pair never
        installs or patches Reader itself.
      - THIS pair only (a) finds/removes legacy & duplicate Reader installs so a
        single product remains, and (b) keeps the Adobe ARM auto-updater enabled
        so devices track the latest version between package refreshes.
      - An outdated-but-healthy unified Reader is LOGGED here but is NOT a
        finding: the Win32 app remediates that, and making it a finding would
        loop this pair daily on devices that are mid-catch-up (updates are
        asynchronous). This keeps the pair loop-safe.

    WHAT COUNTS AS A FINDING (exit 1):
      1. Any LEGACY Adobe Reader in the HKLM Uninstall keys, read in BOTH the
         64-bit and 32-bit registry views:
           - any MSI product code starting {AC76BA86-7AD7-...} -- the entire
             32-bit Reader family (9.x / X / XI / DC 32-bit, every language), or
           - DisplayName matching '^Adobe (Acrobat )?Reader\b' that is NOT the
             unified 64-bit product.
         The unified 64-bit code {AC76BA86-1033-FFFF-7760-BC15014EA700} and paid
         Acrobat Std/Pro (DisplayName "Adobe Acrobat ...", different codes) are
         deliberately EXCLUDED and never touched.
      2. A legacy Reader BINARY (AcroRd32.exe) still on disk under the known
         32-bit install folders. Folder-only leftovers are NOT findings, and a
         binary already queued in PendingFileRenameOperations (delete-on-reboot)
         is NOT a finding -- loop-safety, same as the 7-Zip pair.
      3. The Adobe updater actively BROKEN on a device that has the unified
         Reader: service 'AdobeARMservice' present but Disabled, or policy
         FeatureLockDown bUpdater=0. (Service missing entirely is logged WARN,
         not a finding -- the remediation cannot conjure the service; the Win32
         app reinstall restores it.)
      4. OPTIONAL (off by default): the MSIX 'AdobeAcrobatReaderCoreApp' Store
         package. Enable $HandleStoreCoreApp ONLY after the Win32 app is
         Required on the same devices, or CoreApp-only users lose their PDF
         viewer until the app lands. Keep the flag IDENTICAL in both scripts.

    Reader has NO per-user installer (the unified MSI is machine-context only),
    so the per-user HKU / NTUSER.DAT sweep used in the 7-Zip pair is
    intentionally omitted here -- hive loads would add risk for zero coverage.
    The MSIX side is per-user but Get-AppxPackage -AllUsers covers it.

    EXIT CODES (Intune Remediation convention):
        exit 1 = finding(s) -> triggers remediation.  Errors also exit 1.
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
# CONFIG -- keep these IDENTICAL in Detect-AdobeReader.ps1 / Remediate-AdobeReader.ps1
#--------------------------------------------------------------------------------
# File version of Acrobat.exe shipped by the current Intune Win32 package
# (product version 26.001.21662 -> file version 26.1.21662). Used for LOGGING
# only in this script -- staleness is the Win32 app's job, not a finding here.
$BaselineVersion    = [version]'26.1.21662'
# The one product allowed to stay: unified 64-bit Adobe Acrobat Reader MUI.
$Unified64Code      = '{AC76BA86-1033-FFFF-7760-BC15014EA700}'
$Unified64Exe       = Join-Path $env:ProgramFiles 'Adobe\Acrobat DC\Acrobat\Acrobat.exe'
# OPT-IN: also treat the MSIX Store 'AdobeAcrobatReaderCoreApp' as a finding.
# Only set $true once the Win32 app is Required on these devices (see .DESCRIPTION).
$HandleStoreCoreApp = $false

#--------------------------------------------------------------------------------
# 1. Durable logging under %ProgramData% (SYSTEM-safe; never %TEMP% as SYSTEM).
#--------------------------------------------------------------------------------
$LogDir = Join-Path $env:ProgramData 'Monster\Logs'
if (-not (Test-Path -LiteralPath $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}
$LogFile = Join-Path $LogDir ("Detect-AdobeReader_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
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

# Legacy classifier. Tight by design:
#  - the unified 64-bit product code is never legacy;
#  - {AC76BA86-7AD7-...} = the whole 32-bit Reader family (9.x/X/XI/DC, any lang);
#  - name fallback catches odd registrations, but a '64-bit' name is excluded so
#    a future unified code change cannot make us uninstall the keeper;
#  - paid Acrobat Std/Pro ("Adobe Acrobat ...", no 'Reader') never matches.
function Test-IsLegacyReader {
    param([string]$Code, [string]$Name, [string]$Publisher)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    if ($Code -eq $Unified64Code) { return $false }
    if ($Publisher -notlike 'Adobe*') { return $false }
    if ($Name -match '64-bit') { return $false }
    if ($Code -match '^\{AC76BA86-7AD7-') { return $true }
    return ($Name -match '^Adobe (Acrobat )?Reader\b')
}

Write-Log "=== Adobe Reader cleanup detection started on $env:COMPUTERNAME (64-bit host: $([Environment]::Is64BitProcess)) ==="

try {
    #----------------------------------------------------------------------------
    # 2. HKLM Uninstall keys -- explicit 64-bit AND 32-bit views.
    #----------------------------------------------------------------------------
    $unifiedArpSeen = $false
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
                    if ($subName -eq $Unified64Code) {
                        $unifiedArpSeen = $true
                        Write-Log "Unified 64-bit Reader registered: '$name' v$ver [$view]"
                    } elseif (Test-IsLegacyReader -Code $subName -Name $name -Publisher $pub) {
                        Add-Finding ("[HKLM {0}] LEGACY {1} v{2} ({3})" -f $view, $name, $ver, $subName)
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
    # 3. Legacy binaries on disk. Binary-gated + pending-delete guard (loop-safe).
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

    $legacyBinaries = @()
    if (${env:ProgramFiles(x86)}) {
        $legacyBinaries += (Join-Path ${env:ProgramFiles(x86)} 'Adobe\Acrobat Reader DC\Reader\AcroRd32.exe')
        # Reader 9.x / X / XI installed under "Adobe\Reader <n>.0\Reader".
        try {
            $legacyBinaries += Get-ChildItem -Path (Join-Path ${env:ProgramFiles(x86)} 'Adobe') `
                                   -Directory -Filter 'Reader*' -ErrorAction SilentlyContinue |
                               ForEach-Object { Join-Path $_.FullName 'Reader\AcroRd32.exe' }
        } catch { }
    }
    foreach ($bin in ($legacyBinaries | Select-Object -Unique)) {
        if (Test-Path -LiteralPath $bin) {
            if ($pendingDelete.Contains($bin.TrimEnd('\'))) {
                Write-Log "Binary '$bin' is queued for delete-on-reboot; not counting as a finding."
            } else {
                Add-Finding "[FileSystem] LEGACY binary $bin"
            }
        }
    }

    #----------------------------------------------------------------------------
    # 4. Unified Reader present? Log its version vs baseline (NOT a finding --
    #    the version-based Win32 app detection rule owns upgrades), and verify
    #    the Adobe ARM auto-updater is not actively disabled.
    #----------------------------------------------------------------------------
    $unifiedPresent = (Test-Path -LiteralPath $Unified64Exe)
    if ($unifiedPresent) {
        try {
            $fv = [version](Get-Item -LiteralPath $Unified64Exe).VersionInfo.FileVersion.Split(' ')[0]
            if ($fv -lt $BaselineVersion) {
                Write-Log "Unified Reader is v$fv (< baseline $BaselineVersion). Upgrade is handled by the Win32 app; not a finding." 'WARN'
            } else {
                Write-Log "Unified Reader is v$fv (baseline $BaselineVersion met)."
            }
        } catch {
            Write-Log "Could not read Acrobat.exe file version: $($_.Exception.Message)" 'WARN'
        }
        if (-not $unifiedArpSeen) {
            Write-Log 'Acrobat.exe exists but the unified ARP entry was not seen (unusual; install may be mid-flight).' 'WARN'
        }

        # 4a. Updater service. Missing = WARN only (reinstall by the Win32 app
        #     restores it; this remediation cannot). Disabled = finding (we fix it).
        try {
            $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='AdobeARMservice'" -ErrorAction SilentlyContinue
            if (-not $svc) {
                Write-Log "Service 'AdobeARMservice' not found. Not a finding (Win32 app reinstall restores it)." 'WARN'
            } elseif ($svc.StartMode -eq 'Disabled') {
                Add-Finding "[Updater] AdobeARMservice is Disabled"
            } else {
                Write-Log "AdobeARMservice: StartMode=$($svc.StartMode), State=$($svc.State)."
            }
        } catch { Write-Log "Service check error: $($_.Exception.Message)" 'WARN' }

        # 4b. FeatureLockDown bUpdater=0 turns Adobe updates off entirely.
        foreach ($polKey in @('SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown',
                              'SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown')) {
            foreach ($view in $hklmViews) {
                $base = $null
                try {
                    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                                [Microsoft.Win32.RegistryHive]::LocalMachine, $view)
                    $k = $base.OpenSubKey($polKey)
                    if ($k) {
                        $v = $k.GetValue('bUpdater', $null)
                        if ($v -is [int] -and $v -eq 0) {
                            Add-Finding "[Updater] bUpdater=0 in HKLM($view)\$polKey"
                        }
                        $k.Close()
                    }
                } catch { Write-Log "Policy check error ($polKey/$view): $($_.Exception.Message)" 'WARN' }
                finally { if ($base) { $base.Close() } }
            }
        }
    } else {
        Write-Log 'Unified 64-bit Reader not installed on this device (Win32 app will install it). Updater checks skipped.'
    }

    #----------------------------------------------------------------------------
    # 5. OPTIONAL MSIX Store CoreApp (flag-gated; see header warning).
    #    Tight match: package name contains AcrobatReaderCoreApp AND Adobe Inc.
    #----------------------------------------------------------------------------
    if ($HandleStoreCoreApp) {
        $appxCmd = Get-Command -Name Get-AppxPackage -ErrorAction SilentlyContinue
        if (-not $appxCmd) {
            Write-Log 'Get-AppxPackage unavailable in this host. MSIX state NOT verified.' 'WARN'
        } else {
            try {
                Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -like '*AcrobatReaderCoreApp*' -and $_.Publisher -like '*Adobe Inc*' } |
                    ForEach-Object { Add-Finding "[Appx] $($_.PackageFullName)" }
            } catch { Write-Log "Get-AppxPackage error (MSIX not verified): $($_.Exception.Message)" 'WARN' }
        }
        $provCmd = Get-Command -Name Get-AppxProvisionedPackage -ErrorAction SilentlyContinue
        if ($provCmd) {
            try {
                Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
                    Where-Object { $_.DisplayName -like '*AcrobatReaderCoreApp*' } |
                    ForEach-Object { Add-Finding "[Provisioned] $($_.PackageName)" }
            } catch { Write-Log "Get-AppxProvisionedPackage error: $($_.Exception.Message)" 'WARN' }
        }
    } else {
        Write-Log 'Store CoreApp handling is OFF ($HandleStoreCoreApp=$false); MSIX package (if any) is left alone.'
    }

    #----------------------------------------------------------------------------
    # 6. Result. Exactly ONE Write-Output.
    #----------------------------------------------------------------------------
    if ($found) {
        $summary = ($details -join ' | ')
        if ($summary.Length -gt 1800) { $summary = $summary.Substring(0, 1800) + ' ...(truncated)' }
        Write-Log "RESULT: cleanup NEEDED ($($details.Count) finding(s))" 'WARN'
        try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
        Write-Output "Adobe Reader cleanup needed: $summary"
        exit 1
    } else {
        Write-Log 'RESULT: no legacy Reader, updater healthy. Device is clean.'
        try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
        Write-Output 'Adobe Reader clean: single unified 64-bit install, updater enabled.'
        exit 0
    }
}
catch {
    Write-Log "FATAL detection error: $($_.Exception.Message)" 'ERROR'
    try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch { }
    Write-Output "Adobe Reader detection error (treating as found): $($_.Exception.Message)"
    exit 1
}
