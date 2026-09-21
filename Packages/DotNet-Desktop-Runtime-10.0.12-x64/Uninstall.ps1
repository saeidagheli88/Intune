[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$TargetVersion = [version]'10.0.12'
$InstallerPath = Join-Path $PSScriptRoot 'windowsdesktop-runtime-10.0.12-win-x64.exe'
$LogDirectory = 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs'
$LogPath = Join-Path $LogDirectory 'DotNet-Desktop-Runtime-10.0.12-x64-Uninstall.log'
$RebootRequired = $false

New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null

function Write-Log {
    param([Parameter(Mandatory)][string]$Message)
    ('{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $PID, $Message) |
        Out-File -FilePath $LogPath -Append -Encoding utf8
}

function Get-ExactTargetEntries {
    $results = @()
    $baseKey = $null
    $uninstallKey = $null
    try {
        $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine,
            [Microsoft.Win32.RegistryView]::Registry64
        )
        $uninstallKey = $baseKey.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
        if ($null -eq $uninstallKey) { return @() }

        foreach ($subKeyName in $uninstallKey.GetSubKeyNames()) {
            $subKey = $null
            try {
                $subKey = $uninstallKey.OpenSubKey($subKeyName)
                if ($null -eq $subKey) { continue }
                $displayName = [string]$subKey.GetValue('DisplayName')
                if ($displayName -match '^Microsoft (?<Family>Windows Desktop|\.NET) Runtime - (?<Version>10\.0\.12) \(x64\)') {
                    $results += [pscustomobject]@{
                        KeyName              = $subKeyName
                        DisplayName          = $displayName
                        Family               = $Matches.Family
                        QuietUninstallString = [string]$subKey.GetValue('QuietUninstallString')
                        UninstallString      = [string]$subKey.GetValue('UninstallString')
                    }
                }
            }
            finally {
                if ($null -ne $subKey) { $subKey.Dispose() }
            }
        }
    }
    finally {
        if ($null -ne $uninstallKey) { $uninstallKey.Dispose() }
        if ($null -ne $baseKey) { $baseKey.Dispose() }
    }
    return @($results)
}

function Invoke-CommandLineUninstall {
    param([Parameter(Mandatory)]$Entry)
    $command = $Entry.QuietUninstallString
    if ([string]::IsNullOrWhiteSpace($command)) { $command = $Entry.UninstallString }
    if ([string]::IsNullOrWhiteSpace($command)) { throw "No uninstall command for $($Entry.DisplayName)." }

    if ($command -match '(?i)msiexec(?:\.exe)?\s+.*?(\{[0-9A-F-]{36}\})') {
        $process = Start-Process 'msiexec.exe' -ArgumentList "/x $($Matches[1]) /qn /norestart" -Wait -PassThru
    }
    else {
        if ($command -notmatch '(?i)(^|\s)/quiet(\s|$)') { $command += ' /quiet' }
        if ($command -notmatch '(?i)(^|\s)/norestart(\s|$)') { $command += ' /norestart' }
        $process = Start-Process $env:ComSpec -ArgumentList "/d /s /c `"$command`"" -Wait -PassThru
    }

    Write-Log "Uninstaller exit code for $($Entry.DisplayName): $($process.ExitCode)"
    if ($process.ExitCode -in @(3010, 1641)) { $script:RebootRequired = $true; return }
    if ($process.ExitCode -notin @(0, 1605, 1614)) {
        throw "Uninstall failed for $($Entry.DisplayName) with exit code $($process.ExitCode)."
    }
}

try {
    Write-Log 'Starting removal of Microsoft .NET Desktop Runtime 10.0.12 x64.'

    # Prefer the original signed bundle when it is available in the Intune content.
    if (Test-Path -LiteralPath $InstallerPath) {
        $process = Start-Process -FilePath $InstallerPath -ArgumentList '/uninstall /quiet /norestart' -Wait -PassThru
        Write-Log "Desktop Runtime bundle uninstall exit code: $($process.ExitCode)"
        if ($process.ExitCode -in @(3010, 1641)) { $RebootRequired = $true }
        elseif ($process.ExitCode -notin @(0, 1605, 1614)) {
            throw "Desktop Runtime bundle uninstall failed with exit code $($process.ExitCode)."
        }
    }

    # Remove any exact-version Desktop/Base Runtime registration left behind.
    $entries = @(Get-ExactTargetEntries | Sort-Object @{ Expression = { if ($_.Family -eq 'Windows Desktop') { 0 } else { 1 } } })
    foreach ($entry in $entries) {
        $stillInstalled = @(Get-ExactTargetEntries | Where-Object { $_.KeyName -eq $entry.KeyName })
        if ($stillInstalled.Count -gt 0) { Invoke-CommandLineUninstall -Entry $stillInstalled[0] }
    }

    Write-Log 'Uninstall operation completed. Other versions and x64 installations were not targeted.'
    if ($RebootRequired) { exit 3010 }
    exit 0
}
catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    Write-Log $_.ScriptStackTrace
    exit 1
}

