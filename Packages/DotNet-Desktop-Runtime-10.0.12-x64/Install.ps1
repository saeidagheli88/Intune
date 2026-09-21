[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$TargetVersion = [version]'10.0.12'
$InstallerName = 'windowsdesktop-runtime-10.0.12-win-x64.exe'
$InstallerPath = Join-Path $PSScriptRoot $InstallerName
$LogDirectory = 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs'
$LogPath = Join-Path $LogDirectory 'DotNet-Desktop-Runtime-10.0.12-x64-Install.log'
$RebootRequired = $false

New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null

function Write-Log {
    param([Parameter(Mandatory)][string]$Message)
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $PID, $Message
    $line | Out-File -FilePath $LogPath -Append -Encoding utf8
}

function Get-X64DotNetRuntimeEntries {
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
                if ($displayName -notmatch '^Microsoft (?<Family>Windows Desktop|\.NET) Runtime - (?<Version>10\.0\.\d+) \(x64\)') {
                    continue
                }

                $results += [pscustomobject]@{
                    KeyName              = $subKeyName
                    DisplayName          = $displayName
                    Family               = $Matches.Family
                    Version              = [version]$Matches.Version
                    QuietUninstallString = [string]$subKey.GetValue('QuietUninstallString')
                    UninstallString      = [string]$subKey.GetValue('UninstallString')
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

function Invoke-RegisteredUninstall {
    param([Parameter(Mandatory)]$Entry)

    $command = $Entry.QuietUninstallString
    if ([string]::IsNullOrWhiteSpace($command)) {
        $command = $Entry.UninstallString
    }
    if ([string]::IsNullOrWhiteSpace($command)) {
        throw "No uninstall command is registered for $($Entry.DisplayName)."
    }

    if ($command -match '(?i)msiexec(?:\.exe)?\s+.*?(\{[0-9A-F-]{36}\})') {
        $productCode = $Matches[1]
        $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList "/x $productCode /qn /norestart" -Wait -PassThru
    }
    else {
        if ($command -notmatch '(?i)(^|\s)/quiet(\s|$)') { $command += ' /quiet' }
        if ($command -notmatch '(?i)(^|\s)/norestart(\s|$)') { $command += ' /norestart' }
        $cmdArguments = "/d /s /c `"$command`""
        $process = Start-Process -FilePath $env:ComSpec -ArgumentList $cmdArguments -Wait -PassThru
    }

    Write-Log "Uninstaller exit code for $($Entry.DisplayName): $($process.ExitCode)"

    if ($process.ExitCode -in @(3010, 1641)) {
        $script:RebootRequired = $true
        return
    }
    if ($process.ExitCode -notin @(0, 1605, 1614)) {
        throw "Uninstall failed for $($Entry.DisplayName) with exit code $($process.ExitCode)."
    }
}

function Get-X64RuntimeInventory {
    $dotnetX64 = Join-Path $env:SystemDrive 'Program Files\dotnet\dotnet.exe'
    if (-not (Test-Path -LiteralPath $dotnetX64)) { return @() }
    return @(& $dotnetX64 --list-runtimes 2>$null)
}

try {
    Write-Log 'Starting Microsoft .NET Desktop Runtime 10.0.12 x64 deployment.'

    if (-not (Test-Path -LiteralPath $InstallerPath)) {
        throw "Required installer is missing from the package: $InstallerName"
    }

    $signature = Get-AuthenticodeSignature -FilePath $InstallerPath
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Microsoft Corporation') {
        throw "Installer signature validation failed. Status: $($signature.Status); Signer: $($signature.SignerCertificate.Subject)"
    }
    Write-Log "Installer signature is valid: $($signature.SignerCertificate.Subject)"

    $installProcess = Start-Process -FilePath $InstallerPath -ArgumentList '/install /quiet /norestart' -Wait -PassThru
    Write-Log "Desktop Runtime installer exit code: $($installProcess.ExitCode)"

    if ($installProcess.ExitCode -in @(3010, 1641)) {
        $RebootRequired = $true
    }
    elseif ($installProcess.ExitCode -ne 0) {
        throw "Desktop Runtime installation failed with exit code $($installProcess.ExitCode)."
    }

    # Remove only Microsoft .NET 10.0.x x64 Desktop/Base Runtime patches older than 10.0.12.
    # Desktop entries are removed first, followed by any remaining base-runtime entries.
    $olderEntries = @(Get-X64DotNetRuntimeEntries | Where-Object {
        $_.Version.Major -eq 10 -and $_.Version.Minor -eq 0 -and $_.Version -lt $TargetVersion
    } | Sort-Object @{ Expression = { if ($_.Family -eq 'Windows Desktop') { 0 } else { 1 } } }, Version)

    if ($olderEntries.Count -eq 0) {
        Write-Log 'No older .NET 10.0.x x64 Desktop/Base Runtime entries were found.'
    }

    foreach ($entry in $olderEntries) {
        # A Desktop Runtime uninstall can remove a dependent base-runtime entry. Recheck before each action.
        $stillInstalled = @(Get-X64DotNetRuntimeEntries | Where-Object { $_.KeyName -eq $entry.KeyName })
        if ($stillInstalled.Count -eq 0) {
            Write-Log "Skipping an entry already removed by a previous bundle: $($entry.DisplayName)"
            continue
        }

        Write-Log "Removing older x64 runtime: $($entry.DisplayName)"
        Invoke-RegisteredUninstall -Entry $stillInstalled[0]
    }

    $inventory = Get-X64RuntimeInventory
    $desktopVersions = @($inventory | ForEach-Object {
        if ($_ -match '^Microsoft\.WindowsDesktop\.App\s+(10\.0\.\d+)\s') { [version]$Matches[1] }
    })
    $baseVersions = @($inventory | ForEach-Object {
        if ($_ -match '^Microsoft\.NETCore\.App\s+(10\.0\.\d+)\s') { [version]$Matches[1] }
    })

    if ($TargetVersion -notin $desktopVersions) { throw 'Microsoft.WindowsDesktop.App 10.0.12 x64 was not detected after installation.' }
    if ($TargetVersion -notin $baseVersions) { throw 'Microsoft.NETCore.App 10.0.12 x64 was not detected after installation.' }

    $olderDesktop = @($desktopVersions | Where-Object { $_ -lt $TargetVersion })
    $olderBase = @($baseVersions | Where-Object { $_ -lt $TargetVersion })
    if ($olderDesktop.Count -gt 0 -or $olderBase.Count -gt 0) {
        throw "Older .NET 10.0.x x64 runtimes remain. Desktop: $($olderDesktop -join ', '); Base: $($olderBase -join ', ')"
    }

    Write-Log 'Deployment verification succeeded. Desktop and base Runtime 10.0.12 x64 are installed; older 10.0.x x64 patches are absent.'
    if ($RebootRequired) {
        Write-Log 'A soft reboot is required.'
        exit 3010
    }
    exit 0
}
catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    Write-Log $_.ScriptStackTrace
    exit 1
}

