<#
.SYNOPSIS
    One-time admin helper: adds the devices in Webex-Missing-Assignment-Devices.csv
    to the Entra security group used by the "Remove Webex (all clients)" remediation.

.DESCRIPTION
    Runs on YOUR admin workstation (not on endpoints). Requires the Microsoft
    Graph PowerShell SDK and rights to modify the group:
        Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Groups,
                       Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser

    For each DeviceName in the CSV it finds the Entra DEVICE object(s) by
    displayName and adds them as group members. Already-present members are
    skipped. Names that resolve to nothing (renamed/retired devices) are
    reported at the end so you can chase them manually.

.EXAMPLE
    .\Add-WebexDevicesToGroup.ps1 -GroupName "SG-Remediation-RemoveWebex"
#>
param(
    [Parameter(Mandatory)]
    [string]$GroupName,

    [string]$CsvPath = (Join-Path $PSScriptRoot 'Webex-Missing-Assignment-Devices.csv')
)

$ErrorActionPreference = 'Stop'

Connect-MgGraph -Scopes 'Group.ReadWrite.All','Device.Read.All' -NoWelcome

$group = Get-MgGroup -Filter "displayName eq '$GroupName'"
if (-not $group) { throw "Group '$GroupName' not found." }
if (@($group).Count -gt 1) { throw "Multiple groups named '$GroupName'; pass a unique name." }
Write-Host "Target group: $($group.DisplayName) ($($group.Id))"

$existing = (Get-MgGroupMember -GroupId $group.Id -All).Id
$rows     = Import-Csv -Path $CsvPath
$added    = 0; $skipped = 0; $notFound = @()

foreach ($row in $rows) {
    $name = $row.DeviceName.Trim()
    if ([string]::IsNullOrWhiteSpace($name)) { continue }
    $devices = Get-MgDevice -Filter "displayName eq '$name'" -All
    if (-not $devices) {
        Write-Warning "Not found in Entra: $name"
        $notFound += $name
        continue
    }
    foreach ($dev in @($devices)) {
        if ($existing -contains $dev.Id) {
            Write-Host "Already a member: $name ($($dev.Id))"
            $skipped++
            continue
        }
        New-MgGroupMember -GroupId $group.Id -DirectoryObjectId $dev.Id
        Write-Host "Added: $name ($($dev.Id))"
        $added++
    }
}

Write-Host ''
Write-Host "Done. Added: $added | Already present: $skipped | Not found: $($notFound.Count)"
if ($notFound) {
    Write-Host 'Chase these manually (renamed or retired?):'
    $notFound | ForEach-Object { Write-Host "  $_" }
}
