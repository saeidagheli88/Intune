# ===============================
# Convert Co-Managed Device to Intune-only
# Safe to run multiple times
# Run as SYSTEM via Intune
# ===============================
$ErrorActionPreference = 'SilentlyContinue'

# Stop SCCM services if present
'SmsExec','CcmExec','CcmSetup','smstsmgr' | ForEach-Object {
    $svc = Get-Service -Name $_ -ErrorAction SilentlyContinue
    if ($svc) { Stop-Service $_ -Force }
}

# Uninstall SCCM client if still present
$ccmsetup = 'C:\Windows\ccmsetup\ccmsetup.exe'
if (Test-Path $ccmsetup) {
    Start-Process $ccmsetup -ArgumentList '/uninstall' -Wait
}

# Remove registry remnants
$regKeys = @(
  'HKLM:\SOFTWARE\Microsoft\CCM',
  'HKLM:\SOFTWARE\Microsoft\CCMSetup',
  'HKLM:\SOFTWARE\Microsoft\SMS',
  'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\Device\MDM\CoManagement',
  'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Device\MDM\CoManagement',
  'HKLM:\SOFTWARE\Microsoft\SystemCertificates\SMS'
)
foreach ($key in $regKeys) {
  if (Test-Path $key) {
    Remove-Item -Recurse -Force $key
  }
}

# Remove CCM WMI namespaces (CIM-safe)
$namespaces = @('root\ccm','root\sms')
foreach ($ns in $namespaces) {
  try {
    Get-CimInstance -Namespace $ns -ClassName __Namespace | Remove-CimInstance
  } catch {}
}

# Clear CCM cache
Remove-Item 'C:\Windows\ccmcache' -Recurse -Force -ErrorAction SilentlyContinue

# Force Intune enrollment refresh
dsregcmd /refreshprt | Out-Null

# Trigger Intune Management Extension
$ime = "$env:ProgramFiles\Microsoft Intune Management Extension\Microsoft.Management.Services.IntuneWindowsAgent.exe"
if (Test-Path $ime) {
    Start-Process $ime -ArgumentList "-c" -WindowStyle Hidden
}

exit 0
