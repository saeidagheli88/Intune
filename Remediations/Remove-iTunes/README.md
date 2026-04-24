# Remediation - Remove iTunes

## Overview

This Intune Remediation package detects and silently removes **iTunes** from Windows devices. It consists of two PowerShell scripts — a Detection script and a Remediation script — deployed together as an Intune Remediation policy.

---

## Scripts

| File | Purpose |
|---|---|
| `Remove-iTunes-Detection.ps1` | Checks if iTunes is installed — exits 1 if found, exits 0 if not |
| `Remove-iTunes-Remediation.ps1` | Silently uninstalls iTunes and cleans up all related files and registry keys |

---

## How It Works

### Detection Script
1. Checks the Windows registry for the iTunes uninstall key (64-bit and 32-bit paths)
2. Checks if `iTunes.exe` exists at the default install path
3. Returns `exit 1` (non-compliant) if iTunes is found
4. Returns `exit 0` (compliant) if iTunes is not found

### Remediation Script
1. Stops all running iTunes-related processes: iTunes, iTunesHelper, AppleMobileDeviceService
2. Reads the uninstall string from the registry
3. Runs the MSI uninstaller silently with /qn /norestart
4. Falls back to direct MSI uninstall using the App GUID
5. Removes the iTunes folder from C:\Program Files\iTunes
6. Cleans up all related registry keys

---

## iTunes App Details

| Field | Value |
|---|---|
| App GUID | {9D0D2A8B-7E7B-4D88-8D50-24286ED6A5EB} |
| Install Path | C:\Program Files\iTunes\iTunes.exe |
| Registry Key 64-bit | HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ |
| Registry Key 32-bit | HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\ |

---

## Intune Setup

### Step 1 — Create the Remediation
1. Go to Microsoft Intune Admin Center → Devices → Remediations
2. Click Create script package
3. Fill in:
   - Name: Remove iTunes
   - Description: Detects and silently removes iTunes from Windows devices
4. Click Next

### Step 2 — Upload the Scripts
1. Detection script: upload Remove-iTunes-Detection.ps1
2. Remediation script: upload Remove-iTunes-Remediation.ps1
3. Set options:
   - Run using logged-on credentials: No
   - Enforce script signature check: No
   - Run script in 64-bit PowerShell: Yes
4. Click Next

### Step 3 — Set the Schedule
1. Assign to target device group
2. Set schedule (e.g., every 1 hour or daily)
3. Click Create

---

## Notes

- Runs silently with no user interaction or restart required
- Handles both 64-bit and 32-bit iTunes installations
- Safe to re-run — if iTunes is already removed detection exits 0 and remediation is skipped

---

## Author

Saeid Agheli — Intune Administrator
https://github.com/saeidagheli88
