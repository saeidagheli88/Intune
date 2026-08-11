# Remediation - Remove Webex

## Overview

This Intune Remediation package detects and silently removes **ALL Cisco Webex products** from Windows devices — the modern unified Webex App (machine-wide and per-user), classic Cisco Webex Meetings, Webex Meetings Desktop App, Webex Productivity Tools, and the old Webex Teams / Cisco Spark client, including Microsoft Store (MSIX) installs and provisioned packages. Use it when the organization has standardized on another meeting platform and no Webex client is allowed to remain.

The shared classifier is anchored on `webex` / `cisco spark`, so it can never match Cisco AnyConnect, Cisco Secure Client, Cisco Jabber, the standalone Readdle "Spark" mail app, or Microsoft's `MicrosoftWindows.Client.WebExperience` (Windows Widgets) package.

> **Warning:** remediation force-stops every Webex process before uninstalling — it will kill a live meeting. Send user communications before assigning this broadly.

---

## Scripts

| File | Purpose |
|---|---|
| `Detect-Webex.ps1` | Read-only detection — exits 1 if any Webex product is found (machine or per-user), exits 0 if clean |
| `Remediate-Webex.ps1` | Removes every Webex product, cleans leftovers, then re-verifies with the identical detection rules |
| `Add-WebexDevicesToGroup.ps1` | One-time **admin-workstation** Microsoft Graph helper that fills the targeting Entra group from a device-name CSV — never runs on endpoints |
| `DEPLOYMENT-Webex.md` | Full deployment guide: location coverage map, pilot plan, timeline, known failure signatures |

---

## How It Works

### Detection Script (read-only)
1. Scans HKLM Uninstall keys in **both** 64-bit and 32-bit registry views for Webex entries
2. Sweeps every user profile's HKU Uninstall keys — logged-off `NTUSER.DAT` hives are temporarily `reg load`ed and always unloaded afterwards
3. Checks known machine and per-profile install folders for Webex **binaries** (empty leftover folders are not findings; a binary already queued for delete-on-reboot is not a finding)
4. Checks MSIX/Store packages (all users) and provisioned packages for Cisco-published Webex
5. Exits 1 on any finding, 0 if clean

### Remediation Script
1. Stops every running Webex process (no "meeting in progress" guard)
2. Uninstalls machine-wide MSI products via `msiexec /x <code> /qn /norestart`; deletes orphaned ARP keys that survive an auto-update; brute-force deletes non-MSI ARP keys
3. Deletes the machine-wide Webex folders — locked files are queued for delete-on-reboot via `MoveFileEx`
4. Sweeps every user profile: per-user uninstall keys, Run values, app folders, user-data folders, and shortcuts
5. Cleans machine leftovers: HKLM Run values, vendor registry keys, `webex:`/`wbx*` protocol handlers, the classic `webexservice` service, Start Menu / Public Desktop shortcuts
6. Removes Cisco-published MSIX packages for all users and deprovisions them
7. Runs a **verify pass** using the identical detection rules — any residual Webex makes the run exit 1 so Intune reports the device honestly

### Add-WebexDevicesToGroup.ps1 (admin workstation only)
1. Connects to Microsoft Graph (`Group.ReadWrite.All`, `Device.Read.All`) using the Microsoft Graph PowerShell SDK
2. Reads device names from a CSV, resolves each to its Entra device object, and adds it to the targeting group (already-present members are skipped, unresolved names are listed at the end)
3. Example: `.\Add-WebexDevicesToGroup.ps1 -GroupName "<your-remediation-group>"`

---

## Configuration

The CONFIG block at the top of both scripts **must stay identical** in the pair:

| Variable | Purpose |
|---|---|
| `$WebexStrongName` / `$WebexLooseName` | Name classifier regexes (loose match also requires a Cisco publisher) |
| `$WebexBinaryNames` | Binaries that make a folder count as a finding |
| `$MachineDirs` / `$UserAppDirRel` | Machine-wide and per-profile install folders to check/remove |
| `$UserDataDirRel`, `$RegLeftoverNames`, `$WebexClassesKeyRegex`, `$WebexProcesses` (remediation only) | Opportunistic cleanup targets — never detection findings |

---

## Intune Setup

1. Intune admin center → **Devices** → **Remediations** → **Create script package**
2. Upload `Detect-Webex.ps1` as the detection script and `Remediate-Webex.ps1` as the remediation script
3. Set options:
   - Run this script using the logged-on credentials: **No** (SYSTEM)
   - Enforce script signature check: No
   - Run script in 64-bit PowerShell: **Yes** (required)
4. Assign to the targeting device group and schedule **daily**

Pilot on a small group first — see [DEPLOYMENT-Webex.md](DEPLOYMENT-Webex.md) for the full coverage map, pilot mix, rollout timeline, and known failure signatures.

---

## Exit Codes

| Script | Exit 0 | Exit 1 |
|---|---|---|
| `Detect-Webex.ps1` | Clean — no Webex found (binaries already queued for delete-on-reboot count as clean) | Webex found → triggers remediation; fatal errors also exit 1 |
| `Remediate-Webex.ps1` | Success or no-op — **including "reboot pending"** (MSI 3010/1641 or locked files queued for delete-on-reboot count as success) | At least one action failed or residual Webex remained after the verify pass |

---

## Logs

All runs write transcripts to `C:\ProgramData\Monster\Logs`:

- `Detect-Webex_<timestamp>.log`
- `Remediate-Webex_<timestamp>.log`
- `MsiUninstall-Webex_<productcode>_<timestamp>.log` — verbose msiexec log per MSI product

---

## Safety Notes

- **Never touched:** Cisco AnyConnect, Cisco Secure Client, Cisco Jabber, the Readdle "Spark" mail app (`spark` only matches when prefixed with `cisco`), and Microsoft's `MicrosoftWindows.Client.WebExperience` (Windows Widgets) MSIX package
- Never uses `Win32_Product` (which would trigger MSI self-repair storms)
- User-data folders, shortcuts, Run values, and leftover vendor keys are cleaned opportunistically but are never detection findings, so a stubborn leftover cannot make compliance flap
- Offline user hives are always unloaded (with retry) after use; orphaned hive mounts from a crashed prior run are cleaned at startup
- Idempotent — a second run on a clean device is a no-op exiting 0
