# Tool - RemoveApp Script Generator

## Overview

An **offline HTML tool** (not an Intune script) that generates ready-to-deploy Windows app-removal PowerShell scripts in the house style: SYSTEM context, 64-bit relaunch guard, logging to `C:\ProgramData\Monster\Logs`, and exit codes 0/1. Type an app's details into the form and download a `Remove-<App>.ps1` — plus an optional matching `Detect-<App>.ps1` for use as an Intune Remediation pair.

Use it whenever you need a new app-removal script and don't want to hand-write the registry scanning, uninstall, and safety boilerplate. The pattern is based on the PatchMyPC Community-Scripts Pre-Install / Uninstall-Software approach.

---

## Scripts

| File | Purpose |
|---|---|
| `RemoveApp-Script-Generator.html` | Single-file web form that generates `Remove-<App>.ps1` and optionally `Detect-<App>.ps1` |

---

## How It Works

### Using the Tool
1. Open `RemoveApp-Script-Generator.html` in any browser — it is fully client-side with no network calls, so it works offline
2. Fill in the form: app name, DisplayName pattern(s), optional publisher filter, processes to stop, silent uninstall args, leftover folders
3. Optionally tick **Also generate a matching Detect script** for an Intune Remediation pair
4. Click **Generate**, review the preview, then **Download .ps1** (and **Download Detect .ps1** if enabled)

### Generated Remove Script
1. Scans HKLM Uninstall keys (Registry64 + Registry32 views) for DisplayName matches, gated on the publisher filter if set
2. Optionally scans loaded HKU hives (`S-1-5-21-*`) for per-user installs
3. Stops the configured processes — only after a removable artifact is confirmed
4. MSI entries: `msiexec /x {GUID} /qn /norestart REBOOT=ReallySuppress` with a bounded 10-minute wait (exit 0/1605/1641/3010 counted as success)
5. EXE entries: prefers the vendor `QuietUninstallString`, otherwise runs `UninstallString` with the configured silent args
6. Per-user installs: deletes the ARP registry key and install folder directly (a user's uninstaller run as SYSTEM would target the wrong hive)
7. Deletes configured leftover folders (Test-Path and depth-guarded)
8. Re-scans the registry to verify — the result decides the exit code

### Generated Detect Script
1. Runs the same HKLM (and optionally HKU) registry scan with identical patterns and publisher gate
2. Exits 1 (non-compliant) if any match is found, exits 0 (compliant) if none

---

## Configuration (form fields)

| Field | Effect |
|---|---|
| App name | Used in file names, log names, and script output |
| DisplayName pattern(s) | Matched with `-like` against Add/Remove Programs DisplayName; wildcards allowed. **Keep patterns tight** — a broad pattern like `*App*` can match and remove unrelated software |
| Publisher filter | Optional but recommended extra gate — the entry must also match this Publisher |
| Processes to stop | Comma-separated, no `.exe` |
| Silent args for EXE uninstallers | Default `/S` (NSIS). Inno = `/VERYSILENT /NORESTART`, InstallShield = `/s` |
| Leftover folders | One per line; each delete is Test-Path guarded and must be at least 3 path segments deep |
| Also remove per-user installs | Include loaded HKU hives (default on) |
| Also generate a Detect script | Produces the companion detection script for a Remediation pair |

---

## Intune Setup (for the generated pair)

1. Go to Microsoft Intune Admin Center > Devices > Remediations > Create script package
2. Detection script: upload the generated `Detect-<App>.ps1`
3. Remediation script: upload the generated `Remove-<App>.ps1`
4. Set options:
   - Run using logged-on credentials: No (SYSTEM)
   - Enforce script signature check: No
   - Run script in 64-bit PowerShell: Yes
5. Assign to the target device group and set a schedule (e.g., daily)

Always test the generated scripts on a pilot device or group before broad assignment.

---

## Exit Codes (generated scripts)

| Script | Exit 0 | Exit 1 |
|---|---|---|
| `Detect-<App>.ps1` | Not found — compliant | Found — remediation runs |
| `Remove-<App>.ps1` | All matching installs removed, or nothing found (idempotent no-op) | At least one removal failed or residual entries remain after verification |

MSI uninstall exit codes 1641 and 3010 (reboot initiated / reboot required) are treated as success by the Remove script; the reboot itself is suppressed with `/norestart REBOOT=ReallySuppress`.

---

## Logs

Generated scripts write timestamped logs to:

```
C:\ProgramData\Monster\Logs\Remove-<App>_yyyyMMdd-HHmmss.log
C:\ProgramData\Monster\Logs\Detect-<App>_yyyyMMdd-HHmmss.log
```

The generator itself writes nothing — it runs entirely in the browser and only downloads the files you request.

---

## Safety Notes

Guards built into every generated script:

- Every `Remove-Item` is Test-Path guarded; folder deletes refuse paths shallower than 3 segments (`X:\folder\subfolder`), so a blank or malformed path can never delete a drive root
- Processes are stopped only after a removable artifact is confirmed on the device
- Uninstallers run with a bounded timeout (10 minutes) and are killed if they hang
- `Win32_Product` is never used (it triggers MSI reconfiguration of unrelated apps)
- Idempotent: a second run on a clean device is a no-op and exits 0

Deliberate limits — the generated scripts do **not**:

- Touch MSIX / Appx (Store) packages
- Modify offline user hives — only loaded HKU hives of logged-on users are processed
- Run per-user uninstallers as SYSTEM (per-user installs are removed by deleting the ARP key and install folder instead)
- Delete anything outside the configured patterns, publisher gate, and folder list — keep DisplayName patterns tight

---

## Author

Saeid Agheli — Intune Administrator
https://github.com/saeidagheli88
