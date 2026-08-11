# Remediation - Remove Crestron AirMedia

## Overview

This Intune Remediation package detects and silently removes **Crestron AirMedia** from Windows devices — every version and every install scope, including the machine-wide MSI installer and per-user copies installed under individual user profiles. Use it when AirMedia should no longer be present on managed devices and you want Intune to keep enforcing that automatically.

---

## Scripts

| File | Purpose |
|---|---|
| `Detect-CrestronAirMedia.ps1` | Checks HKLM, every user registry hive (active and offline), and known file paths for AirMedia — exits 1 if found, 0 if clean |
| `Remediate-CrestronAirMedia.ps1` | Silently uninstalls every AirMedia entry found (MSI and EXE), then removes leftover folders and shortcuts |

---

## How It Works

### Detection Script
1. Scans the HKLM uninstall keys (64-bit and 32-bit) for any `DisplayName` matching `*AirMedia*`
2. Enumerates all user profiles; reads already-mounted hives for logged-in users directly, and temporarily mounts `NTUSER.DAT` for users who are not logged in (unloading it afterwards)
3. Falls back to checking `Program Files\Crestron\AirMedia` and `Program Files (x86)\Crestron\AirMedia` on disk
4. Returns `exit 1` (non-compliant) if anything is found, `exit 0` (compliant) otherwise

### Remediation Script
1. Stops any running AirMedia processes so the uninstall cannot fail on locked files
2. Walks the same HKLM and per-user uninstall keys as detection, deduplicating by name + version
3. For MSI entries: runs `msiexec /x <GUID> /qn /norestart REBOOT=ReallySuppress`, retrying on 1618 (another install in progress) and falling back to `Win32_Product` uninstall if msiexec fails (e.g. cached source missing)
4. For EXE entries: prefers `QuietUninstallString`; if only `UninstallString` exists, appends silent flags (`/S /silent /quiet /norestart`)
5. Bounds every uninstall with a 300-second timeout so the script can never hang
6. Removes leftover folders and Start Menu shortcuts for both the legacy (`Crestron\AirMedia`) and modern 5.x (`Crestron Electronics, Inc\AirMedia`) layouts, machine-wide and per profile
7. Verifies the HKLM uninstall keys are clean and always writes a final summary line so Intune never records empty output

---

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `$AppFilter` | `*AirMedia*` | DisplayName wildcard used to match uninstall entries |
| `$LogFile` | `C:\Windows\Temp\<script>_<timestamp>.log` | Timestamped log file path |
| `$ProcTimeoutSec` | `300` | Max seconds to wait for any single uninstall (remediation only) |
| `$MsiSuccess` | `0, 1605, 1614, 1641, 3010` | msiexec exit codes treated as success (remediation only) |

---

## Intune Setup

### Step 1 — Create the Remediation
1. Go to Microsoft Intune Admin Center → Devices → Remediations
2. Click Create script package
3. Fill in:
   - Name: Remove Crestron AirMedia
   - Description: Detects and silently removes all versions of Crestron AirMedia (machine-wide and per-user)
4. Click Next

### Step 2 — Upload the Scripts
1. Detection script: upload `Detect-CrestronAirMedia.ps1`
2. Remediation script: upload `Remediate-CrestronAirMedia.ps1`
3. Set options:
   - Run using logged-on credentials: No (runs as SYSTEM)
   - Enforce script signature check: No
   - Run script in 64-bit PowerShell: Yes
4. Click Next

### Step 3 — Set the Schedule
1. Assign to the target device group
2. Set schedule (daily is a sensible default; hourly if you want faster cleanup)
3. Click Create

---

## Exit Codes

| Script | Exit Code | Meaning |
|---|---|---|
| Detection | `0` | Compliant — no AirMedia found anywhere |
| Detection | `1` | Non-compliant — AirMedia found; remediation runs |
| Remediation | `0` | Success — every entry uninstalled and HKLM verified clean |
| Remediation | `1` | Failure — at least one uninstall failed or an HKLM entry remains |

msiexec exit codes `1641` and `3010` (reboot required) and `1605`/`1614` (product not installed) are treated as **success** by the remediation — a pending reboot does not fail the run.

---

## Logs

Both scripts write timestamped logs to `C:\Windows\Temp` (always writable by SYSTEM):

- `C:\Windows\Temp\Detect-CrestronAirMedia_<yyyyMMdd_HHmmss>.log`
- `C:\Windows\Temp\Remediate-CrestronAirMedia_<yyyyMMdd_HHmmss>.log`

The remediation also echoes its log lines and a final summary to standard output, so the result is visible in the Intune remediation output columns.

---

## Safety Notes

- Only entries whose DisplayName matches `*AirMedia*` are touched — **other Crestron products are left alone**
- Folder cleanup targets only AirMedia-specific paths; the parent `Crestron` / `Crestron Electronics, Inc` folders and any other contents are not removed
- User hives that are already mounted (logged-in users) are read in place, never re-loaded; temporarily mounted hives are always unloaded afterwards
- All uninstalls run with reboot suppression — the script never restarts the device
- Safe to re-run: already-removed entries simply stop being detected, and detection exits 0 so remediation is skipped

---

## Author

Saeid Agheli — Intune Administrator
https://github.com/saeidagheli88
