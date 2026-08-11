# Remediation - Remove DuckDuckGo

## Overview

This Intune Remediation package detects and silently removes the **DuckDuckGo browser** from Windows devices — machine-wide, per-user, and Microsoft Store installs. Use it when policy requires that no DuckDuckGo browser remains on managed devices.

Detection is **MSIX-first**: the DuckDuckGo browser for Windows ships primarily as an MSIX/Store package (`DuckDuckGo.DesktopBrowser`) — even the website's exe installer registers the MSIX package — so the Appx checks are the main signal, with classic registry/folder checks as the backstop. Remediation removes the package for all users **and deprovisions it** so new user profiles don't get it back.

---

## Scripts

| File | Purpose |
|---|---|
| `Detect-DuckDuckGo.ps1` | Read-only detection — exits 1 if any DuckDuckGo browser install is found, exits 0 if clean |
| `Remediate-DuckDuckGo.ps1` | Removes all DuckDuckGo installs and leftovers, then re-verifies with the same rules detection uses |
| `DEPLOYMENT-DuckDuckGo.md` | Full deployment guide with the complete location coverage map |

---

## How It Works

### Detection Script
1. Checks for the DuckDuckGo MSIX/Store package for any user, plus provisioned copies (Microsoft publishers are excluded as a safety net)
2. Scans HKLM Uninstall keys in both the 64-bit and 32-bit registry views
3. Sweeps every user profile's Uninstall keys — logged-off profiles have their NTUSER.DAT hive loaded temporarily and always unloaded afterwards
4. Checks for `DuckDuckGo.exe` on disk in the known machine and per-profile install folders (folder-only leftovers with no binary are not findings)
5. Exits 1 if anything is found, 0 if the device is clean

### Remediation Script
1. Stops all running DuckDuckGo processes (by name and by install path)
2. Removes the MSIX/Store package for all users and deprovisions it
3. Uninstalls classic (ARP) entries — MSI-coded via `msiexec /x /qn /norestart`, non-MSI via direct key deletion
4. Deletes the machine-wide DuckDuckGo folders; locked files are queued for delete-on-reboot
5. Sweeps every user profile: uninstall keys, Run values, app and browser-data folders, leftover Store package data, Classes keys, and shortcuts
6. Cleans machine-level leftovers: HKLM Run values (both views), vendor/Classes keys, Start Menu and Public Desktop shortcuts
7. Runs a verify pass using the identical rules as detection — any residual exits 1 so Intune reports the device honestly

Idempotent: a second run on a clean device is a no-op that exits 0.

---

## Configuration

The `CONFIG` block at the top of each script must stay **identical in both files**:

| Variable | Default | Purpose |
|---|---|---|
| `$DuckStrongName` | `(?i)duckduckgo` | Name match used to classify uninstall entries |
| `$DuckBinaryNames` | `DuckDuckGo.exe` | Binaries that gate a folder finding |
| `$MachineDirs` | `Program Files\DuckDuckGo` (+ x86) | Machine-wide install folders |
| `$UserAppDirRel` | `AppData\Local\Programs\DuckDuckGo`, `AppData\Local\DuckDuckGo\Application` | Per-profile app folders |

The remediation script also has a remediation-only section (data folders, Store package data patterns, process names, shortcut/Run-value regex) that is not part of the shared classifier.

---

## Intune Setup

1. Go to Microsoft Intune Admin Center → Devices → Scripts and remediations → **Create**
2. Detection script: upload `Detect-DuckDuckGo.ps1`; Remediation script: upload `Remediate-DuckDuckGo.ps1`
3. Set options:
   - Run this script using the logged-on credentials: **No** (SYSTEM)
   - Enforce script signature check: **No**
   - Run script in 64-bit PowerShell: **Yes** (required)
4. Assign to the target device group; schedule daily (or hourly for the initial cleanup wave)

Recommended: also assign the Store app (Microsoft Store app (new): *DuckDuckGo Browser*) as **Uninstall** in Intune app management, so the Store cannot reinstall it between remediation runs.

See [DEPLOYMENT-DuckDuckGo.md](DEPLOYMENT-DuckDuckGo.md) for the full deployment guide and location coverage map.

---

## Exit Codes

| Script | Exit 0 | Exit 1 |
|---|---|---|
| `Detect-DuckDuckGo.ps1` | Clean — no DuckDuckGo browser found | DuckDuckGo found (triggers remediation); script errors also exit 1 |
| `Remediate-DuckDuckGo.ps1` | Success or no-op — **including "removal done, reboot pending"** | At least one action failed or residual DuckDuckGo remains |

Reboot-pending counts as success: a locked file queued for delete-on-reboot is treated as compliant by detection and as success by remediation, so devices don't flap between runs.

---

## Logs

Full transcripts are written to `C:\ProgramData\Monster\Logs`:

- `Detect-DuckDuckGo_<timestamp>.log`
- `Remediate-DuckDuckGo_<timestamp>.log`
- `MsiUninstall-DuckDuckGo_*.log` (verbose msiexec log, only if an MSI uninstall runs)

Each script also emits exactly one output line that Intune captures as the pre/post remediation detection output.

---

## Safety Notes

- Removes the DuckDuckGo **browser application only** — it does not (and cannot) block duckduckgo.com as a website or search engine; that belongs to browser/search policy
- Never uses `Win32_Product` (which triggers MSI self-repair storms)
- Only deletes folders, registry keys, Run values, Classes keys, and shortcuts that match the DuckDuckGo classifier — nothing shared with other software is touched
- Folder findings are binary-gated: empty leftover folders never flag a device as non-compliant
- Offline user hives are always unloaded (with retry) after loading; orphaned hive mounts from a prior crashed run are cleaned at startup
- No forced reboots — MSI uninstalls run with `/norestart REBOOT=ReallySuppress`
