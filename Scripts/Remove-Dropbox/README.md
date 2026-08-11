# Remediation - Remove Dropbox

## Overview

This Intune Remediation package detects and silently removes **all Dropbox desktop app installs** from Windows devices — the classic per-user app (`AppData\Local\Dropbox`), machine-wide enterprise installs (`Program Files (x86)\Dropbox`), the Dropbox Update machinery (services + scheduled tasks that could reinstall the app), and the Microsoft Store (MSIX) package. Use it when Dropbox is not an approved app and every copy must go.

**The user's synced files are never touched.** The synced-content folder (`<profile>\Dropbox`, or a custom location) is data, not the app — it is never scanned, never a detection finding, and never deleted. Files already synced remain in that local folder and in the Dropbox cloud; anything not yet uploaded stays safely in the local folder.

---

## Scripts

| File | Purpose |
|---|---|
| `Detect-Dropbox.ps1` | Read-only detection — exits 1 if any Dropbox app install is found, exits 0 if clean |
| `Remediate-Dropbox.ps1` | Removes every Dropbox app install, updater, service, task, and registry footprint, then verifies |
| `DEPLOYMENT-Dropbox.md` | Full deployment guide: location coverage map, design rationale, known limitations |

---

## How It Works

### Detection Script (read-only)
1. Scans HKLM uninstall entries in **both** 64-bit and 32-bit registry views (catches "Dropbox" and "Dropbox Update Helper")
2. Sweeps per-user (HKU) uninstall entries for **every** profile — logged-off users' NTUSER.DAT hives are temporarily loaded and always unloaded afterwards
3. Checks the known app folders (`Program Files [x86]\Dropbox`, each profile's `AppData\Local\Dropbox`) for live Dropbox binaries (`Dropbox.exe`, `DropboxUpdate.exe`, `DbxSvc.exe`) — folder-only leftovers with no binary are not findings, and a binary already queued for delete-on-reboot is not a finding (loop safety)
4. Checks for any Dropbox MSIX/Store package (installed for any user, or provisioned)
5. Exits 1 on any finding, 0 if clean

### Remediation Script
1. Stops Dropbox processes — by name, then by path, with the path match restricted to the app folders (`\Dropbox\Client\`, `\Dropbox\Update\`) so nothing running out of a user's synced folder is ever killed
2. For machine-wide installs, tries the official `DropboxUninstaller.exe /S` first (bounded 180-second wait, any failure tolerated)
3. Removes surviving machine ARP entries: MSI-coded entries via `msiexec /x` (1605/3010/1641 handled), everything else by direct key deletion
4. Stops and deletes Dropbox services — matched by **binary path** (`\Dropbox\Update\`, `System32\DbxSvc.exe`), never by name alone — and unregisters `Dropbox*` scheduled tasks
5. Deletes the machine app folders; locked files are queued for delete-on-reboot
6. Sweeps every user profile: per-user uninstall keys, Run values, the app folder (`AppData\Local\Dropbox`), settings (`AppData\Roaming\Dropbox`), Classes keys, and shortcuts — never the synced-content folder
7. Cleans machine leftovers: Run values, vendor keys, Classes keys, `DropboxExt` shell icon overlays, Start Menu / Public Desktop shortcuts
8. Removes any Dropbox MSIX package for all users and deprovisions it
9. Runs a verify pass using the identical rules as detection — any residual makes the script exit 1 so Intune reports the device honestly

---

## Configuration

The CONFIG block at the top of each script must stay **identical in both files**. Variables an admin might adjust:

| Variable | Default | Meaning |
|---|---|---|
| `$DbxStrongName` / `$DbxLooseName` | `^\s*dropbox\b` / `\bdropbox\b` + Dropbox publisher | How uninstall entries are classified as Dropbox |
| `$DbxBinaryNames` | `Dropbox.exe`, `DropboxUpdate.exe`, `DbxSvc.exe` | Binaries that make an app folder a finding |
| `$MachineDirs` | `Program Files\Dropbox`, `Program Files (x86)\Dropbox` | Machine-wide app folders scanned/removed |
| `$UserAppDirRel` | `AppData\Local\Dropbox` | Per-profile app folder (never the synced folder) |
| `$UserDataDirRel` (remediate only) | `AppData\Roaming\Dropbox` | Settings folder cleaned opportunistically |

---

## Intune Setup

1. Go to Microsoft Intune Admin Center → Devices → Scripts and remediations → Create
2. Upload `Detect-Dropbox.ps1` as the detection script and `Remediate-Dropbox.ps1` as the remediation script
3. Set options:
   - Run this script using the logged-on credentials: **No** (runs as SYSTEM)
   - Enforce script signature check: **No**
   - Run script in 64-bit PowerShell: **Yes** (required)
4. Assign to the target device group with a daily schedule (hourly for the initial cleanup wave)

Full setting-by-setting detail, the location coverage map, and known limitations are in [DEPLOYMENT-Dropbox.md](DEPLOYMENT-Dropbox.md).

---

## Exit Codes

| Script | Exit 0 | Exit 1 |
|---|---|---|
| `Detect-Dropbox.ps1` | Clean — no Dropbox app found (machine or per-user) | Dropbox found → remediation runs; script errors also exit 1 |
| `Remediate-Dropbox.ps1` | Success or no-op — **including "reboot pending"** (locked files queued for delete-on-reboot count as success) | At least one action failed, or residual Dropbox found by the verify pass |

The reboot-pending rule works on both sides: remediation queues locked files via `PendingFileRenameOperations` and still exits 0, and detection treats those queued binaries as compliant — so a device waiting on a reboot never flaps between "found" and "fixed".

---

## Logs

- `C:\ProgramData\Monster\Logs\Detect-Dropbox_<timestamp>.log` — full detection transcript
- `C:\ProgramData\Monster\Logs\Remediate-Dropbox_<timestamp>.log` — full remediation transcript
- `C:\ProgramData\Monster\Logs\MsiUninstall-Dropbox_*.log` — verbose msiexec logs when an MSI uninstall runs
- Intune shows exactly one pre/post remediation output line per device (the scripts emit a single summary line to STDOUT)

---

## Safety Notes

- **Synced files are sacred**: the synced-content folder (`<profile>\Dropbox`, or a custom location) is never listed, scanned, deleted, or reported. Only the app, its settings, updater, services, tasks, and registry footprint are removed.
- **Path-restricted process kills**: the path-based kill only matches `\Dropbox\Client\` and `\Dropbox\Update\` — never a bare `\Dropbox\`, so processes running from a synced folder are untouched.
- **Path-matched services**: services are matched by their binary path, never by name alone, so an unrelated service that happens to be named similarly is never deleted.
- **No Microsoft packages**: Appx matching excludes Microsoft-published packages; the uninstall-entry classifier requires the name to start with "Dropbox" or carry a Dropbox publisher.
- **Shortcut cleanup removes `.lnk`/`.url` files only** — never folders with content.
- **Offline user hives are always unloaded** (with retry) after scanning, so no user's logon is blocked by a leftover mounted hive.
- **Idempotent**: a second run on a clean device is a no-op exit 0.

---

## Author

Saeid Agheli — Intune Administrator
https://github.com/saeidagheli88
