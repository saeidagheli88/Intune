# Remediation - Remove Google Drive

## Overview

This Intune Remediation package detects and silently removes **every Google Drive desktop client** from Windows devices — the current **Google Drive for desktop** (Drive File Stream / DriveFS) and the legacy **Backup and Sync from Google** — machine-wide and per-user (all profiles, including logged-off ones). Use it when policy requires that no Google Drive sync client remain on managed devices.

It deliberately does **not** touch Google Chrome or the shared Google Update machinery, and the user's cloud files are safe — only the local streaming cache is deleted (see [Safety Notes](#safety-notes)).

---

## Scripts

| File | Purpose |
|---|---|
| `Detect-GoogleDrive.ps1` | Read-only detection — exits 1 if any Google Drive client is found, exits 0 if clean |
| `Remediate-GoogleDrive.ps1` | Silently removes all Google Drive clients and leftovers, then verifies with the same rules detection uses |
| `DEPLOYMENT-GoogleDrive.md` | Full deployment guide with a per-location coverage map and known limitations |

---

## How It Works

### Detection Script
1. Scans HKLM Uninstall keys in **both** 64-bit and 32-bit registry views for Google Drive entries (safe classifier: names starting with `Google Drive` / `Drive File Stream` / `Backup and Sync`, or a Google publisher plus the word `drive` — Chrome and OneDrive can never match)
2. Sweeps **every** user profile's HKU Uninstall keys — logged-off `NTUSER.DAT` hives are temporarily loaded and always unloaded afterward
3. Checks for Drive binaries (`GoogleDriveFS.exe`, `googledrivesync.exe`) in the known machine and per-profile folders — folder-only leftovers are not findings, and a binary already queued for delete-on-reboot counts as compliant (loop safety)
4. Checks for any Google Drive MSIX/Store package (any user or provisioned)
5. Exits 1 (non-compliant) on any finding or error; exits 0 if clean

### Remediation Script
1. Stops all Drive processes (by name and by install-folder path, so helper processes are caught too) — stopping DriveFS also **dismounts the virtual G: drive**
2. Tries the official `uninstall.exe --silent --force_stop` for machine installs (best-effort, bounded wait)
3. Removes surviving ARP uninstall entries in both registry views (msiexec for true MSI entries; direct key deletion otherwise)
4. Deletes any Drive-specific service (matched by binary path only) and `GoogleDrive*` scheduled tasks — never the shared Google Update ones
5. Deletes the machine Drive folders; locked files are queued for delete-on-reboot
6. Sweeps every user profile: per-user uninstall keys, Run values, the DriveFS cache folder, legacy sync metadata, Classes keys, and shortcuts
7. Removes machine-level leftovers (Run values, `Google\DriveFS` / `Google\Drive` vendor keys, Classes keys, shortcuts) and any MSIX package
8. Verifies with the identical rules detection uses — any residual exits 1 so Intune reports the device honestly

---

## Configuration

The `CONFIG` block at the top of each script must stay **identical in both files**. Variables an admin might adjust:

| Variable | Purpose |
|---|---|
| `$GDriveStrongName` / `$GDriveLooseName` | Regexes that classify an uninstall entry as Google Drive |
| `$GDriveBinaryNames` | Binaries that gate a folder finding (`GoogleDriveFS.exe`, `googledrivesync.exe`) |
| `$MachineDirs` | Machine install folders — Drive-specific subfolders of `Google\` only |
| `$UserAppDirRel` | Per-profile app/cache folder (`AppData\Local\Google\DriveFS`) |

---

## Intune Setup

1. Go to Microsoft Intune Admin Center → Devices → Remediations → **Create script package**
2. Upload `Detect-GoogleDrive.ps1` as the detection script and `Remediate-GoogleDrive.ps1` as the remediation script
3. Set options:
   - Run this script using the logged-on credentials: **No** (SYSTEM)
   - Enforce script signature check: **No**
   - Run script in 64-bit PowerShell: **Yes** (required)
4. Assign to the target device group and schedule **daily** (hourly for an initial cleanup wave)

See [DEPLOYMENT-GoogleDrive.md](DEPLOYMENT-GoogleDrive.md) for the full deployment guide, location coverage map, and known limitations.

---

## Exit Codes

| Script | Code | Meaning |
|---|---|---|
| Detect | 0 | Clean — no Google Drive client found (a binary queued for delete-on-reboot counts as clean) |
| Detect | 1 | Google Drive client found — remediation runs (fatal detection errors also exit 1) |
| Remediate | 0 | Success or no-op — including "done, **reboot pending**" when locked files were queued for delete-on-reboot |
| Remediate | 1 | At least one action failed, or a residual Drive client remains after the verify pass |

---

## Logs

Full transcripts are written to `C:\ProgramData\Monster\Logs`:

- `Detect-GoogleDrive_<timestamp>.log`
- `Remediate-GoogleDrive_<timestamp>.log`

Intune shows the single summary output line per device (pre- and post-remediation detection output).

---

## Safety Notes

- **Google Chrome and the shared Google Update machinery are never touched** — the `gupdate`/`gupdatem` services, `GoogleUpdateTaskMachine*` scheduled tasks, and the `Google\Update` folder belong to Chrome too. Only Drive-specific subfolders and subkeys of `Google\` are in scope, never the vendor root or the `HKLM\SOFTWARE\Google` key itself.
- **Cloud files are safe.** DriveFS streams files from the cloud; the folder deleted per profile is its local cache (`AppData\Local\Google\DriveFS`). Caveat: any offline edit that has **not yet uploaded** when the client is stopped is lost with the cache — announce the rollout or accept that risk.
- The virtual **G: drive** is dismounted as a side effect of stopping DriveFS — no drive mapping is modified directly.
- Services are matched by binary path (under `\Drive File Stream\`) and never by name alone; scheduled tasks removed are `GoogleDrive*` only.
- Idempotent and flap-safe: a second run on a clean device is a no-op exit 0, and reboot-pending devices are not re-flagged by detection.
