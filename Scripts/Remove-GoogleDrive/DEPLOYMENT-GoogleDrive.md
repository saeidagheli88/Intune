# Google Drive — REMOVE ALL Google Drive desktop clients from Windows devices — Deployment Guide

Management decision (2026-08-07): **no Google Drive desktop client stays**.
Every install is removed from every Windows device — the current **Google
Drive for desktop** (Drive File Stream / DriveFS) AND the legacy **Backup and
Sync from Google** — machine-wide and per-user.

**What is deliberately NOT touched:**

- **Google Chrome and the shared Google Update machinery** (`gupdate`/
  `gupdatem` services, `GoogleUpdateTaskMachine*` scheduled tasks,
  `Google\Update` folder). Chrome depends on them. Machine folders in scope
  are the Drive-specific SUBFOLDERS of `Google\` only — never the vendor root.
- **The user's cloud files.** DriveFS streams from the cloud; the local
  folder deleted is its cache (`AppData\Local\Google\DriveFS`). Caveat: any
  offline edit that had NOT yet uploaded when the client is killed is lost
  with the cache — schedule the wave with that accepted, or announce it to
  users first.

## The pair

| Script | Job |
|---|---|
| `Detect-GoogleDrive.ps1` | Finds ANY Drive client: HKLM uninstall entries (both registry views — "Google Drive" is a GUID-keyed NON-MSI entry), per-user HKU uninstall entries (every profile, offline NTUSER.DAT hives loaded/unloaded), `GoogleDriveFS.exe`/`googledrivesync.exe` on disk in machine + per-profile folders, and any Store package. Exit 1 = found. |
| `Remediate-GoogleDrive.ps1` | Kills Drive processes (path-based kill catches crashpad helpers; stopping DriveFS dismounts the virtual G: drive); tries the official `uninstall.exe --silent --force_stop` for machine installs (best-effort, bounded 180s wait), then brute-forces surviving ARP keys + folders; deletes any Drive-specific service (binary path under `\Drive File Stream\`) and `GoogleDrive*` scheduled tasks — never the shared Google Update ones; cleans Run values, `Google\DriveFS`+`Google\Drive` vendor keys, `GoogleDriveFS*` Classes keys, shortcuts, per-user cache; then VERIFIES with the identical rules detection uses. Exit 0 = clean or reboot-pending. |

Key design points (house conventions):

- **Classifier safety**: strong match is DisplayName STARTING with
  `Google Drive` / `Drive File Stream` / `Backup and Sync`; loose match
  requires a Google publisher AND the word `drive` — `Google Chrome`,
  `Google Update Helper` and `Microsoft OneDrive` can never match.
- **Per-user coverage**: every profile swept; offline hives loaded/unloaded
  with the usual GC+retry unload. The DriveFS cache folder is binary-gated in
  detection (cache-only content never flaps) and deleted by remediation.
- **Loop/flap safety**: folder findings are binary-gated; a binary queued for
  delete-on-reboot counts as compliant; "reboot required" is SUCCESS.
- **Idempotent**: second run on a clean device is a no-op exit 0.

## Full location coverage map

| Location | Path / key | Detection finding? | Remediation |
|---|---|---|---|
| Machine folders | `C:\Program Files\Google\Drive File Stream`, `C:\Program Files\Google\Drive` (legacy), same under `(x86)` | Yes (if `GoogleDriveFS.exe`/`googledrivesync.exe` inside) | Official uninstaller attempted, then deleted entirely; locked files queued |
| Per-user cache folder | `<profile>\AppData\Local\Google\DriveFS` — every profile | Only if a Drive binary is inside (cache alone never flaps) | Deleted entirely (streaming cache; files live in the cloud) |
| Legacy per-user sync metadata | `<profile>\AppData\Local\Google\Drive` | No | Deleted |
| Machine registry (ARP) | `HKLM\...\Uninstall\*` — BOTH views ("Google Drive" GUID key = non-MSI) | Yes | msiexec for true MSI (1605 tolerated), then key deleted directly |
| Per-user registry (ARP) | `HKU\<SID>\...\Uninstall\*` + `WOW6432Node` — every profile, offline hives loaded | Yes | Key deleted |
| Services | Any service with binary path under `\Google\Drive File Stream\` (none ships today; defensive) | No | Stopped + `sc.exe delete` |
| Scheduled tasks | `GoogleDrive*` only — `GoogleUpdateTask*` is SHARED WITH CHROME and never touched | No | Unregistered |
| MSIX/Store package | Any non-Microsoft package named `*googledrive*`/`*drivefs*` | Yes | `Remove-AppxPackage -AllUsers` + deprovision |
| Run values | `GoogleDriveFS` autostart etc. — HKLM (both views) + every HKU (Drive-specific regex; Chrome Run values can never match) | No | Deleted |
| Vendor / Classes keys | `SOFTWARE\Google\DriveFS`, `SOFTWARE\Google\Drive` (never `Google` itself), `GoogleDriveFS*`/`DriveFS*` Classes keys (HKLM both views + every HKU) | No | Deleted |
| Shortcuts | All-users Start Menu, Public Desktop, per-profile Desktop/Start Menu | No | Deleted |

## Intune deployment (Proactive Remediation)

Intune → Devices → Scripts and remediations → **Create**:

| Setting | Value |
|---|---|
| Detection script | `Detect-GoogleDrive.ps1` |
| Remediation script | `Remediate-GoogleDrive.ps1` |
| Run this script using the logged-on credentials | **No** (SYSTEM) |
| Enforce script signature check | **No** |
| Run script in 64-bit PowerShell | **Yes** (REQUIRED) |
| Schedule | Daily (or hourly for the initial cleanup wave) |

## Exit codes / verification

- Detect: `1` = Drive client found (remediation runs), `0` = clean. Errors = `1`.
- Remediate: `0` = removed / no-op / reboot-pending, `1` = failure or residual.
- Logs: `C:\ProgramData\Monster\Logs\Detect-GoogleDrive_*.log` and
  `Remediate-GoogleDrive_*.log` (full transcript). Intune shows the single
  pre/post remediation output line per device.
- Idempotent: a second remediation run on a clean device is a no-op exit 0.

## Known limitations

- Portable/renamed copies outside the known folders are not chased (same as
  the other pairs).
- If a user reinstalls from google.com (no admin needed? — DriveFS requires
  admin, so standard users cannot), the next detection cycle removes it again.
