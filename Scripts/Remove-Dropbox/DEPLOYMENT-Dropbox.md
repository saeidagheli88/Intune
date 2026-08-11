# Dropbox — REMOVE ALL Dropbox app installs from Windows devices — Deployment Guide

Management decision (2026-08-07): **no Dropbox desktop app stays**. Every
install is removed from every Windows device — the classic per-user app, any
machine-wide (enterprise/offline installer) deployment, the **Dropbox Update**
machinery (services + scheduled tasks) that would otherwise put it back, and
the Store (MSIX) version.

**What is deliberately NOT touched — the user's synced files.** The
synced-content folder (`<profile>\Dropbox`, or a custom location) is DATA,
not the app. Neither script ever scans or deletes it. Files already synced
remain both in that local folder and in the Dropbox cloud; anything not yet
uploaded stays safely in the local folder (it just stops syncing). Only the
app (`AppData\Local\Dropbox`, `Program Files (x86)\Dropbox`), its settings
(`AppData\Roaming\Dropbox`), updater, services, tasks and registry footprint
are removed.

## The pair

| Script | Job |
|---|---|
| `Detect-Dropbox.ps1` | Finds ANY Dropbox app: HKLM uninstall entries (both registry views — "Dropbox" machine installs and "Dropbox Update Helper"), per-user HKU uninstall entries (every profile, offline NTUSER.DAT hives loaded/unloaded), `Dropbox.exe`/`DropboxUpdate.exe`/`DbxSvc.exe` on disk in machine + per-profile APP folders, and any Store package (`C27EB4BA.Dropbox`). Exit 1 = found. |
| `Remediate-Dropbox.ps1` | Kills Dropbox processes (path-based kill restricted to the `Client`/`Update` app folders — never the synced folder); tries the official `Client\DropboxUninstaller.exe /S` for machine installs (best-effort, bounded 180s wait), then brute-forces surviving ARP keys + folders; stops/deletes Dropbox services — `dbupdate`/`dbupdatem` (matched by BINARY PATH under `\Dropbox\Update\`, never name alone) and `DbxSvc` (`System32\DbxSvc.exe`, binary deleted too) — and unregisters `Dropbox*` scheduled tasks; cleans Run values, `Dropbox`/`DropboxUpdate` vendor keys, `Dropbox*` Classes keys, `DropboxExt*` shell icon overlays, shortcuts, per-user app + settings folders; then VERIFIES with the identical rules detection uses. Exit 0 = clean or reboot-pending. |

Key design points (house conventions):

- **Per-user app**: the default Dropbox install is PER-USER in
  `<profile>\AppData\Local\Dropbox` with an HKU uninstall key; it cannot run
  its uninstaller reliably from SYSTEM, so it is removed brute-force (keys +
  files), same as the Brave/Telegram pairs. Offline hives loaded/unloaded as
  usual.
- **Updater is a finding**: `DropboxUpdate.exe` gates a folder finding too — a
  surviving Dropbox Update can reinstall the app. Its services and scheduled
  tasks are removed; services are matched by binary path, never by name.
- **Synced files preserved**: `<profile>\Dropbox` is never listed, scanned or
  deleted; the process path-kill regex requires `\Dropbox\Client\` or
  `\Dropbox\Update\` so nothing running out of the synced folder is touched;
  shortcut cleanup removes `.lnk`/`.url` files only.
- **Loop/flap safety**: folder findings are binary-gated; a binary queued for
  delete-on-reboot counts as compliant; "reboot required" is SUCCESS.
- **Classifier safety**: strong match is DisplayName STARTING with `Dropbox`;
  loose match requires a Dropbox publisher. Appx matching excludes Microsoft
  publishers.

## Full location coverage map

| Location | Path / key | Detection finding? | Remediation |
|---|---|---|---|
| Machine APP folders | `C:\Program Files (x86)\Dropbox` (Client + Update), `C:\Program Files\Dropbox` | Yes (if `Dropbox.exe`/`DropboxUpdate.exe`/`DbxSvc.exe` inside) | Official uninstaller attempted, then deleted entirely; locked files queued |
| Per-user APP folder | `<profile>\AppData\Local\Dropbox` — every profile | Yes (if a Dropbox binary inside) | Deleted entirely; locked files queued |
| Per-user settings | `<profile>\AppData\Roaming\Dropbox` | No | Deleted |
| **Synced content** | `<profile>\Dropbox` (or custom location) | **Never** | **Never touched** |
| Machine registry (ARP) | `HKLM\...\Uninstall\*` — BOTH views ("Dropbox", "Dropbox Update Helper" `{099218A5-...}`) | Yes | MSI → msiexec /x (1605 tolerated); non-MSI → key deleted |
| Per-user registry (ARP) | `HKU\<SID>\...\Uninstall\Dropbox` + `WOW6432Node` — every profile, offline hives loaded | Yes | Key deleted |
| Services | `dbupdate`/`dbupdatem` (binary path `\Dropbox\Update\`), `DbxSvc` (`System32\DbxSvc.exe`) | No | Stopped + `sc.exe delete`; `DbxSvc.exe` binary deleted/queued |
| Scheduled tasks | `DropboxUpdateTaskMachineCore/UA`, per-user `DropboxUpdateTaskUser*` (`^Dropbox`) | No | Unregistered |
| MSIX/Store package | `C27EB4BA.Dropbox` (any non-Microsoft `*dropbox*` package) | Yes | `Remove-AppxPackage -AllUsers` + deprovision |
| Run values | HKLM (both views) + every HKU | No | Deleted |
| Vendor / Classes keys | `SOFTWARE\Dropbox`, `SOFTWARE\DropboxUpdate`, `Dropbox*` Classes keys (HKLM both views + every HKU) | No | Deleted |
| Shell icon overlays | `Explorer\ShellIconOverlayIdentifiers\ DropboxExt*` (both views) | No | Deleted |
| Shortcuts | All-users Start Menu, Public Desktop, per-profile Desktop/Start Menu (`.lnk`/`.url` only) | No | Deleted |

## Intune deployment (Proactive Remediation)

Intune → Devices → Scripts and remediations → **Create**:

| Setting | Value |
|---|---|
| Detection script | `Detect-Dropbox.ps1` |
| Remediation script | `Remediate-Dropbox.ps1` |
| Run this script using the logged-on credentials | **No** (SYSTEM) |
| Enforce script signature check | **No** |
| Run script in 64-bit PowerShell | **Yes** (REQUIRED) |
| Schedule | Daily (or hourly for the initial cleanup wave) |

Optional belt-and-braces: if the Store version shows up in reporting, also
assign the Microsoft Store app (new) **Dropbox** with intent **Uninstall** to
the same device group (same approach as the DuckDuckGo rollout).

## Exit codes / verification

- Detect: `1` = Dropbox app found (remediation runs), `0` = clean. Errors = `1`.
- Remediate: `0` = removed / no-op / reboot-pending, `1` = failure or residual.
- Logs: `C:\ProgramData\Monster\Logs\Detect-Dropbox_*.log` and
  `Remediate-Dropbox_*.log` (full transcript). Intune shows the single
  pre/post remediation output line per device.
- Idempotent: a second remediation run on a clean device is a no-op exit 0.

## Known limitations

- Portable/renamed copies outside the known folders are not chased (same as
  the other pairs).
- Dropbox installs per-user WITHOUT admin rights, so a user can reinstall it;
  the next detection cycle removes it again. Consider an AppLocker/WDAC rule
  if reinstalls become a pattern.
