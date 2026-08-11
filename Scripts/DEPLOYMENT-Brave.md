# Brave Browser — REMOVE ALL Brave installs from Windows devices — Deployment Guide

Management decision (2026-08-06): **no Brave Browser stays**. Every Brave
install is removed from every Windows device — release/Beta/Nightly,
machine-wide AND per-user — including the **Brave Update** machinery
(services + scheduled tasks) that would otherwise put it back.

## The pair

| Script | Job |
|---|---|
| `Detect-Brave.ps1` | Finds ANY Brave: HKLM uninstall entries (both registry views), per-user HKU uninstall entries (every profile, offline NTUSER.DAT hives loaded/unloaded), `brave.exe`/`BraveUpdate.exe` on disk in machine + per-profile folders, and any Store package. Exit 1 = found. |
| `Remediate-Brave.ps1` | Kills Brave processes (path-based kill catches `elevation_service.exe`); tries the official `setup.exe --uninstall --system-level --force-uninstall` for machine installs (best-effort), then brute-forces surviving ARP keys + folders; stops/deletes Brave services (matched by BINARY PATH under `\BraveSoftware\`, never name alone) and `BraveSoftwareUpdate*` scheduled tasks; cleans Run values, `BraveSoftware` vendor keys, `Brave*` Classes keys, StartMenuInternet/RegisteredApplications browser registrations, shortcuts, per-user data; then VERIFIES with the identical rules detection uses. Exit 0 = clean or reboot-pending. |

Key design points (house conventions):

- **Updater is a finding**: `BraveUpdate.exe` gates a folder finding too — a
  surviving Brave Update can reinstall the browser. Its services (`brave`,
  `bravem`, elevation/VPN services) and scheduled tasks are removed.
- **Per-user coverage**: per-user installs live in
  `<profile>\AppData\Local\BraveSoftware` with an HKU uninstall key; they
  cannot run their uninstaller reliably from SYSTEM, so they are removed
  brute-force (keys + files). Offline hives loaded/unloaded as usual.
- **Full clean**: `AppData\Local\BraveSoftware` includes the browser profile
  (User Data) — deleting it is intentional (full removal).
- **Loop/flap safety**: folder findings are binary-gated; a binary queued for
  delete-on-reboot counts as compliant; "reboot required" is SUCCESS.
- **Classifier safety**: strong match is DisplayName STARTING with `Brave`;
  loose match requires a Brave Software publisher.

## Full location coverage map

| Location | Path / key | Detection finding? | Remediation |
|---|---|---|---|
| Machine folders | `C:\Program Files\BraveSoftware`, same under `(x86)` (browser + Update) | Yes (if `brave.exe`/`BraveUpdate.exe` inside) | Official uninstaller attempted, then deleted entirely; locked files queued |
| Per-user app folder | `<profile>\AppData\Local\BraveSoftware` — every profile | Yes (if a Brave binary inside) | Deleted entirely (includes User Data); locked files queued |
| Per-user data folder | `<profile>\AppData\Roaming\BraveSoftware` | No | Deleted |
| Machine registry (ARP) | `HKLM\...\Uninstall\*` — BOTH views (`BraveSoftware Brave-Browser`, ...) | Yes | MSI → msiexec /x; non-MSI → key deleted |
| Per-user registry (ARP) | `HKU\<SID>\...\Uninstall\*` + `WOW6432Node` — every profile, offline hives loaded | Yes | Key deleted |
| Services | Any service whose binary path contains `BraveSoftware` (`brave`, `bravem`, elevation, VPN) | No | Stopped + `sc.exe delete` |
| Scheduled tasks | `BraveSoftwareUpdateTaskMachine*` etc. (`^BraveSoftware`) | No | Unregistered |
| MSIX/Store package | Any non-Microsoft package named `*brave*` | Yes | `Remove-AppxPackage -AllUsers` + deprovision |
| Run values | HKLM (both views) + every HKU | No | Deleted |
| Classes / browser registration | `Brave*` Classes keys, `Clients\StartMenuInternet\Brave*`, `RegisteredApplications` values (HKLM both views + every HKU Classes) | No | Deleted |
| Shortcuts | All-users Start Menu, Public Desktop, per-profile Desktop/Start Menu | No | Deleted |

## Intune deployment (Proactive Remediation)

Intune → Devices → Scripts and remediations → **Create**:

| Setting | Value |
|---|---|
| Detection script | `Detect-Brave.ps1` |
| Remediation script | `Remediate-Brave.ps1` |
| Run this script using the logged-on credentials | **No** (SYSTEM) |
| Enforce script signature check | **No** |
| Run script in 64-bit PowerShell | **Yes** (REQUIRED) |
| Schedule | Daily (or hourly for the initial cleanup wave) |

## Exit codes / verification

- Detect: `1` = Brave found (remediation runs), `0` = clean. Errors = `1`.
- Remediate: `0` = removed / no-op / reboot-pending, `1` = failure or residual.
- Logs: `C:\ProgramData\Monster\Logs\Detect-Brave_*.log` and
  `Remediate-Brave_*.log` (full transcript). Intune shows the single pre/post
  remediation output line per device.
- Idempotent: a second remediation run on a clean device is a no-op exit 0.
