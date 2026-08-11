# Telegram — REMOVE ALL Telegram clients from Windows devices — Deployment Guide

Management decision (2026-08-06): **no Telegram client stays**. Every Telegram
client is removed from every Windows device — the desktop app (machine-wide
AND per-user Inno Setup installs) plus the Microsoft Store (MSIX) package.

## The pair

| Script | Job |
|---|---|
| `Detect-Telegram.ps1` | Finds ANY Telegram: HKLM uninstall entries (both registry views), per-user HKU uninstall entries (every profile, offline NTUSER.DAT hives loaded/unloaded), `Telegram.exe` on disk in machine + per-profile folders, and the Store package (any user or provisioned). Exit 1 = found. |
| `Remediate-Telegram.ps1` | Kills Telegram processes (path-based kill catches `Updater.exe`); brute-force removes machine + per-user installs (ARP keys + folders — Telegram is Inno Setup, no reliable silent uninstall from SYSTEM); removes the Store package for all users + deprovisions; cleans Run values, `tg://`/`tdesktop` Classes keys, shortcuts, Store package data; then VERIFIES with the identical rules detection uses. Exit 0 = clean or reboot-pending. |

Key design points (house conventions):

- **Per-user coverage**: Telegram Desktop's DEFAULT install is per-user in
  `<profile>\AppData\Roaming\Telegram Desktop` (note **Roaming**, unusual)
  with an HKU uninstall key. Offline hives are `reg load`ed and ALWAYS
  unloaded; orphaned mounts are cleaned at startup.
- **Full clean**: the `tdata` chat cache lives inside the install folder, so
  removing the folder removes user data too (intentional — full removal).
- **Loop/flap safety**: folder findings are binary-gated (`Telegram.exe`);
  a binary queued for delete-on-reboot counts as compliant; "reboot required"
  is SUCCESS, not failure.
- **Known limitation**: PORTABLE copies (bare `Telegram.exe` unzipped into
  Downloads etc.) are not chased — known install locations only.

## Full location coverage map

| Location | Path / key | Detection finding? | Remediation |
|---|---|---|---|
| Machine folders | `C:\Program Files\Telegram Desktop`, same under `(x86)` | Yes (if `Telegram.exe` inside) | Deleted entirely; locked files queued for delete-on-reboot |
| Per-user app folders | `<profile>\AppData\Roaming\Telegram Desktop`, `...\Local\Telegram Desktop`, `...\Local\Programs\Telegram Desktop` — every profile | Yes (if `Telegram.exe` inside) | Deleted entirely (includes `tdata`); locked files queued |
| Store package data | `<profile>\AppData\Local\Packages\TelegramMessengerLLP.TelegramDesktop*` | No | Deleted opportunistically |
| Machine registry (ARP) | `HKLM\...\Uninstall\*` — BOTH views | Yes | MSI → msiexec /x; non-MSI (Inno) → key deleted |
| Per-user registry (ARP) | `HKU\<SID>\...\Uninstall\*` + `WOW6432Node` — every profile, offline hives loaded | Yes | Key deleted |
| MSIX/Store package | `TelegramMessengerLLP.TelegramDesktop` (any user or provisioned) | Yes | `Remove-AppxPackage -AllUsers` + deprovision |
| Run values | HKLM (both views) + every HKU | No | Deleted |
| Classes keys | `tg` protocol, `tdesktop.*` ProgIDs (HKLM both views + every HKU) | No | Deleted |
| Shortcuts | All-users Start Menu, Public Desktop, per-profile Desktop/Start Menu | No | Deleted |

## Intune deployment (Proactive Remediation)

Intune → Devices → Scripts and remediations → **Create**:

| Setting | Value |
|---|---|
| Detection script | `Detect-Telegram.ps1` |
| Remediation script | `Remediate-Telegram.ps1` |
| Run this script using the logged-on credentials | **No** (SYSTEM) |
| Enforce script signature check | **No** |
| Run script in 64-bit PowerShell | **Yes** (REQUIRED) |
| Schedule | Daily (or hourly for the initial cleanup wave) |

## Exit codes / verification

- Detect: `1` = Telegram found (remediation runs), `0` = clean. Errors = `1`.
- Remediate: `0` = removed / no-op / reboot-pending, `1` = failure or residual.
- Logs: `C:\ProgramData\Monster\Logs\Detect-Telegram_*.log` and
  `Remediate-Telegram_*.log` (full transcript). Intune shows the single
  pre/post remediation output line per device.
- Idempotent: a second remediation run on a clean device is a no-op exit 0.
