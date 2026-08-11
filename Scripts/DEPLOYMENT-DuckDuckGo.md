# DuckDuckGo Browser — REMOVE ALL installs from Windows devices — Deployment Guide

Management decision (2026-08-06): **no DuckDuckGo browser stays**. The
DuckDuckGo browser for Windows ships PRIMARILY as an MSIX/Store package
(`DuckDuckGo.DesktopBrowser`) — even the website's exe installer registers
the MSIX package — so the Appx checks/removal are the main path; classic
ARP/folder handling is the backstop for older or unusual installs.

> Scope note: this removes the DuckDuckGo **browser application** only. It
> does not (and cannot, from a script) stop users from visiting
> duckduckgo.com as a search site — that belongs to browser/search policy.

## The pair

| Script | Job |
|---|---|
| `Detect-DuckDuckGo.ps1` | Finds ANY DuckDuckGo browser: the MSIX package (any user or provisioned), HKLM uninstall entries (both registry views), per-user HKU uninstall entries (every profile, offline NTUSER.DAT hives loaded/unloaded), and `DuckDuckGo.exe` on disk in machine + per-profile folders. Exit 1 = found. |
| `Remediate-DuckDuckGo.ps1` | Kills DuckDuckGo processes; removes the MSIX package for all users + deprovisions it; brute-forces any classic ARP keys + folders; cleans Run values, `DuckDuckGo*` Classes keys, shortcuts, browser data folders and Store package data; then VERIFIES with the identical rules detection uses. Exit 0 = clean or reboot-pending. |

Key design points (house conventions):

- **MSIX-first**: `Remove-AppxPackage -AllUsers` + `Remove-AppxProvisionedPackage`
  are the primary removal actions; the classifier (`Test-IsDuckAppx`) matches
  package names containing `duckduckgo` and excludes Microsoft publishers.
- **Per-user coverage**: every profile is swept for HKU uninstall keys, app
  folders, data folders and Store package data; offline hives are `reg load`ed
  and ALWAYS unloaded; orphaned mounts are cleaned at startup.
- **Full clean**: browser data (`AppData\Local\DuckDuckGo`,
  `AppData\Local\Packages\DuckDuckGo.*`) is deleted opportunistically —
  never a detection finding (flap safety).
- **Loop/flap safety**: folder findings are binary-gated (`DuckDuckGo.exe`);
  a binary queued for delete-on-reboot counts as compliant; "reboot required"
  is SUCCESS, not failure.

## Full location coverage map

| Location | Path / key | Detection finding? | Remediation |
|---|---|---|---|
| MSIX/Store package | `DuckDuckGo.DesktopBrowser` (any user or provisioned) | Yes | `Remove-AppxPackage -AllUsers` + deprovision |
| Machine folders | `C:\Program Files\DuckDuckGo`, same under `(x86)` | Yes (if `DuckDuckGo.exe` inside) | Deleted entirely; locked files queued for delete-on-reboot |
| Per-user app folders | `<profile>\AppData\Local\Programs\DuckDuckGo`, `...\Local\DuckDuckGo\Application` — every profile | Yes (if `DuckDuckGo.exe` inside) | Deleted entirely; locked files queued |
| Per-user data folders | `<profile>\AppData\Local\DuckDuckGo`, `...\Roaming\DuckDuckGo`, `...\Local\Packages\DuckDuckGo*` | No | Deleted |
| Machine registry (ARP) | `HKLM\...\Uninstall\*` — BOTH views | Yes | MSI → msiexec /x; non-MSI → key deleted |
| Per-user registry (ARP) | `HKU\<SID>\...\Uninstall\*` + `WOW6432Node` — every profile, offline hives loaded | Yes | Key deleted |
| Run values | HKLM (both views) + every HKU | No | Deleted |
| Classes keys | `DuckDuckGo*` (HKLM both views + every HKU) | No | Deleted |
| Shortcuts | All-users Start Menu, Public Desktop, per-profile Desktop/Start Menu | No | Deleted |

## Intune deployment (Proactive Remediation)

Intune → Devices → Scripts and remediations → **Create**:

| Setting | Value |
|---|---|
| Detection script | `Detect-DuckDuckGo.ps1` |
| Remediation script | `Remediate-DuckDuckGo.ps1` |
| Run this script using the logged-on credentials | **No** (SYSTEM) |
| Enforce script signature check | **No** |
| Run script in 64-bit PowerShell | **Yes** (REQUIRED) |
| Schedule | Daily (or hourly for the initial cleanup wave) |

Optional belt-and-braces: also block/uninstall the Store app via Intune app
management (Microsoft Store app (new): `DuckDuckGo Browser`, assign as
Uninstall) so the Store can't reinstall it between remediation runs.

## Exit codes / verification

- Detect: `1` = DuckDuckGo found (remediation runs), `0` = clean. Errors = `1`.
- Remediate: `0` = removed / no-op / reboot-pending, `1` = failure or residual.
- Logs: `C:\ProgramData\Monster\Logs\Detect-DuckDuckGo_*.log` and
  `Remediate-DuckDuckGo_*.log` (full transcript). Intune shows the single
  pre/post remediation output line per device.
- Idempotent: a second remediation run on a clean device is a no-op exit 0.
