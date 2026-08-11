# Remediation - Remove Brave

## Overview

This Intune Remediation package detects and silently removes **Brave Browser** (release, Beta, and Nightly) from Windows devices — machine-wide installs, per-user installs in every profile, and any Store (MSIX) package. It also removes the **Brave Update** services and scheduled tasks so a surviving updater cannot reinstall the browser. Use it when the management decision is full removal: no Brave install is allowed to remain.

Browser profile data (`User Data`) is deleted by design — this is a full removal, not just an uninstall.

---

## Scripts

| File | Purpose |
|---|---|
| `Detect-Brave.ps1` | Read-only detection — exits 1 if any Brave install, live Brave binary, or Brave Store package is found; exits 0 if clean |
| `Remediate-Brave.ps1` | Removes all Brave installs, services, scheduled tasks, and leftovers, then verifies with the same rules detection uses |
| `DEPLOYMENT-Brave.md` | Full deployment guide with the complete location coverage map |

---

## How It Works

### Detection Script
1. Scans HKLM Uninstall keys in both the 64-bit and 32-bit registry views for Brave entries
2. Scans per-user (HKU) Uninstall keys for every profile — logged-off `NTUSER.DAT` hives are temporarily loaded and always unloaded afterwards
3. Checks for live Brave binaries (`brave.exe`, `BraveUpdate.exe`) in `Program Files\BraveSoftware`, `Program Files (x86)\BraveSoftware`, and each profile's `AppData\Local\BraveSoftware`
4. Checks for Brave MSIX/Store packages (all users and provisioned)
5. Exits 1 (non-compliant) on any finding; exits 0 (compliant) if clean

Folder-only leftovers with no binary are not findings, and a binary already queued for delete-on-reboot is not a finding — this keeps detection and remediation from flapping.

### Remediation Script
1. Stops all Brave processes — by name and by path (anything running out of a `BraveSoftware` folder, which catches `elevation_service.exe`)
2. Tries the official uninstaller (`setup.exe --uninstall --system-level --force-uninstall`) for machine-wide installs, best-effort
3. Removes surviving machine ARP entries: MSI-coded entries via `msiexec /x /qn /norestart`, everything else by direct key deletion
4. Stops and deletes Brave services — matched by binary path containing `BraveSoftware`, never by name alone — and unregisters the `BraveSoftware*` scheduled tasks so Brave Update cannot reinstall the browser
5. Deletes the machine-wide `BraveSoftware` folders; locked files are queued for delete-on-reboot
6. Sweeps every user profile: per-user Uninstall keys, Run values, `AppData\Local\BraveSoftware` (app + profile data), `AppData\Roaming\BraveSoftware`, Classes keys, and shortcuts
7. Cleans machine-level leftovers: HKLM Run values, `BraveSoftware` vendor keys, `Brave*` Classes keys, StartMenuInternet/RegisteredApplications registrations, Start Menu and Public Desktop shortcuts
8. Removes any Brave MSIX/Store package for all users and deprovisions it
9. Runs a verify pass using the identical classification rules as detection — any residual Brave means exit 1

---

## Configuration

The shared `CONFIG` block must stay **identical** in both scripts:

| Variable | Default | Purpose |
|---|---|---|
| `$BraveStrongName` | `(?i)^\s*brave\b` | DisplayName starting with "Brave" — a match on its own |
| `$BraveLooseName` | `(?i)\bbrave\b` | "brave" anywhere in the name — only counts with a Brave publisher |
| `$BraveBinaryNames` | `brave.exe`, `BraveUpdate.exe` | Binaries that gate a folder finding |
| `$MachineDirs` | `Program Files\BraveSoftware` (+ x86) | Machine-wide vendor folders |
| `$UserAppDirRel` | `AppData\Local\BraveSoftware` | Per-profile app folder (includes User Data) |

Remediation-only settings (process names, service/task regexes, leftover key names) live in a separate block in `Remediate-Brave.ps1`.

---

## Intune Setup

1. Go to Microsoft Intune Admin Center → Devices → Remediations → Create script package
2. Upload `Detect-Brave.ps1` as the detection script and `Remediate-Brave.ps1` as the remediation script
3. Set options:
   - Run this script using the logged-on credentials: **No** (SYSTEM)
   - Enforce script signature check: **No**
   - Run script in 64-bit PowerShell: **Yes** (required)
4. Assign to the target device group and schedule daily (or hourly for the initial cleanup wave)

See [DEPLOYMENT-Brave.md](DEPLOYMENT-Brave.md) for the full deployment guide and location coverage map.

---

## Exit Codes

| Script | Exit 0 | Exit 1 |
|---|---|---|
| `Detect-Brave.ps1` | Clean — no Brave found (machine or per-user) | Brave found → remediation runs; script errors also exit 1 |
| `Remediate-Brave.ps1` | Removed, no-op on a clean device, **or reboot pending** | At least one action failed or residual Brave remains |

A locked file queued for delete-on-reboot counts as **success** — detection treats queued binaries as compliant, so "reboot required" never shows as a failure or causes the pair to flap.

---

## Logs

Both scripts write full transcripts to `C:\ProgramData\Monster\Logs`:

- `Detect-Brave_<timestamp>.log`
- `Remediate-Brave_<timestamp>.log`
- `MsiUninstall-Brave_<code>_<timestamp>.log` (only if an MSI-coded entry is uninstalled)

Each script emits exactly one output line, which Intune shows as the pre/post remediation detection output per device.

---

## Safety Notes

- Services and scheduled tasks are matched by **binary path** (`BraveSoftware`), never by name alone — a short service name like `brave` can never cause an unrelated service to be deleted
- The name classifier requires the DisplayName to **start** with "Brave", or a Brave Software publisher for looser matches — apps that merely mention "brave" are not touched
- MSIX matching excludes anything published by Microsoft
- Offline user hives are always unloaded in a `finally` block, with orphan-mount cleanup at the start of each run
- `Win32_Product` is never used (it triggers MSI self-repair fleet-wide)
- Idempotent: a second run on a clean device is a no-op exit 0
- Deliberate exception to the usual "leave user data" rule: `AppData\Local\BraveSoftware` (including the browser profile / User Data) **is** deleted — full removal is the intent
