# Remediation - Remove Telegram

## Overview

This Intune Remediation package detects and silently removes **every Telegram client** from Windows devices — Telegram Desktop (both machine-wide and per-user Inno Setup installs) and the Microsoft Store (MSIX) package. Use it when policy requires that no Telegram client remain on managed devices.

Telegram Desktop's default install is **per-user** (Inno Setup) into `<profile>\AppData\Roaming\Telegram Desktop`, so both scripts sweep **every user profile** on the device — including logged-off profiles, whose registry hives are loaded temporarily and always unloaded afterwards. The `tdata` chat cache lives inside the install folder and is deleted with it by design (full removal includes user data).

---

## Scripts

| File | Purpose |
|---|---|
| `Detect-Telegram.ps1` | Read-only detection — exits 1 if any Telegram client is found, exits 0 if the device is clean |
| `Remediate-Telegram.ps1` | Removes all Telegram installs, leftovers, and Store packages, then re-verifies with the same rules detection uses |
| [`DEPLOYMENT-Telegram.md`](DEPLOYMENT-Telegram.md) | Full deployment guide with the complete location coverage map |

---

## How It Works

### Detection Script (read-only)
1. Scans HKLM Uninstall keys in **both** the 64-bit and 32-bit registry views for Telegram entries
2. Scans per-user (HKU) Uninstall keys for **every** profile — offline `NTUSER.DAT` hives are loaded temporarily and always unloaded
3. Checks for a live `Telegram.exe` in the machine folders (`Program Files\Telegram Desktop`, same under `(x86)`) and the per-profile folders (`AppData\Roaming\Telegram Desktop`, `AppData\Local\Telegram Desktop`, `AppData\Local\Programs\Telegram Desktop`)
4. Checks for the Telegram MSIX/Store package (any user, plus provisioned copies)
5. Exits 1 on any finding, 0 if clean

Folder findings are **binary-gated**: a leftover folder with no `Telegram.exe` inside is not a finding, and a binary already queued for delete-on-reboot counts as compliant — this prevents detect/remediate loops.

### Remediation Script
1. Stops all Telegram processes — by name (`Telegram`) and by path (anything running out of a `Telegram Desktop` folder, which catches `Updater.exe`)
2. Removes machine-wide Telegram ARP entries (both registry views); Inno Setup entries are removed brute-force (key deleted, files taken by the folder pass), while an MSI-coded entry would go through `msiexec /x` silently
3. Deletes the machine-wide `Telegram Desktop` folders; locked files are queued for delete-on-reboot
4. Sweeps every user profile: per-user Uninstall keys, Run values, app folders (including `tdata`), leftover Store package data folders, `tg://`/`tdesktop` Classes keys, and shortcuts
5. Cleans machine-level leftovers: HKLM Run values, vendor keys, `tg://` protocol Classes keys, Start Menu and Public Desktop shortcuts
6. Removes the Telegram Store package for all users and deprovisions it so new profiles don't get it back
7. Runs a verification pass using the identical classification rules as detection — any residual makes the script exit 1 so Intune reports the device honestly

---

## Configuration

Both scripts share an identical `CONFIG` block near the top — if you change one, change both:

| Variable | Purpose |
|---|---|
| `$TelegramStrongName` / `$TelegramLooseName` | Regexes that classify ARP entries as Telegram |
| `$TelegramBinaryNames` | Binaries that gate a folder finding (default `Telegram.exe`) |
| `$MachineDirs` | Machine-wide install folders to check/remove |
| `$UserAppDirRel` | Per-profile install folders (relative to each profile root) |

The remediation script has additional cleanup-only settings (`$RegLeftoverNames`, `$TelegramClassesKeyRegex`, `$TelegramProcesses`, `$TelegramProcPathRegex`, `$UserPackageDirPatterns`) that never affect detection results.

---

## Intune Setup

1. Go to Microsoft Intune Admin Center → Devices → Remediations → Create script package
2. Detection script: upload `Detect-Telegram.ps1`; Remediation script: upload `Remediate-Telegram.ps1`
3. Set options:
   - Run this script using the logged-on credentials: **No** (SYSTEM)
   - Enforce script signature check: **No**
   - Run script in 64-bit PowerShell: **Yes** (required)
4. Assign to the target device group; schedule daily (hourly for the initial cleanup wave)

See [`DEPLOYMENT-Telegram.md`](DEPLOYMENT-Telegram.md) for the full deployment guide and location coverage map.

---

## Exit Codes

| Script | Exit 0 | Exit 1 |
|---|---|---|
| `Detect-Telegram.ps1` | Clean — no Telegram client found | Telegram found (triggers remediation); script errors also exit 1 |
| `Remediate-Telegram.ps1` | Success or no-op — **including "done, reboot pending"** (locked files queued for delete-on-reboot count as success) | At least one action failed or residual Telegram remains after the verify pass |

Because detection treats binaries queued in `PendingFileRenameOperations` as compliant, a device waiting on a reboot reports as fixed instead of flapping between detect and remediate.

---

## Logs

Full transcripts are written to `C:\ProgramData\Monster\Logs`:

- `Detect-Telegram_<timestamp>.log`
- `Remediate-Telegram_<timestamp>.log`
- `MsiUninstall-Telegram_*.log` (only if an MSI-coded entry is ever uninstalled)

Intune captures a single summary output line per script run (pre/post remediation detection output).

---

## Safety Notes

- **Only Telegram-owned locations are touched** — the ARP classifier is anchored on the word "telegram", and only wholly Telegram-owned folders are deleted
- Microsoft-published Appx packages and provisioned packages are explicitly excluded from Store package matching
- Loaded user hives are read/edited in place; offline hives are always unloaded (with retry) in `finally`, and orphaned hive mounts from a prior crashed run are cleaned up at startup
- `Updater.exe` is only killed by path (inside a `Telegram Desktop` folder), never blindly by name
- The script never uses `Win32_Product` (which would trigger MSI self-repair storms)
- Idempotent: a second run on a clean device is a no-op exit 0
- **Deliberate data removal**: the `tdata` chat cache is deleted with the install folder — this is intentional full removal, not a bug
- **Known limitation**: portable copies (a bare `Telegram.exe` unzipped into Downloads, Desktop, etc.) are not chased — only known install locations are swept

---

## Author

Saeid Agheli — Intune Administrator
https://github.com/saeidagheli88
