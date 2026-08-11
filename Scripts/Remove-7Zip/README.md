# Remediation - Remove 7-Zip

## Overview

This Intune Remediation package detects and silently removes **all 7-Zip installations** (publisher Igor Pavlov) from Windows devices — MSI builds, NSIS EXE builds, per-user installs, and (in the unlikely case one exists) MSIX/Appx packages. Use it when 7-Zip is not approved in your environment and you want devices continuously scanned and cleaned, including leftovers such as install folders, Start Menu shortcuts, and stray registry keys.

---

## Scripts

| File | Purpose |
|---|---|
| `Detect-7Zip.ps1` | Read-only scan for any 7-Zip artifact — exits 1 if found, exits 0 if clean |
| `Remediate-7Zip.ps1` | Uninstalls every 7-Zip install (machine-wide and per-user) and cleans leftovers |
| `DEPLOYMENT.md` | Full deployment guide: prerequisites, Remediation vs Platform Script options, test plan, rollout cautions |

---

## How It Works

### Detection Script
1. Scans HKLM Uninstall keys in **both** the 64-bit and 32-bit registry views (explicit `RegistryView`, so host bitness can never hide an entry)
2. Sweeps every user profile's Uninstall keys via `HKEY_USERS` — logged-off `NTUSER.DAT` hives are temporarily loaded and always unloaded afterward
3. Checks the default install folders (Program Files, Program Files (x86), per-user `AppData\Local\Programs\7-Zip`) — a folder only counts if it actually contains a 7-Zip binary (`7z.exe`, `7zFM.exe`, `7zG.exe`, `7z.dll`)
4. Ignores binaries already queued for delete-on-reboot in `PendingFileRenameOperations`, so a device waiting on a reboot is treated as compliant and the pair never flaps
5. Checks MSIX/Appx and provisioned packages with a tight name + publisher filter
6. Exits 1 if anything is found (any detection error also exits 1, never a silent "compliant")

### Remediation Script
1. Stops running 7-Zip processes — only after confirming something removable exists, and only processes running from a 7-Zip install folder
2. MSI builds: `msiexec /x {GUID} /qn /norestart REBOOT=ReallySuppress`, with retries for transient codes (e.g. 1618 another install in progress) and an orphaned-ARP-key cleanup if the entry lingers
3. NSIS EXE builds: runs `Uninstall.exe /S`, polls for completion, and confirms success by the Uninstall registry key disappearing
4. Per-user installs: sweeps every `HKU\<SID>` hive (loading offline hives as needed) and removes the entry and folder directly from the correct user hive
5. MSIX/Appx: removes matching packages and provisioned packages (tight filter — matches nothing by default)
6. Leftover cleanup: install folders, Start Menu shortcut folders, and stray `Software\7-Zip` keys
7. Files locked in use — classically `7z.dll` held by `explorer.exe` as the shell extension — are scheduled for **delete-on-reboot** and reported as success with reboot pending, not failure
8. Re-verifies everything (mirroring detection) and exits 0 only when nothing removable remains
9. An internal 25-minute deadline makes the script exit cleanly (retry next cycle) before Intune's 30-minute kill

---

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `$script:KnownAppxFamilies` (both scripts) | `@()` (empty) | Allow-list of confirmed 7-Zip MSIX `PackageFamilyName`s. Leave empty unless you have verified a genuine Igor Pavlov MSIX package — the default tight filter cannot match the unofficial third-party Store port. |

---

## Intune Setup

1. Intune admin center → **Devices** → **Remediations** → **Create script package**
2. Detection script: `Detect-7Zip.ps1` — Remediation script: `Remediate-7Zip.ps1`
3. Settings:
   - Run this script using the logged-on credentials: **No** (SYSTEM)
   - Enforce script signature check: **No**
   - Run script in 64-bit PowerShell: **Yes** (required — the Appx cmdlets only work reliably in a 64-bit host)
4. Assign to a pilot group first; schedule **Daily** for production (or Hourly during an active cleanup campaign)

See [DEPLOYMENT.md](DEPLOYMENT.md) for the full guide: Platform-Script alternative, local SYSTEM smoke test, pilot test matrix, and rollout cautions.

---

## Exit Codes

| Script | Exit 0 | Exit 1 |
|---|---|---|
| `Detect-7Zip.ps1` | No 7-Zip found (binaries queued for delete-on-reboot count as *not found*) | 7-Zip artifact found, **or** any detection error (fail-safe: errors trigger remediation rather than reporting compliant) |
| `Remediate-7Zip.ps1` | Removal succeeded — **including** "removed, reboot required" when the only leftovers are locked files scheduled for delete-on-reboot | A removal genuinely failed, a hard residual remains, or the run hit the internal time budget (retried next cycle) |

The reboot-pending rule is deliberate: a device with the locked `7z.dll` queued for deletion reports **remediated (exit 0)**, and detection ignores the queued file, so the pair never loops on a device that simply has not rebooted yet. No reboot is ever forced.

---

## Logs

Both scripts write full transcripts to `C:\ProgramData\Monster\Logs`:

- `Detect-7Zip_<timestamp>.log`
- `Remove-7Zip_<timestamp>.log`

Intune's captured output is a single one-line summary per run by design (e.g. `7-Zip detected: ...`, `7-Zip removed. Uninstalled: N.`); the detail lives in the transcripts.

---

## Safety Notes

- **Allow-listed deletions**: a folder is only ever deleted when its leaf is literally `7-Zip`, and paths are derived from environment/profile variables — a blank or malformed path can never delete a parent like `C:\Program Files`
- **Reparse-safe**: junctions/symlinks are unlinked, never followed, and every delete/reboot-schedule target is verified to physically resolve under the 7-Zip root — a planted junction cannot redirect deletion elsewhere
- **Process kills are scoped**: only 7-Zip-named processes running from a 7-Zip install folder are stopped, each logged with PID and path
- **No `Win32_Product`**: never queried (it would reconfigure every MSI on the device)
- **User hives**: every temporarily loaded hive is always unloaded (with retry); a stuck hive is logged and counted as a failure rather than hidden
- **Shared HKCR shell-extension keys are not touched** — context-menu registration is left to 7-Zip's own uninstaller
- **Tight MSIX filter**: cannot remove the unofficial third-party Store port or any unrelated Store app
- **Idempotent**: safe to re-run — on a clean device both scripts are a no-op and exit 0
