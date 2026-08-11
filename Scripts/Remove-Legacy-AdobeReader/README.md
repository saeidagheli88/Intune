# Remediation - Remove Legacy Adobe Reader

## Overview

This Intune Remediation package detects and silently removes **legacy / duplicate Adobe Reader installs** (Reader 9.x, X, XI, and 32-bit Acrobat Reader DC in any language) so that exactly one product remains: the unified **64-bit Adobe Acrobat Reader** (MSI product code `{AC76BA86-1033-FFFF-7760-BC15014EA700}`). It also repairs the Adobe ARM auto-updater when it has been actively disabled.

**This pair never installs or upgrades Reader.** Installation and upgrades are owned by a separate Intune Win32 app with a version-based detection rule. An outdated-but-healthy unified Reader is logged but is deliberately **not** a finding — otherwise the pair would loop daily on devices that are mid-upgrade.

---

## Scripts

| File | Purpose |
|---|---|
| `Detect-AdobeReader.ps1` | Read-only detection — exits 1 if a legacy Reader or a broken updater is found, exits 0 if clean |
| `Remediate-AdobeReader.ps1` | Uninstalls legacy Readers, cleans leftovers, re-enables the Adobe ARM updater |
| `DEPLOYMENT-AdobeReader.md` | Full deployment guide (Win32 app detection rule, supersedence, timeline, verification) |

---

## How It Works

### Detection Script (read-only)
1. Scans the HKLM Uninstall keys in **both** the 64-bit and 32-bit registry views for legacy Readers: any `{AC76BA86-7AD7-...}` product code (the whole 32-bit Reader family) or a `Adobe (Acrobat) Reader` display name that is not the unified 64-bit product
2. Checks for leftover legacy binaries (`AcroRd32.exe`) under the known 32-bit install folders — a binary already queued for delete-on-reboot is **not** a finding (loop-safe)
3. If the unified Reader is present, verifies the updater: `AdobeARMservice` set to Disabled or `FeatureLockDown bUpdater=0` is a finding (service missing entirely is a warning only — the Win32 app reinstall restores it)
4. Optionally (flag-gated, off by default) treats the MSIX Store `AdobeAcrobatReaderCoreApp` package as a finding
5. Returns `exit 1` (non-compliant) on any finding or error, `exit 0` if clean

### Remediation Script
1. Stops legacy Reader processes (`AcroRd32`, `ReaderCEF`, `RdrCEF`) — the unified Reader's `Acrobat.exe` is left alone
2. Uninstalls every legacy Reader ARP entry via `msiexec /x <code> /qn /norestart` (each product code once, verbose MSI log written); non-MSI entries are flagged for manual review instead of running an arbitrary uninstall string as SYSTEM
3. Deletes leftover legacy install folders (only ones still holding `AcroRd32.exe`); locked files are queued for **delete-on-reboot**, which detection then treats as compliant
4. Re-enables the updater: `AdobeARMservice` Disabled → Automatic + started, and `bUpdater` 0 → 1 wherever set
5. If the unified Reader is below baseline, kicks the `Adobe Acrobat Update Task` scheduled task (fire-and-forget — the Win32 app owns the actual upgrade)
6. Optionally (same flag) removes and deprovisions the MSIX Store CoreApp for all users

---

## Configuration

The CONFIG block at the top of each script — **keep it identical in both**:

| Variable | Default | Meaning |
|---|---|---|
| `$BaselineVersion` | `26.1.21662` | `Acrobat.exe` file version shipped by the current Win32 package. Logging only in detection; in remediation it decides whether the Adobe update task gets kicked. Bump when you refresh the package. |
| `$Unified64Code` | `{AC76BA86-1033-FFFF-7760-BC15014EA700}` | The one product allowed to stay. Stable across unified 64-bit Reader versions. |
| `$HandleStoreCoreApp` | `$false` | Opt-in removal of the MSIX Store `AdobeAcrobatReaderCoreApp` package. |

> **Warning:** only set `$HandleStoreCoreApp = $true` (in **both** scripts) after the Win32 Reader app is assigned **Required** to the same devices. On machines where the Store CoreApp is the only PDF viewer, enabling the flag first leaves users with no PDF viewer until the app installs.

---

## Intune Setup

1. Go to Microsoft Intune Admin Center → Devices → Remediations → Create script package
2. Upload `Detect-AdobeReader.ps1` as the detection script and `Remediate-AdobeReader.ps1` as the remediation script
3. Set options:
   - Run this script using the logged-on credentials: **No** (SYSTEM)
   - Enforce script signature check: No
   - Run script in 64-bit PowerShell: **Yes** (required)
4. Assign to the target device group on a **Daily** schedule; pilot on a small group first

Full deployment detail — including the Win32 app's version-based detection rule, supersedence setup, expected timeline, and verification steps — is in [DEPLOYMENT-AdobeReader.md](DEPLOYMENT-AdobeReader.md).

---

## Exit Codes

| Script | Exit 0 | Exit 1 |
|---|---|---|
| `Detect-AdobeReader.ps1` | Clean — single unified 64-bit install, updater enabled (binaries queued for delete-on-reboot count as clean) | Finding(s) → triggers remediation; fatal errors also exit 1 |
| `Remediate-AdobeReader.ps1` | Success or no-op — **including "done, reboot pending"** (MSI 3010/1641 and delete-on-reboot queuing are success, not failure) | At least one action failed (residual legacy install remains) |

Each script emits exactly one STDOUT summary line, which Intune shows as the per-device pre/post-remediation output.

---

## Logs

All logs land in `C:\ProgramData\Monster\Logs`:

- `Detect-AdobeReader_<timestamp>.log` — detection transcript
- `Remediate-AdobeReader_<timestamp>.log` — remediation transcript
- `MsiUninstall-AdobeReader_<code>_<timestamp>.log` — verbose MSI log per uninstall

---

## Safety Notes

- **Never touches** the unified 64-bit Adobe Acrobat Reader itself — no install, no upgrade, no uninstall
- **Never touches** paid Acrobat Standard / Pro (different product codes, no "Reader" in the name) or Creative Cloud
- **Never touches** the MSIX Store CoreApp unless `$HandleStoreCoreApp` is explicitly enabled in both scripts
- Never uses `Win32_Product` (which repairs/reconfigures every MSI on enumeration); uninstalls only known MSI product codes
- Only deletes folders that still contain the legacy `AcroRd32.exe` binary — anything else under an `Adobe` folder is left alone
- Idempotent: a second run finds nothing legacy and exits 0 as a no-op

---

## Author

Saeid Agheli — Intune Administrator
https://github.com/saeidagheli88
