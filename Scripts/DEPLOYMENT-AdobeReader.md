# Adobe Reader — Standardize on ONE version (unified 64-bit) — Deployment Guide

Goal: every device runs a single Adobe Reader — the unified **64-bit Adobe Acrobat
Reader** (product code `{AC76BA86-1033-FFFF-7760-BC15014EA700}`) at or above the
current baseline — and all legacy/duplicate installs are removed from devices and,
after inventory refresh, from Discovered Apps.

## How the pieces divide the work

| Piece | Job |
|---|---|
| Win32 app "Adobe Acrobat Reader DC (64-bit)" (26.001.21662) | **Installs and UPGRADES** the unified Reader. The version-based detection rule below is what forces stale devices to upgrade. |
| `Detect-AdobeReader.ps1` / `Remediate-AdobeReader.ps1` | **Cleans up**: uninstalls legacy 32-bit / ancient Readers (9.x → DC 32-bit), removes leftovers, re-enables the Adobe ARM auto-updater. Never installs/patches Reader itself. |
| Adobe ARM auto-updater (kept healthy by the pair) | Keeps devices on the latest patch **between** your package refreshes. |

An outdated-but-healthy unified Reader is deliberately NOT a remediation finding —
the Win32 app owns upgrades. This keeps the pair loop-safe (no daily re-fire while
a device is mid-catch-up).

## Step 1 — Fix the Win32 app detection rule (the critical change)

Today the rule is existence-only (`File: C:\Program Files\Adobe\Acrobat DC\Acrobat`),
so any old Reader satisfies it and Intune never upgrades anything.

First confirm the file version on a reference machine with 26.001.21662:

```powershell
(Get-Item 'C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe').VersionInfo.FileVersion
```

Then edit the app → Detection rules:

| Setting | Value |
|---|---|
| Rule type | File |
| Path | `C:\Program Files\Adobe\Acrobat DC\Acrobat` |
| File or folder | `Acrobat.exe` |
| Detection method | **String (version)** |
| Operator | **Greater than or equal to** |
| Value | `26.1.21662` (use what the command above returned) |
| Associated with a 32-bit app on 64-bit clients | No |

`>=` (not `=`) is required: Adobe's auto-updater moves devices past the baseline
and an equals rule would flip them to "not detected" and pointlessly reinstall.

## Step 2 — Supersedence + assignment

1. On the 26.001.21662 app → **Supersedence** → add the old 24.007.21662 app,
   **Uninstall previous version = No** (the installer upgrades in place).
2. Assign the new app **Required** to the device groups (Available alone will not
   upgrade anyone). Move assignments off the old app, then retire it.

## Step 3 — Deploy the remediation pair

Intune → Devices → Scripts and remediations → **Create**:

| Setting | Value |
|---|---|
| Detection script | `Detect-AdobeReader.ps1` |
| Remediation script | `Remediate-AdobeReader.ps1` |
| Run this script using the logged-on credentials | **No** (SYSTEM) |
| Enforce script signature check | No |
| Run script in 64-bit PowerShell | **Yes** (HARD requirement) |
| Schedule | Daily |

Pilot on a small group first — ideally including a couple of the devices still
on 23.x–25.x and at least one with a 32-bit Reader DC duplicate.

### CONFIG block (top of BOTH scripts — keep identical)

| Variable | Default | Meaning |
|---|---|---|
| `$BaselineVersion` | `26.1.21662` | Bump when you refresh the Win32 package. Only affects logging + whether the Adobe update task gets kicked. |
| `$Unified64Code` | `{AC76BA86-1033-FFFF-7760-BC15014EA700}` | The keeper. Stable across Reader 64-bit MUI versions. |
| `$HandleStoreCoreApp` | `$false` | Opt-in removal of the MSIX `AdobeAcrobatReaderCoreApp` Store package (the third inventory entry). **Only set `$true` after the Win32 app is Required on the same devices** — on CoreApp-only machines the user would otherwise have no PDF viewer until the app installs. |

### What the pair will and won't touch

- **Removes**: Reader 9.x/X/XI, 32-bit Acrobat Reader DC (any language —
  matched on the `{AC76BA86-7AD7-…}` MSI family), leftover install folders
  (locked files are queued for delete-on-reboot, which counts as SUCCESS,
  same as the 7-Zip pair).
- **Fixes**: `AdobeARMservice` set back to Automatic + started if Disabled;
  `FeatureLockDown bUpdater` 0 → 1.
- **Never touches**: the unified 64-bit Reader, paid Acrobat Standard/Pro,
  Creative Cloud, and (unless flagged) the Store CoreApp.

## Expected timeline

- **~24 h**: Required app re-evaluates → stale devices upgrade to 26.001.21662;
  remediation strips 32-bit duplicates and Reader 9.1.
- **~7 days**: Discovered Apps inventory refreshes (it's weekly per device) —
  old version rows drain out of the report you exported.
- **Steady state**: one Win32 row per device ("Adobe Acrobat Reader", latest
  26.001.x via ARM), plus the MSIX CoreApp row unless you enable the flag.

## Verification

Re-run the same Discovered Apps export after a week or two:

- `Adobe Acrobat Reader` rows below 26.x → should trend to zero.
- `Adobe Reader 9.1` → gone.
- Remediation node shows per-device output ("Adobe Reader cleanup OK: …").
- Per-device logs: `C:\ProgramData\Monster\Logs\Detect-AdobeReader_*.log` /
  `Remediate-AdobeReader_*.log` (+ verbose MSI uninstall logs).

## Note on inventory naming

Adobe dropped the "DC" branding in 2024: after the app self-updates, its
Add/Remove Programs display name is just **"Adobe Acrobat Reader"**, so Discovered
Apps will never show your Intune app name "Adobe Acrobat Reader DC (64-bit)".
That mismatch is cosmetic and expected. `AdobeAcrobatReaderCoreApp` is the
separate MSIX Store package, not a duplicate of the Win32 install.
