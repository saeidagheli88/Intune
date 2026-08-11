# Remediation - Standardize Python

## Overview

This Intune Remediation package detects and silently removes **outdated python.org Python** from Windows devices, standardizing the fleet on Python 3.14.6. It ships as **two companion Remediation policies** — both are required for full coverage:

- **SYSTEM pair** (`Detect-Python.ps1` / `Remediate-Python.ps1`) — machine-wide (HKLM) python.org installs, orphaned component MSIs, and Microsoft Store Python runtimes.
- **User pair** (`Detect-Python-User.ps1` / `Remediate-Python-User.ps1`) — per-user ("install for just me") python.org installs, which SYSTEM cannot cleanly uninstall. Deployed with **Run using logged-on credentials = Yes**.

The pair runs in **remove-only mode** (`$InstallStandardPython = $false`): the target 3.14.6 is delivered by a separate Win32 app, not by these scripts. Data-science distributions and user-managed tooling are deliberately left alone (see [Safety Notes](#safety-notes)).

---

## Scripts

| File | Purpose |
|---|---|
| `Detect-Python.ps1` | SYSTEM detection — exits 1 if any outdated machine-wide or Store Python is found |
| `Remediate-Python.ps1` | SYSTEM remediation — silently removes outdated machine-wide bundles, orphaned component MSIs, and old Store runtimes |
| `Detect-Python-User.ps1` | User-context detection — exits 1 if the signed-in user has an outdated per-user python.org install |
| `Remediate-Python-User.ps1` | User-context remediation — uninstalls the user's outdated per-user Python and cleans broken shortcuts |
| `DEPLOYMENT-Python.md` | Full deployment guide: prerequisites, test plan, rollout cautions, version-bump procedure |

---

## How It Works

### Detection (SYSTEM)
1. Relaunches itself in 64-bit PowerShell if started 32-bit; scans HKLM Uninstall keys in both 64-bit and 32-bit registry views
2. Parses the version from the ARP **DisplayName** (e.g. `Python 3.13.5 (64-bit)`) — the DisplayVersion field is not semantic (`3.14.150.0` actually means 3.14.0)
3. Flags python.org bundles and orphaned component MSIs older than 3.14.6, and Store runtimes `PythonSoftwareFoundation.Python.3.NN` older than the 3.14 line
4. Sweeps every user profile's hive (loading logged-off `NTUSER.DAT` hives read-only, always unloading them) — per-user finds are logged for inventory only, never gated on
5. Exits 1 (non-compliant) if anything outdated is found; exits 0 if compliant

### Remediation (SYSTEM)
1. Uninstalls outdated python.org bundles via their `QuietUninstallString` (WiX burn engine, `/uninstall /quiet /norestart`), confirming success by the ARP key disappearing
2. Removes orphaned component MSIs with `msiexec /x {GUID} /qn /norestart`
3. Removes old Store runtimes with `Remove-AppxPackage -AllUsers` (per-user fallback); **PythonManager is kept**
4. Force-cleans orphans msiexec could not remove (install folder + ARP keys) under strict guards — folder leaf must match `^Python\d{2,3}(-32)?$` and never the target `Python314` folder; broken all-users Start Menu shortcuts are swept
5. Re-scans HKLM and Store state; exits 0 only when no outdated Python remains

### Detection / Remediation (User pair)
1. Scans the current user's HKCU Uninstall keys (native + WOW6432Node) for python.org installs older than 3.14.6
2. Remediation runs the product's own quiet uninstaller as the user, then force-cleans leftovers (`%LOCALAPPDATA%\Programs\Python\PythonXY` + HKCU keys) and removes now-broken Start Menu / Desktop shortcuts
3. Re-scans and exits 0 only when the profile is clean

---

## Configuration

All settings are top-of-file variables. Keep detection and remediation **in sync**.

| Variable | Default | Meaning |
|---|---|---|
| `$TargetVersion` | `3.14.6` | Anything python.org below this is outdated (set in all four scripts) |
| `$StoreTargetLine` | `3.14` | Store runtimes below this minor line are removed |
| `$InstallStandardPython` | `$false` | Remove-only mode; `$true` makes the SYSTEM pair download 3.14.6 from python.org (SHA-256 + Authenticode verified) and install it machine-wide when no current Python remains |
| `$ForceCleanOrphans` | `$true` | Force-remove orphaned component MSIs that msiexec cannot uninstall |
| `$HandlePerUserFromSystem` | `$false` | Leave `$false`; per-user installs belong to the user-context pair |
| `$DownloadConfig` / `$InstallArgs` | 3.14.6 URLs + hashes | Only used when install mode is enabled |

---

## Intune Setup

Create **two** Remediation policies (Intune admin center > Devices > Remediations > Create script package), assigned to the same group:

1. **Standardize Python (SYSTEM)** — detection `Detect-Python.ps1`, remediation `Remediate-Python.ps1`. Run using logged-on credentials = **No**, Enforce signature check = No, Run in 64-bit PowerShell = **Yes** (required for the Appx cmdlets).
2. **Remove per-user Python (user context)** — detection `Detect-Python-User.ps1`, remediation `Remediate-Python-User.ps1`. Run using logged-on credentials = **Yes**, Enforce signature check = No, Run in 64-bit PowerShell = Yes.

Schedule: Run once for a pilot ring, then Daily for production — the scripts are idempotent. Full prerequisites, test matrix, and rollout cautions are in [DEPLOYMENT-Python.md](DEPLOYMENT-Python.md).

---

## Exit Codes

| Script | Exit 0 | Exit 1 |
|---|---|---|
| `Detect-Python.ps1` | Compliant — only current/allowed Python present | Outdated Python found (or unexpected error — fail toward remediation) |
| `Remediate-Python.ps1` | No outdated HKLM/Store Python remains after the run | Residual outdated Python, or a removal/install failed |
| `Detect-Python-User.ps1` | No outdated per-user python.org for this user | Outdated per-user install found (or error) |
| `Remediate-Python-User.ps1` | User profile clean after the run | Residual outdated per-user Python |

Uninstaller/installer exit codes `3010` and `1641` (reboot required/initiated) are treated as **success** — everything runs with `/norestart`, no reboot is forced, and `1605` (not installed) also counts as success. Success is ultimately confirmed by re-scanning the registry, not by exit codes alone.

---

## Logs

| Context | Location |
|---|---|
| SYSTEM pair | `C:\ProgramData\Monster\Logs\Detect-Python_*.log` and `Remediate-Python_*.log` |
| User pair | `%LOCALAPPDATA%\Monster\Logs\Detect-PythonUser_*.log` and `Remediate-PythonUser_*.log` (falls back to `%TEMP%`) |

Full timestamped transcripts land in the log files; Intune's captured output is a single summary line per run by design.

---

## Safety Notes

- **Anaconda / Miniconda are never touched** — removing them destroys conda environments; install mode also refuses to install python.org over a conda box
- **PythonManager and the runtimes it manages are kept** — they self-update
- **Python Launcher (`py.exe`) is left alone**, as is legacy IDE tooling (Python Tools for Visual Studio, Python Editor)
- **The target `Python314` folder is never force-cleaned** — 3.14.x patches share it with the kept 3.14.6
- **Running `python.exe` is never killed** — an in-use uninstall is reported and retried on the next cycle
- Shortcuts are deleted only when broken (target inside a removed install root and no longer existing); `Win32_Product` is never used; every loaded user hive is always unloaded

---

## Author

Saeid Agheli — Intune Administrator
https://github.com/saeidagheli88
