PYTHON STANDARDIZATION -- Detect-Python.ps1 / Remediate-Python.ps1
=================================================================
Goal: bring every device to the managed standard Python (python.org 3.14.6,
machine-wide) and remove OUTDATED Python, while LEAVING ALONE the things that
are dangerous or pointless to touch (Anaconda/Miniconda, PythonManager + its
runtimes, the py.exe launcher, legacy IDE tooling).

WHAT THE PAIR DOES (decided defaults -- all are top-of-file toggles)
- REMOVE: python.org traditional bundles "Python X.Y.Z (64-bit)" older than 3.14.6
  (covers 3.7 / 3.10 / 3.11 / 3.12 / 3.13 / 3.14.0-3.14.5 on your fleet), plus any
  orphaned python.org component MSIs and Microsoft Store runtimes
  "PythonSoftwareFoundation.Python.3.NN" older than 3.14.
- INSTALL: machine-wide python.org 3.14.6 ONLY when a device would otherwise be left
  with no current Python. The installer is downloaded from python.org and verified by
  SHA-256 (pinned) AND Authenticode (signer "Python Software Foundation") before it
  runs. Set $InstallStandardPython=$false (in BOTH scripts) for remove-only.
- LEAVE ALONE (flagged in the log, never removed): Anaconda/Miniconda (removing them
  destroys conda environments), PythonManager and the runtimes it manages
  ("Python 3.14.x" with no "(64-bit)" suffix / version "3.14-64"), "Python Launcher",
  and "Python Tools for Visual Studio" / "Python Editor".

WHY VERSION IS READ FROM THE NAME, NOT THE VERSION FIELD
The python.org ARP DisplayVersion is NOT semantic: "3.14.150.0" means 3.14.0 and
"3.13.5150.0" means 3.13.5. Both scripts parse major.minor.patch from the DisplayName
("Python 3.14.0 (64-bit)"). Verified against the live inventory: every entry resolves
to the correct REMOVE/KEEP/LEAVE verdict.

PREREQUISITES (same as the 7-Zip pair)
- License: Win10/11 Enterprise/Education (or Win Ent E3/E5 add-on) with the Intune
  Remediations entitlement.
- Files are UTF-8 (no BOM). Upload as-is; do not add a BOM; sign only if your tenant
  enforces signing (sign BOTH scripts with the same cert and set the flag).
- HARD requirement for BOTH scripts: "Run this script using the logged-on
  credentials" = No (SYSTEM); "Run script in 64-bit PowerShell" = Yes; "Enforce
  script signature check" = No (unless you sign them).
- NETWORK: when install is enabled, the device must reach
  https://www.python.org/ftp/python/3.14.6/ from SYSTEM context. If your fleet blocks
  SYSTEM internet egress, use remove-only mode (below) and deploy 3.14.6 as a
  separate Win32/Store app.

OPTION A -- DEPLOY AS A REMEDIATION (recommended)
1. Intune admin center -> Devices -> Remediations -> Create script package.
2. Name: "Standardize Python 3.14.6". Publisher: Monster Energy Endpoint Eng.
3. Detection script: Detect-Python.ps1.  Remediation script: Remediate-Python.ps1.
4. Settings:
   - Run this script using the logged-on credentials = No
   - Enforce script signature check = No
   - Run script in 64-bit PowerShell = Yes  (REQUIRED -- the Appx cmdlets used for
     Store runtimes only work reliably in the 64-bit host)
5. Assign to your PILOT group first (see Test Plan).
6. Schedule: "Run once" for the pilot to watch a single pass; Daily for production.
   The pair is idempotent, so a recurring schedule just confirms compliance.
7. How it gates: detection exit 1 = outdated Python found OR standard missing ->
   remediation runs; exit 0 = compliant -> remediation skipped. Watch the "Detection
   script output" column for the single STDOUT line ("Python update needed: ..." or
   "Python compliant (target 3.14.6).").

SCOPE (IMPORTANT -- two policies, split by capability)
The SYSTEM pair owns MACHINE-WIDE (HKLM) python.org + Microsoft Store (all-users)
Python, and installs the standard 3.14.6. It intentionally does NOT gate on or
remove PER-USER ("install for just me", HKU/HKCU) installs -- SYSTEM cannot cleanly
uninstall a per-user MSI, and gating on it would flap forever. Per-user installs are
handled by the USER-CONTEXT COMPANION below. Most of the fleet's legacy Python is
per-user, so BOTH policies are needed for full coverage.

OPTION A2 -- USER-CONTEXT COMPANION (Detect/Remediate-Python-User.ps1) [REQUIRED for per-user]
1. Remediations -> Create script package. Name: "Remove per-user Python (user
   context)".
2. Detection: Detect-Python-User.ps1.  Remediation: Remediate-Python-User.ps1.
3. Settings -- NOTE the difference from the SYSTEM pair:
   - Run this script using the logged-on credentials = YES  (runs as the user so the
     per-user MSI/burn uninstall actually works)
   - Enforce script signature check = No
   - Run script in 64-bit PowerShell = Yes
4. Assign to the SAME user/device group as the SYSTEM pair (Daily). It only removes
   the signed-in user's old per-user python.org; it leaves Anaconda, PythonManager,
   the launcher, and Store runtimes (those are the SYSTEM pair's job) untouched.
5. Logs: %LOCALAPPDATA%\Monster\Logs\*PythonUser*.log (per user, since ProgramData
   may not be writable by a standard user).

OPTION B -- REMOVE-ONLY (no auto-install), as a Remediation or Platform Script
Use this when you deploy 3.14.6 separately (Win32 app / Company Portal / Store) or
have no SYSTEM internet egress.
1. In BOTH Detect-Python.ps1 and Remediate-Python.ps1 set:  $InstallStandardPython = $false
2. Deploy either as the Remediation pair (Option A) or the remediation alone as a
   Platform Script (Devices -> Scripts and remediations -> Platform scripts). Same
   SYSTEM / 64-bit settings. Platform scripts run once per device; rely on the
   transcripts for evidence.

CHANGING THE TARGET VERSION LATER (e.g. 3.14.7)
1. In BOTH scripts bump  $TargetVersion = [version]'3.14.7'.
2. In Remediate-Python.ps1 update $DownloadConfig URLs to the new filenames and paste
   the new SHA-256 from https://www.python.org/downloads/release/python-3147/ (amd64
   and arm64). Leave a hash '' to rely on Authenticode alone (still secure).
3. $StoreTargetLine only changes when you move to a new MINOR line (e.g. 3.15).

TEST PLAN (before any broad rollout)
1. Local SYSTEM smoke test on a lab VM (use PsExec64 -s -i, as in the 7-Zip plan):
   - Detect-Python.ps1: exit 1 when an old Python is present, exit 0 once clean.
   - Remediate-Python.ps1: exit 0; re-run Detect to confirm exit 0. Inspect
     C:\ProgramData\Monster\Logs\Detect-Python_*.log / Remediate-Python_*.log.
   - Matrix: machine-wide python.org 3.13 (must be removed + 3.14.6 installed); a
     per-user python.org install under a SECOND logged-off profile; a Store runtime
     3.12/3.13 (must be removed, PythonManager kept); a box WITH Anaconda (Anaconda
     must be untouched AND python.org must NOT be force-installed over it); a box with
     ONLY PythonManager (no removal, no install); a clean 3.14.6 box (no-op exit 0).
   - Idempotency: run remediation twice; the second pass changes nothing, exit 0.
2. Pilot ring (5-20 devices spanning the matrix, including a multi-user device and one
   with a user logged on). Watch 48-72h: compliance flips to "Without issues" and
   stays (no flapping), and a few transcripts show "remediation complete".
3. Expand 1% -> 10% -> 50% -> 100% only after a stable pilot.

ROLLOUT CAUTIONS
- Anaconda is protected by design: it is matched by name/publisher and skipped
  everywhere, and the install step refuses to drop python.org onto a conda box. If a
  team wants their conda removed, do it as a separate, communicated task.
- PythonManager + its runtimes are intentionally left to self-update. Devices that
  rely solely on PythonManager will NOT get a python.org install (they already have a
  managed Python). If you want python.org everywhere regardless, change the install
  gate in section 5 of the remediation -- but pilot it.
- Per-user Store runtimes from SYSTEM: Remove-AppxPackage -AllUsers handles installed
  packages; a logged-off per-user MSIX that resists removal is logged and the run is
  marked incomplete (not a false "done"). Pair with a user-context remediation if your
  fleet has stubborn cases (rare).
- Orphaned component MSIs: when a python.org bundle is already gone, its component
  MSIs (Core Interpreter, Standard Library, Tcl/Tk, etc.) can't be uninstalled by
  msiexec (their cached source went with the bundle). The remediation's force-clean
  ($ForceCleanOrphans = $true) removes the version's install folder + ARP keys under
  strict guards: it only deletes a folder whose leaf matches ^Python\d{2,3}(-32)?$ and
  NEVER the target line's folder (Python314 holds the kept 3.14.6). Set
  $ForceCleanOrphans = $false to disable and rely on msiexec only.
- "Invalid key name" fatal: earlier builds could abort the whole run on a device with
  a corrupt HKU child key. Detection/remediation now enumerate HKU via .NET and wrap
  the pre-pass, so a single bad key is skipped instead of failing the device.
- Gate signal: the SYSTEM remediation reports success/failure from the HKLM/Store
  residual re-scan + install result, NOT from a raw failure counter -- so an msiexec
  failure that force-clean then resolves does not keep a device perpetually
  "incomplete".
- No process killing: running python.exe is deliberately NOT terminated (it could be a
  user's script or a service). If an uninstall fails because files are in use, it is
  reported and retried next cycle.
- Reboots: uninstalls/installs run /norestart; exit 3010/1641 are treated as success.
  No reboot is forced (a pending-reboot flag may be set -- fine for a scheduled job).
- PATH: the machine-wide install uses PrependPath=1 so python/py resolve for all users.
  Removing old per-user installs may remove their per-user PATH entries; the launcher
  (py.exe) and the new machine-wide python remain on PATH.
- Evidence lives in C:\ProgramData\Monster\Logs. Intune's captured STDOUT is one
  summary line by design.
