PREREQUISITES (apply to every deployment path below)
- License: Windows 10/11 Enterprise/Education or equivalent with Intune
  Remediations entitlement (Win10/11 E3/E5, A3/A5, F3, or Win Ent E3/E5 add-on).
- Files are UTF-8 (no BOM). Upload as-is; do not re-save in an editor that adds a
  BOM, and do not sign unless your tenant enforces signing (set the signature flag
  accordingly and sign BOTH scripts with the same cert).
- HARD requirement for BOTH scripts: "Run this script using the logged-on
  credentials" = No (runs as SYSTEM); "Run script in 64-bit PowerShell" = Yes;
  "Enforce script signature check" = No (unless you sign them).

OPTION A -- DEPLOY AS A REMEDIATION (recommended: detection + remediation pair)
1. Intune admin center -> Devices -> Remediations -> Create script package.
2. Name: "Remove 7-Zip (Igor Pavlov)". Publisher: Monster Energy Endpoint Eng.
3. Detection script file: Detect-7Zip.ps1.  Remediation script file:
   Remediate-7Zip.ps1.
4. Settings:
   - Run this script using the logged-on credentials = No
   - Enforce script signature check = No
   - Run script in 64-bit PowerShell = Yes  (REQUIRED -- makes the Sysnative
     relaunch dead code and is the only config where the Appx cmdlets are
     guaranteed to work)
5. Assign to your PILOT device group first (see Test Plan).
6. Schedule: start with "Run once" for the pilot to observe a single pass. For
   production use Daily (or Hourly during an active cleanup campaign). The pair is
   idempotent, so a recurring schedule simply confirms compliance after the device
   is clean (detection returns exit 0 and remediation does not run).
7. How it gates: detection exit 1 = 7-Zip found -> remediation runs; exit 0 =
   clean -> remediation skipped. After remediation, the next detection cycle
   reports compliance. Watch the "Detection script output" column -- it shows the
   single STDOUT summary line ("7-Zip detected: ..." or "No 7-Zip found.").

OPTION B -- DEPLOY THE REMEDIATION ALONE AS A PLATFORM SCRIPT
Use this if you want a one-shot forced removal without the detect/gate cycle
(e.g. a known-infected ring), or if Remediations licensing is unavailable.
1. Devices -> Scripts and remediations -> Platform scripts -> Add -> Windows 10
   and later.
2. Upload Remediate-7Zip.ps1.
3. Settings (identical to Option A):
   - Run this script using the logged-on credentials = No
   - Enforce script signature check = No
   - Run script in 64-bit PowerShell host = Yes
4. Assign to the target group. Note: Platform scripts run ONCE per device (they do
   not re-run on a schedule unless you re-create/re-assign or change the script),
   and Intune only reports the exit code, not per-run history -- so rely on the
   transcripts under C:\ProgramData\Monster\Logs for evidence. The script is still
   idempotent, so an accidental re-run on a clean device is a safe no-op (exit 0).

TEST PLAN (do this before any broad rollout)
1. Local SYSTEM smoke test on a lab VM, BEFORE Intune:
   - Run elevated:  PsExec64.exe -s -i powershell.exe -NoProfile -ExecutionPolicy
     Bypass -File "C:\path\Detect-7Zip.ps1" ; echo $LASTEXITCODE
     Confirm exit 1 when 7-Zip is installed, exit 0 after removal. (The
     $PSCommandPath guard means even an ad-hoc -Command invocation won't produce a
     garbage exit code.)
   - Then run Remediate-7Zip.ps1 the same way; confirm exit 0 and re-run detection
     to confirm exit 0. Inspect the transcripts in C:\ProgramData\Monster\Logs.
   - Test matrix: machine-wide MSI x64, NSIS EXE x64, NSIS x86 (Program Files
     (x86)), a per-user NSIS install under a SECOND logged-off profile, and a
     clean machine (must be a no-op, exit 0). Idempotency: run remediation twice;
     the second pass must change nothing and exit 0.
2. Pilot ring in Intune (5-20 devices spanning the matrix above, including at
   least one multi-user/shared device and one device with a user actively logged
   on). Assign Option A to this ring only. Watch for 48-72h:
   - Compliance flips to "Without issues" and stays there (no flapping = no loop).
   - Spot-check transcripts on a few devices for "fully removed" and for any
     "FAILED to unload HKU" or "Get-AppxPackage unavailable" lines.
3. Expand to broader rings progressively (e.g. 1% -> 10% -> 50% -> 100%) only
   after the pilot is stable for a full detection cycle with no regressions.

ROLLOUT CAUTIONS
- 64-bit flag is mandatory. If a device somehow runs the 32-bit host AND Sysnative
  is missing, registry/file/msiexec removal still works (dual RegistryView reads),
  but the Appx cmdlets may be unavailable -- the scripts log this explicitly and
  will NOT report a false "clean" for MSIX. 7-Zip is essentially never an MSIX, so
  this edge is low-impact, but keep the flag = Yes.
- Per-user / MSIX from SYSTEM: per-user Win32 (NSIS/MSI) installs ARE removed (HKU
  hive sweep + direct key/folder deletion from the correct hive). A genuine
  per-user MSIX for a LOGGED-OFF user can fail to remove from SYSTEM; if your fleet
  has that (rare), pair this with a USER-context Remediation that runs the same
  Test-Is7ZipAppx + Remove-AppxPackage logic. The SYSTEM script logs such cases and
  marks the run incomplete rather than falsely "done".
- Process termination: when 7-Zip is being removed, an interactive user's 7-Zip
  File Manager or an in-progress extraction is force-closed (only processes whose
  path is inside a 7-Zip folder, each logged with PID/path). Communicate the
  cleanup window to users to avoid data loss on open archives.
- Reboots: msiexec runs /norestart REBOOT=ReallySuppress; exit 3010/1641 are
  treated as success. No reboot is forced, but a pending-reboot flag may be set --
  fine for a scheduled cleanup.
- $KnownAppxFamilies is intentionally EMPTY. Only populate it with a
  PackageFamilyName you have CONFIRMED on your fleet; the default tight filter
  (name + 'Igor Pavlov' publisher) cannot match the unofficial third-party Store
  port and will not remove unrelated Store apps.
- Evidence lives in C:\ProgramData\Monster\Logs (Detect-7Zip_*.log and
  Remove-7Zip_*.log). Intune's captured STDOUT is a single summary line by design.
- Shell extensions / HKCR ContextMenuHandlers are intentionally left to 7-Zip's
  own uninstaller (shared/global keys). If you confirm stubborn context-menu
  leftovers fleet-wide, add a tightly scoped, separately-piloted cleanup plus an
  explorer.exe restart -- do not broaden this script to touch shared HKCR keys.