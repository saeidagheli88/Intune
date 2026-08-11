# Webex — REMOVE ALL Webex clients from Windows devices — Deployment Guide

Management decision (2026-07-14): **no Webex client stays**. Every Cisco Webex
product is removed from every Windows device — the modern unified Webex App
(machine-wide AND per-user copies) plus all legacy clients.

> Supersedes the earlier draft of this guide that standardized on Webex App
> 46.7 via a Win32 app. If that Win32 app was already created in Intune,
> **do not assign it** — leave it unassigned or delete it.

Scope from the 2026-07-14 Discovered Apps export (`AppInvRawData_….csv`):

| Inventory row | Devices | Install type |
|---|---|---|
| Webex (Cisco Systems, Inc) 41.x–46.x | — | machine MSI and/or per-user |
| Cisco Webex Meetings (classic) 39.x–45.x | — | mostly **per-user** |
| Cisco Webex Productivity Tools | — | machine MSI |
| Cisco Webex Meetings Desktop App | — | machine MSI |
| WebEx Productivity Tools 32.8 | — | machine MSI |
| Webex Teams 3.0 | — | per-user |

**Multiple Windows devices** carry at least one of these. iOS Webex apps
are out of scope — handle those by removing/blocking the app in
Intune app management.

## The pair

| Script | Job |
|---|---|
| `Detect-Webex.ps1` | Finds ANY Webex: HKLM uninstall entries (both registry views), per-user HKU uninstall entries (every profile, offline NTUSER.DAT hives loaded/unloaded), and Webex binaries on disk in machine + per-profile folders. Exit 1 = found. |
| `Remediate-Webex.ps1` | Kills Webex processes; msiexec-uninstalls machine MSI products; brute-force removes non-MSI and per-user installs (registry keys + folders); cleans Run values, the classic `webexservice`, shortcuts, and user-data folders; then VERIFIES with the identical rules detection uses. Exit 0 = clean or reboot-pending. |

Key design points (house conventions):

- **Per-user coverage**: classic Webex Meetings and many modern Webex installs
  live in `<profile>\AppData\Local\...` with HKU uninstall keys. A per-user MSI
  cannot be `msiexec /x`'d from SYSTEM, so per-user copies are removed
  brute-force (keys + files). Offline hives are `reg load`ed and ALWAYS
  unloaded; orphaned mounts are cleaned at startup.
- **Loop/flap safety**: folder findings are binary-gated (an empty leftover
  folder is not a finding); a binary queued for delete-on-reboot counts as
  compliant; "reboot required" (MSI 3010/1641 or locked files queued via
  MoveFileEx) is SUCCESS, not failure — same as the 7-Zip pair.
- **Classifier** (identical in both scripts): DisplayName matching
  `^(cisco )?webex` / `^cisco spark`, or `webex` anywhere in the name when the
  publisher is Cisco. Cisco AnyConnect / Secure Client / Jabber can never
  match; the standalone "Spark" mail app can never match.
- **User data**: user-data folders and leftover vendor registry keys are
  deleted opportunistically during remediation but are never detection
  findings (flap safety).

## Full location coverage map

| Location | Path / key | Detection finding? | Remediation |
|---|---|---|---|
| Machine folders | `C:\Program Files\Cisco Spark`, `C:\Program Files\Webex`, same under `(x86)`, `C:\ProgramData\WebEx`, `C:\ProgramData\Cisco Spark`, `C:\ProgramData\CiscoSparkLauncher` | Yes (if a Webex binary inside) | Deleted entirely; locked files queued for delete-on-reboot |
| Per-user app folders | `<profile>\AppData\Local\Programs\Cisco Spark`, `...\Local\WebEx`, `...\Local\CiscoSpark`, `...\Local\CiscoSparkLauncher` — every profile | Yes (if a Webex binary inside) | Deleted entirely; locked files queued |
| Per-user data folders | `<profile>\AppData\Local\Webex`, `...\Roaming\Webex` (covers `Roaming\WebEx`), `...\LocalLow\WebEx` | No | Deleted |
| Machine registry (ARP) | `HKLM\...\Uninstall\*` — BOTH 64-bit and 32-bit views | Yes | MSI → msiexec /x; non-MSI → key deleted |
| Per-user registry (ARP) | `HKU\<SID>\...\Uninstall\*` + `WOW6432Node` — every profile, offline hives loaded | Yes | Key deleted |
| Autostart | `HKLM\...\Run` (both views) + `HKU\<SID>\...\Run` — name or data matching Webex | No | Value deleted |
| Leftover vendor keys | `SOFTWARE\WebEx`, `SOFTWARE\CiscoSpark`, `SOFTWARE\Cisco Spark`, `SOFTWARE\Cisco Spark Native` — HKLM (both views) and every HKU | No | Subtree deleted |
| Protocol handlers / ProgIDs | `SOFTWARE\Classes\webex*`, `wbx*`, `ciscospark*`, `cisco-spark*` — HKLM (both views) and every HKU | No | Subtree deleted |
| Store / MSIX packages | Appx packages with `webex` in the name AND a Cisco publisher (all users), plus provisioned copies | Yes (installed pkgs) | `Remove-AppxPackage -AllUsers` + deprovisioned. **`MicrosoftWindows.Client.WebExperience` (Windows Widgets, Microsoft) is explicitly excluded — never remove it.** |
| Service | classic `webexservice` | No | Stopped + `sc delete` |
| Shortcuts | per-profile Desktop / Start Menu / Startup, All-Users Start Menu, Public Desktop — `.lnk`/`.url` named Webex/Cisco Spark | No | Deleted (empty Webex program-group folders too) |

"No" in the detection column is deliberate: those artifacts cannot block a
device from being compliant (no flap risk if one resists deletion), but the
remediation cleans them on every device the uninstall-key/binary findings
send it to.

## Deploy

Intune → Devices → Scripts and remediations → **Create**:

| Setting | Value |
|---|---|
| Detection script | `Detect-Webex.ps1` |
| Remediation script | `Remediate-Webex.ps1` |
| Run this script using the logged-on credentials | **No** (SYSTEM) |
| Enforce script signature check | No |
| Run script in 64-bit PowerShell | **Yes** (HARD requirement) |
| Schedule | Daily |

## Pilot first

Target a small group that includes at least:

- one device with the modern Webex App machine-wide (`C:\Program Files\Cisco Spark`),
- one with a per-user modern Webex (stale 41.x–43.x rows in the export),
- one classic "Cisco Webex Meetings" device (per-user install),
- one "Cisco Webex Productivity Tools" device (machine MSI),
- ideally one of the 54 devices carrying multiple legacy variants.

**Heads-up before broad rollout**: this uninstalls a meeting client people may
actively use — remediation kills running Webex meetings on the device. Confirm
comms have gone out (what replaces Webex for meetings, e.g. Teams) and schedule
accordingly. The process-kill list runs before uninstall by design; there is no
"is a meeting in progress" guard.

## Expected timeline

- **~24 h**: detection flags the affected devices; remediation strips machine and
  per-user installs. Devices with locked files show "REBOOT PENDING" (still
  compliant) and finish on next restart.
- **~7 days**: Discovered Apps inventory refreshes (weekly per device) — all
  six Webex rows drain out of the report.
- **Steady state**: detection exits 0 everywhere; if a user manually
  reinstalls Webex, the daily schedule removes it again automatically.

## Verification

- Remediation node output per device: `Webex removal OK: Actions: ...`.
- Re-run the Discovered Apps export after a week: all `Webex*` /
  `Cisco Webex*` rows → zero (only `MicrosoftWindows.Client.WebExperience`
  remains — that's Windows Widgets, not Webex; leave it).
- Per-device logs: `C:\ProgramData\Monster\Logs\Detect-Webex_*.log` /
  `Remediate-Webex_*.log` + verbose `MsiUninstall-Webex_*.log` per product.

## Known failure signatures (from the July 2026 pilot)

- `Actions: uninstalled Webex vX | FAILURES: residual: HKLM Registry64: Webex`
  → **orphaned ARP key**: machine-wide Webex auto-updated and left the original
  product code registered in ARP while Windows Installer no longer knows it
  (msiexec /x returns 1605). Fixed in the current Remediate-Webex.ps1: after a
  successful MSI pass, a surviving ARP key is deleted directly. If you see
  this signature, the device is running the pre-fix script version.
- Remediation "Failed" with EMPTY output → the run's output hadn't synced yet
  or the script died without a summary; check
  `C:\ProgramData\Monster\Logs\Remediate-Webex_*.log` on the device and let
  the next daily run retry before digging further.

## Optional hardening (after the fleet is clean)

- Intune → Apps: add the Webex Store app as **Blocked** / use AppLocker or
  WDAC to stop user re-installs, since the per-user installer needs no admin
  rights. The daily remediation already handles re-installs, but blocking
  prevents them outright.
- Remove any Webex Outlook add-in via M365 admin (integrated apps) if it was
  centrally deployed.
