# Scripts

Each package lives in its own folder with its scripts, a usage README, and (for most) a full `DEPLOYMENT-*.md` guide with step-by-step Intune setup.

## Shared conventions (Windows Detect/Remediate pairs)

- Deploy as **SYSTEM** with **"Run script in 64-bit PowerShell = Yes"** (hard requirement — scripts self-guard/relaunch via Sysnative).
- Full transcripts land in `C:\ProgramData\Monster\Logs`; each script emits exactly one summary line to STDOUT for the Intune console.
- **Exit codes:** Detect `0` = compliant, `1` = found / any error (fail-safe: errors trigger remediation rather than silently passing). Remediate `0` = removed or no-op — **including "reboot pending"** (locked files queued for delete-on-reboot count as success, and detection treats queued binaries as compliant, so pairs never flap), `1` = a removal genuinely failed or residue remains after the verify pass.
- Detection scans HKLM Uninstall keys in **both 64-bit and 32-bit registry views**, per-user HKU hives for **every profile** (logged-off `NTUSER.DAT` hives are temporarily reg-loaded and always unloaded), on-disk binaries (folder-only leftovers don't count), and MSIX/Appx incl. provisioned packages.
- Remediation ends with a **VERIFY pass using the identical classifier as detection**, so the two scripts can never disagree. `Win32_Product` is never queried. No reboot is ever forced.

---

## Windows — app removal & standardization (Detect/Remediate pairs)

| Package | Description |
|---|---|
| [Remove-7Zip](Remove-7Zip/) | Full removal of every 7-Zip install (MSI, NSIS, per-user, MSIX); locked shell-extension DLL handled via delete-on-reboot |
| [Remove-Legacy-AdobeReader](Remove-Legacy-AdobeReader/) | Removes legacy 32-bit Readers and repairs the Adobe auto-updater; upgrades stay owned by the Win32 app |
| [Remove-Brave](Remove-Brave/) | Full removal incl. the Brave Update services and tasks that could reinstall it |
| [Remove-CrestronAirMedia](Remove-CrestronAirMedia/) | Full removal of all AirMedia versions, machine MSI and per-user EXE installs |
| [Remove-Dropbox](Remove-Dropbox/) | Full removal of the desktop app and update machinery — the user's synced-files folder is never touched |
| [Remove-DuckDuckGo](Remove-DuckDuckGo/) | MSIX-first full removal of the DuckDuckGo browser (removed and deprovisioned) |
| [Remove-GoogleDrive](Remove-GoogleDrive/) | Full removal of Drive for desktop / Backup and Sync — never touches Chrome or shared Google Update |
| [Remove-Telegram](Remove-Telegram/) | Full removal of desktop and Store Telegram, incl. per-user Roaming installs and chat cache |
| [Remove-Webex](Remove-Webex/) | Full removal of all Cisco Webex clients, plus a Graph helper to build the targeting group |
| [Standardize-Python](Standardize-Python/) | Clears all python.org Python below 3.14.6 — two pairs (SYSTEM + user context) for full coverage |

## macOS

| Package | Description |
|---|---|
| [macOS-PreInstall](macOS-PreInstall/) | zsh pre-install toolkit (PatchMyPC ports): close apps, remove old versions (Webex, JRE 8, generic), stage zip payloads |

## Tools

| Package | Description |
|---|---|
| [RemoveApp-Script-Generator](RemoveApp-Script-Generator/) | Offline HTML GUI that generates house-style Remove/Detect script pairs for any Windows app |

## Other standalone scripts

| Package | Description |
|---|---|
| [Chrome-LNA-Policy](Chrome-LNA-Policy/) | Chrome Local Network Access (LNA) policy |
| [Convert-CoManaged-To-Intune](Convert-CoManaged-To-Intune/) | Convert a co-managed device to Intune-only management |
| [Uninstall-Classic-Teams](Uninstall-Classic-Teams/) | Remove classic Microsoft Teams |
