# Intune Scripts

PowerShell **detection / remediation pairs** for Microsoft Intune (Windows), a set of **macOS pre-install scripts**, and a **script generator** tool. Each Windows app has `Detect-<App>.ps1` + `Remediate-<App>.ps1` and usually a `DEPLOYMENT-<App>.md` guide with step-by-step Intune setup.

## Shared conventions (Windows pairs)

- Deploy as **SYSTEM** with **"Run script in 64-bit PowerShell = Yes"** (hard requirement — scripts self-guard/relaunch via Sysnative).
- Full transcripts land in `C:\ProgramData\Monster\Logs`; each script emits exactly one summary line to STDOUT for the Intune console.
- **Exit codes:** Detect `0` = compliant, `1` = found / any error (fail-safe: errors trigger remediation rather than silently passing). Remediate `0` = removed or no-op — **including "reboot pending"** (locked files queued for delete-on-reboot count as success, and detection treats queued binaries as compliant, so pairs never flap), `1` = a removal genuinely failed or residue remains after the verify pass.
- Detection scans HKLM Uninstall keys in **both 64-bit and 32-bit registry views**, per-user HKU hives for **every profile** (logged-off `NTUSER.DAT` hives are temporarily reg-loaded and always unloaded, with orphaned-mount cleanup), on-disk binaries (folder-only leftovers don't count), and MSIX/Appx incl. provisioned packages.
- Remediation ends with a **VERIFY pass using the identical classifier as detection**, so the two scripts can never disagree. `Win32_Product` is never queried. No reboot is ever forced.

---

## Windows remediations

### 7-Zip — full removal
`Detect-7Zip.ps1` / `Remediate-7Zip.ps1` / [DEPLOYMENT.md](DEPLOYMENT.md)

Removes every 7-Zip install (publisher Igor Pavlov): MSI, NSIS EXE, per-user, and MSIX. MSI via `msiexec /x` with transient-code retry; NSIS via `Uninstall.exe /S` judged by the ARP key disappearing; per-user by direct key/folder removal. The classic locked `7z.dll` shell extension (held by explorer.exe) is queued for delete-on-reboot — that counts as **success**. Deletions are allow-listed (folder leaf must literally be `7-Zip`) and junction-safe. A 25-minute internal deadline exits 1 for retry before Intune's 30-minute kill. The tight MSIX filter (name + publisher) never touches the unofficial Store port.

### Adobe Reader — standardize on unified 64-bit Reader
`Detect-AdobeReader.ps1` / `Remediate-AdobeReader.ps1` / [DEPLOYMENT-AdobeReader.md](DEPLOYMENT-AdobeReader.md)

Removes legacy/duplicate 32-bit Readers (the whole `{AC76BA86-7AD7-…}` 9.x/X/XI/DC family) and repairs the Adobe ARM auto-updater (service re-enabled, `bUpdater` policy reset). **Never installs or upgrades Reader** — the Intune Win32 app owns that. Never touches the unified 64-bit Reader or paid Acrobat. Optional flag `$HandleStoreCoreApp` (must match in both scripts) also removes the MSIX CoreApp — only enable once the Win32 app is Required, or CoreApp-only users lose their PDF viewer.

### Brave Browser — full removal
`Detect-Brave.ps1` / `Remediate-Brave.ps1` / [DEPLOYMENT-Brave.md](DEPLOYMENT-Brave.md)

Removes release/Beta/Nightly, machine-wide and per-user, **including the Brave Update services** (`brave`, `bravem`, elevation/VPN — matched by binary path, never by name alone) and scheduled tasks that could reinstall it. Cleans ARP keys in both views, per-user AppData (app + User Data — profile data is deleted by design), Run values, Classes keys, StartMenuInternet registrations, shortcuts, and any Brave MSIX.

### Crestron AirMedia — full removal
`Detect-CrestronAirMedia.ps1` / `Remediate-CrestronAirMedia.ps1`

Removes every AirMedia version/scope (machine MSI + per-user 3.x/4.x/5.x EXE). MSI via `msiexec /x` with bounded retries on 1618 (install busy) and a `Win32_Product` fallback only if msiexec can't (e.g. missing source); EXE via Quiet/UninstallString with silent flags; every child process has a hard timeout. Only AirMedia-specific folders are removed — other Crestron products are untouched. Note: this pair logs to `C:\Windows\Temp` (predates the Monster\Logs convention).

### Dropbox — full removal (synced files untouched)
`Detect-Dropbox.ps1` / `Remediate-Dropbox.ps1` / [DEPLOYMENT-Dropbox.md](DEPLOYMENT-Dropbox.md)

Removes the desktop app, machine-wide enterprise install, `DbxSvc`/`dbupdate` services and update tasks, and the Store package. **The user's synced-content folder is never scanned, never a finding, never deleted** — process kills and service matching are path-restricted to `\Dropbox\Client\` / `\Dropbox\Update\`, so nothing running from the synced folder is touched.

### DuckDuckGo Browser — full removal (MSIX-first)
`Detect-DuckDuckGo.ps1` / `Remediate-DuckDuckGo.ps1` / [DEPLOYMENT-DuckDuckGo.md](DEPLOYMENT-DuckDuckGo.md)

The browser ships primarily as the `DuckDuckGo.DesktopBrowser` Store package, so detection is MSIX-first (all users + provisioned), then ARP both views, per-user hives, and on-disk binaries. Remediation removes and **deprovisions** the package so new profiles don't get it back. Removes the app only — doesn't block duckduckgo.com as a search site. The deployment guide also suggests assigning the Store app as Uninstall in Intune.

### Google Drive (desktop client) — full removal
`Detect-GoogleDrive.ps1` / `Remediate-GoogleDrive.ps1` / [DEPLOYMENT-GoogleDrive.md](DEPLOYMENT-GoogleDrive.md)

Removes Drive for desktop (DriveFS) and legacy Backup and Sync; dismounts the virtual `G:` drive. **Never touches Chrome or the shared Google Update machinery** (`gupdate`/`gupdatem`, `GoogleUpdateTaskMachine*`, `Google\Update`) — only Drive-specific subfolders/subkeys, never the Google vendor root. Cloud files are safe (DriveFS streams); only the local cache is deleted — not-yet-uploaded offline edits are lost, which is accepted for this removal.

### Python — standardize on 3.14.6 (remove-only)
`Detect-Python.ps1` / `Remediate-Python.ps1` + user-context pair `Detect-Python-User.ps1` / `Remediate-Python-User.ps1` / [DEPLOYMENT-Python.md](DEPLOYMENT-Python.md)

Two companion pairs: the SYSTEM pair clears machine-wide python.org bundles < 3.14.6, orphaned component MSIs, and old Store runtimes; the user pair (deploy with logged-on credentials = Yes) clears per-user "just me" installs — both policies are needed for full coverage. Versions are parsed from DisplayName because ARP `DisplayVersion` isn't semantic (`3.14.150.0` = 3.14.0). Runs in remove-only mode (`$InstallStandardPython = $false`) — 3.14.6 is delivered by a separate Win32 app. **Never touched:** Anaconda/Miniconda, PythonManager, the Python Launcher (`py.exe`), the target `Python314` folder; running `python.exe` is never killed. Force-clean only deletes folders whose leaf matches `^Python\d{2,3}(-32)?$`. User-context logs go to `%LOCALAPPDATA%\Monster\Logs`. (The `Python-Remediation-Scripts/` folder holds the same pairs.)

### Telegram — full removal
`Detect-Telegram.ps1` / `Remediate-Telegram.ps1` / [DEPLOYMENT-Telegram.md](DEPLOYMENT-Telegram.md)

Telegram installs per-user (Inno Setup) into Roaming — remediation sweeps every profile: uninstall keys, Run values, app folders including the `tdata` chat cache (deleted by design), Store package data, `tg://` protocol keys, and shortcuts, plus the machine-wide install and MSIX package (removed + deprovisioned). Per-user removal deliberately skips the unreliable Inno uninstaller under SYSTEM in favor of direct key/folder deletion. Known limit: portable copies (e.g. in Downloads) aren't chased.

### Webex — full removal (all Cisco Webex clients)
`Detect-Webex.ps1` / `Remediate-Webex.ps1` / [DEPLOYMENT-Webex.md](DEPLOYMENT-Webex.md) / `Add-WebexDevicesToGroup.ps1`

Removes the modern Webex App, classic Webex Meetings, Meetings Desktop App, Productivity Tools, and Webex Teams/Cisco Spark — machine and per-user. The classifier is anchored so Cisco AnyConnect/Secure Client/Jabber, the Readdle "Spark" mail app, and Microsoft's `WebExperience` (Windows Widgets) package can never match. Remediation kills live meetings — send comms before broad rollout. The earlier Webex 46.7 Win32 standardization app must stay **unassigned**. `Add-WebexDevicesToGroup.ps1` is a one-time admin-workstation Graph helper that fills the targeting Entra group from a device CSV — it never runs on endpoints.

---

## macOS — Pre-Install toolkit

[`macOS-PreInstall/`](macOS-PreInstall/) — native zsh ports of the PatchMyPC Community-Scripts Pre-Install collection. Run as **root** (Intune shell script or pkg preinstall); all refuse to run otherwise. Log to `/Library/Logs/Monster/<ScriptName>.log`; exit `0` = success/nothing-to-do, `1` = failure.

| Script | What it does |
|---|---|
| `Preinstall-CloseApp.sh` | Graceful quit via osascript in the console user's session (30 s), then force-kill |
| `Preinstall-RemoveApp.sh` | Template full removal: kill processes, bootout LaunchAgents/Daemons, remove bundles/support folders, forget pkg receipts, sweep every `/Users/*` home (fill in the `ExampleApp` placeholders first) |
| `Preinstall-Remove-Webex.sh` | Full Webex removal, machine + per-user |
| `Preinstall-Remove-JRE8.sh` | Removes JRE 8 (plug-ins, pref panes, receipts); leaves Oracle JDK 8 alone unless `REMOVE_JDK8="true"` |
| `Preinstall-ExtractZip.sh` | Stages a zip payload with `ditto -x -k` (preserves resource forks/signing); `CLEAN_DEST="true"` empties the destination first |

See the folder's [README](macOS-PreInstall/README.md) for details.

---

## Tools

### RemoveApp Script Generator
[`RemoveApp-Script-Generator.html`](RemoveApp-Script-Generator.html) — a self-contained, fully offline HTML GUI that generates a house-style `Remove-<App>.ps1` (and optional matching `Detect-<App>.ps1`) from a form: DisplayName patterns, publisher filter, processes to stop, silent args, leftover folders. Generated scripts follow all conventions above and include safety guards (path-depth check so a malformed path can never delete a drive root, 10-minute bounded uninstaller runs, processes killed only after something removable is confirmed). Generated detection is ARP-registry based only — MSIX and offline user hives are deliberately out of scope for generated scripts.

---

## Also in this folder

Standalone tools that predate this collection, each with its own README:

- [Chrome-LNA-Policy](Chrome-LNA-Policy/) — Chrome Local Network Access (LNA) policy
- [Convert-CoManaged-To-Intune](Convert-CoManaged-To-Intune/) — convert a co-managed device to Intune-only management
- [Uninstall-Classic-Teams](Uninstall-Classic-Teams/) — remove classic Microsoft Teams
