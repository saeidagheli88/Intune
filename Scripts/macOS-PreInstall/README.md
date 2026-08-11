# macOS Pre-Install Scripts

macOS port of the [PatchMyPC Community-Scripts Pre-Install](https://github.com/PatchMyPCTeam/Community-Scripts/tree/main/Install/Pre-Install) collection.
The originals are Windows PowerShell; these are native zsh scripts that do the
equivalent cleanup on Macs before an app install/upgrade.

## Script mapping

| Windows original | macOS script | Notes |
|---|---|---|
| Extract Zip | `Preinstall-ExtractZip.sh` | Uses `ditto` to preserve macOS metadata/code signing |
| Remove-JRE8 | `Preinstall-Remove-JRE8.sh` | Removes Oracle JRE 8 plugin, Control Panel, updater, receipts. Optional JDK 1.8 removal via `REMOVE_JDK8` flag |
| Remove-WebexSystemUser | `Preinstall-Remove-Webex.sh` | Full removal of ALL Webex products (machine + per-user), matching the Windows Detect/Remediate-Webex.ps1 standard |
| Remove-RemoteDesktopSystemUser | — no macOS equivalent | Windows user-profile concept; replaced by generic `Preinstall-RemoveApp.sh` |
| RegisterOracleCodeSigning.ps1 | — no macOS equivalent | Windows registry / WinVerifyTrust concept; replaced by `Preinstall-CloseApp.sh` |
| *(new)* | `Preinstall-RemoveApp.sh` | Generic template: copy per app, fill in the CONFIGURE block |
| *(new)* | `Preinstall-CloseApp.sh` | Graceful quit (osascript in user session) then force kill |

## House conventions

- All scripts must run as **root** (they check and exit 1 if not).
- Logs: `/Library/Logs/Monster/<ScriptName>.log` (macOS counterpart of `C:\Monster\Logs`).
- Exit codes: `0` = success or nothing to do, `1` = failure.
- Per-user cleanup loops over every home in `/Users/` (skips `Shared`), so it
  works even when no one is logged in.

## Deploying with Intune

**Option A — standalone shell script**
Intune admin center → **Devices → macOS → Shell scripts** → Add:
- Run script as signed-in user: **No** (runs as root)
- Hide script notifications: Yes
- Script frequency: Not configured (run once) or on a schedule
- Max retries if script fails: 3

**Option B — pkg preinstall script**
When wrapping an installer as a distribution pkg (e.g. with `pkgbuild`/`munkipkg`),
drop the script in as the `preinstall` script so cleanup always runs immediately
before the payload installs.

**Option C — before an Unmanaged/DMG app deployment**
Assign the shell script to the same group as the app, sequenced ahead of it
(scripts generally run at check-in before app installs complete).

## Local testing

```bash
sudo zsh -n Preinstall-Remove-Webex.sh    # syntax check only
sudo ./Preinstall-Remove-Webex.sh         # real run
tail -f "/Library/Logs/Monster/Preinstall-Remove-Webex.log"
```
