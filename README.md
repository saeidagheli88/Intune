# Intune Scripts

A collection of production-ready scripts and packages for managing Windows and macOS devices with **Microsoft Intune**. Scripts are organized by category and each includes full documentation and setup instructions.

---

---

## Categories

### Remediations
Detection and Remediation script pairs deployed via Intune Remediations.

| Name | Platform | Description |
|---|---|---|
| [Remove-iTunes](./Remediations/Remove-iTunes/) | Windows | Detects and silently removes iTunes from Windows devices |

### Scripts
Standalone scripts deployed via Intune Script policies.

| Name | Platform | Description |
|---|---|---|
| [Remove-7Zip](./Scripts/Remove-7Zip/) | Windows | Full removal of every 7-Zip install (MSI, NSIS, per-user, MSIX) |
| [Remove-Legacy-AdobeReader](./Scripts/Remove-Legacy-AdobeReader/) | Windows | Removes legacy 32-bit Adobe Readers and repairs the auto-updater |
| [Remove-Brave](./Scripts/Remove-Brave/) | Windows | Full Brave removal incl. its update services and tasks |
| [Remove-CrestronAirMedia](./Scripts/Remove-CrestronAirMedia/) | Windows | Full removal of all Crestron AirMedia versions and scopes |
| [Remove-Dropbox](./Scripts/Remove-Dropbox/) | Windows | Full Dropbox app removal — synced files are never touched |
| [Remove-DuckDuckGo](./Scripts/Remove-DuckDuckGo/) | Windows | MSIX-first full removal of the DuckDuckGo browser |
| [Remove-GoogleDrive](./Scripts/Remove-GoogleDrive/) | Windows | Full Drive-for-desktop removal — Chrome/Google Update untouched |
| [Remove-Telegram](./Scripts/Remove-Telegram/) | Windows | Full removal of desktop and Store Telegram, all profiles |
| [Remove-Webex](./Scripts/Remove-Webex/) | Windows | Full removal of all Cisco Webex clients + targeting-group helper |
| [Standardize-Python](./Scripts/Standardize-Python/) | Windows | Clears python.org Python below 3.14.6 (SYSTEM + user pairs) |
| [macOS-PreInstall](./Scripts/macOS-PreInstall/) | macOS | zsh pre-install toolkit: close apps, remove old versions, stage zips |
| [RemoveApp-Script-Generator](./Scripts/RemoveApp-Script-Generator/) | Tool | Offline HTML GUI that generates Remove/Detect script pairs |
| [Chrome-LNA-Policy](./Scripts/Chrome-LNA-Policy/) | Windows | Configures the Chrome Local Network Access (LNA) policy |
| [Convert-CoManaged-To-Intune](./Scripts/Convert-CoManaged-To-Intune/) | Windows | Converts a co-managed device to Intune-only management |
| [Uninstall-Classic-Teams](./Scripts/Uninstall-Classic-Teams/) | Windows | Detects and removes classic Microsoft Teams |

### Packages
Application packages deployed via Intune Win32 App or DMG/PKG policies.

| Name | Platform | Description |
|---|---|---|
| Coming soon | | |

---

## Author

Saeid Agheli — Intune Administrator
https://github.com/saeidagheli88
