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
| [App Removal & Standardization collection](./Scripts/) | Windows + macOS | Detect/Remediate pairs for 10 apps (7-Zip, Adobe Reader, Brave, Crestron AirMedia, Dropbox, DuckDuckGo, Google Drive, Python, Telegram, Webex), deployment guides, a macOS pre-install toolkit, and a script generator — see the [collection README](./Scripts/README.md) |
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
