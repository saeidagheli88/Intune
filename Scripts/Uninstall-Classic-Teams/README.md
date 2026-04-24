# Script - Uninstall Classic Microsoft Teams

## Overview

This folder contains two official **Microsoft** PowerShell scripts (MIT Licensed) for completely removing **Classic Microsoft Teams** from Windows devices and remediating any leftover Teams Meeting Add-in (TMA) components. These are designed to be deployed via **Intune Script policies** as part of migrating users to **New Microsoft Teams**.

---

## Scripts

| File | Version | Purpose |
|---|---|---|
| `UninstallClassicTeams.ps1` | 1.1.9 | Fully uninstalls Classic Teams for all user profiles on the machine |
| `DetectAndUninstallTMA.ps1` | 1.1.0 | Detects and removes a faulty Teams Meeting Add-in left behind after Classic Teams removal |

---

## UninstallClassicTeams.ps1

### What It Does
- Finds and removes Classic Teams for **all user profiles** on the machine
- Kills any running Teams processes before uninstalling
- Runs the Teams uninstall command from the registry
- Removes all Teams-related file system entries (AppData, Roaming, SquirrelTemp)
- Cleans up all stale registry keys from HKEY_USERS
- Removes the Teams Machine-Wide Installer (64-bit and 32-bit)
- Removes Teams Meeting Add-in folders per user profile
- Cleans up VDI-related Teams components (unless -SkipAllArtifactsRemoval is passed)
- Removes Teams shortcuts from all user Start Menus
- Writes a detailed log to `C:\Windows\Temp\Classic_Teams_Uninstallation-[timestamp].txt`
- Creates a registry key `HKLM\Software\Microsoft\TeamsAdminLevelScript` when complete (used by DetectAndUninstallTMA.ps1)

### Parameters

| Parameter | Type | Description |
|---|---|---|
| `-SkipAllArtifactsRemoval` | Switch | If passed, skips VDI cleanup steps |

---

## DetectAndUninstallTMA.ps1

### What It Does
- Only runs remediation if `UninstallClassicTeams.ps1` was previously executed (checks for registry marker)
- Detects if the **Teams Meeting Add-in (TMA)** is in a faulty state after Classic Teams removal
- A faulty state means TMA is still installed but its required registry keys are missing
- If a faulty TMA is detected, silently uninstalls it via MSI product code
- Outputs a JSON result summary with detection and remediation status

### Faulty TMA Detection Logic
TMA is considered faulty when ALL three conditions are true:
1. `UninstallClassicTeams.ps1` has been run (registry marker exists)
2. Teams Meeting Add-in MSI package is still installed
3. One or more required TMA registry keys are missing from HKCU

---

## Deployment Order

> ⚠️ These scripts must be deployed in the c
cat > ~/Desktop/Intune/Scripts/Uninstall-Classic-Teams/README.md << 'EOF'
# Script - Uninstall Classic Microsoft Teams

## Overview

This folder contains two official **Microsoft** PowerShell scripts (MIT Licensed) for completely removing **Classic Microsoft Teams** from Windows devices and remediating any leftover Teams Meeting Add-in (TMA) components. These are designed to be deployed via **Intune Script policies** as part of migrating users to **New Microsoft Teams**.

---

## Scripts

| File | Version | Purpose |
|---|---|---|
| `UninstallClassicTeams.ps1` | 1.1.9 | Fully uninstalls Classic Teams for all user profiles on the machine |
| `DetectAndUninstallTMA.ps1` | 1.1.0 | Detects and removes a faulty Teams Meeting Add-in left behind after Classic Teams removal |

---

## UninstallClassicTeams.ps1

### What It Does
- Finds and removes Classic Teams for **all user profiles** on the machine
- Kills any running Teams processes before uninstalling
- Runs the Teams uninstall command from the registry
- Removes all Teams-related file system entries (AppData, Roaming, SquirrelTemp)
- Cleans up all stale registry keys from HKEY_USERS
- Removes the Teams Machine-Wide Installer (64-bit and 32-bit)
- Removes Teams Meeting Add-in folders per user profile
- Cleans up VDI-related Teams components (unless -SkipAllArtifactsRemoval is passed)
- Removes Teams shortcuts from all user Start Menus
- Writes a detailed log to `C:\Windows\Temp\Classic_Teams_Uninstallation-[timestamp].txt`
- Creates a registry key `HKLM\Software\Microsoft\TeamsAdminLevelScript` when complete (used by DetectAndUninstallTMA.ps1)

### Parameters

| Parameter | Type | Description |
|---|---|---|
| `-SkipAllArtifactsRemoval` | Switch | If passed, skips VDI cleanup steps |

---

## DetectAndUninstallTMA.ps1

### What It Does
- Only runs remediation if `UninstallClassicTeams.ps1` was previously executed (checks for registry marker)
- Detects if the **Teams Meeting Add-in (TMA)** is in a faulty state after Classic Teams removal
- A faulty state means TMA is still installed but its required registry keys are missing
- If a faulty TMA is detected, silently uninstalls it via MSI product code
- Outputs a JSON result summary with detection and remediation status

### Faulty TMA Detection Logic
TMA is considered faulty when ALL three conditions are true:
1. `UninstallClassicTeams.ps1` has been run (registry marker exists)
2. Teams Meeting Add-in MSI package is still installed
3. One or more required TMA registry keys are missing from HKCU

---

## Deployment Order

> ⚠️ These scripts must be deployed in the c
---

## Output

Both scripts output a JSON summary at the end. Example from `UninstallClassicTeams.ps1`:
```json
{
  "NumProfiles": 3,
  "NumApplicationsFound": 1,
  "NumApplicationsRemoved": 1,
  "StaleFileSystemEntryDeleted": 2,
  "StaleRegkeyEntryDeleted": 1
}
```

---

## Notes

- Scripts are **digitally signed by Microsoft** and contain a signature block at the end — do not modify the scripts or the signature will be invalidated
- Safe to run on machines where Classic Teams is already removed — scripts handle missing components gracefully
- After running, allow **15-30 minutes** for New Teams to reinstall the TMA correctly

---

## License

MIT License — Copyright (c) 2024 Microsoft and Contributors

---

## Author

Scripts by: **Microsoft Corporation**
Documented by: Saeid Agheli — Intune Administrator
https://github.com/saeidagheli88
