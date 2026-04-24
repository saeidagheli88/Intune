# Script - Convert Co-Managed Device to Intune-Only

## Overview

This PowerShell script converts a **co-managed Windows device** (managed by both SCCM/ConfigMgr and Microsoft Intune) to **Intune-only management**. It removes all SCCM client components, cleans up registry keys and WMI namespaces, and refreshes the Intune enrollment to ensure the device is fully under Intune control.

Safe to run multiple times and designed to run silently as **SYSTEM** via an Intune Script policy.

---

## Key Features

- Stops and removes all **SCCM/ConfigMgr client services**
- Runs the SCCM **uninstaller** if the client is still present
- Cleans up all **SCCM registry keys** including co-management policy keys
- Removes **CCM WMI namespaces** using CIM-safe methods
- Clears the **CCM cache** folder
- Forces an **Intune enrollment refresh** via dsregcmd
- Triggers the **Intune Management Extension** to re-sync policies
- Safe to run multiple times — skips steps if components are already removed

---

## How It Works

1. Stops SCCM-related services: `SmsExec`, `CcmExec`, `CcmSetup`, `smstsmgr`
2. Runs `ccmsetup.exe /uninstall` if the SCCM client installer is present
3. Removes SCCM registry keys from `HKLM:\SOFTWARE\Microsoft\CCM` and related paths
4. Removes co-management policy keys from the PolicyManager registry hive
5. Cleans up `root\ccm` and `root\sms` WMI namespaces
6. Deletes the `C:\Windows\ccmcache` folder
7. Runs `dsregcmd /refreshprt` to refresh the Intune device registration
8. Restarts the Intune Management Extension agent

---

## Requirements

| Requirement | Details |
|---|---|
| **Platform** | Windows 10 / Windows 11 |
| **Run As** | SYSTEM |
| **Execution** | Via Intune Script policy |
| **Prerequisites** | Device must be Azure AD Joined or Hybrid Azure AD Joined |

---

## Intune Setup

### Step 1 — Upload the Script
1. Go to **Microsoft Intune Admin Center** → **Devices → Scripts and remediations → Platform scripts**
2. Click **Add** → **Windows 10 and later**
3. Fill in:
   - **Name:** `Convert Co-Managed Device to Intune-Only`
   - **Description:** `Removes SCCM client and converts co-managed devices to Intune-only management`
4. Upload `Convert-CoManaged-To-Intune.ps1`
5. Set the following options:
   - Run this script using the logged-on credentials: **No**
   - Enforce script signature check: **No**
   - Run script in 64-bit PowerShell: **Yes**
6. Click **Next**

### Step 2 — Assign the Script
1. Scope to the device group containing co-managed devices
2. Set **Execution Frequency** to `Once` — the script is safe to re-run but typically only needs to run once per device
3. Click **Create**

---

## What Gets Removed

| Component | Details |
|---|---|
| SCCM Services | SmsExec, CcmExec, CcmSetup, smstsmgr |
| SCCM Client | Uninstalled via ccmsetup.exe /uninstall |
| Registry Keys | CCM, CCMSetup, SMS, CoManagement policy keys |
| WMI Namespaces | root\ccm, root\sms |
| CCM Cache | C:\Windows\ccmcache |

---

## Post-Script Verification

After the script runs, verify the device is fully Intune-managed:

1
cat > ~/Desktop/Intune/Scripts/Convert-CoManaged-To-Intune/README.md << 'EOF'
# Script - Convert Co-Managed Device to Intune-Only

## Overview

This PowerShell script converts a **co-managed Windows device** (managed by both SCCM/ConfigMgr and Microsoft Intune) to **Intune-only management**. It removes all SCCM client components, cleans up registry keys and WMI namespaces, and refreshes the Intune enrollment to ensure the device is fully under Intune control.

Safe to run multiple times and designed to run silently as **SYSTEM** via an Intune Script policy.

---

## Key Features

- Stops and removes all **SCCM/ConfigMgr client services**
- Runs the SCCM **uninstaller** if the client is still present
- Cleans up all **SCCM registry keys** including co-management policy keys
- Removes **CCM WMI namespaces** using CIM-safe methods
- Clears the **CCM cache** folder
- Forces an **Intune enrollment refresh** via dsregcmd
- Triggers the **Intune Management Extension** to re-sync policies
- Safe to run multiple times — skips steps if components are already removed

---

## How It Works

1. Stops SCCM-related services: `SmsExec`, `CcmExec`, `CcmSetup`, `smstsmgr`
2. Runs `ccmsetup.exe /uninstall` if the SCCM client installer is present
3. Removes SCCM registry keys from `HKLM:\SOFTWARE\Microsoft\CCM` and related paths
4. Removes co-management policy keys from the PolicyManager registry hive
5. Cleans up `root\ccm` and `root\sms` WMI namespaces
6. Deletes the `C:\Windows\ccmcache` folder
7. Runs `dsregcmd /refreshprt` to refresh the Intune device registration
8. Restarts the Intune Management Extension agent

---

## Requirements

| Requirement | Details |
|---|---|
| **Platform** | Windows 10 / Windows 11 |
| **Run As** | SYSTEM |
| **Execution** | Via Intune Script policy |
| **Prerequisites** | Device must be Azure AD Joined or Hybrid Azure AD Joined |

---

## Intune Setup

### Step 1 — Upload the Script
1. Go to **Microsoft Intune Admin Center** → **Devices → Scripts and remediations → Platform scripts**
2. Click **Add** → **Windows 10 and later**
3. Fill in:
   - **Name:** `Convert Co-Managed Device to Intune-Only`
   - **Description:** `Removes SCCM client and converts co-managed devices to Intune-only management`
4. Upload `Convert-CoManaged-To-Intune.ps1`
5. Set the following options:
   - Run this script using the logged-on credentials: **No**
   - Enforce script signature check: **No**
   - Run script in 64-bit PowerShell: **Yes**
6. Click **Next**

### Step 2 — Assign the Script
1. Scope to the device group containing co-managed devices
2. Set **Execution Frequency** to `Once` — the script is safe to re-run but typically only needs to run once per device
3. Click **Create**

---

## What Gets Removed

| Component | Details |
|---|---|
| SCCM Services | SmsExec, CcmExec, CcmSetup, smstsmgr |
| SCCM Client | Uninstalled via ccmsetup.exe /uninstall |
| Registry Keys | CCM, CCMSetup, SMS, CoManagement policy keys |
| WMI Namespaces | root\ccm, root\sms |
| CCM Cache | C:\Windows\ccmcache |

---

## Post-Script Verification

After the script runs, verify the device is fully Intune-managed:

1
cat > ~/Desktop/Intune/Scripts/Convert-CoManaged-To-Intune/README.md << 'EOF'
# Script - Convert Co-Managed Device to Intune-Only

## Overview

This PowerShell script converts a **co-managed Windows device** (managed by both SCCM/ConfigMgr and Microsoft Intune) to **Intune-only management**. It removes all SCCM client components, cleans up registry keys and WMI namespaces, and refreshes the Intune enrollment to ensure the device is fully under Intune control.

Safe to run multiple times and designed to run silently as **SYSTEM** via an Intune Script policy.

---

## Key Features

- Stops and removes all **SCCM/ConfigMgr client services**
- Runs the SCCM **uninstaller** if the client is still present
- Cleans up all **SCCM registry keys** including co-management policy keys
- Removes **CCM WMI namespaces** using CIM-safe methods
- Clears the **CCM cache** folder
- Forces an **Intune enrollment refresh** via dsregcmd
- Triggers the **Intune Management Extension** to re-sync policies
- Safe to run multiple times — skips steps if components are already removed

---

## How It Works

1. Stops SCCM-related services: `SmsExec`, `CcmExec`, `CcmSetup`, `smstsmgr`
2. Runs `ccmsetup.exe /uninstall` if the SCCM client installer is present
3. Removes SCCM registry keys from `HKLM:\SOFTWARE\Microsoft\CCM` and related paths
4. Removes co-management policy keys from the PolicyManager registry hive
5. Cleans up `root\ccm` and `root\sms` WMI namespaces
6. Deletes the `C:\Windows\ccmcache` folder
7. Runs `dsregcmd /refreshprt` to refresh the Intune device registration
8. Restarts the Intune Management Extension agent

---

## Requirements

| Requirement | Details |
|---|---|
| **Platform** | Windows 10 / Windows 11 |
| **Run As** | SYSTEM |
| **Execution** | Via Intune Script policy |
| **Prerequisites** | Device must be Azure AD Joined or Hybrid Azure AD Joined |

---

## Intune Setup

### Step 1 — Upload the Script
1. Go to **Microsoft Intune Admin Center** → **Devices → Scripts and remediations → Platform scripts**
2. Click **Add** → **Windows 10 and later**
3. Fill in:
   - **Name:** `Convert Co-Managed Device to Intune-Only`
   - **Description:** `Removes SCCM client and converts co-managed devices to Intune-only management`
4. Upload `Convert-CoManaged-To-Intune.ps1`
5. Set the following options:
   - Run this script using the logged-on credentials: **No**
   - Enforce script signature check: **No**
   - Run script in 64-bit PowerShell: **Yes**
6. Click **Next**

### Step 2 — Assign the Script
1. Scope to the device group containing co-managed devices
2. Set **Execution Frequency** to `Once` — the script is safe to re-run but typically only needs to run once per device
3. Click **Create**

---

## What Gets Removed

| Component | Details |
|---|---|
| SCCM Services | SmsExec, CcmExec, CcmSetup, smstsmgr |
| SCCM Client | Uninstalled via ccmsetup.exe /uninstall |
| Registry Keys | CCM, CCMSetup, SMS, CoManagement policy keys |
| WMI Namespaces | root\ccm, root\sms |
| CCM Cache | C:\Windows\ccmcache |

---

## Post-Script Verification

After the script runs, verify the device is fully Intune-managed:

1. Run `dsregcmd /status` in Command Prompt
2. Confirm `MDMUrl` is populated with your Intune URL
3. Check **Intune Admin Center → Devices** — the device should show as compliant
4. Confirm no SCCM services are running: `Get-Service CcmExec`

---

## Notes

- The script uses `$ErrorActionPreference = 'SilentlyContinue'` so it continues even if some components are already removed
- WMI cleanup uses CIM-safe methods to avoid errors on newer Windows versions
- After running, allow 15-30 minutes for Intune policies to fully re-apply
- If the device was heavily co-managed, a restart may be required after the script runs

---

## Author

Saeid Agheli — Intune Administrator
https://github.com/saeidagheli88
