# Script - Chrome Local Network Access (LNA) Policy

## Overview

This PowerShell script enforces a **Google Chrome enterprise policy** that controls **Local Network Access (LNA)** restrictions on Windows devices. It enables Chrome's `LocalNetworkAccessRestrictionsEnabled` policy and configures a specific allowlist of trusted public origins that are permitted to make requests to local network resources.

Deployed via **Intune Script policy** and runs as SYSTEM.

---

## Background

Chrome's Local Network Access restrictions (introduced in Chrome 123+) block public websites from making requests to private or local network resources (e.g., internal APIs, localhost) by default. This script allows specific trusted origins to bypass this restriction, which is required for web applications that need to communicate with local services.

---

## What It Does

1. Creates the Chrome enterprise policy registry path if it doesn't exist:
   `HKLM:\SOFTWARE\Policies\Google\Chrome`
2. Creates the allowlist subkey:
   `HKLM:\SOFTWARE\Policies\Google\Chrome\LocalNetworkAccessAllowedForUrls`
3. Enables LNA restrictions by setting `LocalNetworkAccessRestrictionsEnabled = 1`
4. Clears any existing allowlist entries
5. Writes the allowed origins as numbered REG_SZ values (1, 2, 3...)
6. Verifies and outputs the applied policy values

---

## Customization

Before deploying, edit the `$AllowedOrigins` array at the top of the script:

```powershell
cat > ~/Desktop/Intune/Scripts/Chrome-LNA-Policy/README.md << 'EOF'
# Script - Chrome Local Network Access (LNA) Policy

## Overview

This PowerShell script enforces a **Google Chrome enterprise policy** that controls **Local Network Access (LNA)** restrictions on Windows devices. It enables Chrome's `LocalNetworkAccessRestrictionsEnabled` policy and configures a specific allowlist of trusted public origins that are permitted to make requests to local network resources.

Deployed via **Intune Script policy** and runs as SYSTEM.

---

## Background

Chrome's Local Network Access restrictions (introduced in Chrome 123+) block public websites from making requests to private or local network resources (e.g., internal APIs, localhost) by default. This script allows specific trusted origins to bypass this restriction, which is required for web applications that need to communicate with local services.

---

## What It Does

1. Creates the Chrome enterprise policy registry path if it doesn't exist:
   `HKLM:\SOFTWARE\Policies\Google\Chrome`
2. Creates the allowlist subkey:
   `HKLM:\SOFTWARE\Policies\Google\Chrome\LocalNetworkAccessAllowedForUrls`
3. Enables LNA restrictions by setting `LocalNetworkAccessRestrictionsEnabled = 1`
4. Clears any existing allowlist entries
5. Writes the allowed origins as numbered REG_SZ values (1, 2, 3...)
6. Verifies and outputs the applied policy values

---

## Customization

Before deploying, edit the `$AllowedOrigins` array at the top of the script:

```powershell
$AllowedOrigins = @(
  'https://your-app.example.com'        # Replace with your production origin
  'https://staging.example.com'         # Optional: staging origin
)
```

Use **origin-only format** (scheme + host, no trailing slash or path) unless a specific path is required.

---

## Registry Values Applied

| Path | Name | Type | Value |
|---|---|---|---|
| `HKLM:\SOFTWARE\Policies\Google\Chrome` | `LocalNetworkAccessRestrictionsEnabled` | DWORD | `1` |
| `HKLM:\SOFTWARE\Policies\Google\Chrome\LocalNetworkAccessAllowedForUrls` | `1` | REG_SZ | Your origin URL |
| `HKLM:\SOFTWARE\Policies\Google\Chrome\LocalNetworkAccessAllowedForUrls` | `2` | REG_SZ | Additional origin (if needed) |

---

## Requirements

| Requirement | Details |
|---|---|
| **Platform** | Windows 10 / Windows 11 |
| **Run As** | SYSTEM (Administrator) |
| **Chrome Version** | 123 or later |
| **Deployment** | Intune Script policy |

---

## Intune Setup

### Step 1 — Edit the Script
Before uploading, open `Set-ChromeLNAPolicy.ps1` and replace the placeholder origins in `$AllowedOrigins` with your actual production origins.

### Step 2 — Upload the Script
1. Go to **Microsoft Intune Admin Center → Devices → Scripts and remediations → Platform scripts**
2. Click **Add → Windows 10 and later**
3. Fill in:
   - **Name:** `Chrome LNA Policy`
   - **Description:** `Enables Chrome Local Network Access restrictions and configures allowed origins`
4. Upload `Set-ChromeLNAPolicy.ps1`
5. Set options:
   - Run using logged-on credentials: **No**
   - Enforce script signature check: **No**
   - Run script in 64-bit PowerShell: **Yes**
6. Click **Next**

### Step 3 — Assign
1. Assign to your target device group
2. Set Execution Frequency to **Once** or **Every 1 day** if origins may change
3. Click **Create**

---

## Verification

After the script runs, verify on a target device:

1. Open Chrome and go to `chrome://policy`
2. Look for:
   - `LocalNetworkAccessRestrictionsEnabled` = **Enabled**
   - `LocalNetworkAccessAllowedForUrls` = your allowed origins
3. Confirm **Source** shows **Platform**

Or check the registry directly:
```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Google\Chrome'
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Google\Chrome\LocalNetworkAccessAllowedForUrls'
```

---

## Notes

- Chrome must be **restarted** after the policy is applied for changes to take effect
- The script **clears existing allowlist entries** before writing new ones — comment out that section to append instead
- This policy only applies to **managed Chrome** on the device
- Requires Chrome 123 or later

---

## Author

Saeid Agheli — Intune Administrator
https://github.com/saeidagheli88
