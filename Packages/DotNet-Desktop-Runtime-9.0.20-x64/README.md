MICROSOFT .NET DESKTOP RUNTIME 9.0.20 x64 - INTUNE WIN32 PACKAGE
=================================================================

PURPOSE
-------
Installs Microsoft .NET Desktop Runtime 9.0.20 x64. The Desktop Runtime
installer also installs Microsoft .NET Runtime 9.0.20 x64.

After installation, Install.ps1 removes only these older x64 versions:
  - Microsoft Windows Desktop Runtime 9.0.x below 9.0.20
  - Microsoft .NET Runtime 9.0.x below 9.0.20

It does NOT target:
  - x86 or Arm64 installations
  - .NET 6 or 7
  - .NET 8 or 10
  - ASP.NET Core Runtime
  - .NET SDKs

IMPORTANT
---------
The ZIP intentionally does not redistribute Microsoft's EXE. Download the
official signed installer into this folder before creating the .intunewin.

STEP 1 - DOWNLOAD THE INSTALLER
-------------------------------
Open Windows PowerShell in this folder and run:

  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Download-DesktopRuntime.ps1

Confirm this file now exists directly beside Install.ps1:

  windowsdesktop-runtime-9.0.20-win-x64.exe

STEP 2 - CREATE THE INTUNEWIN FILE
----------------------------------
Use Install.ps1 as the setup file. You can run IntuneWinAppUtil manually, or:

  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Package-Win32.ps1 `
    -IntuneWinAppUtilPath "C:\Intune\IntuneWinAppUtil.exe" `
    -OutputFolder "C:\Intune\Output"

If using the IntuneWinAppUtil prompts:
  Source folder: this extracted folder
  Setup file: Install.ps1
  Output folder: your output folder
  Catalog folder: No

STEP 3 - INTUNE APP INFORMATION
--------------------------------
App type: Windows app (Win32)

Name:
  Windows - .NET Desktop Runtime - 9.0.20 x64

Description:
  Installs Microsoft .NET Desktop Runtime 9.0.20 x64 And Removes Older
  .NET 9.0 x64 Desktop And Base Runtime Patch Versions Below 9.0.20.
  Other Major Versions, x86 Installations, ASP.NET Core Runtime, And SDKs
  Are Not Modified.

Publisher: Microsoft
App version: 9.0.20

STEP 4 - PROGRAM
----------------
Install command:
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\Install.ps1"

Uninstall command:
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\Uninstall.ps1"

Install behavior:
  System

Device restart behavior:
  Determine behavior based on return codes

Keep the default return codes, including:
  0    = Success
  3010 = Soft reboot
  1618 = Retry

NOTE: Intune runs the uninstall command only when the app is assigned with
intent Uninstall, or when removal is triggered from the Company Portal.
Use the Uninstall.ps1 packaged with this app; it removes 9.0.20 x64 only.

STEP 5 - REQUIREMENTS
---------------------
Operating system architecture:
  64-bit

Minimum operating system:
  Select the lowest Windows version supported by your organization.

The x64 runtime installs beneath C:\Program Files\dotnet.

STEP 6 - DETECTION RULE
-----------------------
Rules format:
  Use a custom detection script

Script file:
  Detect.ps1

Run script as 32-bit process on 64-bit clients:
  No

Enforce script signature check:
  No

Detection requires all of the following:
  - Microsoft.WindowsDesktop.App 9.0.20 x64 exists
  - Microsoft.NETCore.App 9.0.20 x64 exists
  - No Microsoft.WindowsDesktop.App 9.0.x x64 below 9.0.20 remains
  - No Microsoft.NETCore.App 9.0.x x64 below 9.0.20 remains

NOTE: All three .NET Desktop Runtime packages ship a file named Detect.ps1,
and all three ship a file named Uninstall.ps1. The names are shared but each
copy checks and removes a different version and architecture. Upload the
Detect.ps1 from THIS folder to this app, not a copy from another package.

STEP 7 - ASSIGNMENT
-------------------
First assign as Required to a small test DEVICE group. Do not deploy to All
Devices until the required applications launch and the compliance test passes.

MANUAL TEST ON A DEVICE
-----------------------
Run as Administrator:

  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Test-Compliance.ps1

Or inspect x64 runtimes directly:

  & "${env:ProgramFiles}\dotnet\dotnet.exe" --list-runtimes

Expected required lines:
  Microsoft.NETCore.App 9.0.20 [C:\Program Files\dotnet\shared\Microsoft.NETCore.App]
  Microsoft.WindowsDesktop.App 9.0.20 [C:\Program Files\dotnet\shared\Microsoft.WindowsDesktop.App]

LIST EVERY INSTALLED .NET RUNTIME AND SDK
-----------------------------------------
This package targets one major version and one architecture. To see everything
installed on a device, open PowerShell and query both hosts:

  # x64 runtimes
  & "$env:SystemDrive\Program Files\dotnet\dotnet.exe" --list-runtimes

  # x86 runtimes
  & "${env:ProgramFiles(x86)}\dotnet\dotnet.exe" --list-runtimes

To list installed SDKs as well:

  & "$env:SystemDrive\Program Files\dotnet\dotnet.exe" --list-sdks
  & "${env:ProgramFiles(x86)}\dotnet\dotnet.exe" --list-sdks

If a path does not exist, that architecture's .NET host is not installed.

INSTALL LOG
-----------
C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\DotNet-Desktop-Runtime-9.0.20-x64-Install.log

UNINSTALL LOG
-------------
C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\DotNet-Desktop-Runtime-9.0.20-x64-Uninstall.log

NOTE: This package updates Desktop and base Runtime only. It does not remediate older ASP.NET Core runtimes or versions included in an SDK.
If an older runtime still appears after installation, review the install log and the parent SDK before removing it.

CURRENT PATCH AT PACKAGE CREATION (2026-09-21)
-----------------------------------------
Latest published .NET 9 Desktop Runtime: 9.0.20 x64.
https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/runtime-desktop-9.0.20-windows-x64-installer
