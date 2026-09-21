MICROSOFT .NET DESKTOP RUNTIME 8.0.31 x86 - INTUNE WIN32 PACKAGE
=================================================================

PURPOSE
-------
Installs Microsoft .NET Desktop Runtime 8.0.31 x86. The Desktop Runtime
installer also installs Microsoft .NET Runtime 8.0.31 x86.

After installation, Install.ps1 removes only these older x86 versions:
  - Microsoft Windows Desktop Runtime 8.0.x below 8.0.31
  - Microsoft .NET Runtime 8.0.x below 8.0.31

It does NOT target:
  - x64 or Arm64 installations
  - .NET 6 or 7
  - .NET 9 or 10
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

  windowsdesktop-runtime-8.0.31-win-x86.exe

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
  Windows - .NET Desktop Runtime - 8.0.31 x86

Description:
  Installs Microsoft .NET Desktop Runtime 8.0.31 x86 And Removes Older
  .NET 8.0 x86 Desktop And Base Runtime Patch Versions Below 8.0.31.
  Newer Major Versions, x64 Installations, ASP.NET Core Runtime, And SDKs
  Are Not Modified.

Publisher: Microsoft
App version: 8.0.31

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

STEP 5 - REQUIREMENTS
---------------------
Operating system architecture:
  64-bit

Minimum operating system:
  Select the lowest Windows version supported by your organization.

The app is x86, but the targeted endpoints are 64-bit Windows devices and the
x86 runtime installs beneath C:\Program Files (x86)\dotnet.

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
  - Microsoft.WindowsDesktop.App 8.0.31 x86 exists
  - Microsoft.NETCore.App 8.0.31 x86 exists
  - No Microsoft.WindowsDesktop.App 8.0.x x86 below 8.0.31 remains
  - No Microsoft.NETCore.App 8.0.x x86 below 8.0.31 remains

STEP 7 - ASSIGNMENT
-------------------
First assign as Required to a small test DEVICE group. Do not deploy to All
Devices until Citrix launches successfully and the compliance test passes.

MANUAL TEST ON A DEVICE
-----------------------
Run as Administrator:

  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Test-Compliance.ps1

Or inspect x86 runtimes directly:

  & "${env:ProgramFiles(x86)}\dotnet\dotnet.exe" --list-runtimes

Expected required lines:
  Microsoft.NETCore.App 8.0.31 [C:\Program Files (x86)\dotnet\shared\Microsoft.NETCore.App]
  Microsoft.WindowsDesktop.App 8.0.31 [C:\Program Files (x86)\dotnet\shared\Microsoft.WindowsDesktop.App]

INSTALL LOG
-----------
C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\DotNet-Desktop-Runtime-8.0.31-x86-Install.log

UNINSTALL LOG
-------------
C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\DotNet-Desktop-Runtime-8.0.31-x86-Uninstall.log

OFFICIAL MICROSOFT DOWNLOAD PAGE
--------------------------------
https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/runtime-desktop-8.0.31-windows-x86-installer

