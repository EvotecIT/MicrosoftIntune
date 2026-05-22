# Global Secure Access Client Installation

## Overview
This optional script package installs or uninstalls the Microsoft Global Secure Access (GSA) Windows client as an Intune Win32 app.

Use this package only for client deployment. GSA configuration and browser policy remediation live separately in `Scripts\GlobalSecureAccessClientSettings`.

## Script

### Install-GlobalSecureAccessClient.ps1
Installs or uninstalls the GSA Windows client silently.

Package the Microsoft installer in the same folder as the script:
- x64 installer: `GlobalSecureAccessClient.exe`
- Arm64 installer: `GlobalSecureAccessClient-Arm64.exe`

Windows on Arm devices require the Arm64 client installer. The script fails deliberately on Arm64 if only the x64 installer is packaged.

## Configuration Settings

1. `Operation`
   - `Install`: installs or upgrades the client
   - `Uninstall`: uninstalls the client

2. `MinimumClientVersion`
   - Empty: run the packaged installer
   - Version value: skip install when the installed client already meets or exceeds the version

3. `ConfigureIPv4Preference`
   - Configures `DisabledComponents` as Microsoft documents in the Intune install sample

4. `PreferIPv4OverIPv6`
   - `true`: sets `DisabledComponents` to `0x20`
   - `false`: sets `DisabledComponents` to `0`

## Recommended Intune Win32 App Settings

Install command:
```powershell
powershell.exe -ExecutionPolicy Bypass -File Install-GlobalSecureAccessClient.ps1
```

Uninstall command:
```powershell
powershell.exe -ExecutionPolicy Bypass -File Install-GlobalSecureAccessClient.ps1 -Operation Uninstall
```

Return codes:
- `0`: Success
- `3010`: Soft reboot
- `1618`: Retry

Detection rule:
- Path: `C:\Program Files\Global Secure Access Client\TrayApp`
- File or folder: `GlobalSecureAccessClient.exe`
- Detection method: String (version)
- Operator: Greater than or equal to
- Value: your deployed client version

## References

- [Install the Global Secure Access client for Windows](https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-install-windows-client)
