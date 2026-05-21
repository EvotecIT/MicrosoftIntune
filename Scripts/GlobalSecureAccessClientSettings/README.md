# Global Secure Access Client Settings

## Overview
This script package manages documented Microsoft Global Secure Access (GSA) client-side controls through Microsoft Intune remediation.

It includes:
- Detection and remediation scripts for GSA client registry settings
- Optional browser controls for Microsoft Entra Internet Access compatibility

It does not install or uninstall the GSA client. Keep client deployment as a separate Win32 app package.

## Scripts

### Detect-GlobalSecureAccessSettings.ps1
Detects whether the configured GSA client, registry, and browser settings are compliant.

### Remediate-GlobalSecureAccessSettings.ps1
Creates or updates the configured registry and browser policy settings.

## Configuration Settings

Configure these settings at the top of both detection and remediation scripts:

1. `RequireClientInstalled`
   - Detection-only setting
   - `false`: check only registry and browser settings
   - `true`: also require the installed client executable

2. `MinimumClientVersion`
   - Empty: accept any installed version
   - Version value: require at least that client version when `RequireClientInstalled` is enabled

3. `GsaMachineSettings`
   - `RestrictNonPrivilegedUsers`
     - `0`: nonprivileged users can disable and enable the client
     - `1`: local admin credentials are required
   - `HideSignOutButton`
     - `0`: show Sign out
     - `1`: hide Sign out
   - `HideDisablePrivateAccessButton`
     - `0`: show Disable Private Access
     - `1`: hide Disable Private Access
   - `HideDisableButton`
     - `0`: show Disable
     - `1`: hide Disable

4. `ConfigurePrivateAccessForUsers`
   - `false` by default because Microsoft documents this under `HKCU`
   - When enabled, configures `IsPrivateAccessDisabledByUser`

5. `PrivateAccessScope`
   - `CurrentUser`: use `HKCU`
   - `LoadedUsers`: use loaded user hives under `HKEY_USERS`, useful when Intune runs as SYSTEM

6. `DisablePrivateAccessForUser`
   - `false`: Private Access is enabled on the device
   - `true`: Private Access is disabled on the device

7. `ConfigureBrowserTrafficControls`
   - `true`: configure browser policy mitigations for Microsoft Entra Internet Access
   - `false`: do not manage browser QUIC or DNS over HTTPS policies

8. Browser controls
   - `DisableEdgeQuic`
   - `DisableEdgeDnsOverHttps`
   - `DisableChromeQuic`
   - `DisableChromeDnsOverHttps`
   - `DisableFirefoxQuic`
   - `DisableFirefoxDnsOverHttps`

9. `ApplyFirefoxPolicyWhenFirefoxMissing`
   - `false`: skip Firefox policy when Firefox is not installed
   - `true`: create the Firefox distribution policy path even when Firefox is not currently installed

## Registry and Policy Paths

GSA machine settings:
- `HKLM:\SOFTWARE\Microsoft\Global Secure Access Client`

GSA user settings:
- `HKCU:\Software\Microsoft\Global Secure Access Client`
- Or loaded hives under `Registry::HKEY_USERS\<SID>\Software\Microsoft\Global Secure Access Client`

IPv4 preference:
- `HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters`
  - `DisabledComponents`

Microsoft Edge policies:
- `HKLM:\SOFTWARE\Policies\Microsoft\Edge`
  - `QuicAllowed`
  - `DnsOverHttpsMode`

Google Chrome policies:
- `HKLM:\SOFTWARE\Policies\Google\Chrome`
  - `QuicAllowed`
  - `DnsOverHttpsMode`

Firefox policy:
- `C:\Program Files\Mozilla Firefox\distribution\policies.json`
  - `network.http.http3.enable`
  - `network.trr.mode`

## Implementation Notes

- Configure Intune remediation scripts to run in 64-bit PowerShell.
- Use these detection and remediation scripts after or alongside a separate client deployment package.
- Browser policy changes can require browser restart before they are fully effective.
- The IPv4 preference registry change can require a device restart.

## References

- [Install the Global Secure Access client for Windows](https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-install-windows-client)
- [Microsoft Edge QuicAllowed policy](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-browser-policies/quicallowed)
- [Microsoft Edge DnsOverHttpsMode policy](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-browser-policies/dnsoverhttpsmode)
