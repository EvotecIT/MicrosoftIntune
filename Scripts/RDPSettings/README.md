# RDP Settings

## Overview
This script package manages Remote Desktop Protocol (RDP) settings through Microsoft Intune. It can enable or disable RDP and configure security settings like Network Level Authentication (NLA) to ensure secure remote access.

## Configuration Settings

Configure these settings at the top of both detection and remediation scripts:

1. `EnableRDP` (true/false)
   - `true`: Enable RDP with security settings
   - `false`: Disable RDP completely

2. `RequireNLA` (true/false)
   - Requires Network Level Authentication
   - Recommended: true for enhanced security

3. `AllowOnlySecureConnections` (true/false)
   - Forces encryption and secure RDP connections
   - Recommended: true for enhanced security

## Implementation Notes

The scripts manage several RDP components:
- Terminal Services (TermService) service state
- Registry settings for RDP and NLA
- Windows Firewall rules for RDP
- Security layer settings

### Security Considerations
- Network Level Authentication (NLA) adds a security layer before full RDP connection
- Secure connections ensure encrypted communication
- Firewall rules are automatically managed based on RDP state

## Common Issues

- The scripts require administrative privileges
- Group Policy might override these settings on domain-joined devices
- Some settings require a system restart to take full effect
- Firewall rules might conflict with third-party security software

## Script Usage

### Detection Script
```powershell
.\Detect-RDPSettings.ps1
# Returns exit code 0 if compliant, 1 if not
```

### Remediation Script
```powershell
.\Remediate-RDPSettings.ps1
# Configures RDP settings
```

## Registry Settings Modified

- `HKLM:\System\CurrentControlSet\Control\Terminal Server`
  - `fDenyTSConnections`: Controls RDP access
- `HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`
  - `UserAuthentication`: Controls NLA requirement
  - `SecurityLayer`: Controls connection security level
