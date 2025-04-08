# Disable Domain Credentials Storage

## Overview
These scripts configure and detect the "Network access: Do not allow storage of passwords and credentials for network authentication" security policy on Windows devices through Microsoft Intune. This setting enhances security by preventing the automatic caching of credentials in Credential Manager.

## Included Scripts

1. **Detect-DisableDomainCreds.ps1** - Detects if credential storage is disabled
2. **Remediate-DisableDomainCreds.ps1** - Disables credential storage if not already disabled

## Security Benefit

When this setting is enabled:

- Credential Manager will not save passwords or credentials for later use
- Prevents stored credentials from being compromised in the event of a security breach
- Forces users to enter credentials each time they connect to a network resource
- Reduces the risk of lateral movement within the network

## Implementation Notes

- These scripts modify the following registry value:
  - Key: `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa`
  - Name: `DisableDomainCreds`
  - Value: `1` (DWORD)
- This setting takes effect immediately and does not require a system restart

## User Experience Impact

When this setting is enabled:
- Users will be prompted for credentials each time they access network resources
- Credentials cannot be saved for future connections
- Mapped drives that require authentication may need to be reconnected after user logon

## References

- [Network access: Do not allow storage of passwords and credentials for network authentication](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-do-not-allow-storage-of-passwords-and-credentials-for-network-authentication)
- [Credential Theft Mitigation](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/reducing-the-active-directory-attack-surface)
