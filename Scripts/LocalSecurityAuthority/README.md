# Local Security Authority (LSA) Protection

## Overview
These scripts enable and detect LSA protection on Windows devices through Microsoft Intune. LSA protection helps prevent credential theft by protecting the LSA process from code injection and other attacks that attempt to extract credentials from memory.

## Included Scripts

1. **Detect-LsaProtection.ps1** - Detects if LSA protection is enabled
2. **Remediate-LsaProtection.ps1** - Enables LSA protection if not already enabled

## Security Benefit

When LSA protection is enabled, the Local Security Authority process (LSASS.EXE) runs as a Protected Process Light (PPL), which prevents:

- Code injection into the LSA process
- Unauthorized access to memory contents of the LSA process
- Common credential theft techniques used in pass-the-hash attacks

## Implementation Notes

- **Important:** A system restart is required for this setting to take effect
- These scripts modify the following registry value:
  - Key: `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa`
  - Name: `RunAsPPL`
  - Value: `1` (DWORD)

## Requirements

- Administrative privileges are required to modify these security settings
- Compatible with Windows 8.1/Windows Server 2012 R2 and newer operating systems
- Newer hardware that supports Virtualization-Based Security will provide additional protection

## Compatibility Considerations

LSA Protection may cause compatibility issues with certain:
- Security products that inject into LSASS
- Backup solutions that need to access LSASS memory
- Legacy credential providers

## References

- [Configuring Additional LSA Protection](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [Protected Users Security Group](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
