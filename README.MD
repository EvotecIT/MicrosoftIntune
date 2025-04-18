﻿# Intune Scripts

This repository contains PowerShell scripts to manage and enforce security policies on Windows devices through Microsoft Intune. These scripts are designed to help organizations comply with security best practices and enhance the overall security posture of their devices.

Since Intune does not support the direct application of security policies, these scripts can be deployed as Intune scripts to configure and enforce security settings on Windows devices.

## Available Scripts

### Password Policy Settings
- **Detect-PasswordPolicy.ps1**: Detects compliance with password policy settings.
- **Remediate-PasswordPolicy.ps1**: Configures password policy settings to meet security requirements.

### Account Lockout Settings
- **Detect-AccountLockoutSettings.ps1**: Detects compliance with account lockout settings.
- **Remediate-AccountLockoutSettings.ps1**: Configures account lockout settings to meet security requirements.

### Local Security Authority (LSA) Protection
- **Detect-LsaProtection.ps1**: Detects if LSA protection is enabled.
- **Remediate-LsaProtection.ps1**: Enables LSA protection to prevent credential theft.

### Disable Domain Credentials Storage
- **Detect-DisableDomainCreds.ps1**: Detects if credential storage is disabled.
- **Remediate-DisableDomainCreds.ps1**: Disables credential storage for network authentication.

### Windows Store App Management
- **Detect-AppRemoval.ps1**: Detects compliance with configured app presence policy.
- **Remediate-AppRemoval.ps1**: Removes or ensures presence of specified Windows Store apps.
  - Supports both inclusion and exclusion modes
  - Protects critical system apps
  - Includes WhatIf support for safe testing

### Remote Desktop Protocol Settings
- **Detect-RDPSettings.ps1**: Detects if RDP settings comply with security requirements.
- **Remediate-RDPSettings.ps1**: Configures RDP security settings and access.
  - Can enable or disable RDP completely
  - Enforces Network Level Authentication (NLA)
  - Manages Windows Firewall rules automatically
  - Includes WhatIf support for safe testing

## Usage

- Refer to the `.SYNOPSIS` and `.EXAMPLE` sections in each script for detailed usage instructions.
- Check each script folder's README.md for detailed configuration options.
- Ensure you have administrative privileges to execute these scripts.