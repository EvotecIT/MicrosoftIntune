# Password Policy Settings

## Overview
This script package enforces password policy settings on Windows devices through Microsoft Intune. These settings help enhance security by implementing strong password requirements including minimum length, age restrictions, and password history.

## Recommended Settings

```
Minimum password length:                              14
Maximum password age (days):                          90
Minimum password age (days):                          1
Length of password history maintained:                24
```

## Configuration Parameters

You can configure the following settings at the top of both the detection and remediation scripts:

1. `MinPasswordLength` - Minimum number of characters in password
   - Recommended: 14+ characters
   - Set to `$null` to ignore this setting

2. `MaxPasswordAge` - Days before password expires
   - Recommended: 42-90 days (NIST recommends against forced expiration)
   - Set to `0` for passwords that never expire
   - Set to `$null` to ignore this setting

3. `MinPasswordAge` - Days before password can be changed
   - Recommended: 1+ days (prevents rapid cycling of passwords)
   - Set to `$null` to ignore this setting

4. `PasswordHistory` - Number of previous passwords remembered
   - Recommended: 24+ passwords (prevents password reuse)
   - Set to `$null` to ignore this setting

5. Detection and remediation flexibility options:
   - `AllowStrongerSettings` - When true, allows settings that exceed minimum security requirements
   - `RequireExactMatch` - When false, allows values that meet security needs but aren't exact matches

## Implementation Notes

- **IMPORTANT**: Ensure both detection and remediation scripts have matching configuration values
- Any setting can be set to `$null` to ignore that particular policy setting
- The detection script checks if settings match the configured values based on flexibility options
- The remediation script will only change settings that don't comply with the configured values

## Security Best Practices

- **Password Length**: Longer is better; 14+ characters are recommended by security experts
- **Password Complexity**: Modern guidance favors length over complexity, but complexity still helps
- **Password Age**: NIST SP 800-63B now recommends against forced regular password changes
  - For maximum age, a higher value means passwords expire less frequently (less secure)
  - For minimum age, a higher value means users must wait longer before changing passwords (more secure)
- **Password History**: Preventing reuse of the last 24 passwords is considered a strong policy

## Common Issues

- The scripts require administrative privileges
- Domain policies may override these local settings on domain-joined devices
- Some settings may affect user experience negatively if set too restrictively
- Ensure maximum password age is reasonable for your environment (too short causes user frustration)

## Command Line Reference

For manual verification or troubleshooting:
```powershell
# View current password policy settings
net accounts

# Set minimum password length
net accounts /minpwlen:14

# Set maximum password age (days, 0 = never expires)
net accounts /maxpwage:90

# Set minimum password age (days)
net accounts /minpwage:1

# Set password history length
net accounts /uniquepw:24
```
