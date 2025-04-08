# Account Lockout Settings

## Overview
This script package enforces account lockout security settings on Windows devices through Microsoft Intune. These settings help protect against brute force attacks by locking accounts after a specified number of failed login attempts.

## Recommended Settings

```
Force user logoff how long after time expires?:       Never
Minimum password age (days):                          0
Maximum password age (days):                          42
Minimum password length:                              0
Length of password history maintained:                None
Lockout threshold:                                    5
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 15
Computer role:                                        WORKSTATION
```

## Configuration Parameters

You can configure the following settings at the top of both the detection and remediation scripts:

1. `LockoutThreshold` (1-10) - Number of invalid attempts before lockout
   - Recommended: 5

2. `LockoutDuration` (30+ minutes) - Minutes before locked account is automatically unlocked
   - Recommended: 30 or higher (Windows often requires minimum of 30)

3. `LockoutWindow` (15+ minutes) - Minutes before the bad logon attempts counter is reset
   - Recommended: 15 or higher

4. Detection script flexibility options:
   - `AllowHigherDurations` - When true, allows durations higher than specified
   - `RequireExactMatch` - When false, allows values that meet security needs but aren't exact matches

## Implementation Notes

- **IMPORTANT**: Ensure both detection and remediation scripts have matching configuration values
- Both scripts now use identical functions for parsing and checking settings
- The detection script checks if settings match the configured values based on flexibility options
- The remediation script will only change settings that don't comply with the configured values

## Common Issues

- The scripts require administrative privileges
- Domain policies may override these local settings on domain-joined devices
- Changes require a restart of the device to take full effect
- Some Windows systems enforce a minimum lockout duration of 30 minutes