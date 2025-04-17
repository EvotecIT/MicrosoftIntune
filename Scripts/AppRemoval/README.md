# App Removal Settings

## Overview
This script package manages Windows Store apps (UWP/Modern apps) through Microsoft Intune. It can operate in two modes to either remove specific apps or ensure only approved apps remain on devices, helping maintain a clean and secure Windows environment.

## Operation Modes

### Exclusion Mode
- Apps in the list will be removed
- All other apps (except critical system apps) are allowed to remain
- Best for removing specific unwanted apps while leaving others untouched

### Inclusion Mode
- Only apps in the list (plus critical system apps) are allowed to remain
- All other apps will be removed
- Best for enforcing a strict set of allowed apps

## Configuration Parameters

Configure these settings at the top of both detection and remediation scripts:

1. `Mode` ("Inclusion" or "Exclusion") - Determines how the AppList is interpreted
   - "Inclusion": Only listed apps (plus critical apps) are allowed
   - "Exclusion": Listed apps will be removed

2. `AppList` - Array of app package names to process
   ```powershell
   $AppList = @(
       "Microsoft.BingWeather"
       "Microsoft.GetHelp"
       # Add more apps as needed
   )
   ```

3. `CriticalApps` - System apps that should never be removed
   - Predefined list of essential Windows components
   - Can be customized if needed, but use caution

## Implementation Notes

- Both scripts support -WhatIf parameter to preview changes
- Apps are checked at both system level (provisioned) and user level
- Critical system apps are protected from removal in both modes
- Empty AppList behavior:
  - Exclusion Mode: No apps will be removed
  - Inclusion Mode: All non-critical apps will be removed (with warning)

## Common Issues

- The scripts require administrative privileges
- Some apps may be dependencies for others
- Store apps may reinstall automatically if required by Windows
- User profile apps may differ from provisioned apps

## Script Usage

### Detection Script
```powershell
.\Detect-AppRemoval.ps1
# Returns exit code 0 if compliant, 1 if not
```

### Remediation Script
```powershell
.\Remediate-AppRemoval.ps1
# Removes non-compliant apps

.\Remediate-AppRemoval.ps1 -WhatIf
# Shows what would be removed without making changes
```
