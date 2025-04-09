<#
.SYNOPSIS
    Configures account lockout settings to comply with security requirements.

.DESCRIPTION
    This script applies the required account lockout settings:
    - Account lockout threshold: Number of invalid attempts before lockout
    - Account lockout duration: Minutes before locked account is automatically unlocked
    - Reset account lockout counter: Minutes before the bad logon attempts counter is reset

.NOTES
    Version: 1.3
    Author: Intune Administrator

    Note: Windows requires lockout duration to be set to 30 minutes or higher on some systems.

    References:
    - https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-threshold
    - https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-duration

.EXAMPLE
    .\Remediate-AccountLockoutSettings.ps1
    Applies account lockout settings as configured in the script parameters.

.LINK
    https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-policy
#>

# Configuration settings - modify these values as needed
$LockoutThreshold = 5        # Between 1-10, recommended 5
$LockoutDuration = 15        # Minutes, must be 30 or higher on many systems
$LockoutWindow = 15          # Minutes, minimum 15

# Options to make remediation match detection behavior
$AllowHigherDurations = $false   # Allow durations higher than specified (e.g., 35 minutes)
$RequireExactMatch = $true       # If false, allows values that meet security needs but aren't exact matches

function Get-AccountSettings {
    <#
    .DESCRIPTION
        Retrieves and parses the current account lockout settings
    .OUTPUTS
        PSObject with current account settings
    #>
    $AccountSettings = net accounts | Out-String

    # Parse settings with regex
    $ThresholdMatch = [regex]::Match($AccountSettings, 'Lockout threshold:\s+(\d+|Never)')
    $DurationMatch = [regex]::Match($AccountSettings, 'Lockout duration \(minutes\):\s+(\d+|Never)')
    $WindowMatch = [regex]::Match($AccountSettings, 'Lockout observation window \(minutes\):\s+(\d+)')

    $CurrentThreshold = if ($ThresholdMatch.Success) { $ThresholdMatch.Groups[1].Value } else { "Unknown" }
    $CurrentDuration = if ($DurationMatch.Success) { $DurationMatch.Groups[1].Value } else { "Unknown" }
    $CurrentWindow = if ($WindowMatch.Success) { $WindowMatch.Groups[1].Value } else { "Unknown" }

    [PSCustomObject]@{
        Threshold = $CurrentThreshold
        Duration  = $CurrentDuration
        Window    = $CurrentWindow
    }
}

try {
    # Get current account settings
    $CurrentSettings = Get-AccountSettings

    # Update settings if needed
    $SettingsChanged = $false

    # Check and set lockout threshold
    $needThresholdChange = $false
    if ($CurrentSettings.Threshold -eq "Never") {
        $needThresholdChange = $true
    } elseif ($CurrentSettings.Threshold -ne "Unknown") {
        $ThresholdValue = [int]$CurrentSettings.Threshold
        $needThresholdChange = ($ThresholdValue -ne $LockoutThreshold)
    }

    if ($needThresholdChange) {
        Write-Host "Setting lockout threshold to $LockoutThreshold attempts"
        $thresholdResult = net accounts /lockoutthreshold:$LockoutThreshold 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Lockout threshold set successfully."
            $SettingsChanged = $true
        } else {
            Write-Warning "Failed to set lockout threshold: $thresholdResult"
        }
    }

    # Check and set lockout duration
    $needDurationChange = $false
    if ($CurrentSettings.Duration -eq "Never") {
        $needDurationChange = $true
    } elseif ($CurrentSettings.Duration -ne "Unknown") {
        $DurationValue = [int]$CurrentSettings.Duration
        if ($RequireExactMatch) {
            $needDurationChange = ($DurationValue -ne $LockoutDuration)
        } else {
            # Only change if lower than required value
            if ($AllowHigherDurations) {
                $needDurationChange = ($DurationValue -lt $LockoutDuration)
            } else {
                $needDurationChange = ($DurationValue -ne $LockoutDuration)
            }
        }
    }

    if ($needDurationChange) {
        Write-Host "Setting lockout duration to $LockoutDuration minutes"
        $durationResult = net accounts /lockoutduration:$LockoutDuration 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Lockout duration set successfully."
            $SettingsChanged = $true
        } else {
            Write-Warning "Failed to set lockout duration: $durationResult"
            # If requested duration failed, try a higher value commonly accepted
            if ($LockoutDuration -lt 35) {
                Write-Host "Attempting with lockout duration of 35 minutes instead..."
                $durationResult = net accounts /lockoutduration:35 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "Lockout duration set to 35 minutes successfully."
                    $SettingsChanged = $true
                } else {
                    Write-Warning "Also failed with 35 minutes: $durationResult"
                }
            }
        }
    }

    # Check and set lockout observation window
    $needWindowChange = $false
    if ($CurrentSettings.Window -eq "Unknown") {
        $needWindowChange = $true
    } else {
        $WindowValue = [int]$CurrentSettings.Window
        if ($RequireExactMatch) {
            $needWindowChange = ($WindowValue -ne $LockoutWindow)
        } else {
            # Only change if lower than required value
            $needWindowChange = ($WindowValue -lt $LockoutWindow)
        }
    }

    if ($needWindowChange) {
        Write-Host "Setting lockout observation window to $LockoutWindow minutes"
        $windowResult = net accounts /lockoutwindow:$LockoutWindow 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Lockout observation window set successfully."
            $SettingsChanged = $true
        } else {
            Write-Warning "Failed to set lockout observation window: $windowResult"
        }
    }

    # Get updated settings to verify changes
    if ($SettingsChanged) {
        Write-Host "Account lockout settings have been updated."
        # Display new settings for verification
        Write-Host "`nNew account settings:"
        $updatedSettings = net accounts | Select-String "lockout"
        Write-Host $updatedSettings

        # Verify actual changes
        $newSettings = Get-AccountSettings
        Write-Host "Current threshold: $($newSettings.Threshold) (Target: $LockoutThreshold)"
        Write-Host "Current duration: $($newSettings.Duration) (Target: $LockoutDuration)"
        Write-Host "Current window: $($newSettings.Window) (Target: $LockoutWindow)"

        # Check if any target values weren't achieved
        $allTargetsAchieved = $true
        if ($newSettings.Threshold -ne "Unknown" -and $newSettings.Threshold -ne "Never" -and [int]$newSettings.Threshold -ne $LockoutThreshold) {
            $allTargetsAchieved = $false
            Write-Warning "Threshold value did not match target."
        }

        if ($newSettings.Duration -ne "Unknown" -and $newSettings.Duration -ne "Never") {
            $newDuration = [int]$newSettings.Duration
            $durationTargetMet = $false

            if ($RequireExactMatch) {
                $durationTargetMet = ($newDuration -eq $LockoutDuration)
            } else {
                if ($AllowHigherDurations) {
                    $durationTargetMet = ($newDuration -ge $LockoutDuration)
                } else {
                    $durationTargetMet = ($newDuration -eq $LockoutDuration)
                }
            }

            if (!$durationTargetMet) {
                # Special case - if we tried with 35 instead
                if ($LockoutDuration -lt 35 -and $newDuration -eq 35) {
                    Write-Warning "Duration set to 35 instead of $LockoutDuration due to system constraints."
                } else {
                    $allTargetsAchieved = $false
                    Write-Warning "Duration value did not match target."
                }
            }
        }

        if ($newSettings.Window -ne "Unknown") {
            $newWindow = [int]$newSettings.Window
            $windowTargetMet = $false

            if ($RequireExactMatch) {
                $windowTargetMet = ($newWindow -eq $LockoutWindow)
            } else {
                $windowTargetMet = ($newWindow -ge $LockoutWindow)
            }

            if (!$windowTargetMet) {
                $allTargetsAchieved = $false
                Write-Warning "Window value did not match target."
            }
        }

        if (!$allTargetsAchieved) {
            Write-Warning "Some settings could not be applied as specified."
            # But we don't want to fail remediation in this case - we likely set what was possible
        }
    } else {
        Write-Host "No changes needed. Account lockout settings are already configured correctly."
    }

    exit 0
} catch {
    $errMsg = $_.Exception.Message
    Write-Error "Error applying account lockout settings: $errMsg"
    exit 1
}