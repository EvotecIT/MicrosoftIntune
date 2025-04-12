<#
.SYNOPSIS
    Configures password policy settings to comply with security requirements.

.DESCRIPTION
    This script applies the required password policy settings:
    - Minimum password length: Number of characters required in password
    - Maximum password age: Days before password expires
    - Minimum password age: Days before password can be changed
    - Password history: Number of previous passwords remembered

.NOTES
    Version: 1.1
    Author: Intune Administrator

    Security recommendation: NIST SP 800-63B recommends:
    - Minimum length of 8 characters (14+ recommended by many standards)
    - No mandatory periodic password resets
    - Password history to prevent reuse

    References:
    - https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-policy
    - https://pages.nist.gov/800-63-3/sp800-63b.html

.EXAMPLE
    .\Remediate-PasswordPolicy.ps1
    Applies password policy settings as configured in the script parameters.

.LINK
    https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-policy
#>

# Configuration settings - modify these values as needed
# Set any value to $null to ignore that setting
$MinPasswordLength = 14     # Minimum number of characters in password (recommended 14+)
$MaxPasswordAge = 60        # Days before password expires (42-90 days typical, 0 for never)
$MinPasswordAge = 1         # Days before password can be changed (1+ recommended)
$PasswordHistory = 24       # Number of previous passwords remembered (24+ recommended)

# Options to make remediation match detection behavior
$AllowStrongerSettings = $false    # Allow settings that exceed minimum security requirements
$RequireExactMatch = $true       # If false, allows values that meet security needs but aren't exact matches

function Get-PasswordPolicy {
    <#
    .DESCRIPTION
        Retrieves and parses the current password policy settings
    .OUTPUTS
        PSObject with current password policy settings
    #>
    $PasswordPolicy = net accounts | Out-String

    # Parse settings with regex
    $MinPasswordLengthMatch = [regex]::Match($PasswordPolicy, 'Minimum password length:\s+(\d+)')
    $MaxPasswordAgeMatch = [regex]::Match($PasswordPolicy, 'Maximum password age \(days\):\s+(\d+|Never)')
    $MinPasswordAgeMatch = [regex]::Match($PasswordPolicy, 'Minimum password age \(days\):\s+(\d+)')
    $PasswordHistoryMatch = [regex]::Match($PasswordPolicy, 'Length of password history maintained:\s+(\d+|None)')

    # Extract values with appropriate handling
    $CurrentMinLength = if ($MinPasswordLengthMatch.Success) { $MinPasswordLengthMatch.Groups[1].Value } else { "Unknown" }
    $CurrentMaxAge = if ($MaxPasswordAgeMatch.Success) {
        $val = $MaxPasswordAgeMatch.Groups[1].Value
        if ($val -eq "Never") { "0" } else { $val }
    } else { "Unknown" }
    $CurrentMinAge = if ($MinPasswordAgeMatch.Success) { $MinPasswordAgeMatch.Groups[1].Value } else { "Unknown" }
    $CurrentHistory = if ($PasswordHistoryMatch.Success) {
        $val = $PasswordHistoryMatch.Groups[1].Value
        if ($val -eq "None") { "0" } else { $val }
    } else { "Unknown" }

    # For debugging if needed
    Write-Verbose "Password policy output: $PasswordPolicy"
    Write-Verbose "Regex matches: Length=$($MinPasswordLengthMatch.Success), MaxAge=$($MaxPasswordAgeMatch.Success), MinAge=$($MinPasswordAgeMatch.Success), History=$($PasswordHistoryMatch.Success)"

    [PSCustomObject]@{
        MinPasswordLength = $CurrentMinLength
        MaxPasswordAge    = $CurrentMaxAge
        MinPasswordAge    = $CurrentMinAge
        PasswordHistory   = $CurrentHistory
    }
}

try {
    # Get current password policy settings
    $CurrentPolicy = Get-PasswordPolicy

    # Initialize change tracking
    $SettingsChanged = $false

    # Check and update minimum password length if configured
    if ($null -ne $MinPasswordLength) {
        $needMinLengthChange = $false
        if ($CurrentPolicy.MinPasswordLength -ne "Unknown") {
            $CurrentMinLength = [int]$CurrentPolicy.MinPasswordLength
            if ($RequireExactMatch) {
                $needMinLengthChange = ($CurrentMinLength -ne $MinPasswordLength)
            } else {
                if ($AllowStrongerSettings) {
                    $needMinLengthChange = ($CurrentMinLength -lt $MinPasswordLength)
                } else {
                    $needMinLengthChange = ($CurrentMinLength -ne $MinPasswordLength)
                }
            }
        } else {
            $needMinLengthChange = $true
        }

        if ($needMinLengthChange) {
            Write-Host "Setting minimum password length to $MinPasswordLength characters"
            $result = net accounts /minpwlen:$MinPasswordLength 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Minimum password length set successfully."
                $SettingsChanged = $true
            } else {
                Write-Warning "Failed to set minimum password length: $result"
            }
        }
    }

    # Check and update maximum password age if configured
    if ($null -ne $MaxPasswordAge) {
        $needMaxAgeChange = $false
        if ($CurrentPolicy.MaxPasswordAge -ne "Unknown") {
            $CurrentMaxAge = [int]$CurrentPolicy.MaxPasswordAge

            # Add diagnostic information
            Write-Host "Maximum password age check: Current=$CurrentMaxAge, Required=$MaxPasswordAge"

            if ($RequireExactMatch) {
                $needMaxAgeChange = ($CurrentMaxAge -ne $MaxPasswordAge)
                Write-Host "Using exact match comparison: Need change = $needMaxAgeChange"
            } else {
                if ($AllowStrongerSettings) {
                    # For max age, lower is stronger (except 0 which means never expire)
                    if ($MaxPasswordAge -eq 0) {
                        # If policy requires never expire, only never expire is compliant
                        $needMaxAgeChange = ($CurrentMaxAge -ne 0)
                        Write-Host "Checking for never expire: Need change = $needMaxAgeChange"
                    } elseif ($CurrentMaxAge -eq 0) {
                        # If current is never expire but policy requires expiry, need to change
                        $needMaxAgeChange = $true
                        Write-Host "Current setting is never expire, but expiration required: Need change = true"
                    } else {
                        # For max age, change needed if current is LESS than required
                        # Lower values make passwords expire sooner (more frequently)
                        $needMaxAgeChange = ($CurrentMaxAge -lt $MaxPasswordAge)
                        Write-Host "Checking if current ($CurrentMaxAge) < required ($MaxPasswordAge): Need change = $needMaxAgeChange"
                    }
                } else {
                    $needMaxAgeChange = ($CurrentMaxAge -ne $MaxPasswordAge)
                    Write-Host "Using exact match (AllowStrongerSettings=false): Need change = $needMaxAgeChange"
                }
            }
        } else {
            $needMaxAgeChange = $true
            Write-Host "Unknown current MaxPasswordAge: Need change = true"
        }

        if ($needMaxAgeChange) {
            $displayMaxAge = if ($MaxPasswordAge -eq 0) { "never expire (unlimited)" } else { "$MaxPasswordAge days" }
            Write-Host "Setting maximum password age to $displayMaxAge"
            $result = net accounts /maxpwage:$MaxPasswordAge 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Maximum password age set successfully."
                $SettingsChanged = $true
            } else {
                Write-Warning "Failed to set maximum password age: $result"
            }
        } else {
            Write-Host "No change needed for maximum password age."
        }
    }

    # Check and update minimum password age if configured
    if ($null -ne $MinPasswordAge) {
        $needMinAgeChange = $false
        if ($CurrentPolicy.MinPasswordAge -ne "Unknown") {
            $CurrentMinAge = [int]$CurrentPolicy.MinPasswordAge
            if ($RequireExactMatch) {
                $needMinAgeChange = ($CurrentMinAge -ne $MinPasswordAge)
            } else {
                if ($AllowStrongerSettings) {
                    # For min age, higher is stronger
                    $needMinAgeChange = ($CurrentMinAge -lt $MinPasswordAge)
                } else {
                    $needMinAgeChange = ($CurrentMinAge -ne $MinPasswordAge)
                }
            }
        } else {
            $needMinAgeChange = $true
        }

        if ($needMinAgeChange) {
            Write-Host "Setting minimum password age to $MinPasswordAge days"
            $result = net accounts /minpwage:$MinPasswordAge 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Minimum password age set successfully."
                $SettingsChanged = $true
            } else {
                Write-Warning "Failed to set minimum password age: $result"
            }
        }
    }

    # Check and update password history if configured
    if ($null -ne $PasswordHistory) {
        $needHistoryChange = $false
        if ($CurrentPolicy.PasswordHistory -ne "Unknown") {
            $CurrentHistory = [int]$CurrentPolicy.PasswordHistory
            if ($RequireExactMatch) {
                $needHistoryChange = ($CurrentHistory -ne $PasswordHistory)
            } else {
                if ($AllowStrongerSettings) {
                    # For history, higher is stronger
                    $needHistoryChange = ($CurrentHistory -lt $PasswordHistory)
                } else {
                    $needHistoryChange = ($CurrentHistory -ne $PasswordHistory)
                }
            }
        } else {
            $needHistoryChange = $true
        }

        if ($needHistoryChange) {
            $displayHistory = if ($PasswordHistory -eq 0) { "none" } else { "$PasswordHistory passwords" }
            Write-Host "Setting password history to remember $displayHistory"
            $result = net accounts /uniquepw:$PasswordHistory 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Password history setting updated successfully."
                $SettingsChanged = $true
            } else {
                Write-Warning "Failed to set password history: $result"
            }
        }
    }

    # Get updated settings to verify changes
    if ($SettingsChanged) {
        Write-Host "Password policy settings have been updated."

        # Display new settings for verification
        Write-Host "`nNew password policy settings:"
        $updatedSettings = net accounts | Out-String
        Write-Host $updatedSettings

        # Verify actual changes
        $newSettings = Get-PasswordPolicy

        # Check if any target values weren't achieved
        $AllTargetsAchieved = $true

        if ($null -ne $MinPasswordLength -and [int]$newSettings.MinPasswordLength -ne $MinPasswordLength) {
            Write-Warning "Minimum password length: Expected $MinPasswordLength, but found $($newSettings.MinPasswordLength)."
            $AllTargetsAchieved = $false
        }
        if ($null -ne $MaxPasswordAge -and [int]$newSettings.MaxPasswordAge -ne $MaxPasswordAge) {
            Write-Warning "Maximum password age: Expected $MaxPasswordAge days, but found $($newSettings.MaxPasswordAge) days."
            $AllTargetsAchieved = $false
        }
        if ($null -ne $MinPasswordAge -and [int]$newSettings.MinPasswordAge -ne $MinPasswordAge) {
            Write-Warning "Minimum password age: Expected $MinPasswordAge days, but found $($newSettings.MinPasswordAge) days."
            $AllTargetsAchieved = $false
        }
        if ($null -ne $PasswordHistory -and [int]$newSettings.PasswordHistory -ne $PasswordHistory) {
            Write-Warning "Password history: Expected $PasswordHistory, but found $($newSettings.PasswordHistory)."
            $AllTargetsAchieved = $false
        }

        if ($AllTargetsAchieved) {
            Write-Host "Password policy settings are now compliant."
            exit 0
        } else {
            Write-Error "Failed to apply all required password policy settings. Some settings are still non-compliant."
            exit 1
        }
    } else {
        # If no changes were made, verify compliance
        $newSettings = Get-PasswordPolicy
        $AllTargetsAchieved = $true

        if ($null -ne $MinPasswordLength -and [int]$newSettings.MinPasswordLength -ne $MinPasswordLength) {
            Write-Warning "Minimum password length: Expected $MinPasswordLength, but found $($newSettings.MinPasswordLength)."
            $AllTargetsAchieved = $false
        }
        if ($null -ne $MaxPasswordAge -and [int]$newSettings.MaxPasswordAge -ne $MaxPasswordAge) {
            Write-Warning "Maximum password age: Expected $MaxPasswordAge days, but found $($newSettings.MaxPasswordAge) days."
            $AllTargetsAchieved = $false
        }
        if ($null -ne $MinPasswordAge -and [int]$newSettings.MinPasswordAge -ne $MinPasswordAge) {
            Write-Warning "Minimum password age: Expected $MinPasswordAge days, but found $($newSettings.MinPasswordAge) days."
            $AllTargetsAchieved = $false
        }
        if ($null -ne $PasswordHistory -and [int]$newSettings.PasswordHistory -ne $PasswordHistory) {
            Write-Warning "Password history: Expected $PasswordHistory, but found $($newSettings.PasswordHistory)."
            $AllTargetsAchieved = $false
        }

        if ($AllTargetsAchieved) {
            Write-Host "Password policy settings are already compliant."
            exit 0
        } else {
            Write-Error "Password policy settings are not compliant. No changes were made due to errors."
            exit 1
        }
    }
} catch {
    $errMsg = $_.Exception.Message
    Write-Error "Error applying password policy settings: $errMsg"
    exit 1
}
