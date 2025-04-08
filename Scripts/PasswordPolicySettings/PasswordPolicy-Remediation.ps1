<#
.SYNOPSIS
    Remediation script for Password Policy Settings in Intune
.DESCRIPTION
    Applies the required password policy settings:
    - Minimum password length: Number of characters required in password
    - Maximum password age: Days before password expires
    - Minimum password age: Days before password can be changed
    - Password history: Number of previous passwords remembered
.NOTES
    Version: 1.1
    Security recommendation: NIST SP 800-63B recommends:
    - Minimum length of 8 characters (14+ recommended by many standards)
    - No mandatory periodic password resets
    - Password history to prevent reuse
#>

# Configuration settings - modify these values as needed
# Set any value to $null to ignore that setting
$MinPasswordLength = $null       # Minimum number of characters in password (recommended 14+)
$MaxPasswordAge = 41          # Days before password expires (42-90 days typical, 0 for never)
$MinPasswordAge = $null          # Days before password can be changed (1+ recommended)
$PasswordHistory = $null         # Number of previous passwords remembered (24+ recommended)

# Options to make remediation match detection behavior
$AllowStrongerSettings = $true    # Allow settings that exceed minimum security requirements
$RequireExactMatch = $false       # If false, allows values that meet security needs but aren't exact matches

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
            if ($RequireExactMatch) {
                $needMaxAgeChange = ($CurrentMaxAge -ne $MaxPasswordAge)
            } else {
                if ($AllowStrongerSettings) {
                    # For max age, lower is stronger (except 0 which means never expire)
                    if ($MaxPasswordAge -eq 0) {
                        # If policy requires never expire, only never expire is compliant
                        $needMaxAgeChange = ($CurrentMaxAge -ne 0)
                    } elseif ($CurrentMaxAge -eq 0) {
                        # If current is never expire but policy requires expiry, need to change
                        $needMaxAgeChange = $true
                    } else {
                        # Otherwise, any value less than or equal to max age is compliant
                        $needMaxAgeChange = ($CurrentMaxAge -gt $MaxPasswordAge)
                    }
                } else {
                    $needMaxAgeChange = ($CurrentMaxAge -ne $MaxPasswordAge)
                }
            }
        } else {
            $needMaxAgeChange = $true
        }

        if ($needMaxAgeChange) {
            $displayMaxAge = $MaxPasswordAge -eq 0 ? "never expire (unlimited)" : "$MaxPasswordAge days"
            Write-Host "Setting maximum password age to $displayMaxAge"
            $result = net accounts /maxpwage:$MaxPasswordAge 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Maximum password age set successfully."
                $SettingsChanged = $true
            } else {
                Write-Warning "Failed to set maximum password age: $result"
            }
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
            $displayHistory = $PasswordHistory -eq 0 ? "none" : "$PasswordHistory passwords"
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
        if ($null -ne $MinPasswordLength) {
            Write-Host "Current minimum password length: $($newSettings.MinPasswordLength) (Target: $MinPasswordLength)"
        }
        if ($null -ne $MaxPasswordAge) {
            $maxAgeDisplay = $newSettings.MaxPasswordAge -eq "0" ? "Never" : "$($newSettings.MaxPasswordAge) days"
            $targetMaxAgeDisplay = $MaxPasswordAge -eq 0 ? "Never" : "$MaxPasswordAge days"
            Write-Host "Current maximum password age: $maxAgeDisplay (Target: $targetMaxAgeDisplay)"
        }
        if ($null -ne $MinPasswordAge) {
            Write-Host "Current minimum password age: $($newSettings.MinPasswordAge) days (Target: $MinPasswordAge days)"
        }
        if ($null -ne $PasswordHistory) {
            $historyDisplay = $newSettings.PasswordHistory -eq "0" ? "None" : $newSettings.PasswordHistory
            $targetHistoryDisplay = $PasswordHistory -eq 0 ? "None" : $PasswordHistory
            Write-Host "Current password history: $historyDisplay (Target: $targetHistoryDisplay)"
        }
    } else {
        Write-Host "No changes needed. Password policy settings are already configured correctly."
    }

    exit 0
} catch {
    $errMsg = $_.Exception.Message
    Write-Error "Error applying password policy settings: $errMsg"
    exit 1
}
