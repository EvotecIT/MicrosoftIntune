<#
.SYNOPSIS
    Detection script for Password Policy Settings in Intune
.DESCRIPTION
    Checks if the current password policy settings match the required configuration:
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
$MaxPasswordAge = 42         # Days before password expires (42-90 days typical, 0 for never)
$MinPasswordAge = $null          # Days before password can be changed (1+ recommended)
$PasswordHistory = $null         # Number of previous passwords remembered (24+ recommended)

# Options to make detection more flexible
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

    # Initialize compliance tracking
    $AllCompliant = $true
    $ComplianceStatus = [PSCustomObject]@{
        MinPasswordLengthCompliant = $null
        MaxPasswordAgeCompliant    = $null
        MinPasswordAgeCompliant    = $null
        PasswordHistoryCompliant   = $null
    }

    # Check minimum password length compliance if configured
    if ($null -ne $MinPasswordLength) {
        if ($CurrentPolicy.MinPasswordLength -ne "Unknown") {
            $CurrentMinLength = [int]$CurrentPolicy.MinPasswordLength
            if ($RequireExactMatch) {
                $ComplianceStatus.MinPasswordLengthCompliant = ($CurrentMinLength -eq $MinPasswordLength)
            } else {
                if ($AllowStrongerSettings) {
                    $ComplianceStatus.MinPasswordLengthCompliant = ($CurrentMinLength -ge $MinPasswordLength)
                } else {
                    $ComplianceStatus.MinPasswordLengthCompliant = ($CurrentMinLength -eq $MinPasswordLength)
                }
            }
        } else {
            $ComplianceStatus.MinPasswordLengthCompliant = $false
        }

        $AllCompliant = $AllCompliant -and $ComplianceStatus.MinPasswordLengthCompliant
    } else {
        $ComplianceStatus.MinPasswordLengthCompliant = $true  # Ignored
    }

    # Check maximum password age compliance if configured
    if ($null -ne $MaxPasswordAge) {
        if ($CurrentPolicy.MaxPasswordAge -ne "Unknown") {
            $CurrentMaxAge = [int]$CurrentPolicy.MaxPasswordAge

            # Add diagnostic information
            Write-Host "Maximum password age check: Current=$CurrentMaxAge, Required=$MaxPasswordAge"

            if ($RequireExactMatch) {
                $ComplianceStatus.MaxPasswordAgeCompliant = ($CurrentMaxAge -eq $MaxPasswordAge)
                Write-Host "Using exact match comparison: $($ComplianceStatus.MaxPasswordAgeCompliant)"
            } else {
                if ($AllowStrongerSettings) {
                    # For max age, lower is stronger (except 0 which means never expire)
                    if ($MaxPasswordAge -eq 0) {
                        # If policy requires never expire, only never expire is compliant
                        $ComplianceStatus.MaxPasswordAgeCompliant = ($CurrentMaxAge -eq 0)
                        Write-Host "Checking for never expire: $($ComplianceStatus.MaxPasswordAgeCompliant)"
                    } elseif ($CurrentMaxAge -eq 0) {
                        # If current is never expire but policy requires expiry, not compliant
                        $ComplianceStatus.MaxPasswordAgeCompliant = $false
                        Write-Host "Current setting is never expire, but expiration required: Not Compliant"
                    } else {
                        # For max age, current should be EQUAL to or GREATER than required
                        # Lower values make passwords expire sooner (more frequently)
                        $ComplianceStatus.MaxPasswordAgeCompliant = ($CurrentMaxAge -ge $MaxPasswordAge)
                        Write-Host "Checking if current ($CurrentMaxAge) >= required ($MaxPasswordAge): $($ComplianceStatus.MaxPasswordAgeCompliant)"
                    }
                } else {
                    $ComplianceStatus.MaxPasswordAgeCompliant = ($CurrentMaxAge -eq $MaxPasswordAge)
                    Write-Host "Using exact match (AllowStrongerSettings=false): $($ComplianceStatus.MaxPasswordAgeCompliant)"
                }
            }
        } else {
            $ComplianceStatus.MaxPasswordAgeCompliant = $false
            Write-Host "Unknown current MaxPasswordAge: Not Compliant"
        }

        $AllCompliant = $AllCompliant -and $ComplianceStatus.MaxPasswordAgeCompliant
        Write-Host "MaxPasswordAge compliance status: $($ComplianceStatus.MaxPasswordAgeCompliant)"
    } else {
        $ComplianceStatus.MaxPasswordAgeCompliant = $true  # Ignored
        Write-Host "MaxPasswordAge check ignored (null value)"
    }

    # Check minimum password age compliance if configured
    if ($null -ne $MinPasswordAge) {
        if ($CurrentPolicy.MinPasswordAge -ne "Unknown") {
            $CurrentMinAge = [int]$CurrentPolicy.MinPasswordAge
            if ($RequireExactMatch) {
                $ComplianceStatus.MinPasswordAgeCompliant = ($CurrentMinAge -eq $MinPasswordAge)
            } else {
                if ($AllowStrongerSettings) {
                    # For min age, higher is stronger
                    $ComplianceStatus.MinPasswordAgeCompliant = ($CurrentMinAge -ge $MinPasswordAge)
                } else {
                    $ComplianceStatus.MinPasswordAgeCompliant = ($CurrentMinAge -eq $MinPasswordAge)
                }
            }
        } else {
            $ComplianceStatus.MinPasswordAgeCompliant = $false
        }

        $AllCompliant = $AllCompliant -and $ComplianceStatus.MinPasswordAgeCompliant
    } else {
        $ComplianceStatus.MinPasswordAgeCompliant = $true  # Ignored
    }

    # Check password history compliance if configured
    if ($null -ne $PasswordHistory) {
        if ($CurrentPolicy.PasswordHistory -ne "Unknown") {
            $CurrentHistory = [int]$CurrentPolicy.PasswordHistory
            if ($RequireExactMatch) {
                $ComplianceStatus.PasswordHistoryCompliant = ($CurrentHistory -eq $PasswordHistory)
            } else {
                if ($AllowStrongerSettings) {
                    # For history, higher is stronger
                    $ComplianceStatus.PasswordHistoryCompliant = ($CurrentHistory -ge $PasswordHistory)
                } else {
                    $ComplianceStatus.PasswordHistoryCompliant = ($CurrentHistory -eq $PasswordHistory)
                }
            }
        } else {
            $ComplianceStatus.PasswordHistoryCompliant = $false
        }

        $AllCompliant = $AllCompliant -and $ComplianceStatus.PasswordHistoryCompliant
    } else {
        $ComplianceStatus.PasswordHistoryCompliant = $true  # Ignored
    }

    # Exit with status code based on compliance
    if ($AllCompliant) {
        Write-Host "Password policy settings are compliant."
        # Add detailed compliance summary
        Write-Host "`nCompliance Summary:"
        if ($null -ne $MinPasswordLength) {
            Write-Host "MinPasswordLength: $($ComplianceStatus.MinPasswordLengthCompliant)"
        }
        if ($null -ne $MaxPasswordAge) {
            Write-Host "MaxPasswordAge: $($ComplianceStatus.MaxPasswordAgeCompliant)"
        }
        if ($null -ne $MinPasswordAge) {
            Write-Host "MinPasswordAge: $($ComplianceStatus.MinPasswordAgeCompliant)"
        }
        if ($null -ne $PasswordHistory) {
            Write-Host "PasswordHistory: $($ComplianceStatus.PasswordHistoryCompliant)"
        }
        exit 0
    } else {
        Write-Host "Password policy settings are not compliant."

        # Report individual settings status with fixed conditional operator format
        if ($null -ne $MinPasswordLength) {
            $complianceText = if ($ComplianceStatus.MinPasswordLengthCompliant) { "Compliant" } else { "Not Compliant" }
            Write-Host "Minimum password length: $($CurrentPolicy.MinPasswordLength) (Required: $MinPasswordLength) - $complianceText"
        }
        if ($null -ne $MaxPasswordAge) {
            $currentMaxAgeDisplay = if ($CurrentPolicy.MaxPasswordAge -eq "0") { "Never" } else { $CurrentPolicy.MaxPasswordAge }
            $requiredMaxAgeDisplay = if ($MaxPasswordAge -eq 0) { "Never" } else { $MaxPasswordAge }
            $complianceText = if ($ComplianceStatus.MaxPasswordAgeCompliant) { "Compliant" } else { "Not Compliant" }
            Write-Host "Maximum password age: $currentMaxAgeDisplay (Required: $requiredMaxAgeDisplay) - $complianceText"
        }
        if ($null -ne $MinPasswordAge) {
            $complianceText = if ($ComplianceStatus.MinPasswordAgeCompliant) { "Compliant" } else { "Not Compliant" }
            Write-Host "Minimum password age: $($CurrentPolicy.MinPasswordAge) (Required: $MinPasswordAge) - $complianceText"
        }
        if ($null -ne $PasswordHistory) {
            $currentHistoryDisplay = if ($CurrentPolicy.PasswordHistory -eq "0") { "None" } else { $CurrentPolicy.PasswordHistory }
            $requiredHistoryDisplay = if ($PasswordHistory -eq 0) { "None" } else { $PasswordHistory }
            $complianceText = if ($ComplianceStatus.PasswordHistoryCompliant) { "Compliant" } else { "Not Compliant" }
            Write-Host "Password history: $currentHistoryDisplay (Required: $requiredHistoryDisplay) - $complianceText"
        }

        exit 1
    }
} catch {
    $errMsg = $_.Exception.Message
    Write-Error $errMsg
    exit 1
}
