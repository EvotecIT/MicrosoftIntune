<#
.SYNOPSIS
    Detection script for Account Lockout Settings in Intune
.DESCRIPTION
    Checks if the current account lockout settings match the required configuration
    - Account lockout threshold: Number of invalid attempts before lockout
    - Account lockout duration: Minutes before locked account is automatically unlocked
    - Reset account lockout counter: Minutes before the bad logon attempts counter is reset
.NOTES
    Version: 1.2
    Note: Windows requires lockout duration to be set to 30 minutes or higher on some systems
#>

# Configuration settings - modify these values as needed
$LockoutThreshold = 5        # Between 1-10, recommended 5
$LockoutDuration = 30        # Minutes, must be 30 or higher on many systems
$LockoutWindow = 15          # Minutes, minimum 15

# Options to make detection more flexible
$AllowHigherDurations = $true    # Allow durations higher than specified (e.g., 35 minutes)
$RequireExactMatch = $true      # If false, allows values that meet security needs but aren't exact matches

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

    # Check if settings meet requirements
    $ThresholdCompliant = $false
    $DurationCompliant = $false
    $WindowCompliant = $false

    # Check threshold compliance
    if ($CurrentSettings.Threshold -ne "Never" -and $CurrentSettings.Threshold -ne "Unknown") {
        $ThresholdValue = [int]$CurrentSettings.Threshold
        $ThresholdCompliant = ($ThresholdValue -eq $LockoutThreshold)
    }

    # Check duration compliance
    if ($CurrentSettings.Duration -ne "Never" -and $CurrentSettings.Duration -ne "Unknown") {
        $DurationValue = [int]$CurrentSettings.Duration
        if ($RequireExactMatch) {
            $DurationCompliant = ($DurationValue -eq $LockoutDuration)
        } else {
            # Accept higher values if allowed (more secure)
            if ($AllowHigherDurations) {
                $DurationCompliant = ($DurationValue -ge $LockoutDuration)
            } else {
                $DurationCompliant = ($DurationValue -eq $LockoutDuration)
            }
        }
    }

    # Check window compliance
    if ($CurrentSettings.Window -ne "Unknown") {
        $WindowValue = [int]$CurrentSettings.Window
        if ($RequireExactMatch) {
            $WindowCompliant = ($WindowValue -eq $LockoutWindow)
        } else {
            # Accept higher values if allowed (more secure)
            $WindowCompliant = ($WindowValue -ge $LockoutWindow)
        }
    }

    # Exit with status code based on compliance
    if ($ThresholdCompliant -and $DurationCompliant -and $WindowCompliant) {
        Write-Host "Account lockout settings are compliant."
        exit 0
    } else {
        Write-Host "Account lockout settings are not compliant."
        Write-Host "Current threshold: $($CurrentSettings.Threshold) (Required: $LockoutThreshold)"
        Write-Host "Current duration: $($CurrentSettings.Duration) (Required: $LockoutDuration)"
        Write-Host "Current window: $($CurrentSettings.Window) (Required: $LockoutWindow)"
        exit 1
    }
} catch {
    $errMsg = $_.Exception.Message
    Write-Error $errMsg
    exit 1
}