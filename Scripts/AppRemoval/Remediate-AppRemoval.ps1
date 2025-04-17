<#
.SYNOPSIS
    Removes specified Windows apps from the device.

.DESCRIPTION
    This script removes specified Windows apps from the device based on
    inclusion and exclusion lists to ensure compliance with organizational policy.

    The script can operate in two modes:
    - Inclusion Mode: Only listed apps should be present, all others will be removed
    - Exclusion Mode: Listed apps will be removed, all others will remain

.PARAMETER WhatIf
    Shows what would happen if the script runs. No apps are removed.

.NOTES
    Version: 1.1
    Author: Intune Administrator

    References:
    - https://learn.microsoft.com/en-us/powershell/module/appx/remove-appxpackage
    - https://learn.microsoft.com/en-us/powershell/module/appx/remove-appxprovisionedpackage

.EXAMPLE
    .\Remediate-AppRemoval.ps1
    Removes non-compliant apps based on the configured policy.

.EXAMPLE
    .\Remediate-AppRemoval.ps1 -WhatIf
    Shows which apps would be removed without actually removing them.

.LINK
    https://learn.microsoft.com/en-us/powershell/module/appx
#>

# Script parameters
$WhatIf = $true

# Configuration settings - modify these values as needed
$Mode = "Inclusion" # "Inclusion" or "Exclusion"

# Apps to keep or remove depending on mode
# For Inclusion mode: only these apps are allowed to be present
# For Exclusion mode: these apps should be removed
$AppList = @(
    # "Microsoft.BingWeather"
    # "Microsoft.GetHelp"
    # "Microsoft.Getstarted"
    # "Microsoft.Microsoft3DViewer"
    # "Microsoft.MicrosoftOfficeHub"
    # "Microsoft.MicrosoftSolitaireCollection"
    # "Microsoft.MicrosoftStickyNotes"
    # "Microsoft.MSPaint"
    # "Microsoft.OneConnect"
    # "Microsoft.People"
    # "Microsoft.Print3D"
    # "Microsoft.SkypeApp"
    # "Microsoft.Wallet"
    # "Microsoft.WindowsAlarms"
    # "Microsoft.WindowsCamera"
    # "Microsoft.WindowsCommunicationsApps" # Mail, Calendar
    # "Microsoft.WindowsFeedbackHub"
    # "Microsoft.WindowsMaps"
    # "Microsoft.Xbox.TCUI"
    # "Microsoft.XboxApp"
    # "Microsoft.XboxGameOverlay"
    # "Microsoft.XboxGamingOverlay"
    # "Microsoft.XboxIdentityProvider"
    # "Microsoft.XboxSpeechToTextOverlay"
    # "Microsoft.YourPhone"
    # "Microsoft.ZuneMusic"
    # "Microsoft.ZuneVideo"
)

# Critical apps that should never be removed (used in both modes)
$CriticalApps = @(
    'Microsoft.AAD.BrokerPlugin'
    'Microsoft.AccountsControl'
    'Microsoft.AsyncTextService'
    'Microsoft.BioEnrollment'
    'Microsoft.CredDialogHost'
    'Microsoft.LockApp'
    'Microsoft.MicrosoftEdgeDevToolsClient'
    'Microsoft.Win32WebViewHost'
    "Microsoft.Windows.*"
    "Microsoft.Windows.StartMenuExperienceHost"
    "Microsoft.Windows.ShellExperienceHost"
    "Microsoft.WindowsStore"
    "Microsoft.VCLibs.*"
    "Microsoft.NET.*"
    "Microsoft.DesktopAppInstaller"
    "Microsoft.SecHealthUI"
    "Microsoft.WindowsCalculator"
)

function Get-InstalledApps {
    <#
    .DESCRIPTION
        Gets all installed Windows Apps (both provisioned and regular)
    .OUTPUTS
        PSCustomObject with collections of all app types
    #>

    # Get provisioned packages (installed for all users)
    $ProvisionedApps = Get-AppxProvisionedPackage -Online

    # Get installed packages for current user
    $InstalledApps = Get-AppxPackage

    # Return both collections
    [PSCustomObject]@{
        ProvisionedApps = $ProvisionedApps
        InstalledApps   = $InstalledApps
    }
}

function Test-AppShouldBeRemoved {
    <#
    .DESCRIPTION
        Tests if a specific app should be removed based on the configured policy
    .PARAMETER AppName
        The display name or package name of the app to test
    .OUTPUTS
        Boolean indicating if the app should be removed
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$AppName
    )

    # First check if app is critical - never remove critical apps
    foreach ($CriticalApp in $CriticalApps) {
        if ($AppName -like $CriticalApp) {
            return $false
        }
    }

    if ($Mode -eq "Exclusion") {
        # In exclusion mode, only remove apps in the list
        foreach ($ExcludedApp in $AppList) {
            if ($AppName -like $ExcludedApp) {
                return $true
            }
        }
        return $false
    } else {
        # In inclusion mode, remove apps NOT in the list
        foreach ($IncludedApp in $AppList) {
            if ($AppName -like $IncludedApp) {
                return $false
            }
        }
        return $true
    }
}

function Remove-NonCompliantApps {
    <#
    .DESCRIPTION
        Removes apps that don't comply with the configured policy
    .PARAMETER WhatIf
        If specified, shows what apps would be removed without actually removing them
    .OUTPUTS
        PSObject with results of the removal operations
    #>
    param (
        [Parameter(Mandatory = $false)]
        [switch]$WhatIf
    )

    $AllApps = Get-InstalledApps
    $RemovedApps = @()
    $FailedRemovals = @()

    # Process provisioned apps (for all users)
    foreach ($App in $AllApps.ProvisionedApps) {
        # Check if this app should be removed
        if (Test-AppShouldBeRemoved -AppName $App.DisplayName) {
            try {
                if ($WhatIf) {
                    Write-Host "WhatIf: Would remove provisioned app: $($App.DisplayName)" -ForegroundColor Cyan
                    $RemovedApps += "Provisioned: $($App.DisplayName) (WhatIf)"
                } else {
                    Write-Host "Removing provisioned app: $($App.DisplayName)"
                    Remove-AppxProvisionedPackage -Online -PackageName $App.PackageName -ErrorAction Stop | Out-Null
                    $RemovedApps += "Provisioned: $($App.DisplayName)"
                }
            } catch {
                Write-Warning "Failed to remove provisioned app $($App.DisplayName): $_"
                $FailedRemovals += "Provisioned: $($App.DisplayName)"
            }
        } else {
            Write-Host "Keeping provisioned app: $($App.DisplayName)"
        }
    }    # Process installed apps (for current user)
    foreach ($App in $AllApps.InstalledApps) {
        # Check if this app should be removed
        if (Test-AppShouldBeRemoved -AppName $App.Name) {
            try {
                if ($WhatIf) {
                    Write-Host "WhatIf: Would remove installed app: $($App.Name)" -ForegroundColor Cyan
                    $RemovedApps += "Installed: $($App.Name) (WhatIf)"
                } else {
                    Write-Host "Removing installed app: $($App.Name)"
                    Remove-AppxPackage -Package $App.PackageFullName -ErrorAction Stop | Out-Null
                    $RemovedApps += "Installed: $($App.Name)"
                }
            } catch {
                Write-Warning "Failed to remove installed app $($App.Name): $_"
                $FailedRemovals += "Installed: $($App.Name)"
            }
        } else {
            Write-Host "Keeping installed app: $($App.Name)"
        }
    }

    return [PSCustomObject]@{
        RemovedApps    = $RemovedApps
        FailedRemovals = $FailedRemovals
    }
}

try {
    $ModeDescription = if ($Mode -eq "Exclusion") { "will be removed" } else { "will be kept" }
    Write-Host "Running in $Mode mode: Apps in the configured list $ModeDescription."

    # Check if AppList is empty
    if ($AppList.Count -eq 0) {
        if ($Mode -eq "Exclusion") {
            Write-Host "`No apps configured for removal in exclusion list - no action needed."
            exit 0
        } else {
            Write-Host "`No apps configured in inclusion list - will remove all non-critical apps!"
        }
    }# Remove non-compliant apps
    $RemovalResult = Remove-NonCompliantApps -WhatIf:$WhatIf

    # Report results
    if ($RemovalResult.RemovedApps.Count -gt 0) {
        Write-Host "`nSuccessfully removed $($RemovalResult.RemovedApps.Count) app(s):"
        $RemovalResult.RemovedApps | ForEach-Object { Write-Host "- $_" }
    } else {
        Write-Host "`nNo apps were removed."
    }

    if ($RemovalResult.FailedRemovals.Count -gt 0) {
        Write-Warning "`nFailed to remove $($RemovalResult.FailedRemovals.Count) app(s):"
        $RemovalResult.FailedRemovals | ForEach-Object { Write-Warning "- $_" }

        # Exit with error if any removals failed
        Write-Error "Some app removals failed. Check the warnings for details."
        exit 1
    }

    Write-Host "`nApp removal completed successfully."
    exit 0
} catch {
    $errMsg = $_.Exception.Message
    Write-Error "Error removing apps: $errMsg"
    exit 1
}
