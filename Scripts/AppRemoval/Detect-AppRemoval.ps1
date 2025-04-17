<#
.SYNOPSIS
    Detects if specified Windows apps are present on the device.

.DESCRIPTION
    This script checks if specified Windows apps are installed on the device
    and determines compliance based on inclusion and exclusion lists.

    The script can operate in two modes:
    - Inclusion Mode: Only listed apps should be present, all others should be removed
    - Exclusion Mode: Listed apps should be removed, all others can remain

.NOTES
    Version: 1.0
    Author: Intune Administrator

    References:
    - https://learn.microsoft.com/en-us/powershell/module/appx/get-appxpackage
    - https://learn.microsoft.com/en-us/powershell/module/appx/get-appxprovisionedpackage

.EXAMPLE
    .\Detect-AppRemoval.ps1
    Returns exit code 0 if app state complies with policy, 1 if not.

.LINK
    https://learn.microsoft.com/en-us/powershell/module/appx
#>

# Configuration settings - modify these values as needed
$Mode = "Inclusion" # "Inclusion" or "Exclusion"

# Apps to keep or remove depending on mode
# For Inclusion mode: only these apps are allowed to be present
# For Exclusion mode: these apps should be removed
$AppList = @(
    # Uncomment and modify the apps list as needed
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

# Critical apps that should never be removed (only used in Inclusion mode)
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
        Array of installed app names
    #>

    # Get provisioned packages (installed for all users)
    $ProvisionedApps = Get-AppxProvisionedPackage -Online | Select-Object -ExpandProperty DisplayName

    # Get installed packages for current user
    $InstalledApps = Get-AppxPackage | Select-Object -ExpandProperty Name

    # Combine both lists and remove duplicates
    $AllApps = $ProvisionedApps + $InstalledApps | Select-Object -Unique

    return $AllApps
}

function Test-AppCompliance {
    <#
    .DESCRIPTION
        Tests if installed apps comply with the configured policy
    .OUTPUTS
        PSObject with compliance status, compliant and non-compliant apps with detailed status
    #>

    $InstalledApps = Get-InstalledApps
    $NonCompliantApps = @()
    $CompliantApps = @()
    $IsCompliant = $true

    foreach ($App in $InstalledApps) {
        $IsCritical = $false
        $IsInList = $false
        $Status = ""

        # First check if app is critical
        foreach ($CriticalApp in $CriticalApps) {
            if ($App -like $CriticalApp) {
                $IsCritical = $true
                $Status = "Critical system app - always kept"
                break
            }
        }

        # Then check if app is in the main list
        foreach ($ListedApp in $AppList) {
            if ($App -like $ListedApp) {
                $IsInList = $true
                break
            }
        }

        if ($Mode -eq "Exclusion") {
            if ($IsCritical) {
                $CompliantApps += [PSCustomObject]@{
                    Name   = $App
                    Status = $Status
                }
            } elseif ($IsInList) {
                $NonCompliantApps += [PSCustomObject]@{
                    Name   = $App
                    Status = "Non-compliant: App is in exclusion list and should be removed"
                }
                $IsCompliant = $false
            } else {
                $CompliantApps += [PSCustomObject]@{
                    Name   = $App
                    Status = "Not in exclusion list - allowed to remain"
                }
            }
        } else {
            # Inclusion mode
            if ($IsCritical) {
                $CompliantApps += [PSCustomObject]@{
                    Name   = $App
                    Status = $Status
                }
            } elseif ($IsInList) {
                $CompliantApps += [PSCustomObject]@{
                    Name   = $App
                    Status = "In inclusion list - allowed to remain"
                }
            } else {
                $NonCompliantApps += [PSCustomObject]@{
                    Name   = $App
                    Status = "Non-compliant: App not in inclusion list and should be removed"
                }
                $IsCompliant = $false
            }
        }
    }

    return [PSCustomObject]@{
        IsCompliant      = $IsCompliant
        CompliantApps    = $CompliantApps
        NonCompliantApps = $NonCompliantApps
    }
}

try {
    $ModeDescription = if ($Mode -eq "Exclusion") { "should be removed" } else { "are allowed" }
    Write-Host "Running in $Mode mode: Apps in the configured list $ModeDescription."

    $ComplianceResult = Test-AppCompliance Write-Host "`nDetailed App Compliance Report:"
    Write-Host "--------------------------------"

    if ($ComplianceResult.CompliantApps.Count -gt 0) {
        Write-Host "`nCompliant Apps:" -ForegroundColor Green
        $ComplianceResult.CompliantApps | ForEach-Object {
            Write-Host "V $($_.Name)" -ForegroundColor Green
            Write-Host "  $($_.Status)" -ForegroundColor DarkGray
        }
    }

    if ($ComplianceResult.NonCompliantApps.Count -gt 0) {
        Write-Host "`nNon-Compliant Apps:" -ForegroundColor Red
        $ComplianceResult.NonCompliantApps | ForEach-Object {
            Write-Host "X $($_.Name)" -ForegroundColor Red
            Write-Host "  $($_.Status)" -ForegroundColor DarkGray
        }
    }

    Write-Host "`nSummary:"
    Write-Host "--------"
    Write-Host "Total Apps: $($ComplianceResult.CompliantApps.Count + $ComplianceResult.NonCompliantApps.Count)"
    Write-Host "Compliant Apps: $($ComplianceResult.CompliantApps.Count)" -ForegroundColor Green
    Write-Host "Non-Compliant Apps: $($ComplianceResult.NonCompliantApps.Count)" -ForegroundColor Red

    if ($ComplianceResult.IsCompliant) {
        Write-Host "`nOverall Status: COMPLIANT" -ForegroundColor Green
        exit 0
    } else {
        Write-Host "`nOverall Status: NON-COMPLIANT" -ForegroundColor Red
        exit 1
    }
} catch {
    $errMsg = $_.Exception.Message
    Write-Error $errMsg
    exit 1
}
