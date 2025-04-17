<#
.SYNOPSIS
    Configures Remote Desktop Protocol (RDP) settings to comply with security requirements.

.DESCRIPTION
    This script enables or disables RDP and configures security settings:
    - RDP Service Status (TermService)
    - Firewall Rules for RDP
    - Network Level Authentication requirement
    - RDP Registry Settings

.PARAMETER WhatIf
    Shows what would happen if the script runs. No settings are changed.

.NOTES
    Version: 1.0
    Author: Intune Administrator

    References:
    - https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access
    - https://learn.microsoft.com/en-us/windows/win32/termserv/terminal-services-registry-settings

.EXAMPLE
    .\Remediate-RDPSettings.ps1
    Configures RDP settings based on policy requirements.

.EXAMPLE
    .\Remediate-RDPSettings.ps1 -WhatIf
    Shows what settings would be changed without making actual changes.

.LINK
    https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/
#>

# Configuration settings - modify these values as needed
$WhatIf = $false
$EnableRDP = $false           # Set to $false to ensure RDP is disabled
$RequireNLA = $true         # Require Network Level Authentication
$AllowOnlySecureConnections = $true  # Allow only connections with Network Level Authentication

# Registry paths
$RDPPath = "HKLM:\System\CurrentControlSet\Control\Terminal Server"
$NLAPath = "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"

function Get-RDPSettings {
    <#
    .DESCRIPTION
        Gets current RDP settings from registry and services
    .OUTPUTS
        PSObject with current RDP settings
    #>

    $RDPService = Get-Service -Name "TermService" -ErrorAction SilentlyContinue
    $fDenyTSConnections = (Get-ItemProperty -Path $RDPPath -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections
    $UserAuthentication = (Get-ItemProperty -Path $NLAPath -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication
    $SecurityLayer = (Get-ItemProperty -Path $NLAPath -Name "SecurityLayer" -ErrorAction SilentlyContinue).SecurityLayer

    # Get firewall rules
    $FWRules = Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue |
    Where-Object { $_.Direction -eq "Inbound" } |
    Select-Object -Property DisplayName, Enabled

    [PSCustomObject]@{
        ServiceEnabled       = $RDPService.Status -eq 'Running'
        ServiceStartType     = $RDPService.StartType
        RDPEnabled           = $fDenyTSConnections -eq 0
        NLAEnabled           = $UserAuthentication -eq 1
        SecurityLayer        = $SecurityLayer
        FirewallRulesEnabled = $FWRules.Enabled -contains $true
    }
}

function Set-RDPSettings {
    <#
    .DESCRIPTION
        Configures RDP settings according to policy
    .PARAMETER WhatIf
        If specified, shows what settings would be changed without making changes
    .OUTPUTS
        PSObject with results of the configuration changes
    #>
    param (
        [Parameter(Mandatory = $false)]
        [switch]$WhatIf
    )

    $ChangedSettings = @()
    $FailedSettings = @()
    $CurrentSettings = Get-RDPSettings

    # Configure RDP Service
    try {
        if ($EnableRDP) {
            if ($CurrentSettings.ServiceStartType -ne 'Automatic') {
                if ($WhatIf) {
                    Write-Host "WhatIf: Would set RDP service (TermService) to Automatic startup" -ForegroundColor Cyan
                } else {
                    Set-Service -Name "TermService" -StartupType Automatic
                }
                $ChangedSettings += "Set RDP service to Automatic startup"
            }
            if (-not $CurrentSettings.ServiceEnabled) {
                if ($WhatIf) {
                    Write-Host "WhatIf: Would start RDP service (TermService)" -ForegroundColor Cyan
                } else {
                    Start-Service -Name "TermService"
                }
                $ChangedSettings += "Started RDP service"
            }
        } else {
            if ($CurrentSettings.ServiceEnabled) {
                if ($WhatIf) {
                    Write-Host "WhatIf: Would stop RDP service (TermService)" -ForegroundColor Cyan
                } else {
                    Stop-Service -Name "TermService" -Force
                }
                $ChangedSettings += "Stopped RDP service"
            }
            if ($CurrentSettings.ServiceStartType -ne 'Disabled') {
                if ($WhatIf) {
                    Write-Host "WhatIf: Would disable RDP service (TermService)" -ForegroundColor Cyan
                } else {
                    Set-Service -Name "TermService" -StartupType Disabled
                }
                $ChangedSettings += "Disabled RDP service"
            }
        }
    } catch {
        $FailedSettings += "Failed to configure RDP service: $_"
    }

    # Configure Registry Settings
    try {
        if ($EnableRDP) {
            if ($CurrentSettings.RDPEnabled -eq $false) {
                if ($WhatIf) {
                    Write-Host "WhatIf: Would enable RDP in registry" -ForegroundColor Cyan
                } else {
                    Set-ItemProperty -Path $RDPPath -Name "fDenyTSConnections" -Value 0
                }
                $ChangedSettings += "Enabled RDP in registry"
            }

            # Configure NLA if RDP is enabled
            if ($RequireNLA -and -not $CurrentSettings.NLAEnabled) {
                if ($WhatIf) {
                    Write-Host "WhatIf: Would enable Network Level Authentication" -ForegroundColor Cyan
                } else {
                    Set-ItemProperty -Path $NLAPath -Name "UserAuthentication" -Value 1
                }
                $ChangedSettings += "Enabled Network Level Authentication"
            }

            if ($AllowOnlySecureConnections -and $CurrentSettings.SecurityLayer -ne 2) {
                if ($WhatIf) {
                    Write-Host "WhatIf: Would set Security Layer to require encryption" -ForegroundColor Cyan
                } else {
                    Set-ItemProperty -Path $NLAPath -Name "SecurityLayer" -Value 2
                }
                $ChangedSettings += "Set Security Layer to require encryption"
            }
        } else {
            if ($CurrentSettings.RDPEnabled -eq $true) {
                if ($WhatIf) {
                    Write-Host "WhatIf: Would disable RDP in registry" -ForegroundColor Cyan
                } else {
                    Set-ItemProperty -Path $RDPPath -Name "fDenyTSConnections" -Value 1
                }
                $ChangedSettings += "Disabled RDP in registry"
            }
        }
    } catch {
        $FailedSettings += "Failed to configure registry settings: $_"
    }

    # Configure Firewall Rules
    try {
        $FWRules = Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction Stop |
        Where-Object { $_.Direction -eq "Inbound" }

        foreach ($Rule in $FWRules) {
            if ($EnableRDP -and -not $Rule.Enabled) {
                if ($WhatIf) {
                    Write-Host "WhatIf: Would enable firewall rule: $($Rule.DisplayName)" -ForegroundColor Cyan
                } else {
                    Enable-NetFirewallRule -Name $Rule.Name
                }
                $ChangedSettings += "Enabled firewall rule: $($Rule.DisplayName)"
            } elseif (-not $EnableRDP -and $Rule.Enabled) {
                if ($WhatIf) {
                    Write-Host "WhatIf: Would disable firewall rule: $($Rule.DisplayName)" -ForegroundColor Cyan
                } else {
                    Disable-NetFirewallRule -Name $Rule.Name
                }
                $ChangedSettings += "Disabled firewall rule: $($Rule.DisplayName)"
            }
        }
    } catch {
        $FailedSettings += "Failed to configure firewall rules: $_"
    }

    [PSCustomObject]@{
        ChangedSettings = $ChangedSettings
        FailedSettings  = $FailedSettings
    }
}

try {
    $RequiredState = if ($EnableRDP) { "enable" } else { "disable" }
    Write-Host "Attempting to $RequiredState RDP with required security settings..."

    # Apply RDP settings
    $Result = Set-RDPSettings -WhatIf:$WhatIf

    # Report results
    if ($Result.ChangedSettings.Count -gt 0) {
        Write-Host "`nSuccessfully changed the following settings:"
        $Result.ChangedSettings | ForEach-Object { Write-Host "- $_" }
    } else {
        Write-Host "`nNo settings needed to be changed."
    }

    if ($Result.FailedSettings.Count -gt 0) {
        Write-Warning "`nFailed to apply some settings:"
        $Result.FailedSettings | ForEach-Object { Write-Warning "- $_" }
        exit 1
    }

    Write-Host "`nRDP configuration completed successfully."
    exit 0
} catch {
    $errMsg = $_.Exception.Message
    Write-Error "Error configuring RDP settings: $errMsg"
    exit 1
}
