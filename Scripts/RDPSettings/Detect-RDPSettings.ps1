<#
.SYNOPSIS
    Detects if Remote Desktop Protocol (RDP) settings comply with security requirements.

.DESCRIPTION
    This script checks if RDP is enabled/disabled and verifies security settings:
    - RDP Service Status (TermService)
    - Firewall Rules for RDP
    - Network Level Authentication requirement
    - RDP Registry Settings

.NOTES
    Version: 1.0
    Author: Intune Administrator

    References:
    - https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access
    - https://learn.microsoft.com/en-us/windows/win32/termserv/terminal-services-registry-settings

.EXAMPLE
    .\Detect-RDPSettings.ps1
    Returns exit code 0 if RDP settings are compliant, 1 if not.

.LINK
    https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/
#>

# Configuration settings - modify these values as needed
$EnableRDP = $false                   # Set to $false to ensure RDP is disabled
$RequireNLA = $true                  # Require Network Level Authentication
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

function Test-RDPCompliance {
    <#
    .DESCRIPTION
        Tests if RDP settings comply with the configured policy
    .OUTPUTS
        PSObject with compliance status and details
    #>

    $Settings = Get-RDPSettings
    $NonCompliantSettings = @()
    $IsCompliant = $true

    if ($EnableRDP) {
        # Check if RDP should be enabled
        if (-not $Settings.ServiceEnabled) {
            $NonCompliantSettings += "RDP Service is not running"
            $IsCompliant = $false
        }
        if (-not $Settings.RDPEnabled) {
            $NonCompliantSettings += "RDP is not enabled in registry"
            $IsCompliant = $false
        }
        if (-not $Settings.FirewallRulesEnabled) {
            $NonCompliantSettings += "RDP firewall rules are not enabled"
            $IsCompliant = $false
        }

        # Check security settings if RDP is enabled
        if ($RequireNLA -and -not $Settings.NLAEnabled) {
            $NonCompliantSettings += "Network Level Authentication is not enabled"
            $IsCompliant = $false
        }
        if ($AllowOnlySecureConnections -and $Settings.SecurityLayer -ne 2) {
            $NonCompliantSettings += "Security layer is not set to require secure connections"
            $IsCompliant = $false
        }
    } else {
        # Check if RDP should be disabled
        if ($Settings.ServiceEnabled) {
            $NonCompliantSettings += "RDP Service is running but should be disabled"
            $IsCompliant = $false
        }
        if ($Settings.RDPEnabled) {
            $NonCompliantSettings += "RDP is enabled in registry but should be disabled"
            $IsCompliant = $false
        }
        if ($Settings.FirewallRulesEnabled) {
            $NonCompliantSettings += "RDP firewall rules are enabled but should be disabled"
            $IsCompliant = $false
        }
    }

    [PSCustomObject]@{
        IsCompliant          = $IsCompliant
        NonCompliantSettings = $NonCompliantSettings
    }
}

try {
    $RequiredState = if ($EnableRDP) { "enabled" } else { "disabled" }
    Write-Host "Checking if RDP is properly $RequiredState with required security settings..."

    $ComplianceResult = Test-RDPCompliance

    if ($ComplianceResult.IsCompliant) {
        Write-Host "RDP settings are compliant with policy."
        exit 0
    } else {
        Write-Host "RDP settings are not compliant with policy."
        Write-Host "Non-compliant settings:"
        $ComplianceResult.NonCompliantSettings | ForEach-Object { Write-Host "- $_" }
        exit 1
    }
} catch {
    $errMsg = $_.Exception.Message
    Write-Error "Error checking RDP settings: $errMsg"
    exit 1
}
