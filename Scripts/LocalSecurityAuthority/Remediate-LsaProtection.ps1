<#
.SYNOPSIS
    Enables Local Security Authority (LSA) protection.

.DESCRIPTION
    This script enables LSA protection by setting the RunAsPPL registry value to 1.
    LSA protection helps prevent credential theft by protecting the LSA process from code injection
    and other attacks that attempt to extract credentials from memory.

.NOTES
    Version: 1.0
    Author: Intune Administrator
    Last Updated: 2023-11-28

    This setting requires a reboot to take effect.

    References:
    - https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection
    - https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group

.EXAMPLE
    .\Remediate-LsaProtection.ps1
    Sets the RunAsPPL registry value to 1, enabling LSA protection.

.LINK
    https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection
#>

$Key = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$Name = "RunAsPPL"

# The value we are expecting
[System.Int32] $Value = 1

Write-Host "Enabling LSA Protection by setting registry value $Name to $Value..."

# Set the current value
try {
    $params = @{
        Path        = $Key
        Name        = $Name
        Value       = $Value
        Force       = $true
        ErrorAction = "Stop"
    }
    Set-ItemProperty @params | Out-Null
    Write-Host "Registry value set successfully."
} catch {
    $errorMessage = $_.Exception.Message
    Write-Error "Failed to set registry value: $errorMessage"
    exit 1
}

# Verify the value was set correctly
$params = @{
    Path = $Key
    Name = $Name
}
$Property = Get-ItemProperty @params
if ($Property.$Name -eq $Value) {
    Write-Host "LSA Protection has been enabled. A reboot is required for this setting to take effect."
    exit 0
} else {
    Write-Error "Failed to verify registry value was set correctly. Current value: $($Property.$Name)"
    exit 1
}
