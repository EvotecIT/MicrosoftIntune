<#
.SYNOPSIS
    Detects if storage of passwords and credentials for network authentication is disabled.

.DESCRIPTION
    This script checks if the "Network access: Do not allow storage of passwords and credentials for network authentication"
    security policy is enabled by verifying the DisableDomainCreds registry value.

    When this setting is enabled, Credential Manager does not save passwords or credentials for later use when a user
    connects to a network resource, enhancing security by preventing credential caching.

.NOTES
    Version: 1.0
    Author: Intune Administrator
    Last Updated: 2023-11-28

    References:
    - https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-do-not-allow-storage-of-passwords-and-credentials-for-network-authentication
    - https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.CredentialsUI::DisallowSavingPassword

.EXAMPLE
    .\Detect-DisableDomainCreds.ps1
    Returns exit code 0 if credential storage is disabled, 1 if it is not.

.LINK
    https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-do-not-allow-storage-of-passwords-and-credentials-for-network-authentication
#>

$Key = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$Name = "DisableDomainCreds"

# The value we are expecting
[System.Int32] $Value = 1

# Get the current value
try {
    $params = @{
        Path        = $Key
        Name        = $Name
        ErrorAction = "SilentlyContinue"
    }
    $Property = Get-ItemProperty @params
} catch {
    throw [System.Management.Automation.ItemNotFoundException] "Failed to retrieve value for $Name with $($_.Exception.Message)"
}

if ($Property.$Name -eq $Value) {
    Write-Host "Storage of passwords and credentials for network authentication is disabled."
    exit 0
} else {
    Write-Host "Storage of passwords and credentials for network authentication is NOT disabled."
    if ($null -eq $Property.$Name) {
        Write-Host "The registry value $Name is not present."
    } else {
        Write-Host "The registry value $Name is set to $($Property.$Name)."
    }
    exit 1
}
