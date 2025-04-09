<#
.SYNOPSIS
    Disables storage of passwords and credentials for network authentication.

.DESCRIPTION
    This script enables the "Network access: Do not allow storage of passwords and credentials for network authentication"
    security policy by setting the DisableDomainCreds registry value to 1.

    When this setting is enabled, Credential Manager does not save passwords or credentials for later use when a user
    connects to a network resource, enhancing security by preventing credential caching.

    This script detects & fixes: Disable the local storage of passwords and credentials in Secure Score
.NOTES
    Version: 1.0
    Author: Intune Administrator

    This setting takes effect immediately and does not require a reboot.

    References:
    - https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-do-not-allow-storage-of-passwords-and-credentials-for-network-authentication
    - https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.CredentialsUI::DisallowSavingPassword

.EXAMPLE
    .\Remediate-DisableDomainCreds.ps1
    Sets the DisableDomainCreds registry value to 1, disabling storage of credentials.

.LINK
    https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-do-not-allow-storage-of-passwords-and-credentials-for-network-authentication
#>

$Key = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$Name = "DisableDomainCreds"

# The value we are expecting
[System.Int32] $Value = 1

Write-Host "Disabling storage of passwords and credentials for network authentication..."

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
    Write-Host "Storage of passwords and credentials for network authentication has been disabled."
    exit 0
} else {
    Write-Error "Failed to verify registry value was set correctly. Current value: $($Property.$Name)"
    exit 1
}
