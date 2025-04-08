<#
.SYNOPSIS
    Detects if Local Security Authority (LSA) protection is enabled.

.DESCRIPTION
    This script checks if LSA protection is enabled by verifying the RunAsPPL registry value.
    LSA protection helps prevent credential theft by protecting the LSA process from code injection
    and other attacks that attempt to extract credentials from memory.

.NOTES
    Version: 1.0
    Author: Intune Administrator
    Last Updated: 2023-11-28

    References:
    - https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection
    - https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group

.EXAMPLE
    .\Detect-LsaProtection.ps1
    Returns exit code 0 if LSA protection is enabled, 1 if it is not.

.LINK
    https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection
#>

$Key = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$Name = "RunAsPPL"

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
    Write-Host "LSA Protection is enabled. Registry value $Name is set to $Value."
    exit 0
} else {
    Write-Host "LSA Protection is not enabled. Registry value $Name is not set to $Value."
    if ($null -eq $Property.$Name) {
        Write-Host "The registry value $Name is not present."
    } else {
        Write-Host "The registry value $Name is set to $($Property.$Name)."
    }
    exit 1
}
