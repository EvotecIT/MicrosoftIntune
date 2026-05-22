<#
.SYNOPSIS
    Detects if Global Secure Access client settings comply with policy.

.DESCRIPTION
    This script checks the Microsoft Global Secure Access client install state,
    documented client registry values, optional IPv4 preference, and optional
    browser mitigations for Microsoft Entra Internet Access.

.NOTES
    Version: 1.0
    Author: Intune Administrator

    References:
    - https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-install-windows-client
    - https://learn.microsoft.com/en-us/deployedge/microsoft-edge-browser-policies/quicallowed
    - https://learn.microsoft.com/en-us/deployedge/microsoft-edge-browser-policies/dnsoverhttpsmode

.EXAMPLE
    .\Detect-GlobalSecureAccessSettings.ps1
    Returns exit code 0 if settings are compliant, 1 if not.
.LINK
    https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-install-windows-client
#>

# Configuration settings - keep these aligned with the remediation script
$RequireClientInstalled = $false
$MinimumClientVersion = "" # Leave empty to accept any installed version

$ConfigureIPv4Preference = $true
$PreferIPv4OverIPv6 = $true

$GsaMachineSettings = @{
    "HideSignOutButton"                = 1
    "HideDisablePrivateAccessButton"   = 1
    "HideDisableButton"                = 1
    "RestrictNonPrivilegedUsers"       = 1
}

# Optional per-user setting from Microsoft docs.
# Scope can be "CurrentUser" or "LoadedUsers". Use LoadedUsers when running as SYSTEM.
$ConfigurePrivateAccessForUsers = $false
$PrivateAccessScope = "LoadedUsers"
$DisablePrivateAccessForUser = $false

# Microsoft Entra Internet Access does not support DoH or QUIC traffic.
$ConfigureBrowserTrafficControls = $true
$DisableEdgeQuic = $true
$DisableEdgeDnsOverHttps = $true
$DisableChromeQuic = $true
$DisableChromeDnsOverHttps = $true
$DisableFirefoxQuic = $true
$DisableFirefoxDnsOverHttps = $true
$ApplyFirefoxPolicyWhenFirefoxMissing = $false

$NativeProgramFiles = if ([Environment]::Is64BitOperatingSystem -and -not [string]::IsNullOrWhiteSpace($env:ProgramW6432)) {
    $env:ProgramW6432
} else {
    $env:ProgramFiles
}

$GsaMachinePath = "HKLM:\SOFTWARE\Microsoft\Global Secure Access Client"
$GsaUserSubPath = "Software\Microsoft\Global Secure Access Client"
$ClientExecutablePath = Join-Path -Path $NativeProgramFiles -ChildPath "Global Secure Access Client\TrayApp\GlobalSecureAccessClient.exe"
$IPv6ParametersPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
$IPv6DisabledComponentsName = "DisabledComponents"
$IPv4PreferredValue = 0x20
$EdgePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
$ChromePolicyPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
$FirefoxPolicyPath = Join-Path -Path $NativeProgramFiles -ChildPath "Mozilla Firefox\distribution\policies.json"
$FirefoxExecutablePath = Join-Path -Path $NativeProgramFiles -ChildPath "Mozilla Firefox\firefox.exe"

function Get-RegistryValue {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    try {
        $Value = Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction Stop
        return [PSCustomObject]@{
            Exists = $true
            Value  = $Value
        }
    } catch {
        return [PSCustomObject]@{
            Exists = $false
            Value  = $null
        }
    }
}

function Test-RegistryValue {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [object]$ExpectedValue,

        [Parameter(Mandatory = $true)]
        [ValidateSet("DWord", "String")]
        [string]$PropertyType
    )

    $Current = Get-RegistryValue -Path $Path -Name $Name
    $ExpectedKind = switch ($PropertyType) {
        "DWord" { [Microsoft.Win32.RegistryValueKind]::DWord }
        "String" { [Microsoft.Win32.RegistryValueKind]::String }
    }

    if (-not $Current.Exists -or $Current.Value -ne $ExpectedValue) {
        return "Registry value $Path\$Name is '$($Current.Value)', expected '$ExpectedValue'"
    }

    $CurrentKind = $null
    try {
        $CurrentKind = (Get-Item -Path $Path -ErrorAction Stop).GetValueKind($Name)
    } catch {
        return "Registry value $Path\$Name type could not be read, expected '$ExpectedKind'"
    }

    if ($CurrentKind -ne $ExpectedKind) {
        return "Registry value $Path\$Name type is '$CurrentKind', expected '$ExpectedKind'"
    }

    return $null
}

function Test-ClientInstall {
    $Issues = @()

    if (-not $RequireClientInstalled) {
        return $Issues
    }

    if (-not (Test-Path -Path $ClientExecutablePath)) {
        $Issues += "Global Secure Access client executable was not found at $ClientExecutablePath"
        return $Issues
    }

    if (-not [string]::IsNullOrWhiteSpace($MinimumClientVersion)) {
        try {
            $CurrentVersion = [version](Get-Item -Path $ClientExecutablePath).VersionInfo.FileVersion
            if ($CurrentVersion -lt [version]$MinimumClientVersion) {
                $Issues += "Global Secure Access client version is $CurrentVersion, expected at least $MinimumClientVersion"
            }
        } catch {
            $Issues += "Unable to read Global Secure Access client version. $_"
        }
    }

    return $Issues
}

function Get-UserRegistryTargets {
    if ($PrivateAccessScope -eq "CurrentUser") {
        return @("HKCU:\$GsaUserSubPath")
    }

    $Targets = @()
    $LoadedUserSids = Get-ChildItem -Path "Registry::HKEY_USERS" -ErrorAction SilentlyContinue |
        Where-Object {
            ($_.PSChildName -match "^S-1-5-21-" -or $_.PSChildName -match "^S-1-12-1-") -and
            $_.PSChildName -notlike "*_Classes"
        } |
        Select-Object -ExpandProperty PSChildName

    foreach ($Sid in $LoadedUserSids) {
        $Targets += "Registry::HKEY_USERS\$Sid\$GsaUserSubPath"
    }

    return $Targets
}

function ConvertTo-Hashtable {
    param (
        [Parameter(Mandatory = $false)]
        [object]$InputObject
    )

    if ($null -eq $InputObject) {
        return @{}
    }

    if ($InputObject -is [hashtable]) {
        return $InputObject
    }

    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
        $Items = New-Object System.Collections.ArrayList
        foreach ($Item in $InputObject) {
            if ($null -eq $Item -or $Item -is [string] -or $Item.GetType().IsValueType) {
                [void]$Items.Add($Item)
            } else {
                [void]$Items.Add((ConvertTo-Hashtable -InputObject $Item))
            }
        }

        return @($Items.ToArray())
    }

    $Hashtable = @{}
    foreach ($Property in $InputObject.PSObject.Properties) {
        if ($Property.Value -and $Property.Value.PSObject.Properties.Count -gt 0 -and $Property.Value -isnot [string]) {
            $Hashtable[$Property.Name] = ConvertTo-Hashtable -InputObject $Property.Value
        } else {
            $Hashtable[$Property.Name] = $Property.Value
        }
    }

    return $Hashtable
}

function Test-FirefoxPolicy {
    $Issues = @()
    $FirefoxInstalled = Test-Path -Path $FirefoxExecutablePath

    if (-not $FirefoxInstalled -and -not $ApplyFirefoxPolicyWhenFirefoxMissing) {
        Write-Host "Firefox is not installed. Skipping Firefox policy detection."
        return $Issues
    }

    if (-not (Test-Path -Path $FirefoxPolicyPath)) {
        $Issues += "Firefox policies.json was not found at $FirefoxPolicyPath"
        return $Issues
    }

    try {
        $Json = Get-Content -Path $FirefoxPolicyPath -Raw | ConvertFrom-Json
        $Policies = ConvertTo-Hashtable -InputObject $Json
        $Preferences = @{}
        if ($Policies.ContainsKey("policies") -and $Policies["policies"].ContainsKey("Preferences")) {
            $Preferences = $Policies["policies"]["Preferences"]
        }

        if ($DisableFirefoxQuic) {
            if (-not $Preferences.ContainsKey("network.http.http3.enable") -or
                $Preferences["network.http.http3.enable"].Value -ne $false -or
                $Preferences["network.http.http3.enable"].Status -ne "locked") {
                $Issues += "Firefox QUIC policy network.http.http3.enable is not disabled and locked"
            }
        }

        if ($DisableFirefoxDnsOverHttps) {
            if (-not $Preferences.ContainsKey("network.trr.mode") -or
                $Preferences["network.trr.mode"].Value -ne 0 -or
                $Preferences["network.trr.mode"].Status -ne "locked") {
                $Issues += "Firefox DNS over HTTPS policy network.trr.mode is not disabled and locked"
            }
        }
    } catch {
        $Issues += "Unable to parse Firefox policies.json. $_"
    }

    return $Issues
}

function Test-GlobalSecureAccessCompliance {
    $NonCompliantSettings = @()

    $NonCompliantSettings += Test-ClientInstall

    foreach ($Setting in $GsaMachineSettings.GetEnumerator()) {
        $Issue = Test-RegistryValue -Path $GsaMachinePath -Name $Setting.Key -ExpectedValue $Setting.Value -PropertyType DWord
        if ($Issue) {
            $NonCompliantSettings += $Issue
        }
    }

    if ($ConfigureIPv4Preference) {
        $ExpectedIPv6Value = if ($PreferIPv4OverIPv6) { $IPv4PreferredValue } else { 0 }
        $Issue = Test-RegistryValue -Path $IPv6ParametersPath -Name $IPv6DisabledComponentsName -ExpectedValue $ExpectedIPv6Value -PropertyType DWord
        if ($Issue) {
            $NonCompliantSettings += $Issue
        }
    }

    if ($ConfigurePrivateAccessForUsers) {
        $ExpectedPrivateAccessValue = if ($DisablePrivateAccessForUser) { 1 } else { 0 }
        $UserTargets = Get-UserRegistryTargets
        if ($UserTargets.Count -eq 0) {
            Write-Host "No loaded user registry hives were found for Private Access policy detection. Skipping user-scoped check."
        }

        foreach ($Target in $UserTargets) {
            $Issue = Test-RegistryValue -Path $Target -Name "IsPrivateAccessDisabledByUser" -ExpectedValue $ExpectedPrivateAccessValue -PropertyType DWord
            if ($Issue) {
                $NonCompliantSettings += $Issue
            }
        }
    }

    if ($ConfigureBrowserTrafficControls) {
        if ($DisableEdgeQuic) {
            $Issue = Test-RegistryValue -Path $EdgePolicyPath -Name "QuicAllowed" -ExpectedValue 0 -PropertyType DWord
            if ($Issue) { $NonCompliantSettings += $Issue }
        }

        if ($DisableEdgeDnsOverHttps) {
            $Issue = Test-RegistryValue -Path $EdgePolicyPath -Name "DnsOverHttpsMode" -ExpectedValue "off" -PropertyType String
            if ($Issue) { $NonCompliantSettings += $Issue }
        }

        if ($DisableChromeQuic) {
            $Issue = Test-RegistryValue -Path $ChromePolicyPath -Name "QuicAllowed" -ExpectedValue 0 -PropertyType DWord
            if ($Issue) { $NonCompliantSettings += $Issue }
        }

        if ($DisableChromeDnsOverHttps) {
            $Issue = Test-RegistryValue -Path $ChromePolicyPath -Name "DnsOverHttpsMode" -ExpectedValue "off" -PropertyType String
            if ($Issue) { $NonCompliantSettings += $Issue }
        }

        if ($DisableFirefoxQuic -or $DisableFirefoxDnsOverHttps) {
            $NonCompliantSettings += Test-FirefoxPolicy
        }
    }

    return [PSCustomObject]@{
        IsCompliant          = $NonCompliantSettings.Count -eq 0
        NonCompliantSettings = $NonCompliantSettings
    }
}

try {
    Write-Host "Checking Global Secure Access client settings..."

    $ComplianceResult = Test-GlobalSecureAccessCompliance

    if ($ComplianceResult.IsCompliant) {
        Write-Host "Global Secure Access settings are compliant with policy."
        exit 0
    } else {
        Write-Host "Global Secure Access settings are not compliant with policy."
        Write-Host "Non-compliant settings:"
        $ComplianceResult.NonCompliantSettings | ForEach-Object { Write-Host "- $_" }
        exit 1
    }
} catch {
    $errMsg = $_.Exception.Message
    Write-Error "Error checking Global Secure Access settings: $errMsg"
    exit 1
}
