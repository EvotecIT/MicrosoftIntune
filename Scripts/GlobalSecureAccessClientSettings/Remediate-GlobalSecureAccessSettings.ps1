<#
.SYNOPSIS
    Configures Global Secure Access client settings to comply with policy.

.DESCRIPTION
    This script configures documented Microsoft Global Secure Access client
    registry values, optional IPv4 preference, and optional browser mitigations
    for Microsoft Entra Internet Access.

.PARAMETER WhatIf
    Shows what would happen if the script runs. No settings are changed.

.NOTES
    Version: 1.0
    Author: Intune Administrator

    References:
    - https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-install-windows-client
    - https://learn.microsoft.com/en-us/deployedge/microsoft-edge-browser-policies/quicallowed
    - https://learn.microsoft.com/en-us/deployedge/microsoft-edge-browser-policies/dnsoverhttpsmode

.EXAMPLE
    .\Remediate-GlobalSecureAccessSettings.ps1
    Configures Global Secure Access settings based on policy requirements.

.EXAMPLE
    Set $WhatIf = $true and run the script.
    Shows what settings would be changed without making actual changes.
.LINK
    https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-install-windows-client
#>

# Configuration settings - keep these aligned with the detection script
$WhatIf = $false

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
$IPv6ParametersPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
$IPv6DisabledComponentsName = "DisabledComponents"
$IPv4PreferredValue = 0x20
$EdgePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
$ChromePolicyPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
$FirefoxDistributionPath = Join-Path -Path $NativeProgramFiles -ChildPath "Mozilla Firefox\distribution"
$FirefoxPolicyPath = Join-Path -Path $FirefoxDistributionPath -ChildPath "policies.json"
$FirefoxExecutablePath = Join-Path -Path $NativeProgramFiles -ChildPath "Mozilla Firefox\firefox.exe"

function Set-RegistryValue {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [object]$Value,

        [Parameter(Mandatory = $true)]
        [ValidateSet("DWord", "String")]
        [string]$PropertyType
    )

    if (-not (Test-Path -Path $Path)) {
        if ($WhatIf) {
            Write-Host "WhatIf: Would create registry key $Path" -ForegroundColor Cyan
        } else {
            New-Item -Path $Path -Force | Out-Null
        }
    }

    $ExpectedKind = switch ($PropertyType) {
        "DWord" { [Microsoft.Win32.RegistryValueKind]::DWord }
        "String" { [Microsoft.Win32.RegistryValueKind]::String }
    }
    $ExistingValue = $null
    $ExistingKind = $null
    $Exists = $false
    try {
        $ExistingValue = Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction Stop
        $ExistingKind = (Get-Item -Path $Path -ErrorAction Stop).GetValueKind($Name)
        $Exists = $true
    } catch {
        $Exists = $false
    }

    if ($Exists -and $ExistingValue -eq $Value -and $ExistingKind -eq $ExpectedKind) {
        return $false
    }

    if ($WhatIf) {
        if ($Exists -and $ExistingKind -ne $ExpectedKind) {
            Write-Host "WhatIf: Would replace $Path\$Name with $PropertyType value $Value" -ForegroundColor Cyan
        } else {
            Write-Host "WhatIf: Would set $Path\$Name to $Value as $PropertyType" -ForegroundColor Cyan
        }
        return $true
    }

    if ($Exists -and $ExistingKind -ne $ExpectedKind) {
        Remove-ItemProperty -Path $Path -Name $Name -Force
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType -Force | Out-Null
    } elseif ($Exists) {
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force
    } else {
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType -Force | Out-Null
    }

    return $true
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

function Set-FirefoxPreference {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$Preferences,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [object]$Value
    )

    $NeedsChange = $true
    if ($Preferences.ContainsKey($Name)) {
        $CurrentPreference = $Preferences[$Name]
        if ($CurrentPreference.Value -eq $Value -and $CurrentPreference.Status -eq "locked") {
            $NeedsChange = $false
        }
    }

    if ($NeedsChange) {
        $Preferences[$Name] = @{
            Value  = $Value
            Status = "locked"
        }
    }

    return $NeedsChange
}

function Set-FirefoxPolicy {
    $FirefoxInstalled = Test-Path -Path $FirefoxExecutablePath
    if (-not $FirefoxInstalled -and -not $ApplyFirefoxPolicyWhenFirefoxMissing) {
        Write-Host "Firefox is not installed. Skipping Firefox policy remediation."
        return $false
    }

    $ExistingJson = $null
    if (Test-Path -Path $FirefoxPolicyPath) {
        try {
            $ExistingJson = Get-Content -Path $FirefoxPolicyPath -Raw | ConvertFrom-Json
        } catch {
            Write-Warning "Existing Firefox policies.json is malformed. Starting with a clean policy object."
        }
    }

    $Policies = ConvertTo-Hashtable -InputObject $ExistingJson
    if (-not $Policies.ContainsKey("policies")) {
        $Policies["policies"] = @{}
    }

    if (-not $Policies["policies"].ContainsKey("Preferences")) {
        $Policies["policies"]["Preferences"] = @{}
    }

    $Preferences = $Policies["policies"]["Preferences"]
    $Updated = $false

    if ($DisableFirefoxQuic) {
        if (Set-FirefoxPreference -Preferences $Preferences -Name "network.http.http3.enable" -Value $false) {
            $Updated = $true
        }
    }

    if ($DisableFirefoxDnsOverHttps) {
        if (Set-FirefoxPreference -Preferences $Preferences -Name "network.trr.mode" -Value 0) {
            $Updated = $true
        }
    }

    if (-not $Updated) {
        return $false
    }

    if ($WhatIf) {
        Write-Host "WhatIf: Would update Firefox policies at $FirefoxPolicyPath" -ForegroundColor Cyan
        return $true
    }

    if (-not (Test-Path -Path $FirefoxDistributionPath)) {
        New-Item -Path $FirefoxDistributionPath -ItemType Directory -Force | Out-Null
    }

    if (Test-Path -Path $FirefoxPolicyPath) {
        Copy-Item -Path $FirefoxPolicyPath -Destination "$FirefoxPolicyPath.bak" -Force
    }

    $JsonOut = $Policies | ConvertTo-Json -Depth 10
    $Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($FirefoxPolicyPath, $JsonOut, $Utf8NoBomEncoding)

    return $true
}

function Set-GlobalSecureAccessSettings {
    $ChangedSettings = @()
    $FailedSettings = @()

    foreach ($Setting in $GsaMachineSettings.GetEnumerator()) {
        try {
            if (Set-RegistryValue -Path $GsaMachinePath -Name $Setting.Key -Value $Setting.Value -PropertyType DWord) {
                $ChangedSettings += "Set GSA machine setting $($Setting.Key) to $($Setting.Value)"
            }
        } catch {
            $FailedSettings += "Failed to set GSA machine setting $($Setting.Key): $_"
        }
    }

    if ($ConfigureIPv4Preference) {
        try {
            $ExpectedIPv6Value = if ($PreferIPv4OverIPv6) { $IPv4PreferredValue } else { 0 }
            if (Set-RegistryValue -Path $IPv6ParametersPath -Name $IPv6DisabledComponentsName -Value $ExpectedIPv6Value -PropertyType DWord) {
                $ChangedSettings += "Set IPv4 preference registry value to $ExpectedIPv6Value"
            }
        } catch {
            $FailedSettings += "Failed to configure IPv4 preference: $_"
        }
    }

    if ($ConfigurePrivateAccessForUsers) {
        try {
            $ExpectedPrivateAccessValue = if ($DisablePrivateAccessForUser) { 1 } else { 0 }
            $UserTargets = Get-UserRegistryTargets

            if ($UserTargets.Count -eq 0) {
                Write-Host "No loaded user registry hives were found for Private Access policy remediation. Skipping user-scoped setting."
            }

            foreach ($Target in $UserTargets) {
                if (Set-RegistryValue -Path $Target -Name "IsPrivateAccessDisabledByUser" -Value $ExpectedPrivateAccessValue -PropertyType DWord) {
                    $ChangedSettings += "Set Private Access user setting for $Target to $ExpectedPrivateAccessValue"
                }
            }
        } catch {
            $FailedSettings += "Failed to configure Private Access user setting: $_"
        }
    }

    if ($ConfigureBrowserTrafficControls) {
        try {
            if ($DisableEdgeQuic -and (Set-RegistryValue -Path $EdgePolicyPath -Name "QuicAllowed" -Value 0 -PropertyType DWord)) {
                $ChangedSettings += "Disabled QUIC in Microsoft Edge"
            }

            if ($DisableEdgeDnsOverHttps -and (Set-RegistryValue -Path $EdgePolicyPath -Name "DnsOverHttpsMode" -Value "off" -PropertyType String)) {
                $ChangedSettings += "Disabled DNS over HTTPS in Microsoft Edge"
            }

            if ($DisableChromeQuic -and (Set-RegistryValue -Path $ChromePolicyPath -Name "QuicAllowed" -Value 0 -PropertyType DWord)) {
                $ChangedSettings += "Disabled QUIC in Google Chrome"
            }

            if ($DisableChromeDnsOverHttps -and (Set-RegistryValue -Path $ChromePolicyPath -Name "DnsOverHttpsMode" -Value "off" -PropertyType String)) {
                $ChangedSettings += "Disabled DNS over HTTPS in Google Chrome"
            }
        } catch {
            $FailedSettings += "Failed to configure Edge or Chrome browser policy: $_"
        }

        try {
            if (($DisableFirefoxQuic -or $DisableFirefoxDnsOverHttps) -and (Set-FirefoxPolicy)) {
                $ChangedSettings += "Updated Firefox policies.json for QUIC/DNS over HTTPS"
            }
        } catch {
            $FailedSettings += "Failed to configure Firefox policy: $_"
        }
    }

    return [PSCustomObject]@{
        ChangedSettings = $ChangedSettings
        FailedSettings  = $FailedSettings
    }
}

try {
    Write-Host "Configuring Global Secure Access client settings..."

    $Result = Set-GlobalSecureAccessSettings

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

    Write-Host "`nGlobal Secure Access configuration completed successfully."
    exit 0
} catch {
    $errMsg = $_.Exception.Message
    Write-Error "Error configuring Global Secure Access settings: $errMsg"
    exit 1
}
