<#
.SYNOPSIS
    Installs or uninstalls the Microsoft Global Secure Access client.

.DESCRIPTION
    This script installs the Global Secure Access client silently from the
    installer packaged with the script. It can also uninstall the client using
    the same installer command line documented by Microsoft.

    The script can optionally set the Windows IPv4 preference registry value
    before installation. Microsoft includes this setting in their Intune
    installation sample for the Global Secure Access client.

.NOTES
    Version: 1.0
    Author: Intune Administrator

    References:
    - https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-install-windows-client

.EXAMPLE
    .\Install-GlobalSecureAccessClient.ps1
    Installs the Global Secure Access client silently.

.EXAMPLE
    Set $Operation = "Uninstall" and run the script.
    Uninstalls the Global Secure Access client silently.
.LINK
    https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-install-windows-client
#>

# Configuration settings - modify these values as needed
$WhatIf = $false
$Operation = "Install" # "Install" or "Uninstall"

# Put the Microsoft installer in the same folder as this script.
# Windows on Arm devices require the Arm64 client installer from Microsoft.
$InstallerFileNameX64 = "GlobalSecureAccessClient.exe"
$InstallerFileNameArm64 = "GlobalSecureAccessClient-Arm64.exe"

$InstallArguments = "/quiet"
$UninstallArguments = "/uninstall /quiet /norestart"

# Optional version gate. Leave empty to install or upgrade using the packaged installer.
$MinimumClientVersion = ""
$ForceInstall = $false

# Microsoft installation sample sets this to prefer IPv4 over IPv6 traffic.
$ConfigureIPv4Preference = $true
$PreferIPv4OverIPv6 = $true

$LogFile = "$env:ProgramData\GSAInstall\install.log"
$ClientExecutablePath = "$env:ProgramFiles\Global Secure Access Client\TrayApp\GlobalSecureAccessClient.exe"
$IPv6ParametersPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
$IPv6DisabledComponentsName = "DisabledComponents"
$IPv4PreferredValue = 0x20

function Write-GsaLog {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $LogDirectory = Split-Path -Path $LogFile -Parent
    if (-not (Test-Path -Path $LogDirectory)) {
        New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
    }

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFile -Value "$Timestamp - $Message"
    Write-Host $Message
}

function Get-ClientVersion {
    if (-not (Test-Path -Path $ClientExecutablePath)) {
        return $null
    }

    try {
        return [version](Get-Item -Path $ClientExecutablePath).VersionInfo.FileVersion
    } catch {
        Write-GsaLog "Unable to read client version from $ClientExecutablePath. $_"
        return $null
    }
}

function Test-MinimumVersionMet {
    param (
        [Parameter(Mandatory = $false)]
        [string]$MinimumVersion
    )

    if ([string]::IsNullOrWhiteSpace($MinimumVersion)) {
        return $false
    }

    $InstalledVersion = Get-ClientVersion
    if ($null -eq $InstalledVersion) {
        return $false
    }

    return ($InstalledVersion -ge [version]$MinimumVersion)
}

function Get-ProcessorArchitecture {
    if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64" -or $env:PROCESSOR_ARCHITEW6432 -eq "ARM64") {
        return "Arm64"
    }

    return "X64"
}

function Resolve-InstallerPath {
    $ScriptRoot = if ($PSScriptRoot) {
        $PSScriptRoot
    } else {
        Split-Path -Path $MyInvocation.MyCommand.Path -Parent
    }

    $Architecture = Get-ProcessorArchitecture
    if ($Architecture -eq "Arm64") {
        $ArmInstaller = Join-Path -Path $ScriptRoot -ChildPath $InstallerFileNameArm64
        if (Test-Path -Path $ArmInstaller) {
            return $ArmInstaller
        }

        throw "This device is Arm64. Package the Arm64 Global Secure Access installer as $InstallerFileNameArm64. Do not use the standard x64 installer on Arm64 devices."
    }

    $X64Installer = Join-Path -Path $ScriptRoot -ChildPath $InstallerFileNameX64
    if (Test-Path -Path $X64Installer) {
        return $X64Installer
    }

    throw "Installer not found at $X64Installer."
}

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
        New-Item -Path $Path -Force | Out-Null
        Write-GsaLog "Created registry key: $Path"
    }

    $ExistingValue = $null
    $Exists = $false
    try {
        $ExistingValue = Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction Stop
        $Exists = $true
    } catch {
        $Exists = $false
    }

    if ($Exists -and $ExistingValue -eq $Value) {
        Write-GsaLog "Registry value already correct: $Path\$Name = $Value"
        return $false
    }

    if ($WhatIf) {
        Write-GsaLog "WhatIf: Would set $Path\$Name to $Value as $PropertyType"
        return $true
    }

    if ($Exists) {
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force
    } else {
        New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType -Force | Out-Null
    }

    Write-GsaLog "Set registry value: $Path\$Name = $Value"
    return $true
}

function Set-IPv4Preference {
    if (-not $ConfigureIPv4Preference) {
        Write-GsaLog "IPv4 preference configuration is disabled."
        return $false
    }

    $ExpectedValue = if ($PreferIPv4OverIPv6) { $IPv4PreferredValue } else { 0 }
    return Set-RegistryValue -Path $IPv6ParametersPath -Name $IPv6DisabledComponentsName -Value $ExpectedValue -PropertyType DWord
}

function Invoke-Installer {
    param (
        [Parameter(Mandatory = $true)]
        [string]$InstallerPath,

        [Parameter(Mandatory = $true)]
        [string]$Arguments
    )

    if ($WhatIf) {
        Write-GsaLog "WhatIf: Would run $InstallerPath $Arguments"
        return 0
    }

    Write-GsaLog "Running $InstallerPath $Arguments"
    $Process = Start-Process -FilePath $InstallerPath -ArgumentList $Arguments -Wait -PassThru
    Write-GsaLog "Installer exited with code $($Process.ExitCode)."
    return $Process.ExitCode
}

try {
    $ErrorActionPreference = "Stop"
    Write-GsaLog "Starting Global Secure Access client $Operation operation."

    $Operation = $Operation.Trim()
    if ($Operation -notin @("Install", "Uninstall")) {
        throw "Unsupported operation '$Operation'. Use Install or Uninstall."
    }

    if ($Operation -eq "Install" -and -not $ForceInstall -and (Test-MinimumVersionMet -MinimumVersion $MinimumClientVersion)) {
        Write-GsaLog "Installed Global Secure Access client already meets minimum version $MinimumClientVersion."
        exit 0
    }

    $RebootRequired = $false
    if ($Operation -eq "Install") {
        $RebootRequired = Set-IPv4Preference
    }

    $InstallerPath = Resolve-InstallerPath
    $Arguments = if ($Operation -eq "Install") { $InstallArguments } else { $UninstallArguments }
    $ExitCode = Invoke-Installer -InstallerPath $InstallerPath -Arguments $Arguments

    if ($ExitCode -eq 1618) {
        Write-GsaLog "Another installation is in progress. Intune should retry."
        exit 1618
    }

    if ($ExitCode -eq 3010) {
        Write-GsaLog "Installer reported that a soft reboot is required."
        exit 3010
    }

    if ($ExitCode -ne 0) {
        exit $ExitCode
    }

    if ($RebootRequired) {
        Write-GsaLog "A reboot is required for the IPv4 preference registry change."
        exit 3010
    }

    Write-GsaLog "Global Secure Access client $Operation operation completed successfully."
    exit 0
} catch {
    Write-GsaLog "Fatal error: $_"
    exit 1603
}
