# Test script to check if device is Autopilot-eligible (offline test)
param(
    [switch]$NoLogging
)

$LogFolder = "C:\ProgramData\Autopilot"
$LogFile = Join-Path -Path $LogFolder -ChildPath "Device-Eligibility-Test.log"

if (-not $NoLogging) {
    if (-not (Test-Path -Path $LogFolder)) {
        New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null
    }
}

# Helper function for conditional logging
function Write-LogEntry {
    param([string]$Message)
    if (-not $NoLogging) {
        Add-Content -Path $LogFile -Value "$(Get-Date -Format s) $Message"
    }
}

Write-Host "🔍 Device Autopilot Eligibility Test" -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan
Write-LogEntry "Starting device eligibility test..."

# Test 1: BIOS/UEFI Check
Write-Host "`n1. Checking firmware type..." -ForegroundColor Yellow
try {
    $firmware = Get-CimInstance -Class Win32_ComputerSystem | Select-Object -ExpandProperty BootupState
    $biosMode = Get-CimInstance -Class Win32_ComputerSystem | Select-Object -ExpandProperty SystemType
    Write-Host "   System Type: $biosMode" -ForegroundColor Gray
    Write-LogEntry "System Type: $biosMode"

    # Check for UEFI
    $isUEFI = $false
    try {
        $uefiCheck = Get-CimInstance -Class Win32_SystemEnclosure | Select-Object -ExpandProperty ChassisTypes
        $isUEFI = Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State"
        if ($isUEFI) {
            Write-Host "   ✅ UEFI firmware detected" -ForegroundColor Green
            Add-Content -Path $LogFile -Value "$(Get-Date -Format s) UEFI firmware confirmed"
        } else {
            Write-Host "   ⚠️  Legacy BIOS detected - may not support Autopilot" -ForegroundColor Yellow
            Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Legacy BIOS detected"
        }
    } catch {
        Write-Host "   ❓ Could not determine firmware type" -ForegroundColor Yellow
        Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Could not determine firmware type"
    }
} catch {
    Write-Host "   ❌ Error checking firmware: $_" -ForegroundColor Red
    Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Error checking firmware: $_"
}

# Test 2: TPM Check
Write-Host "`n2. Checking TPM availability..." -ForegroundColor Yellow
try {
    $tpm = Get-CimInstance -Namespace root/cimv2/security/microsofttpm -Class Win32_Tpm -ErrorAction SilentlyContinue
    if ($tpm) {
        $tpmVersion = $tpm.SpecVersion
        $tpmEnabled = $tpm.IsEnabled_InitialValue
        $tpmActivated = $tpm.IsActivated_InitialValue

        Write-Host "   TPM Version: $tpmVersion" -ForegroundColor Gray
        Write-Host "   TPM Enabled: $tpmEnabled" -ForegroundColor Gray
        Write-Host "   TPM Activated: $tpmActivated" -ForegroundColor Gray

        if ($tpmVersion -like "2.*" -and $tpmEnabled -and $tpmActivated) {
            Write-Host "   ✅ TPM 2.0 is enabled and activated" -ForegroundColor Green
            Add-Content -Path $LogFile -Value "$(Get-Date -Format s) TPM 2.0 confirmed - Version: $tpmVersion"
        } else {
            Write-Host "   ⚠️  TPM may not meet Autopilot requirements" -ForegroundColor Yellow
            Add-Content -Path $LogFile -Value "$(Get-Date -Format s) TPM issue - Version: $tpmVersion, Enabled: $tpmEnabled, Activated: $tpmActivated"
        }
    } else {
        Write-Host "   ❌ No TPM detected" -ForegroundColor Red
        Add-Content -Path $LogFile -Value "$(Get-Date -Format s) No TPM detected"
    }
} catch {
    Write-Host "   ❌ Error checking TPM: $_" -ForegroundColor Red
    Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Error checking TPM: $_"
}

# Test 3: Serial Number
Write-Host "`n3. Checking device serial number..." -ForegroundColor Yellow
try {
    $serial = (Get-CimInstance -Class Win32_BIOS).SerialNumber
    if ($serial -and $serial.Trim() -ne "" -and $serial -notlike "*To be filled*" -and $serial -notlike "*Default*") {
        Write-Host "   ✅ Serial Number: $serial" -ForegroundColor Green
        Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Valid serial number: $serial"
        $serialOK = $true
    } else {
        Write-Host "   ❌ Invalid or missing serial number: '$serial'" -ForegroundColor Red
        Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Invalid serial number: $serial"
        $serialOK = $false
    }
} catch {
    Write-Host "   ❌ Error getting serial number: $_" -ForegroundColor Red
    Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Error getting serial number: $_"
    $serialOK = $false
}

# Test 4: Hardware Hash (Most Important)
Write-Host "`n4. Checking hardware hash availability..." -ForegroundColor Yellow
try {
    $devDetail = Get-CimInstance -Namespace root/cimv2/mdm/dmmap -Class MDM_DevDetail_Ext01 -Filter "InstanceID='Ext' AND ParentID='./DevDetail'" -ErrorAction SilentlyContinue

    if ($devDetail) {
        $hash = $devDetail.DeviceHardwareData
        if ($hash -and $hash.Length -gt 0) {
            Write-Host "   ✅ Hardware Hash: Available (Length: $($hash.Length) characters)" -ForegroundColor Green
            Write-Host "   Preview: $($hash.Substring(0, [Math]::Min(50, $hash.Length)))..." -ForegroundColor Gray
            Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Hardware hash available - Length: $($hash.Length)"
            $hashOK = $true
        } else {
            Write-Host "   ❌ Hardware hash is empty" -ForegroundColor Red
            Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Hardware hash is empty"
            $hashOK = $false
        }
    } else {
        Write-Host "   ❌ Cannot access MDM_DevDetail_Ext01 WMI class" -ForegroundColor Red
        Write-Host "   This usually means:" -ForegroundColor Yellow
        Write-Host "   • Device doesn't support Autopilot" -ForegroundColor Yellow
        Write-Host "   • TPM not properly configured" -ForegroundColor Yellow
        Write-Host "   • Not running as Administrator" -ForegroundColor Yellow
        Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Cannot access MDM_DevDetail_Ext01"
        $hashOK = $false
    }
} catch {
    Write-Host "   ❌ Error accessing hardware hash: $_" -ForegroundColor Red
    Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Error accessing hardware hash: $_"
    $hashOK = $false
}

# Test 5: Windows Version
Write-Host "`n5. Checking Windows version..." -ForegroundColor Yellow
try {
    $os = Get-CimInstance -Class Win32_OperatingSystem
    $version = $os.Version
    $caption = $os.Caption
    $buildNumber = $os.BuildNumber

    Write-Host "   OS: $caption" -ForegroundColor Gray
    Write-Host "   Version: $version (Build $buildNumber)" -ForegroundColor Gray

    if ($caption -like "*Pro*" -or $caption -like "*Enterprise*" -or $caption -like "*Education*") {
        Write-Host "   ✅ Windows edition supports Autopilot" -ForegroundColor Green
        Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Compatible Windows edition: $caption"
    } else {
        Write-Host "   ⚠️  Windows edition may not support Autopilot: $caption" -ForegroundColor Yellow
        Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Questionable Windows edition: $caption"
    }
} catch {
    Write-Host "   ❌ Error checking Windows version: $_" -ForegroundColor Red
    Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Error checking Windows version: $_"
}

# Summary
Write-Host "`n📋 Device Eligibility Summary:" -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor Cyan

if ($serialOK -and $hashOK) {
    Write-Host "🎉 DEVICE IS AUTOPILOT READY!" -ForegroundColor Green
    Write-Host "   • Serial number is valid" -ForegroundColor Green
    Write-Host "   • Hardware hash can be extracted" -ForegroundColor Green
    Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Device passed eligibility test"
} else {
    Write-Host "❌ DEVICE IS NOT AUTOPILOT READY" -ForegroundColor Red
    if (-not $serialOK) {
        Write-Host "   • Serial number issue detected" -ForegroundColor Red
    }
    if (-not $hashOK) {
        Write-Host "   • Hardware hash cannot be extracted" -ForegroundColor Red
    }
    Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Device failed eligibility test"
}

if (-not $NoLogging) {
    Write-Host "`nLog saved to: $LogFile" -ForegroundColor Gray
} else {
    Write-Host "`nLogging disabled (-NoLogging parameter used)" -ForegroundColor Gray
}
Write-Host "Run as Administrator if you got permission errors." -ForegroundColor Yellow