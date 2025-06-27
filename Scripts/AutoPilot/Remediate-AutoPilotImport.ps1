# ========= Configuration =========
$TenantId = '<tenant_id>'
$ClientId = '<client_id>'
$ClientSecret = '<client_secret>'
$GroupTag = 'ImportedByIntune'

# ========= Prep Environment =========
$LogFolder = "C:\ProgramData\Autopilot"
$LogFile = Join-Path -Path $LogFolder -ChildPath "autopilot-log-$(Get-Date -Format 'yyyy-MM-dd').txt"
$DoneFlag = Join-Path -Path $LogFolder -ChildPath "autopilot-complete.txt"

if (-not (Test-Path -Path $LogFolder)) {
    New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null
}

# ========= Early exit if already uploaded =========
if (Test-Path -Path $DoneFlag) {
    Add-Content -Path $LogFile -Value "$(Get-Date -Format s) SKIPPED: Already uploaded."
    exit 0
}

# ========= Function: Get Access Token =========
function Get-AccessToken {
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$ClientSecret
    )

    $tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $body = @{
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = "https://graph.microsoft.com/.default"
        grant_type    = "client_credentials"
    }

    try {
        $response = Invoke-RestMethod -Uri $tokenEndpoint -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
        return $response.access_token
    } catch {
        throw "Failed to get access token: $_"
    }
}

# ========= Function: Get Device Hardware Info =========
function Get-DeviceInfo {
    try {
        # Get serial number
        $serial = (Get-CimInstance -Class Win32_BIOS).SerialNumber

        # Get hardware hash
        $devDetail = Get-CimInstance -Namespace root/cimv2/mdm/dmmap -Class MDM_DevDetail_Ext01 -Filter "InstanceID='Ext' AND ParentID='./DevDetail'" -ErrorAction SilentlyContinue

        if (-not $devDetail) {
            throw "Unable to retrieve device hardware data (hash). This typically means the device is not eligible for Autopilot."
        }

        $hash = $devDetail.DeviceHardwareData

        return @{
            SerialNumber = $serial
            HardwareHash = $hash
        }
    } catch {
        throw "Failed to get device info: $_"
    }
}

# ========= Function: Check if Device Already Exists =========
function Test-DeviceAlreadyRegistered {
    param(
        [string]$AccessToken,
        [string]$SerialNumber
    )

    $headers = @{
        "Authorization" = "Bearer $AccessToken"
    }

    try {
        # Search for device by serial number
        $response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/deviceManagement/importedWindowsAutopilotDeviceIdentities?`$filter=serialNumber eq '$SerialNumber'" -Headers $headers

        if ($response.value -and $response.value.Count -gt 0) {
            $existingDevice = $response.value[0]
            Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Found existing AutoPilot device: ID $($existingDevice.id), Status: $($existingDevice.state.deviceImportStatus)"
            return @{
                Exists   = $true
                DeviceId = $existingDevice.id
                Status   = $existingDevice.state.deviceImportStatus
            }
        } else {
            return @{
                Exists   = $false
                DeviceId = $null
                Status   = $null
            }
        }
    } catch {
        Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Could not check existing devices: $_"
        # Return false to continue with registration attempt
        return @{
            Exists   = $false
            DeviceId = $null
            Status   = $null
        }
    }
}

# ========= Function: Register Device with Autopilot =========
function Register-AutopilotDevice {
    param(
        [string]$AccessToken,
        [string]$SerialNumber,
        [string]$HardwareHash,
        [string]$GroupTag
    )

    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }

    $body = @{
        "@odata.type"        = "#microsoft.graph.importedWindowsAutopilotDeviceIdentity"
        "serialNumber"       = $SerialNumber
        "hardwareIdentifier" = $HardwareHash
    }

    if ($GroupTag) {
        $body["groupTag"] = $GroupTag
    }

    $jsonBody = $body | ConvertTo-Json -Depth 10

    try {
        $response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/deviceManagement/importedWindowsAutopilotDeviceIdentities" -Method Post -Headers $headers -Body $jsonBody
        return @{
            Success       = $true
            ImportId      = $response.id
            AlreadyExists = $false
            Message       = "Device registered successfully"
        }
    } catch {
        # Check if device already exists
        if ($_.Exception.Response.StatusCode -eq 409 -or $_.Exception.Message -like "*already exists*") {
            Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Device already exists in AutoPilot - this is expected for re-runs"
            return @{
                Success       = $true
                ImportId      = $null
                AlreadyExists = $true
                Message       = "Device already registered in AutoPilot"
            }
        }
        throw "Failed to register device: $_"
    }
}

# ========= Function: Check Import Status =========
function Wait-ForImportCompletion {
    <#
    .SYNOPSIS
    Waits for AutoPilot device import to complete with enhanced progress tracking

    .DESCRIPTION
    Monitors the import status and provides detailed feedback about the process
    #>
    param(
        [string]$AccessToken,
        [string]$ImportId,
        [int]$TimeoutMinutes = 15
    )

    $headers = @{
        "Authorization" = "Bearer $AccessToken"
    }

    $timeout = (Get-Date).AddMinutes($TimeoutMinutes)
    $startTime = Get-Date
    $checkCount = 0
    $lastStatus = ""

    Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Monitoring import progress (timeout: $TimeoutMinutes minutes)..."

    do {
        $checkCount++
        $elapsed = (Get-Date) - $startTime
        $elapsedMinutes = [Math]::Round($elapsed.TotalMinutes, 1)

        try {
            $response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/deviceManagement/importedWindowsAutopilotDeviceIdentities/$ImportId" -Headers $headers

            $status = $response.state.deviceImportStatus

            # Only log if status changed or every 5th check to reduce log noise
            if ($status -ne $lastStatus -or $checkCount % 5 -eq 0) {
                $progressMsg = "Check $checkCount (${elapsedMinutes}m elapsed): Import status = $status"
                Add-Content -Path $LogFile -Value "$(Get-Date -Format s) $progressMsg"

                # Provide helpful context for different statuses
                switch ($status) {
                    "unknown" {
                        if ($checkCount -eq 1) {
                            Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Status 'unknown' is normal during initial processing..."
                        }
                    }
                    "pending" {
                        Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Import is queued for processing..."
                    }
                    "processing" {
                        Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Microsoft is actively processing the device import..."
                    }
                }
            }

            if ($status -eq "complete") {
                Add-Content -Path $LogFile -Value "$(Get-Date -Format s) ✅ Device import completed successfully after ${elapsedMinutes} minutes!"
                return $true
            } elseif ($status -eq "error" -or $status -eq "failed") {
                $errorCode = $response.state.deviceErrorCode
                $errorName = $response.state.deviceErrorName

                # Check if this is the "already assigned" error (806 - ZtdDeviceAlreadyAssigned)
                if ($errorCode -eq 806 -or $errorName -eq "ZtdDeviceAlreadyAssigned") {
                    Add-Content -Path $LogFile -Value "$(Get-Date -Format s) ✅ Device already assigned to AutoPilot after ${elapsedMinutes} minutes - treating as success"
                    return $true
                } else {
                    Add-Content -Path $LogFile -Value "$(Get-Date -Format s) ❌ Import failed after ${elapsedMinutes} minutes"
                    throw "Device import failed: $errorCode - $errorName"
                }
            }

            $lastStatus = $status
            Start-Sleep -Seconds 30

        } catch {
            if ($_.Exception.Response.StatusCode -eq 404) {
                Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Check ${checkCount}: Device not found yet (still initializing)..."
                Start-Sleep -Seconds 30
            } else {
                Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Error checking import status: $_"
                throw $_
            }
        }
    } while ((Get-Date) -lt $timeout)

    Add-Content -Path $LogFile -Value "$(Get-Date -Format s) ⏱️ Import timed out after $TimeoutMinutes minutes ($checkCount checks performed)"
    throw "Import timed out after $TimeoutMinutes minutes. The device may still be processing in the background."
}

# ========= Main Execution =========
try {
    Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Starting Autopilot device registration for $env:COMPUTERNAME"

    # Get device information
    Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Gathering device hardware information..."
    $deviceInfo = Get-DeviceInfo
    Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Device Serial: $($deviceInfo.SerialNumber)"

    # Get access token
    Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Authenticating with Microsoft Graph..."
    $accessToken = Get-AccessToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
    Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Successfully authenticated"

    # Check if device is already registered
    Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Checking if device is already registered..."
    $existingDevice = Test-DeviceAlreadyRegistered -AccessToken $accessToken -SerialNumber $deviceInfo.SerialNumber

    if ($existingDevice.Exists) {
        if ($existingDevice.Status -eq "complete") {
            Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Device already successfully registered and completed"
            $completed = $true
            $importResult = @{
                ImportId      = $existingDevice.DeviceId
                AlreadyExists = $true
            }
        } elseif ($existingDevice.Status -eq "error" -or $existingDevice.Status -eq "failed") {
            Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Device exists but in error state, will monitor for completion..."
            $completed = Wait-ForImportCompletion -AccessToken $accessToken -ImportId $existingDevice.DeviceId
            $importResult = @{
                ImportId      = $existingDevice.DeviceId
                AlreadyExists = $true
            }
        } else {
            Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Device exists in status '$($existingDevice.Status)', monitoring for completion..."
            $completed = Wait-ForImportCompletion -AccessToken $accessToken -ImportId $existingDevice.DeviceId
            $importResult = @{
                ImportId      = $existingDevice.DeviceId
                AlreadyExists = $true
            }
        }
    } else {
        # Register device
        Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Device not found, registering with Autopilot..."
        $importResult = Register-AutopilotDevice -AccessToken $accessToken -SerialNumber $deviceInfo.SerialNumber -HardwareHash $deviceInfo.HardwareHash -GroupTag $GroupTag

        if ($importResult.AlreadyExists) {
            Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Device already registered - $($importResult.Message)"
            $completed = $true
        } else {
            Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Device registration initiated with ID: $($importResult.ImportId)"

            # Wait for import to complete
            Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Waiting for import to complete..."
            $completed = Wait-ForImportCompletion -AccessToken $accessToken -ImportId $importResult.ImportId
        }
    }

    if ($completed) {
        # Create success flag with completion details
        $importIdInfo = if ($importResult.ImportId) { $importResult.ImportId } else { "Already existed" }
        $statusInfo = if ($importResult.AlreadyExists) { "Device was already registered" } else { "Device newly registered" }

        $completionInfo = @"
AutoPilot Import Completed Successfully
=======================================
Computer: $env:COMPUTERNAME
Serial Number: $($deviceInfo.SerialNumber)
Import ID: $importIdInfo
Status: $statusInfo
Completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Group Tag: $GroupTag

Log Management:
- Current log: $($LogFile | Split-Path -Leaf)
- Detection will maintain last 5 log files
- All temporary files will be cleaned up on next detection
"@
        $completionInfo | Out-File -FilePath $DoneFlag -Encoding UTF8

        Add-Content -Path $LogFile -Value "$(Get-Date -Format s) SUCCESS: Autopilot registration completed for $env:COMPUTERNAME (Serial: $($deviceInfo.SerialNumber))"
        Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Success flag created: $DoneFlag"

        exit 0
    }
} catch {
    Add-Content -Path $LogFile -Value "$(Get-Date -Format s) ERROR: $($_.Exception.Message)"
    Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Full error: $_"
    exit 1
}
