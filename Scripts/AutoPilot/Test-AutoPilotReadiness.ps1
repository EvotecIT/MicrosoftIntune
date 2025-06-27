# Test script to validate Autopilot readiness without actually registering
param(
    [switch]$NoLogging
)

$LogFolder = "C:\ProgramData\Autopilot"
$LogFile = Join-Path -Path $LogFolder -ChildPath "Autopilot-Test.log"

if (-not $NoLogging) {
    if (-not (Test-Path -Path $LogFolder)) {
        New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null
    }
}

function Test-DeviceEligibility {
    Write-Host "Testing device Autopilot eligibility..." -ForegroundColor Yellow
    if (-not $NoLogging) { Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Testing device eligibility..." }

    try {
        # Test serial number extraction
        $serial = (Get-CimInstance -Class Win32_BIOS).SerialNumber
        Write-Host "✅ Serial Number: $serial" -ForegroundColor Green
        if (-not $NoLogging) { Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Serial Number: $serial" }

        # Test hardware hash extraction
        $devDetail = Get-CimInstance -Namespace root/cimv2/mdm/dmmap -Class MDM_DevDetail_Ext01 -Filter "InstanceID='Ext' AND ParentID='./DevDetail'" -ErrorAction SilentlyContinue

        if ($devDetail) {
            $hash = $devDetail.DeviceHardwareData
            Write-Host "✅ Hardware Hash: Available (length: $($hash.Length))" -ForegroundColor Green
            if (-not $NoLogging) { Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Hardware hash extracted successfully" }
            return $true
        } else {
            Write-Host "❌ Hardware Hash: Not available - Device may not be Autopilot eligible" -ForegroundColor Red
            if (-not $NoLogging) { Add-Content -Path $LogFile -Value "$(Get-Date -Format s) ERROR: Could not extract hardware hash" }
            return $false
        }
    } catch {
        Write-Host "❌ Device Info Error: $_" -ForegroundColor Red
        if (-not $NoLogging) { Add-Content -Path $LogFile -Value "$(Get-Date -Format s) ERROR: $_" }
        return $false
    }
}

function Test-NetworkConnectivity {
    Write-Host "Testing network connectivity..." -ForegroundColor Yellow
    if (-not $NoLogging) { Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Testing network connectivity..." }

    $endpoints = @(
        "https://login.microsoftonline.com",
        "https://graph.microsoft.com"
    )

    $allGood = $true
    foreach ($endpoint in $endpoints) {
        try {
            $response = Invoke-WebRequest -Uri $endpoint -Method Head -TimeoutSec 10 -UseBasicParsing
            Write-Host "✅ $endpoint - Reachable" -ForegroundColor Green
            if (-not $NoLogging) { Add-Content -Path $LogFile -Value "$(Get-Date -Format s) $endpoint - Reachable" }
        } catch {
            Write-Host "❌ $endpoint - Not reachable: $_" -ForegroundColor Red
            if (-not $NoLogging) { Add-Content -Path $LogFile -Value "$(Get-Date -Format s) $endpoint - Not reachable: $_" }
            $allGood = $false
        }
    }
    return $allGood
}

function Test-AuthenticationFlow {
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$ClientSecret
    )

    Write-Host "Testing authentication flow..." -ForegroundColor Yellow
    if (-not $NoLogging) { Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Testing authentication..." }

    $tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $body = @{
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = "https://graph.microsoft.com/.default"
        grant_type    = "client_credentials"
    }

    try {
        $response = Invoke-RestMethod -Uri $tokenEndpoint -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
        Write-Host "✅ Authentication: Success" -ForegroundColor Green
        if (-not $NoLogging) { Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Authentication successful" }

        # Test Graph API access
        $headers = @{ "Authorization" = "Bearer $($response.access_token)" }
        $graphTest = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/deviceManagement/importedWindowsAutopilotDeviceIdentities?`$top=1" -Headers $headers
        Write-Host "✅ Graph API Access: Success" -ForegroundColor Green
        if (-not $NoLogging) { Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Graph API access confirmed" }
        return $true
    } catch {
        Write-Host "❌ Authentication Error: $_" -ForegroundColor Red
        if (-not $NoLogging) { Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Authentication error: $_" }
        return $false
    }
}

# Main test execution
Write-Host "`n🧪 Autopilot Readiness Test" -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor Cyan

$deviceOK = Test-DeviceEligibility
$networkOK = Test-NetworkConnectivity

# Prompt for credentials to test auth
Write-Host "`nTo test authentication, please provide your app credentials:" -ForegroundColor Yellow
$tenantId = Read-Host "Tenant ID"
$clientId = Read-Host "Client ID"
$clientSecret = Read-Host "Client Secret" -AsSecureString
$clientSecretPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($clientSecret))

$authOK = Test-AuthenticationFlow -TenantId $tenantId -ClientId $clientId -ClientSecret $clientSecretPlain

Write-Host "`n📋 Test Results:" -ForegroundColor Cyan
Write-Host "=================" -ForegroundColor Cyan
Write-Host "Device Eligibility: $(if($deviceOK){'✅ PASS'}else{'❌ FAIL'})"
Write-Host "Network Connectivity: $(if($networkOK){'✅ PASS'}else{'❌ FAIL'})"
Write-Host "Authentication: $(if($authOK){'✅ PASS'}else{'❌ FAIL'})"

if ($deviceOK -and $networkOK -and $authOK) {
    Write-Host "`n🎉 All tests passed! The main script should work." -ForegroundColor Green
    if (-not $NoLogging) { Add-Content -Path $LogFile -Value "$(Get-Date -Format s) All readiness tests passed" }
} else {
    Write-Host "`n⚠️  Some tests failed. Fix these issues before running the main script." -ForegroundColor Yellow
    if (-not $NoLogging) { Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Some readiness tests failed" }
}

if (-not $NoLogging) {
    Write-Host "`nLog file: $LogFile" -ForegroundColor Gray
} else {
    Write-Host "`nLogging disabled (-NoLogging parameter used)" -ForegroundColor Gray
}