# Test script to check network connectivity for Autopilot (no device checks)
param(
    [switch]$NoLogging
)

$LogFolder = "C:\ProgramData\Autopilot"
$LogFile = Join-Path -Path $LogFolder -ChildPath "Network-Test.log"

if (-not $NoLogging) {
    if (-not (Test-Path -Path $LogFolder)) {
        New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null
    }
}

Write-Host "🌐 Autopilot Network Connectivity Test" -ForegroundColor Cyan
Write-Host "=======================================" -ForegroundColor Cyan

if (-not $NoLogging) {
    Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Starting network connectivity test..."
}

# Define required endpoints
$endpoints = @(
    @{
        Name = "Microsoft Login"
        Url = "https://login.microsoftonline.com"
        Purpose = "OAuth2 authentication"
    },
    @{
        Name = "Microsoft Graph API"
        Url = "https://graph.microsoft.com"
        Purpose = "Device registration API"
    },
    @{
        Name = "Microsoft Graph Beta"
        Url = "https://graph.microsoft.com/beta"
        Purpose = "Extended API features"
    },
    @{
        Name = "Azure Management"
        Url = "https://management.azure.com"
        Purpose = "Azure resource management"
    }
)

# Test basic internet connectivity first
Write-Host "`n1. Testing basic internet connectivity..." -ForegroundColor Yellow
try {
    $basicTest = Test-NetConnection -ComputerName "8.8.8.8" -Port 53 -InformationLevel Quiet
    if ($basicTest) {
        Write-Host "   ✅ Basic internet connectivity: OK" -ForegroundColor Green
        if (-not $NoLogging) { Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Basic internet connectivity confirmed" }
    } else {
        Write-Host "   ❌ No internet connectivity detected" -ForegroundColor Red
        if (-not $NoLogging) { Add-Content -Path $LogFile -Value "$(Get-Date -Format s) No internet connectivity" }
    }
} catch {
    Write-Host "   ❌ Error testing basic connectivity: $_" -ForegroundColor Red
    if (-not $NoLogging) { Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Error testing basic connectivity: $_" }
}

# Test DNS resolution
Write-Host "`n2. Testing DNS resolution..." -ForegroundColor Yellow
foreach ($endpoint in $endpoints) {
    $hostname = ([System.Uri]$endpoint.Url).Host
    try {
        $dnsResult = Resolve-DnsName -Name $hostname -ErrorAction Stop
        # Get the first A record (IPv4 address)
        $ipAddress = ($dnsResult | Where-Object { $_.Type -eq "A" } | Select-Object -First 1).IPAddress
        if (-not $ipAddress) {
            # Fallback to any IP address in the result
            $ipAddress = ($dnsResult | Where-Object { $_.IPAddress } | Select-Object -First 1).IPAddress
        }
        if ($ipAddress) {
            Write-Host "   ✅ $hostname resolves to $ipAddress" -ForegroundColor Green
            if (-not $NoLogging) { Add-Content -Path $LogFile -Value "$(Get-Date -Format s) DNS OK for $hostname -> $ipAddress" }
        } else {
            Write-Host "   ✅ $hostname resolves (no A record found)" -ForegroundColor Green
            if (-not $NoLogging) { Add-Content -Path $LogFile -Value "$(Get-Date -Format s) DNS OK for $hostname (no A record)" }
        }
    } catch {
        Write-Host "   ❌ $hostname - DNS resolution failed: $_" -ForegroundColor Red
        if (-not $NoLogging) { Add-Content -Path $LogFile -Value "$(Get-Date -Format s) DNS failed for $hostname : $_" }
    }
}

# Test HTTPS connectivity to each endpoint
Write-Host "`n3. Testing HTTPS connectivity..." -ForegroundColor Yellow
$httpsResults = @()

foreach ($endpoint in $endpoints) {
    Write-Host "   Testing $($endpoint.Name)..." -ForegroundColor Gray
    try {
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $response = Invoke-WebRequest -Uri $endpoint.Url -Method Head -TimeoutSec 15 -UseBasicParsing -ErrorAction Stop
        $stopwatch.Stop()

        $result = @{
            Name = $endpoint.Name
            Url = $endpoint.Url
            StatusCode = $response.StatusCode
            ResponseTime = $stopwatch.ElapsedMilliseconds
            Success = $true
            Error = $null
        }

        Write-Host "     ✅ Status: $($response.StatusCode) - Response time: $($stopwatch.ElapsedMilliseconds)ms" -ForegroundColor Green
        if (-not $NoLogging) { Add-Content -Path $LogFile -Value "$(Get-Date -Format s) $($endpoint.Name) - Status: $($response.StatusCode), Time: $($stopwatch.ElapsedMilliseconds)ms" }

    } catch {
        # Check if this is a "good" HTTP error (means we reached the server)
        $httpError = $_.Exception.Response
        if ($httpError -and $httpError.StatusCode) {
            $statusCode = [int]$httpError.StatusCode
            # HTTP 4xx and 5xx responses mean we reached the server - this is success for connectivity testing
            if ($statusCode -ge 400 -and $statusCode -lt 600) {
                $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                $stopwatch.Stop()

                $result = @{
                    Name = $endpoint.Name
                    Url = $endpoint.Url
                    StatusCode = $statusCode
                    ResponseTime = 0  # Can't measure response time in catch block
                    Success = $true
                    Error = $null
                }

                Write-Host "     ✅ Status: $statusCode (Server reachable) - Connectivity OK" -ForegroundColor Green
                if (-not $NoLogging) { Add-Content -Path $LogFile -Value "$(Get-Date -Format s) $($endpoint.Name) - Status: $statusCode (Server reachable)" }
            } else {
                $result = @{
                    Name = $endpoint.Name
                    Url = $endpoint.Url
                    StatusCode = "Error"
                    ResponseTime = -1
                    Success = $false
                    Error = $_.Exception.Message
                }

                Write-Host "     ❌ Failed: $($_.Exception.Message)" -ForegroundColor Red
                if (-not $NoLogging) { Add-Content -Path $LogFile -Value "$(Get-Date -Format s) $($endpoint.Name) - Error: $($_.Exception.Message)" }
            }
        } else {
            # Real network error (DNS, timeout, etc.)
            $result = @{
                Name = $endpoint.Name
                Url = $endpoint.Url
                StatusCode = "Error"
                ResponseTime = -1
                Success = $false
                Error = $_.Exception.Message
            }

            Write-Host "     ❌ Failed: $($_.Exception.Message)" -ForegroundColor Red
            if (-not $NoLogging) { Add-Content -Path $LogFile -Value "$(Get-Date -Format s) $($endpoint.Name) - Error: $($_.Exception.Message)" }
        }
    }

    $httpsResults += $result
}

# Test specific ports
Write-Host "`n4. Testing specific ports..." -ForegroundColor Yellow
$portTests = @(
    @{ Host = "login.microsoftonline.com"; Port = 443; Name = "HTTPS" },
    @{ Host = "graph.microsoft.com"; Port = 443; Name = "HTTPS" }
)

foreach ($test in $portTests) {
    try {
        $portResult = Test-NetConnection -ComputerName $test.Host -Port $test.Port -InformationLevel Quiet -WarningAction SilentlyContinue
        if ($portResult) {
            Write-Host "   ✅ $($test.Host):$($test.Port) ($($test.Name)) - Reachable" -ForegroundColor Green
            if (-not $NoLogging) { Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Port test OK - $($test.Host):$($test.Port)" }
        } else {
            Write-Host "   ❌ $($test.Host):$($test.Port) ($($test.Name)) - Not reachable" -ForegroundColor Red
            if (-not $NoLogging) { Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Port test failed - $($test.Host):$($test.Port)" }
        }
    } catch {
        Write-Host "   ❌ $($test.Host):$($test.Port) - Error: $_" -ForegroundColor Red
        if (-not $NoLogging) { Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Port test error - $($test.Host):$($test.Port) - $_" }
    }
}

# Check proxy settings
Write-Host "`n5. Checking proxy configuration..." -ForegroundColor Yellow
try {
    $proxySettings = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
    if ($proxySettings.ProxyEnable -eq 1) {
        Write-Host "   ⚠️  Proxy enabled: $($proxySettings.ProxyServer)" -ForegroundColor Yellow
        Write-Host "   Proxy override: $($proxySettings.ProxyOverride)" -ForegroundColor Gray
        if (-not $NoLogging) { Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Proxy enabled: $($proxySettings.ProxyServer)" }
    } else {
        Write-Host "   ✅ No proxy configured" -ForegroundColor Green
        if (-not $NoLogging) { Add-Content -Path $LogFile -Value "$(Get-Date -Format s) No proxy configured" }
    }
} catch {
    Write-Host "   ❓ Could not check proxy settings: $_" -ForegroundColor Yellow
    if (-not $NoLogging) { Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Could not check proxy settings: $_" }
}

# Check firewall status
Write-Host "`n6. Checking Windows Firewall..." -ForegroundColor Yellow
try {
    $firewallProfiles = Get-NetFirewallProfile
    foreach ($firewallProfile in $firewallProfiles) {
        $status = if ($firewallProfile.Enabled) { "Enabled" } else { "Disabled" }
        $color = if ($firewallProfile.Enabled) { "Yellow" } else { "Green" }
        Write-Host "   $($firewallProfile.Name) Profile: $status" -ForegroundColor $color
        if (-not $NoLogging) { Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Firewall $($firewallProfile.Name): $status" }
    }
} catch {
    Write-Host "   ❓ Could not check firewall status: $_" -ForegroundColor Yellow
    if (-not $NoLogging) { Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Could not check firewall: $_" }
}

# Summary
Write-Host "`n📋 Network Connectivity Summary:" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

$successfulConnections = ($httpsResults | Where-Object { $_.Success }).Count
$totalConnections = $httpsResults.Count

Write-Host "Successful connections: $successfulConnections / $totalConnections" -ForegroundColor Gray

if ($successfulConnections -eq $totalConnections) {
    Write-Host "🎉 ALL NETWORK TESTS PASSED!" -ForegroundColor Green
    Write-Host "   • All required endpoints are reachable" -ForegroundColor Green
    Write-Host "   • HTTPS connectivity confirmed" -ForegroundColor Green
    if (-not $NoLogging) { Add-Content -Path $LogFile -Value "$(Get-Date -Format s) All network tests passed" }
} else {
    Write-Host "❌ SOME NETWORK TESTS FAILED" -ForegroundColor Red
    Write-Host "Failed endpoints (actual connectivity issues):" -ForegroundColor Red

    $failedTests = $httpsResults | Where-Object { -not $_.Success }
    foreach ($failed in $failedTests) {
        Write-Host "   • $($failed.Name): $($failed.Error)" -ForegroundColor Red
    }
    if (-not $NoLogging) { Add-Content -Path $LogFile -Value "$(Get-Date -Format s) Some network tests failed" }
}

Write-Host "`n💡 Note:" -ForegroundColor Cyan
Write-Host "   • HTTP 4xx/5xx responses are considered SUCCESS for connectivity testing" -ForegroundColor Gray
Write-Host "   • Only DNS/timeout/connection errors indicate real network issues" -ForegroundColor Gray

Write-Host "`n💡 Troubleshooting tips:" -ForegroundColor Yellow
Write-Host "   • Check corporate firewall/proxy settings" -ForegroundColor Gray
Write-Host "   • Verify internet connectivity" -ForegroundColor Gray
Write-Host "   • Ensure *.microsoftonline.com and *.microsoft.com are allowed" -ForegroundColor Gray

if (-not $NoLogging) {
    Write-Host "`nLog saved to: $LogFile" -ForegroundColor Gray
} else {
    Write-Host "`nLogging disabled (-NoLogging parameter used)" -ForegroundColor Gray
}