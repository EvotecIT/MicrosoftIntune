# ========= AutoPilot Import Detection with Cleanup =========
<#
.SYNOPSIS
Detects if AutoPilot import has been completed and manages working files

.DESCRIPTION
Checks for the AutoPilot completion flag and performs cleanup of temporary files
while maintaining the last 5 log files for troubleshooting.
#>

# Configuration
$LogFolder = "C:\ProgramData\Autopilot"
$DoneFlag = Join-Path -Path $LogFolder -ChildPath "autopilot-complete.txt"

function Remove-AutoPilotWorkingFiles {
    <#
    .SYNOPSIS
    Cleans up AutoPilot working files while preserving success flag and recent logs
    #>
    try {
        if (Test-Path -Path $LogFolder) {
            $itemsRemoved = 0

            # Get all items in the folder
            $allItems = Get-ChildItem -Path $LogFolder -Force -ErrorAction SilentlyContinue

            # Separate log files from other files
            $logFiles = $allItems | Where-Object { $_.Name -like "autopilot-log-*.txt" } | Sort-Object -Property LastWriteTime -Descending
            $otherFiles = $allItems | Where-Object { $_.Name -notlike "autopilot-log-*.txt" -and $_.Name -ne "autopilot-complete.txt" }

            # Keep only the last 5 log files, remove the rest
            $logsToKeep = $logFiles | Select-Object -First 5
            $logsToRemove = $logFiles | Select-Object -Skip 5

            # Remove old log files
            foreach ($logFile in $logsToRemove) {
                try {
                    Remove-Item -Path $logFile.FullName -Force -ErrorAction SilentlyContinue
                    $itemsRemoved++
                } catch {
                    # Silently continue if we can't remove some files
                }
            }

            # Remove all other files (except completion flag)
            foreach ($item in $otherFiles) {
                try {
                    if ($item.PSIsContainer) {
                        Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction SilentlyContinue
                    } else {
                        Remove-Item -Path $item.FullName -Force -ErrorAction SilentlyContinue
                    }
                    $itemsRemoved++
                } catch {
                    # Silently continue if we can't remove some files
                }
            }

            # Log cleanup results if we have a recent log file
            if ($itemsRemoved -gt 0 -and $logsToKeep.Count -gt 0) {
                try {
                    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    $cleanupMsg = "$timestamp [Detection] Cleaned up $itemsRemoved items, kept $($logsToKeep.Count) recent log files"
                    Add-Content -Path $logsToKeep[0].FullName -Value $cleanupMsg -ErrorAction SilentlyContinue
                } catch {
                    # Don't fail if we can't log
                }
            }
        }
    } catch {
        # Don't fail detection if cleanup fails
    }
}

# Check if AutoPilot import has been completed
if (Test-Path -Path $DoneFlag) {
    # Device was already imported successfully
    # Clean up old files and maintain log rotation
    Remove-AutoPilotWorkingFiles

    # No remediation needed
    exit 0
} else {
    # Device needs to be imported - trigger remediation
    exit 1
}