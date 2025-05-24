# GShield Gorstak

# Define paths and parameters
$taskName = "GShieldStartup"
$taskDescription = "Runs the GShield script at user logon with admin privileges."
$scriptDir = "C:\Windows\Setup\Scripts"
$scriptPath = "$scriptDir\GShield.ps1"
$quarantineFolder = "C:\Quarantine"
$destPath = "$env:windir\Setup\Scripts\Bin"
$currentScript = $MyInvocation.MyCommand.Path

# Ensure the script isn't running multiple times
$existingProcess = Get-Process | Where-Object { $_.Path -eq $currentScript -and $_.Id -ne $PID }
if ($existingProcess) {
    Write-Host "The script is already running. Exiting."
    exit
}

# Check admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
Write-Host "Running as admin: $isAdmin"

# Initial log with diagnostics
Write-Output "Script initialized. Admin: $isAdmin, User: $env:USERNAME, SID: $([Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"

# Ensure execution policy allows script
if ((Get-ExecutionPolicy) -eq "Restricted") {
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force -ErrorAction SilentlyContinue
    Write-Output "Set execution policy to Bypass for current process."
}

# Setup script directory and copy script
if (-not (Test-Path $scriptDir)) {
    New-Item -Path $scriptDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
    Write-Output "Created script directory: $scriptDir"
}
if (-not (Test-Path $scriptPath) -or (Get-Item $scriptPath).LastWriteTime -lt (Get-Item $currentScript).LastWriteTime) {
    Copy-Item -Path $currentScript -Destination $scriptPath -Force -ErrorAction Stop
    Write-Output "Copied/Updated script to: $scriptPath"
}

# Register scheduled task as SYSTEM
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if (-not $existingTask -and $isAdmin) {
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Description $taskDescription
    Register-ScheduledTask -TaskName $taskName -InputObject $task -Force -ErrorAction Stop
    Write-Output "Scheduled task '$taskName' registered to run as SYSTEM."
} elseif (-not $isAdmin) {
    Write-Output "Skipping task registration: Admin privileges required"
}

# Ensure quarantine folder exists
try {
    if (!(Test-Path $quarantineFolder)) {
        New-Item -ItemType Directory -Path $quarantineFolder -Force | Out-Null
        Write-Output "Created quarantine folder at $quarantineFolder"
    }
} catch {
    Write-Output "Failed to create quarantine folder: $($_.Exception.Message)"
}

function Stop-ProcessUsingDLL {
    param ([string]$filePath)
    try {
        $processes = Get-Process | Where-Object {
            try {
                $_.Modules | Where-Object { $_.FileName -eq $filePath }
            } catch {}
        }

        foreach ($process in $processes) {
            try {
                taskkill /F /PID $($process.Id) | Out-Null
                Write-Output "Killed process $($process.Name) (PID: $($process.Id))"
            } catch {
                Write-Output "Failed to kill process $($process.Id): $($_.Exception.Message)"
            }

            try {
                $parentId = (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $($process.Id)").ParentProcessId
                if ($parentId -and $parentId -ne 0 -and $parentId -ne $process.Id) {
                    $parentProc = Get-Process -Id $parentId -ErrorAction SilentlyContinue
                    if ($parentProc) {
                        taskkill /F /PID $parentId | Out-Null
                        Write-Output "Killed parent process $($parentProc.Name) (PID: $parentId)"
                    }
                }
            } catch {
                Write-Output "Failed to get or kill parent process for $($process.Id): $($_.Exception.Message)"
            }
        }
    } catch {
        Write-Output "Failed to stop process using ${filePath}: $($_.Exception.Message)"
    }
}

# Watch for newly created or changed DLL files
function Remove-UnsignedDLLs {
    param ([string]$changedPath)

    try {
        if (Test-Path $changedPath -PathType Leaf -and $changedPath -like "*.dll") {
            Write-Output "Detected DLL: $changedPath"
            $isValid = Is-SignedFileValid -filePath $changedPath
            if (-not $isValid) {
                if (Set-FileOwnershipAndPermissions -filePath $changedPath) {
                    Stop-ProcessUsingDLL -filePath $changedPath
                    Quarantine-File -filePath $changedPath
                }
            }
        }
    } catch {
        Write-Output "Error during file handling for ${changedPath}: $($_.Exception.Message)"
    }
}

# Start background job to continuously monitor for rootkit activity
Start-Job -ScriptBlock {
    while ($true) {
        Stop-AllVMs
        Detect-RootkitByNetstat
        Start-Sleep -Seconds 60  # Sleep to prevent busy-looping
    }
} | Out-Null

Write-Output "Script started successfully and is now monitoring system activity."
