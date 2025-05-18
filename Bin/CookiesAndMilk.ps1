# Ensure the script runs with administrative privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "You need to run this script as an administrator."
    exit
}

# Define paths
$cookiePath = "$env:LocalAppData\Google\Chrome\User Data\Default\Cookies"
$backupDir = "$env:ProgramData\CookieBackup"
$backupPath = "$backupDir\Cookies.bak"
$cookieLogPath = "$backupDir\CookieMonitor.log"
$passwordLogPath = "$backupDir\NewPassword.log"
$errorLogPath = "$backupDir\ScriptErrors.log"
$scriptPath = $PSCommandPath  # Full path to this script

# Create backup directory if it doesn't exist
if (-not (Test-Path $backupDir)) {
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
}

# Function to log errors to file
function Log-Error {
    param ($Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $errorLogPath -Append
}

# Function to generate a simple random password
function Generate-SimplePassword {
    $chars = [char[]]('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*')
    $password = -join ($chars | Get-Random -Count 16)
    return $password
}

# Function to set a new password for the current user
function Set-NewPassword {
    try {
        $newPassword = Generate-SimplePassword
        $securePassword = ConvertTo-SecureString -String $newPassword -AsPlainText -Force
        Set-LocalUser -Name $env:USERNAME -Password $securePassword -ErrorAction Stop
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        "$timestamp - New password set: $newPassword" | Out-File -FilePath $passwordLogPath -Append
        Write-Host "Password changed due to potential cookie theft. New password logged to $passwordLogPath"
        return $newPassword
    } catch {
        $errorMsg = "Failed to set new password: $_"
        Write-Error $errorMsg
        Log-Error $errorMsg
    }
}

# Function to reset user password to blank
function Reset-UserPassword {
    try {
        $nullPassword = ConvertTo-SecureString "" -AsPlainText -Force
        Set-LocalUser -Name $env:USERNAME -Password $nullPassword -ErrorAction Stop
        Write-Host "Password reset to blank for user $env:USERNAME"
    } catch {
        $errorMsg = "Failed to reset password to blank: $_"
        Write-Error $errorMsg
        Log-Error $errorMsg
    }
}

# Function to back up Chrome cookies
function Backup-Cookies {
    try {
        if (Test-Path $cookiePath) {
            Stop-Process -Name "chrome" -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            Copy-Item -Path $cookiePath -Destination $backupPath -Force -ErrorAction Stop
            Write-Host "Cookies backed up to $backupPath"
        } else {
            Write-Warning "Chrome cookie file not found at $cookiePath"
        }
    } catch {
        $errorMsg = "Failed to back up cookies: $_"
        Write-Error $errorMsg
        Log-Error $errorMsg
    }
}

# Function to restore cookies from backup
function Restore-Cookies {
    try {
        if (Test-Path $backupPath) {
            Stop-Process -Name "chrome" -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            Copy-Item -Path $backupPath -Destination $cookiePath -Force -ErrorAction Stop
            Write-Host "Cookies restored from $backupPath"
        } else {
            Write-Warning "No cookie backup found at $backupPath"
        }
    } catch {
        $errorMsg = "Failed to restore cookies: $_"
        Write-Error $errorMsg
        Log-Error $errorMsg
    }
}

# Function to monitor cookies for potential theft
function Monitor-Cookies {
    try {
        if (-not (Test-Path $cookiePath)) {
            Write-Warning "Cookie file not found. Skipping monitoring."
            return
        }

        $currentHash = (Get-FileHash -Path $cookiePath -Algorithm SHA256).Hash
        $lastHash = if (Test-Path $cookieLogPath) { Get-Content $cookieLogPath } else { "" }

        if ($lastHash -and $currentHash -ne $lastHash) {
            Write-Host "Potential cookie theft detected. Initiating password reset and cookie restore."
            Set-NewPassword
            Restore-Cookies
        }

        $currentHash | Out-File -FilePath $cookieLogPath -Force
    } catch {
        $errorMsg = "Failed to monitor cookies: $_"
        Write-Error $errorMsg
        Log-Error $errorMsg
    }
}

# Schedule a task to back up cookies on system startup
$actionBackup = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -Command `"& { . '$scriptPath'; Backup-Cookies }`""
$triggerBackup = New-ScheduledTaskTrigger -AtStartup
$taskNameBackup = "BackupCookiesOnStartup"
try {
    if (Get-ScheduledTask -TaskName $taskNameBackup -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskNameBackup -Confirm:$false -ErrorAction Stop
    }
    Register-ScheduledTask -TaskName $taskNameBackup -Action $actionBackup -Trigger $triggerBackup -User "SYSTEM" -Description "Backs up Chrome cookies on system startup" -ErrorAction Stop | Out-Null
    Write-Host "Created task: $taskNameBackup"
} catch {
    $errorMsg = "Failed to create backup task: $_"
    Write-Error $errorMsg
    Log-Error $errorMsg
}

# Schedule a task to monitor cookies every 5 minutes
$actionMonitor = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -Command `"& { . '$scriptPath'; Monitor-Cookies }`""
$triggerMonitor = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 365)
$taskNameMonitor = "MonitorCookies"
try {
    if (Get-ScheduledTask -TaskName $taskNameMonitor -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskNameMonitor -Confirm:$false -ErrorAction Stop
    }
    Register-ScheduledTask -TaskName $taskNameMonitor -Action $actionMonitor -Trigger $triggerMonitor -User "SYSTEM" -Description "Monitors Chrome cookies every 5 minutes" -ErrorAction Stop | Out-Null
    Write-Host "Created task: $taskNameMonitor"
} catch {
    $errorMsg = "Failed to create monitoring task: $_"
    Write-Error $errorMsg
    Log-Error $errorMsg
}

# Schedule a task to reset password to blank on shutdown or restart
$actionReset = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -Command `"& { . '$scriptPath'; Reset-UserPassword }`""
$eventTriggerQuery = @"
<QueryList>
  <Query Id="0" Path="System">
    <Select Path="System">*[System[(EventID=1074)]]</Select>
  </Query>
</QueryList>
"@
$taskNameReset = "ResetPasswordOnShutdown"
try {
    if (Get-ScheduledTask -TaskName $taskNameReset -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskNameReset -Confirm:$false -ErrorAction Stop
    }
    $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    # Create the event trigger using a COM-based approach for Task Scheduler
    $taskService = New-Object -ComObject Schedule.Service
    $taskService.Connect()
    $taskDefinition = $taskService.NewTask(0)
    $triggers = $taskDefinition.Triggers
    $eventTrigger = $triggers.Create(0) # 0 = TASK_TRIGGER_EVENT
    $eventTrigger.Subscription = $eventTriggerQuery
    $eventTrigger.Enabled = $true
    $action = $taskDefinition.Actions.Create(0) # 0 = TASK_ACTION_EXEC
    $action.Path = "powershell.exe"
    $action.Arguments = "-NoProfile -ExecutionPolicy Bypass -Command `"& { . '$scriptPath'; Reset-UserPassword }`""
    $taskDefinition.Settings.Enabled = $true
    $taskDefinition.Settings.AllowDemandStart = $true
    $taskDefinition.Settings.StartWhenAvailable = $true
    $taskService.GetFolder("\").RegisterTaskDefinition($taskNameReset, $taskDefinition, 6, "SYSTEM", $null, 4) | Out-Null
    Write-Host "Created task: $taskNameReset"
} catch {
    $errorMsg = "Failed to create password reset task: $_"
    Write-Error $errorMsg
    Log-Error $errorMsg
}

# Fallback: Configure Group Policy shutdown script (uncomment if event trigger fails)
<#
$command = "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command `"& { . '$scriptPath'; Reset-UserPassword }`""
$gpoScriptPath = "$env:SystemRoot\System32\GroupPolicy\Machine\Scripts\Shutdown\ResetPassword.ps1"
New-Item -Path (Split-Path $gpoScriptPath -Parent) -ItemType Directory -Force | Out-Null
Set-Content -Path $gpoScriptPath -Value $command
gpupdate /force
Write-Host "Configured Group Policy shutdown script as fallback"
#>

Write-Host "Scheduled task creation completed. Check $errorLogPath for any errors."