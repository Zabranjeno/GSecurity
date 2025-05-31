# PowerShell script to auto-fetch and install latest stable uBlock Origin (Manifest V2) for Firefox, Chrome, Edge, and Opera
# Configures for YouTube ad blocking with enhanced debugging and folder renaming

# Function to get latest stable uBlock Origin release
function Get-LatestuBlockVersion {
    Write-Host "DEBUG: Fetching releases from GitHub..."
    $releasePage = Invoke-WebRequest -Uri "https://api.github.com/repos/gorhill/uBlock/releases" -UseBasicParsing -ErrorAction Stop
    $releases = $releasePage.Content | ConvertFrom-Json
    $latestRelease = $releases | Where-Object { $_.tag_name -notlike "*b*" -and $_.tag_name -notlike "*uBlock0.lite*" } | Select-Object -First 1
    if (-not $latestRelease) { Write-Host "DEBUG: No stable release found."; exit }
    Write-Host "DEBUG: Found release $($latestRelease.tag_name)"
    return $latestRelease
}

# Function to get Chrome profile path
function Get-ChromeProfilePath {
    Write-Host "DEBUG: Checking Chrome profile path..."
    $defaultPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
    $chromeVersion = (Get-ItemProperty -Path "HKCU:\Software\Google\Chrome\BLBeacon" -ErrorAction SilentlyContinue).version
    if ($chromeVersion) { Write-Host "DEBUG: Default Chrome profile detected."; return $defaultPath }
    $profiles = Get-ChildItem -Path "$env:LOCALAPPDATA\Google\Chrome\User Data" -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne "System Profile" }
    if ($profiles) { Write-Host "DEBUG: Custom Chrome profile found: $($profiles[0].FullName)"; return "$($profiles[0].FullName)" }
    Write-Host "DEBUG: Using default Chrome profile path."
    return $defaultPath
}

# Function to get Edge profile path
function Get-EdgeProfilePath {
    Write-Host "DEBUG: Checking Edge profile path..."
    $defaultPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"
    $edgeVersion = (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Edge\BLBeacon" -ErrorAction SilentlyContinue).version
    if ($edgeVersion) { Write-Host "DEBUG: Default Edge profile detected."; return $defaultPath }
    $profiles = Get-ChildItem -Path "$env:LOCALAPPDATA\Microsoft\Edge\User Data" -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne "System Profile" }
    if ($profiles) { Write-Host "DEBUG: Custom Edge profile found: $($profiles[0].FullName)"; return "$($profiles[0].FullName)" }
    Write-Host "DEBUG: Using default Edge profile path."
    return $defaultPath
}

# Variables
$tempPath = "$env:TEMP\uBlock0"
$zipPath = "$tempPath\uBlock0.zip"
$extractPath = "$tempPath\uBlock0_Extracted"
$firefoxProfilePath = "$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release"
$chromeExtensionPath = "$(Get-ChromeProfilePath)\Extensions"
$edgeExtensionPath = "$(Get-EdgeProfilePath)\Extensions"
$operaExtensionPath = "$env:APPDATA\Opera Software\Opera Stable\Extensions"
$uBlockId = "cjpalhdlnbpafiamejdnhcphjbkeiagm" # uBlock Origin extension ID
$firefoxUBlockId = "uBlock0@raymondhill.net"

# Clean up existing extension folders to avoid conflicts
Write-Host "DEBUG: Cleaning up existing uBlock Origin folders..."
Remove-Item -Path "$chromeExtensionPath\$uBlockId" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$edgeExtensionPath\$uBlockId" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$operaExtensionPath\$uBlockId" -Recurse -Force -ErrorAction SilentlyContinue

# Create temp directories
Write-Host "DEBUG: Creating temp directory $tempPath..."
if (-not (Test-Path $tempPath)) { New-Item -ItemType Directory -Path $tempPath -Force -ErrorAction Stop }

# Fetch latest stable uBlock Origin release
Write-Host "Fetching latest stable uBlock Origin release..."
$release = Get-LatestuBlockVersion
$version = $release.tag_name
$firefoxUrl = ($release.assets | Where-Object { $_.name -like "*.firefox.signed.xpi" }).browser_download_url
$chromiumUrl = ($release.assets | Where-Object { $_.name -like "*.chromium.zip" }).browser_download_url

if (-not $firefoxUrl -or -not $chromiumUrl) {
    Write-Host "Error: Could not find latest stable uBlock Origin release for Firefox or Chromium."
    exit
}
Write-Host "DEBUG: Firefox URL: $firefoxUrl"
Write-Host "DEBUG: Chromium URL: $chromiumUrl"

# --- Firefox Installation ---
Write-Host "Installing uBlock Origin v$version for Firefox..."
if (Test-Path $firefoxProfilePath) {
    $firefoxExtensionPath = "$firefoxProfilePath\extensions"
    Write-Host "DEBUG: Firefox profile found at $firefoxProfilePath"
    if (-not (Test-Path $firefoxExtensionPath)) { New-Item -ItemType Directory -Path $firefoxExtensionPath -Force -ErrorAction Stop }
    Invoke-WebRequest -Uri $firefoxUrl -OutFile "$tempPath\uBlock0.xpi" -ErrorAction Stop
    Move-Item -Path "$tempPath\uBlock0.xpi" -Destination "$firefoxExtensionPath\$firefoxUBlockId.xpi" -Force -ErrorAction Stop
    # Configure filter lists
    $settingsFile = "$firefoxProfilePath\ublock0.settings"
    if (-not (Test-Path $settingsFile)) {
        $settings = @{
            "selectedFilterLists" = @("ublock-annoyances", "easylist", "easyprivacy")
        }
        $settings | ConvertTo-Json | Out-File $settingsFile -Encoding UTF8 -ErrorAction Stop
    }
    Write-Host "Firefox: uBlock Origin installed. Restart Firefox to apply."
} else {
    Write-Host "Firefox: Not detected, skipping installation."
}

# --- Chrome Installation ---
Write-Host "Installing uBlock Origin v$version for Chrome..."
if (Test-Path "$(Get-ChromeProfilePath)") {
    Write-Host "DEBUG: Chrome profile found at $(Get-ChromeProfilePath)"
    # Enable Manifest V2
    $chromeRegistryPath = "HKLM:\Software\Policies\Google\Chrome"
    if (-not (Test-Path $chromeRegistryPath)) { New-Item -Path $chromeRegistryPath -Force -ErrorAction Stop }
    Set-ItemProperty -Path $chromeRegistryPath -Name "ExtensionManifestV2Availability" -Value 2 -Type DWord -Force -ErrorAction Stop
    # Enable Developer Mode
    $regPath = "HKCU:\Software\Google\Chrome"
    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force -ErrorAction Stop }
    Set-ItemProperty -Path $regPath -Name "DeveloperMode" -Value 1 -Type DWord -Force -ErrorAction Stop
    # Download and install
    Write-Host "DEBUG: Downloading Chromium zip..."
    Invoke-WebRequest -Uri $chromiumUrl -OutFile $zipPath -ErrorAction Stop
    Write-Host "DEBUG: Extracting to $extractPath..."
    Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force -ErrorAction Stop
    $extractedFolder = Get-ChildItem -Path $extractPath -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($extractedFolder) {
        Write-Host "DEBUG: Extracted folder found: $($extractedFolder.FullName)"
        # Rename folder to standard format
        $targetFolder = "$extractPath\1.64.0_0"
        if ($extractedFolder.FullName -ne $targetFolder) {
            Move-Item -Path $extractedFolder.FullName -Destination $targetFolder -Force -ErrorAction Stop
        }
        if (-not (Test-Path $chromeExtensionPath)) { New-Item -ItemType Directory -Path $chromeExtensionPath -Force -ErrorAction Stop }
        Write-Host "DEBUG: Moving to $chromeExtensionPath\$uBlockId..."
        Move-Item -Path $targetFolder -Destination "$chromeExtensionPath\$uBlockId" -Force -ErrorAction Stop
        Write-Host "Chrome: uBlock Origin installed. Enable in 'chrome://extensions/' (Developer Mode)."
    } else {
        Write-Host "Chrome: Failed to find extracted uBlock Origin folder."
    }
} else {
    Write-Host "Chrome: Not detected, skipping installation."
}

# --- Edge Installation ---
Write-Host "Installing uBlock Origin v$version for Edge..."
if (Test-Path "$(Get-EdgeProfilePath)") {
    Write-Host "DEBUG: Edge profile found at $(Get-EdgeProfilePath)"
    # Enable Manifest V2
    $edgeRegistryPath = "HKLM:\Software\Policies\Microsoft\Edge"
    if (-not (Test-Path $edgeRegistryPath)) { New-Item -Path $edgeRegistryPath -Force -ErrorAction Stop }
    Set-ItemProperty -Path $edgeRegistryPath -Name "ExtensionManifestV2Availability" -Value 2 -Type DWord -Force -ErrorAction Stop
    # Enable Developer Mode
    $regPath = "HKCU:\Software\Microsoft\Edge"
    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force -ErrorAction Stop }
    Set-ItemProperty -Path $regPath -Name "DeveloperMode" -Value 1 -Type DWord -Force -ErrorAction Stop
    # Download and install
    Write-Host "DEBUG: Downloading Chromium zip..."
    Invoke-WebRequest -Uri $chromiumUrl -OutFile $zipPath -ErrorAction Stop
    Write-Host "DEBUG: Extracting to $extractPath..."
    Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force -ErrorAction Stop
    $extractedFolder = Get-ChildItem -Path $extractPath -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($extractedFolder) {
        Write-Host "DEBUG: Extracted folder found: $($extractedFolder.FullName)"
        # Rename folder to standard format
        $targetFolder = "$extractPath\1.64.0_0"
        if ($extractedFolder.FullName -ne $targetFolder) {
            Move-Item -Path $extractedFolder.FullName -Destination $targetFolder -Force -ErrorAction Stop
        }
        if (-not (Test-Path $edgeExtensionPath)) { New-Item -ItemType Directory -Path $edgeExtensionPath -Force -ErrorAction Stop }
        Write-Host "DEBUG: Moving to $edgeExtensionPath\$uBlockId..."
        Move-Item -Path $targetFolder -Destination "$edgeExtensionPath\$uBlockId" -Force -ErrorAction Stop
        Write-Host "Edge: uBlock Origin installed. Enable in 'edge://extensions/' (Developer Mode)."
    } else {
        Write-Host "Edge: Failed to find extracted uBlock Origin folder."
    }
} else {
    Write-Host "Edge: Not detected, skipping installation."
}

# --- Opera Installation ---
Write-Host "Installing uBlock Origin v$version for Opera..."
if (Test-Path "$env:APPDATA\Opera Software\Opera Stable") {
    Write-Host "DEBUG: Opera profile found at $env:APPDATA\Opera Software\Opera Stable"
    # Enable Developer Mode
    $regPath = "HKCU:\Software\Opera Software"
    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force -ErrorAction Stop }
    Set-ItemProperty -Path $regPath -Name "DeveloperMode" -Value 1 -Type DWord -Force -ErrorAction Stop
    # Download and install
    Write-Host "DEBUG: Downloading Chromium zip..."
    Invoke-WebRequest -Uri $chromiumUrl -OutFile $zipPath -ErrorAction Stop
    Write-Host "DEBUG: Extracting to $extractPath..."
    Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force -ErrorAction Stop
    $extractedFolder = Get-ChildItem -Path $extractPath -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($extractedFolder) {
        Write-Host "DEBUG: Extracted folder found: $($extractedFolder.FullName)"
        # Rename folder to standard format
        $targetFolder = "$extractPath\1.64.0_0"
        if ($extractedFolder.FullName -ne $targetFolder) {
            Move-Item -Path $extractedFolder.FullName -Destination $targetFolder -Force -ErrorAction Stop
        }
        if (-not (Test-Path $operaExtensionPath)) { New-Item -ItemType Directory -Path $operaExtensionPath -Force -ErrorAction Stop }
        Write-Host "DEBUG: Moving to $operaExtensionPath\$uBlockId..."
        Move-Item -Path $targetFolder -Destination "$operaExtensionPath\$uBlockId" -Force -ErrorAction Stop
        Write-Host "Opera: uBlock Origin installed. Enable in 'opera://extensions/' (Developer Mode)."
    } else {
        Write-Host "Opera: Failed to find extracted uBlock Origin folder."
    }
} else {
    Write-Host "Opera: Not detected, skipping installation."
}

# Clean up
Write-Host "DEBUG: Cleaning up $tempPath..."
Remove-Item $tempPath -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "uBlock Origin v$version installed for detected browsers."
Write-Host "For Chrome/Edge/Opera: Enable the extension in Developer Mode."
Write-Host "For all browsers: In uBlock Origin settings, ensure 'uBlock filters - Annoyances' and 'EasyList' are enabled for YouTube ad blocking."
Write-Host "If ads persist, update filter lists manually in uBlock Origin's dashboard."