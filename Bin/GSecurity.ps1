#Requires -RunAsAdministrator

<#
    GSecurity.ps1
    Author: Gorstak
    Description: Windows security script with improved YARA/Sigma parsing, optimized rule application, and enhanced telemetry
#>

# Define parameters
param (
    [switch]$Start,
    [string]$SnortOinkcode = "723e4cbaeb83692a45ef8dd4f9ab19461cb086ce",
    [switch]$DebugMode,
    [switch]$NonInteractive = $false,
    [switch]$NoMonitor = $false,
    [string]$ConfigPath = "$env:USERPROFILE\GSecurity_config.json"
)

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"  # Suppresses progress bars

# Add proper exit code handling
function Exit-Script {
    param (
        [int]$ExitCode = 0,
        [string]$Message = ""
    )
    
    if ($Message -ne "") {
        if ($ExitCode -ne 0) {
            Write-Log $Message -EntryType "Error"
        } else {
            Write-Log $Message -EntryType "Information"
        }
    }
    
    # Clean up any resources if needed
    exit $ExitCode
}

# Initialize Event Log source
if (-not [System.Diagnostics.EventLog]::SourceExists("SecureWindows")) {
    New-EventLog -LogName "Application" -Source "SecureWindows"
}

# Log function with truncation and file logging
function Write-Log {
    param ([string]$Message, [string]$EntryType = "Information")
    $maxEventLogLength = 32766
    $logDir = "$env:TEMP\security_rules\logs"
    $logFile = "$logDir\SecureWindows_$(Get-Date -Format 'yyyyMMdd').log"
    
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    
    $truncatedMessage = if ($Message.Length -gt $maxEventLogLength) {
        $Message.Substring(0, $maxEventLogLength - 100) + "... [Truncated, see log file]"
    } else {
        $Message
    }
    
    if (-not $NonInteractive) {
        Write-Host "[$EntryType] $truncatedMessage" -ForegroundColor $(switch ($EntryType) { "Error" { "Red" } "Warning" { "Yellow" } default { "White" } })
    }
    
    $logEntry = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$EntryType] $Message"
    $logEntry | Out-File -FilePath $logFile -Append -Encoding UTF8
    
    try {
        Write-EventLog -LogName "Application" -Source "SecureWindows" -EventId 1000 -EntryType $EntryType -Message $truncatedMessage -ErrorAction Stop
    }
    catch {
        $errorMsg = "Failed to write to Event Log: $_ (Message length: $($truncatedMessage.Length))"
        if (-not $NonInteractive) {
            Write-Host "[$EntryType] $errorMsg" -ForegroundColor Red
        }
        $errorMsg | Out-File -FilePath $logFile -Append -Encoding UTF8
    }
}

# Initialize or load configuration
function Initialize-Config {
    if (Test-Path $ConfigPath) {
        try {
            $config = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json
            Write-Log "Loaded configuration from $ConfigPath"
            return $config
        }
        catch {
            Write-Log "Error loading configuration: $_" -EntryType "Warning"
        }
    }
    
    # Default configuration
    $config = @{
        Sources = @{
            YaraForge = "https://github.com/YARAHQ/yara-forge/releases"
            YaraRules = "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip"
            SigmaHQ = "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip"
            EmergingThreats = "https://rules.emergingthreats.net/open/snort-3.0.0/emerging.rules.tar.gz"
            SnortCommunity = "https://www.snort.org/downloads/community/community-rules.tar.gz"
        }
        ExcludedSystemFiles = @(
            "svchost.exe", "lsass.exe", "cmd.exe", "explorer.exe", "winlogon.exe", 
            "csrss.exe", "services.exe", "msiexec.exe", "conhost.exe", "dllhost.exe", 
            "WmiPrvSE.exe", "MsMpEng.exe", "TrustedInstaller.exe", "spoolsv.exe", "LogonUI.exe"
        )
        Telemetry = @{
            Enabled = $true
            MaxEvents = 1000
            Path = "$env:TEMP\security_rules\telemetry.json"
        }
        RetrySettings = @{
            MaxRetries = 3
            RetryDelaySeconds = 5
            UseExponentialBackoff = $true
        }
        FirewallBatchSize = 50
    }
    
    # Save configuration
    $config | ConvertTo-Json -Depth 4 | Out-File -FilePath $ConfigPath -Encoding UTF8
    Write-Log "Created default configuration at $ConfigPath"
    return $config
}

# Validate URL accessibility with retry
function Test-Url {
    param (
        [string]$Uri,
        [int]$MaxRetries = 3,
        [int]$InitialDelay = 2
    )
    
    $attempt = 0
    $delay = $InitialDelay
    
    while ($attempt -lt $MaxRetries) {
        try {
            $response = Invoke-WebRequest -Uri $Uri -Method Head -UseBasicParsing -TimeoutSec 10
            return $response.StatusCode -eq 200
        }
        catch {
            $attempt++
            Write-Log "URL validation failed for ${Uri}: $_ (Status: $($_.Exception.Response.StatusCode))" -EntryType "Warning"
            
            if ($attempt -ge $MaxRetries) {
                return $false
            }
            
            # Exponential backoff
            Start-Sleep -Seconds $delay
            $delay *= 2
        }
    }
    return $false
}

# Check if rule source has been updated
function Test-RuleSourceUpdated {
    param (
        [string]$Uri,
        [string]$LocalFile,
        [int]$MaxRetries = 3
    )
    
    $attempt = 0
    $delay = 2
    
    while ($attempt -lt $MaxRetries) {
        try {
            Write-Log "Checking update for ${Uri}..."
            $webRequest = Invoke-WebRequest -Uri $Uri -Method Head -UseBasicParsing -TimeoutSec 15
            $lastModified = $webRequest.Headers['Last-Modified']
            
            if ($lastModified) {
                $lastModifiedDate = [DateTime]::Parse($lastModified)
                if (Test-Path $LocalFile) {
                    $fileLastModified = (Get-Item $LocalFile).LastWriteTime
                    return $lastModifiedDate -gt $fileLastModified
                }
                return $true
            }
            return $true
        }
        catch {
            $attempt++
            Write-Log "Error checking update for ${Uri}: $_ (Status: $($_.Exception.Response.StatusCode))" -EntryType "Warning"
            
            if ($attempt -ge $MaxRetries) {
                return $true
            }
            
            # Exponential backoff
            Start-Sleep -Seconds $delay
            $delay *= 2
        }
    }
    return $true
}

# Get latest YARA Forge release URL
function Get-YaraForgeUrl {
    try {
        $releases = Invoke-WebRequest -Uri "https://api.github.com/repos/YARAHQ/yara-forge/releases" -UseBasicParsing
        $latest = ($releases.Content | ConvertFrom-Json)[0]
        $asset = $latest.assets | Where-Object { $_.name -match "yara-forge-.*-full\.zip|rules-full\.zip" } | Select-Object -First 1
        if ($asset) {
            Write-Log "Found YARA Forge release: $($asset.name)"
            return $asset.browser_download_url
        }
        Write-Log "No valid YARA Forge full zip found" -EntryType "Warning"
        return $null
    }
    catch {
        Write-Log "Error fetching YARA Forge release: $_" -EntryType "Warning"
        return $null
    }
}

# Count individual YARA rules in a file
function Get-YaraRuleCount {
    param ([string]$FilePath)
    try {
        if (-not (Test-Path $FilePath)) { return 0 }
        $content = Get-Content $FilePath -Raw
        $ruleMatches = [regex]::Matches($content, 'rule\s+\w+\s*{')
        return $ruleMatches.Count
    }
    catch {
        Write-Log "Error counting rules in ${FilePath}: $_" -EntryType "Warning"
        return 0
    }
}

# Improved web request with retry and exponential backoff
function Invoke-WebRequestWithRetry {
    param (
        [string]$Uri, 
        [string]$OutFile, 
        [int]$MaxRetries = 3,
        [int]$InitialDelay = 5,
        [switch]$UseExponentialBackoff
    )
    
    $attempt = 0
    $delay = $InitialDelay
    
    while ($attempt -lt $MaxRetries) {
        try {
            Write-Log "Downloading ${Uri} (Attempt $(${attempt}+1))..."
            Invoke-WebRequest -Uri $Uri -OutFile $OutFile -TimeoutSec 30 -UseBasicParsing
            return $true
        }
        catch {
            $attempt++
            $statusCode = if ($_.Exception.Response) { $_.Exception.Response.StatusCode } else { "Unknown" }
            Write-Log "Download attempt $attempt for ${Uri} failed: $_ (Status: $statusCode)" -EntryType "Warning"
            
            if ($attempt -eq $MaxRetries) { 
                return $false 
            }
            
            # Apply backoff
            Start-Sleep -Seconds $delay
            if ($UseExponentialBackoff) {
                $delay *= 2
            }
        }
    }
    return $false
}

# Download and verify YARA, Sigma, and Snort rules
function Get-SecurityRules {
    param ($Config)
    
    $tempDir = "$env:TEMP\security_rules"
    if (-not (Test-Path $tempDir)) { New-Item -ItemType Directory -Path $tempDir -Force | Out-Null }
    $successfulSources = @()
    $rules = @{ Yara = @(); Sigma = @(); Snort = @() }

    try {
        Add-MpPreference -ExclusionPath $tempDir
        Write-Log "Added Defender exclusion for $tempDir"

        # YARA Forge rules
        Write-Log "Processing YARA Forge rules..."
        $yaraForgeDir = "$tempDir\yara_forge"
        $yaraForgeZip = "$tempDir\yara_forge.zip"
        if (-not (Test-Path $yaraForgeDir)) { New-Item -ItemType Directory -Path $yaraForgeDir -Force | Out-Null }
        $yaraForgeUri = Get-YaraForgeUrl
        $yaraRuleCount = 0
        
        if (-not $yaraForgeUri) {
            Write-Log "YARA Forge URL unavailable, trying fallback..." -EntryType "Warning"
        }
        elseif (Test-Url -Uri $yaraForgeUri) {
            if (Test-RuleSourceUpdated -Uri $yaraForgeUri -LocalFile $yaraForgeZip) {
                if (Invoke-WebRequestWithRetry -Uri $yaraForgeUri -OutFile $yaraForgeZip -UseExponentialBackoff) {
                    Start-MpScan -ScanPath $yaraForgeZip -ScanType CustomScan
                    Expand-Archive -Path $yaraForgeZip -DestinationPath $yaraForgeDir -Force
                    Write-Log "Downloaded and extracted YARA Forge rules"
                    $rules.Yara = Get-ChildItem -Path $yaraForgeDir -Recurse -Include "*.yar","*.yara" -ErrorAction SilentlyContinue
                    foreach ($file in $rules.Yara) {
                        $yaraRuleCount += Get-YaraRuleCount -FilePath $file.FullName
                    }
                    Write-Log "Found $($rules.Yara.Count) YARA Forge files with $yaraRuleCount individual rules in $yaraForgeDir"
                    $successfulSources += "YARA Forge"
                } else {
                    Write-Log "Failed to download YARA Forge rules after retries, trying fallback..." -EntryType "Warning"
                }
            } else {
                Write-Log "YARA Forge rules are up to date"
                $rules.Yara = Get-ChildItem -Path $yaraForgeDir -Recurse -Include "*.yar","*.yara" -ErrorAction SilentlyContinue
                foreach ($file in $rules.Yara) {
                    $yaraRuleCount += Get-YaraRuleCount -FilePath $file.FullName
                }
                Write-Log "Found $($rules.Yara.Count) YARA Forge files with $yaraRuleCount individual rules in $yaraForgeDir"
                $successfulSources += "YARA Forge"
            }
        } else {
            Write-Log "YARA Forge URL is invalid, trying fallback..." -EntryType "Warning"
        }

        # Yara-Rules fallback
        if (-not ($successfulSources -contains "YARA Forge") -or $yaraRuleCount -lt 10) {
            Write-Log "Processing Yara-Rules as fallback due to low YARA Forge rule count ($yaraRuleCount)..."
            $yaraRulesDir = "$tempDir\yara_rules"
            $yaraRulesZip = "$tempDir\yara_rules.zip"
            if (-not (Test-Path $yaraRulesDir)) { New-Item -ItemType Directory -Path $yaraRulesDir -Force | Out-Null }
            $yaraRulesUri = $Config.Sources.YaraRules
            
            if (Test-Url -Uri $yaraRulesUri) {
                if (Test-RuleSourceUpdated -Uri $yaraRulesUri -LocalFile $yaraRulesZip) {
                    if (Invoke-WebRequestWithRetry -Uri $yaraRulesUri -OutFile $yaraRulesZip -UseExponentialBackoff) {
                        Start-MpScan -ScanPath $yaraRulesZip -ScanType CustomScan
                        Expand-Archive -Path $yaraRulesZip -DestinationPath $yaraRulesDir -Force
                        Write-Log "Downloaded and extracted Yara-Rules"
                        $yaraRulesFiles = Get-ChildItem -Path $yaraRulesDir -Recurse -Include "*.yar","*.yara" -ErrorAction SilentlyContinue
                        $rules.Yara += $yaraRulesFiles
                        $yaraRuleCount = 0
                        foreach ($file in $yaraRulesFiles) {
                            $yaraRuleCount += Get-YaraRuleCount -FilePath $file.FullName
                        }
                        Write-Log "Found $($yaraRulesFiles.Count) Yara-Rules files with $yaraRuleCount individual rules in $yaraRulesDir"
                        $successfulSources += "Yara-Rules"
                    } else {
                        Write-Log "Failed to download Yara-Rules after retries, skipping..." -EntryType "Warning"
                    }
                } else {
                    Write-Log "Yara-Rules are up to date"
                    $yaraRulesFiles = Get-ChildItem -Path $yaraRulesDir -Recurse -Include "*.yar","*.yara" -ErrorAction SilentlyContinue
                    $rules.Yara += $yaraRulesFiles
                    $yaraRuleCount = 0
                    foreach ($file in $yaraRulesFiles) {
                        $yaraRuleCount += Get-YaraRuleCount -FilePath $file.FullName
                    }
                    Write-Log "Found $($yaraRulesFiles.Count) Yara-Rules files with $yaraRuleCount individual rules in $yaraRulesDir"
                    $successfulSources += "Yara-Rules"
                }
            } else {
                Write-Log "Yara-Rules URL is invalid, skipping..." -EntryType "Warning"
            }
        }

        # SigmaHQ rules
        Write-Log "Processing SigmaHQ rules..."
        $sigmaDir = "$tempDir\sigma"
        $sigmaZip = "$tempDir\sigma_rules.zip"
        if (-not (Test-Path $sigmaDir)) { New-Item -ItemType Directory -Path $sigmaDir -Force | Out-Null }
        $sigmaUri = $Config.Sources.SigmaHQ
        
        if (Test-Url -Uri $sigmaUri) {
            if (Test-RuleSourceUpdated -Uri $sigmaUri -LocalFile $sigmaZip) {
                if (Invoke-WebRequestWithRetry -Uri $sigmaUri -OutFile $sigmaZip -UseExponentialBackoff) {
                    Start-MpScan -ScanPath $sigmaZip -ScanType CustomScan
                    Expand-Archive -Path $sigmaZip -DestinationPath $sigmaDir -Force
                    Write-Log "Downloaded and extracted SigmaHQ rules"
                    $successfulSources += "SigmaHQ"
                } else {
                    Write-Log "Failed to download SigmaHQ rules after retries, skipping..." -EntryType "Warning"
                }
            } else {
                Write-Log "SigmaHQ rules are up to date"
                $successfulSources += "SigmaHQ"
            }
        } else {
            Write-Log "SigmaHQ URL is invalid, skipping..." -EntryType "Warning"
        }
        
        $sigmaRulesPath = "$sigmaDir\sigma-master\rules"
        if (Test-Path $sigmaRulesPath) {
            $rules.Sigma = Get-ChildItem -Path $sigmaRulesPath -Recurse -Include "*.yml" -Exclude "*deprecated*" -ErrorAction SilentlyContinue
            Write-Log "Found $($rules.Sigma.Count) Sigma rules in $sigmaRulesPath"
        } else {
            Write-Log "Sigma rules directory $sigmaRulesPath does not exist" -EntryType "Warning"
        }

        # Snort Community rules
        Write-Log "Processing Snort Community rules..."
        $snortRules = "$tempDir\snort_community.rules"
        $snortUri = if ($SnortOinkcode) {
            "$($Config.Sources.SnortCommunity)?oinkcode=$SnortOinkcode"
        } else {
            Write-Log "No Snort Oinkcode provided. Snort Community rules require an Oinkcode from https://www.snort.org/users/sign_up" -EntryType "Warning"
            $null
        }
        
        if ($snortUri -and (Test-Url -Uri $snortUri)) {
            if (Test-RuleSourceUpdated -Uri $snortUri -LocalFile $snortRules) {
                if (Invoke-WebRequestWithRetry -Uri $snortUri -OutFile $snortRules -UseExponentialBackoff) {
                    Start-MpScan -ScanPath $snortRules -ScanType CustomScan
                    try {
                        Write-Log "Checking Snort Community hash..."
                        $snortPage = Invoke-WebRequest -Uri "https://www.snort.org/downloads" -UseBasicParsing -TimeoutSec 15
                        if ($snortPage.Content -match 'community-rules\.tar\.gz\.md5.*([a-f0-9]{32})') {
                            $expectedHash = $matches[1]
                            $fileHash = (Get-FileHash -Path $snortRules -Algorithm MD5).Hash
                            if ($fileHash -ne $expectedHash) {
                                Write-Log "Snort Community rules hash mismatch!" -EntryType "Error"
                                throw "Snort Community rules hash verification failed"
                            }
                            Write-Log "Snort Community rules hash verified"
                        } else {
                            Write-Log "Snort Community hash not found, proceeding without verification" -EntryType "Warning"
                        }
                    }
                    catch {
                        Write-Log "Error checking Snort Community hash: $_" -EntryType "Warning"
                    }
                    Write-Log "Downloaded Snort Community rules"
                    $successfulSources += "Snort Community"
                    $rules.Snort += $snortRules
                } else {
                    Write-Log "Failed to download Snort Community rules after retries, trying fallback..." -EntryType "Warning"
                }
            } else {
                Write-Log "Snort Community rules are up to date"
                $successfulSources += "Snort Community"
                $rules.Snort += $snortRules
            }
        } else {
            Write-Log "Snort Community URL is invalid or no Oinkcode provided, trying fallback..." -EntryType "Warning"
        }

        # Emerging Threats fallback
        if (-not ($successfulSources -contains "Snort Community")) {
            Write-Log "Processing Emerging Threats rules as fallback..."
            $emergingRules = "$tempDir\snort_emerging.rules"
            $emergingUri = $Config.Sources.EmergingThreats
            $emergingTar = "$tempDir\emerging_rules.tar.gz"
            
            if (Test-Url -Uri $emergingUri) {
                if (Test-RuleSourceUpdated -Uri $emergingUri -LocalFile $emergingTar) {
                    if (Invoke-WebRequestWithRetry -Uri $emergingUri -OutFile $emergingTar -UseExponentialBackoff) {
                        Start-MpScan -ScanPath $emergingTar -ScanType CustomScan
                        try {
                            $hashUri = "https://rules.emergingthreats.net/open/snort-3.0.0/emerging.rules.tar.gz.md5"
                            $hashResponse = Invoke-WebRequest -Uri $hashUri -UseBasicParsing -TimeoutSec 15
                            if ($hashResponse.Content -match '([a-f0-9]{32})') {
                                $expectedHash = $matches[1]
                                $fileHash = (Get-FileHash -Path $emergingTar -Algorithm MD5).Hash
                                if ($fileHash -ne $expectedHash) {
                                    Write-Log "Emerging Threats rules hash mismatch!" -EntryType "Error"
                                    throw "Emerging Threats rules hash verification failed"
                                }
                                Write-Log "Emerging Threats rules hash verified"
                            } else {
                                Write-Log "Emerging Threats hash not found, proceeding without verification" -EntryType "Warning"
                            }
                        }
                        catch {
                            Write-Log "Error checking Emerging Threats hash: $_" -EntryType "Warning"
                        }
                        
                        # Extract tar.gz file
                        try {
                            tar -xzf $emergingTar -C $tempDir
                            if (Test-Path "$tempDir\rules") {
                                Move-Item -Path "$tempDir\rules\*.rules" -Destination $emergingRules -Force
                                Write-Log "Downloaded and extracted Emerging Threats rules"
                                $successfulSources += "Emerging Threats"
                                $rules.Snort += $emergingRules
                            } else {
                                Write-Log "Emerging Threats extraction failed: rules directory not found" -EntryType "Warning"
                            }
                        }
                        catch {
                            Write-Log "Error extracting Emerging Threats rules: $_" -EntryType "Warning"
                        }
                    } else {
                        Write-Log "Failed to download Emerging Threats rules after retries, skipping..." -EntryType "Warning"
                    }
                } else {
                    Write-Log "Emerging Threats rules are up to date"
                    $successfulSources += "Emerging Threats"
                    $rules.Snort += $emergingRules
                }
            } else {
                Write-Log "Emerging Threats URL is invalid, skipping..." -EntryType "Warning"
            }
        }

        if ($successfulSources.Count -eq 0) {
            Write-Log "No rule sources were successfully processed!" -EntryType "Error"
            throw "No valid rule sources available"
        }
        
        Write-Log "Successfully processed rules from: $($successfulSources -join ', ')"
        return $rules
    }
    catch {
        Write-Log "Error in Get-SecurityRules: $_" -EntryType "Error"
        return $rules
    }
}

# Parse rules for actionable indicators - FIXED VERSION
function Parse-Rules {
    param (
        $Rules,
        $Config
    )

    $indicators = @()
    $batchSize = 1000
    $systemFiles = $Config.ExcludedSystemFiles
    $debugSamples = @()
    $isDebug = $DebugMode -or (-not (Test-Path "$env:TEMP\security_rules\debug_done.txt"))

    if ($isDebug -and -not $DebugMode) {
        Write-Log "Debug mode enabled for first run to capture unmatched rule samples"
    }

    # YARA rule parsing - FIXED
    Write-Log "Parsing YARA rules..."
    $yaraCount = $Rules.Yara.Count
    $processed = 0
    $yaraBatches = [math]::Ceiling($yaraCount / $batchSize)
    
    for ($i = 0; $i -lt $yaraBatches; $i++) {
        $batch = $Rules.Yara | Select-Object -Skip ($i * $batchSize) -First $batchSize
        foreach ($rule in $batch) {
            try {
                if (-not (Test-Path $rule.FullName)) { continue }
                $content = Get-Content $rule.FullName -Raw -ErrorAction Stop
                
                # Fixed hash extraction - simplified quote matching
                $hashPatterns = @(
                    "(?i)meta:.*?(md5|hash)\s*=\s*(\""|')([a-f0-9]{32})(\""|')",
                    "(?i)meta:.*?(sha1|hash1)\s*=\s*(\""|')([a-f0-9]{40})(\""|')",
                    "(?i)meta:.*?(sha256|hash256)\s*=\s*(\""|')([a-f0-9]{64})(\""|')",
                    "(?i)\$[a-z0-9_]*\s*=\s*(\""|')([a-f0-9]{32,64})(\""|').*?\/\*\s*(md5|sha1|sha256)\s*\*\/"
                )
                
                foreach ($pattern in $hashPatterns) {
                    $matches = [regex]::Matches($content, $pattern)
                    foreach ($match in $matches) {
                        $hash = $match.Groups[3].Value
                        $indicators += @{ Type = "Hash"; Value = $hash; Source = "YARA"; RuleFile = $rule.Name }
                        Write-Log "Found YARA hash: $hash in $($rule.FullName)"
                    }
                }
                
                # Improved filename extraction
                $filenamePatterns = @(
                    "(?i)meta:.*?(filename|file_name|original_filename)\s*=\s*(\""|')([^\""']+\.(exe|dll|bat|ps1|scr|cmd))(\""|')",
                    "(?i)\$[a-z0-9_]*\s*=\s*(\""|')([^\""']*\.(exe|dll|bat|ps1|scr|cmd))(\""|')",
                    "(?i)fullword\s+ascii\s+(\""|')([^\""']*\.(exe|dll|bat|ps1|scr|cmd))(\""|')"
                )
                
                foreach ($pattern in $filenamePatterns) {
                    $matches = [regex]::Matches($content, $pattern)
                    foreach ($match in $matches) {
                        $fileName = $match.Groups[3].Value -replace '\\\\', '\'
                        $baseFileName = [System.IO.Path]::GetFileName($fileName)
                        if ($baseFileName -and $baseFileName -notin $systemFiles) {
                            $indicators += @{ Type = "FileName"; Value = $baseFileName; Source = "YARA"; RuleFile = $rule.Name }
                            Write-Log "Found YARA filename: $baseFileName in $($rule.FullName)"
                        }
                    }
                }
                
                # Extract domains and URLs
                $domainPatterns = @(
                    "(?i)meta:.*?(domain|url|c2|command_and_control)\s*=\s*(\""|')([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\""|')",
                    "(?i)\$[a-z0-9_]*\s*=\s*(\""|')https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\""|')",
                    "(?i)fullword\s+ascii\s+(\""|')https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\""|')"
                )
                
                foreach ($pattern in $domainPatterns) {
                    $matches = [regex]::Matches($content, $pattern)
                    foreach ($match in $matches) {
                        $domain = $match.Groups[3].Value
                        $indicators += @{ Type = "Domain"; Value = $domain; Source = "YARA"; RuleFile = $rule.Name }
                        Write-Log "Found YARA domain: $domain in $($rule.FullName)"
                    }
                }
                
                # Debug unmatched rules
                if ($isDebug -and -not ($indicators | Where-Object { $_.Source -eq "YARA" -and $_.RuleFile -eq $rule.Name })) {
                    $sample = $content -split '\n' | Select-Object -First 10
                    $debugSamples += "YARA rule $($rule.FullName) no match:`n$($sample -join '`n')`n"
                }
                
                $processed++
                if ($processed % 25 -eq 0 -or $processed -eq $yaraCount) {
                    Write-Log "Processed $processed/$yaraCount YARA rules"
                }
            }
            catch {
                Write-Log "Error parsing YARA rule $($rule.FullName): $_" -EntryType "Warning"
            }
        }
    }
    
    if ($indicators.Where({$_.Source -eq "YARA"}).Count -eq 0) {
        Write-Log "No indicators extracted from YARA rules" -EntryType "Warning"
        if ($isDebug -and $debugSamples) {
            $debugSamplesFile = "$env:TEMP\security_rules\yara_debug_samples.txt"
            $debugSamples | Out-File -FilePath $debugSamplesFile -Encoding UTF8
            Write-Log "Debug: Saved unmatched YARA rule samples to $debugSamplesFile" -EntryType "Warning"
        }
    }

    # Sigma rule parsing
    Write-Log "Parsing Sigma rules..."
    $sigmaCount = $Rules.Sigma.Count
    $processed = 0
    $sigmaBatches = [math]::Ceiling($sigmaCount / $batchSize)
    $yamlModule = Get-Module -ListAvailable -Name PowerShell-YAML
    
    for ($i = 0; $i -lt $sigmaBatches; $i++) {
        $batch = $Rules.Sigma | Select-Object -Skip ($i * $batchSize) -First $batchSize
        foreach ($rule in $batch) {
            try {
                if (-not (Test-Path $rule.FullName)) { continue }
                $content = Get-Content $rule.FullName -Raw -ErrorAction Stop
                $fileNames = @()
                
                if ($yamlModule) {
                    # Parse YAML if module is available
                    $yaml = ConvertFrom-Yaml -Yaml $content -ErrorAction Stop
                    
                    # Check detection section
                    if ($yaml.detection) {
                        # Process selection criteria
                        foreach ($selectionKey in $yaml.detection.Keys) {
                            $selection = $yaml.detection[$selectionKey]
                            if ($selection -is [hashtable] -or $selection -is [System.Collections.Specialized.OrderedDictionary]) {
                                foreach ($key in @('Image', 'TargetFilename', 'CommandLine', 'ParentImage', 'OriginalFileName', 'ProcessName', 'FileName')) {
                                    $value = $selection[$key]
                                    if ($value -is [string] -and $value -match '\.(exe|dll|bat|ps1|scr|cmd)$') {
                                        $fileName = [System.IO.Path]::GetFileName($value)
                                        if ($fileName -and $fileName -notin $systemFiles) {
                                            $fileNames += $fileName
                                        }
                                    }
                                    elseif ($value -is [array]) {
                                        foreach ($item in $value) {
                                            if ($item -is [string] -and $item -match '\.(exe|dll|bat|ps1|scr|cmd)$') {
                                                $fileName = [System.IO.Path]::GetFileName($item)
                                                if ($fileName -and $fileName -notin $systemFiles) {
                                                    $fileNames += $fileName
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                } 
                else {
                    # Fallback to regex if YAML module is not available
                    $filenamePatterns = @(
                        "(?i)(Image|TargetFilename|CommandLine|ParentImage|OriginalFileName|ProcessName|FileName):\s*['""]?.*?\\([^\s\\|]+?\.(exe|dll|bat|ps1|scr|cmd))['""]?",
                        "(?i)(Image|TargetFilename|CommandLine|ParentImage|OriginalFileName|ProcessName|FileName):\s*['""]?([^\s\\|/]+?\.(exe|dll|bat|ps1|scr|cmd))['""]?"
                    )
                    
                    foreach ($pattern in $filenamePatterns) {
                        if ($content -match $pattern) {
                            $fileName = $matches[2]
                            if ($fileName -and $fileName -notin $systemFiles) {
                                $fileNames += $fileName
                            }
                        }
                    }
                }
                
                # Add unique filenames to indicators
                $fileNames = $fileNames | Select-Object -Unique
                foreach ($fileName in $fileNames) {
                    $indicators += @{ Type = "FileName"; Value = $fileName; Source = "Sigma"; RuleFile = $rule.Name }
                    Write-Log "Found Sigma filename: $fileName in $($rule.FullName)"
                }
                
                # Debug unmatched rules
                if ($isDebug -and -not $fileNames) {
                    $sample = $content -split '\n' | Select-Object -First 10
                    $debugSamples += "Sigma rule $($rule.FullName) no match:`n$($sample -join '`n')`n"
                }
                
                $processed++
                if ($processed % 1000 -eq 0 -or $processed -eq $sigmaCount) {
                    Write-Log "Processed $processed/$sigmaCount Sigma rules"
                }
            }
            catch {
                Write-Log "Error parsing Sigma rule $($rule.FullName): $_" -EntryType "Warning"
            }
        }
    }
    
    if ($indicators.Where({$_.Source -eq "Sigma"}).Count -eq 0) {
        Write-Log "No indicators extracted from Sigma rules" -EntryType "Warning"
        if ($isDebug -and $debugSamples) {
            $debugSamplesFile = "$env:TEMP\security_rules\sigma_debug_samples.txt"
            $debugSamples | Out-File -FilePath $debugSamplesFile -Encoding UTF8
            Write-Log "Debug: Saved unmatched Sigma rule samples to $debugSamplesFile" -EntryType "Warning"
        }
    }

    # Snort rule parsing
    Write-Log "Parsing Snort rules..."
    $totalIPs = 0
    $totalDomains = 0
    $ipList = @()
    $domainList = @()
    
    foreach ($snortFile in $Rules.Snort) {
        if (Test-Path $snortFile) {
            try {
                $lines = Get-Content $snortFile -ErrorAction Stop
                $lineCount = $lines.Count
                $processed = 0
                
                for ($i = 0; $i -lt $lineCount; $i++) {
                    $line = $lines[$i]
                    
                    # Extract IPs from traditional format
                    if ($line -match '(?:^|\s)(?:alert|log|pass|drop|reject|sdrop)\s+\w+\s+(?:\$\w+\s+)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:/\d{1,2})?\s+\w+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:/\d{1,2})?') {
                        $srcIp = $matches[1]
                        $dstIp = $matches[2]
                        
                        foreach ($ip in @($srcIp, $dstIp)) {
                            if ($ip -notmatch "^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.|0\.)") {
                                $ipList += @{ Type = "IP"; Value = $ip; Source = "Snort"; RuleFile = [System.IO.Path]::GetFileName($snortFile) }
                                $totalIPs++
                                Write-Log "Found Snort IP: $ip in $snortFile"
                            }
                        }
                    }
                    
                    # Extract IPs from Emerging Threats format (e.g., [IP1,IP2,...])
                    if ($line -match '\[((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:,\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})*))\]') {
                        $ipString = $matches[1]
                        $ips = $ipString -split ',' | ForEach-Object { $_.Trim() }
                        foreach ($ip in $ips) {
                            if ($ip -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$' -and $ip -notmatch "^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.|0\.)") {
                                $ipList += @{ Type = "IP"; Value = $ip; Source = "Snort"; RuleFile = [System.IO.Path]::GetFileName($snortFile) }
                                $totalIPs++
                                Write-Log "Found Snort IP: $ip in $snortFile (Emerging Threats format)"
                            }
                        }
                    }
                    
                    # Extract domains
                    if ($line -match "content:.*?(\""|')([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\""|')") {
                        $domain = $matches[2]
                        $domainList += @{ Type = "Domain"; Value = $domain; Source = "Snort"; RuleFile = [System.IO.Path]::GetFileName($snortFile) }
                        $totalDomains++
                        Write-Log "Found Snort domain: $domain in $snortFile"
                    }
                    
                    $processed++
                    if ($processed % 250 -eq 0) {
                        Write-Log "Processed $processed/$lineCount lines in ${snortFile}"
                    }
                }
                
                Write-Log "Completed parsing $processed/$lineCount lines in ${snortFile}"
            }
            catch {
                Write-Log "Error parsing Snort file ${snortFile}: $_" -EntryType "Warning"
            }
        } else {
            Write-Log "Snort file ${snortFile} does not exist" -EntryType "Warning"
        }
    }
    
    # Add unique IPs and domains
    $indicators += $ipList
    $indicators += $domainList
    
    $uniqueIPs = ($ipList | Select-Object -Property Value -Unique).Count
    $uniqueDomains = ($domainList | Select-Object -Property Value -Unique).Count
    
    Write-Log "Extracted $totalIPs total IPs ($uniqueIPs unique), $totalDomains domains ($uniqueDomains unique) from Snort rules"
    
    if ($indicators.Where({$_.Source -eq "Snort"}).Count -eq 0) {
        Write-Log "No indicators extracted from Snort rules" -EntryType "Warning"
    }

    # Log all indicators before deduplication
    Write-Log "All indicators before deduplication: $($indicators.Count) total"
    
    # Improved deduplication that preserves source information
    $uniqueIndicators = @()
    $indicators | Group-Object -Property Type, Value | ForEach-Object {
        $uniqueIndicator = $_.Group[0]
        if ($_.Group[0].PSObject.Properties.Name -contains "Source") {
            $sources = ($_.Group | Select-Object -ExpandProperty Source -Unique) -join ','
            $uniqueIndicator.Source = $sources
        } else {
            $uniqueIndicator | Add-Member -NotePropertyName "Source" -NotePropertyValue "Unknown" -Force
        }
        $uniqueIndicators += $uniqueIndicator
    }
    
    Write-Log "Parsed $($uniqueIndicators.Count) unique indicators from rules (Hashes: $($uniqueIndicators.Where({$_.Type -eq 'Hash'}).Count), Files: $($uniqueIndicators.Where({$_.Type -eq 'FileName'}).Count), IPs: $($uniqueIndicators.Where({$_.Type -eq 'IP'}).Count), Domains: $($uniqueIndicators.Where({$_.Type -eq 'Domain'}).Count))."

    if ($isDebug -and -not $DebugMode) {
        New-Item -Path "$env:TEMP\security_rules\debug_done.txt" -ItemType File -Force | Out-Null
    }
    
    return $uniqueIndicators
}

# Apply rules to Windows Defender ASR, Firewall, and Custom Threats
function Apply-SecurityRules {
    param (
        $Indicators,
        $Config
    )

    Write-Log "Applying security rules..."
    
    # Clean up existing firewall and custom threat rules
    try {
        $existingFirewallRules = Get-NetFirewallRule -Name "Block_C2_*" -ErrorAction SilentlyContinue
        if ($existingFirewallRules) {
            $existingFirewallRules | Remove-NetFirewallRule -ErrorAction SilentlyContinue
            Write-Log "Removed $($existingFirewallRules.Count) existing firewall rules"
        }
        
        # Remove existing custom threat definitions
        $existingThreats = Get-MpThreatDetection | Where-Object { $_.ThreatName -like "GSecurity_*" }
        foreach ($threat in $existingThreats) {
            try {
                Remove-MpThreat -ThreatID $threat.ThreatID -ErrorAction SilentlyContinue
                Write-Log "Removed existing custom threat: $($threat.ThreatName)"
            }
            catch {
                Write-Log "Error removing custom threat $($threat.ThreatName): $_" -EntryType "Warning"
            }
        }
    }
    catch {
        Write-Log "Error cleaning up existing rules: $_" -EntryType "Warning"
    }
    
    # Apply custom threat definitions for hashes
    $hashIndicators = $Indicators | Where-Object { $_.Type -eq "Hash" }
    $hashCount = $hashIndicators.Count
    $processedHash = 0
    
    foreach ($indicator in $hashIndicators) {
        try {
            $hash = $indicator.Value
            $threatName = "GSecurity_Hash_$hash"
            $description = "Malicious file hash detected from $($indicator.Source) rules"
            
            # Create a temporary file with the hash for Windows Defender to process
            $tempFile = "$env:TEMP\GSecurity_threat_$hash.txt"
            $hash | Out-File -FilePath $tempFile -Encoding ASCII
            
            # Add the hash as a custom threat
            Add-MpPreference -ThreatIDDefaultAction_Actions Block -ThreatIDDefaultAction_Ids $threatName
            Add-MpPreference -SubmissionFile $tempFile
            Write-Log "Added custom threat for hash: $hash"
            $processedHash++
            
            # Clean up
            Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
        }
        catch {
            Write-Log "Error applying custom threat for hash $($indicator.Value): $_" -EntryType "Warning"
        }
    }
    
    # Apply ASR rules for suspicious filenames
    $fileIndicators = $Indicators | Where-Object { $_.Type -eq "FileName" }
    $asrCount = $fileIndicators.Count
    $processedAsr = 0
    
    # Configure the predefined ASR rule (optional, for broader protection)
    $asrRuleId = "e6db77e5-3df2-4cf1-b95a-636979351e5b" # Block executable files unless trusted
    try {
        $asrRules = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids -ErrorAction SilentlyContinue
        $asrActions = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions -ErrorAction SilentlyContinue
        
        $asrIndex = $null
        if ($asrRules) {
            $asrIndex = $asrRules.IndexOf($asrRuleId)
        }
        
        if ($asrIndex -ge 0) {
            if ($asrActions[$asrIndex] -ne 1) {
                Add-MpPreference -AttackSurfaceReductionRules_Ids $asrRuleId -AttackSurfaceReductionRules_Actions Enabled
                Write-Log "Enabled existing ASR rule $asrRuleId"
            }
        }
        else {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $asrRuleId -AttackSurfaceReductionRules_Actions Enabled
            Write-Log "Added and enabled ASR rule $asrRuleId"
        }
    }
    catch {
        Write-Log "Error configuring ASR rule: $_" -EntryType "Warning"
    }
    
    # Add filename-based custom threats
    foreach ($indicator in $fileIndicators) {
        try {
            $fileName = $indicator.Value
            $threatName = "GSecurity_File_$([System.IO.Path]::GetFileNameWithoutExtension($fileName))"
            $description = "Malicious filename detected from $($indicator.Source) rules"
            
            # Add the filename as a custom threat
            Add-MpPreference -ThreatIDDefaultAction_Actions Block -ThreatIDDefaultAction_Ids $threatName
            Add-MpPreference -AttackSurfaceReductionOnlyExclusions $fileName
            Write-Log "Added custom threat and ASR exclusion for filename: $fileName"
            $processedAsr++
        }
        catch {
            Write-Log "Error applying custom threat for filename $($indicator.Value): $_" -EntryType "Warning"
        }
    }

    # Apply firewall rules for malicious IPs in batches
    $ipIndicators = $Indicators | Where-Object { $_.Type -eq "IP" }
    $ipCount = $ipIndicators.Count
    $processedIp = 0
    $batchSize = $Config.FirewallBatchSize
    
    for ($i = 0; $i -lt $ipCount; $i += $batchSize) {
        $batch = $ipIndicators | Select-Object -Skip $i -First $batchSize
        $batchIPs = $batch | ForEach-Object { $_.Value }
        
        if ($batchIPs.Count -gt 0) {
            try {
                $batchName = "Block_C2_Batch_$($i / $batchSize)"
                New-NetFirewallRule -Name $batchName -DisplayName $batchName -Direction Outbound -Action Block `
                                   -RemoteAddress $batchIPs -ErrorAction Stop
                $processedIp += $batchIPs.Count
                Write-Log "Created batch firewall rule $batchName with $($batchIPs.Count) IPs"
            }
            catch {
                Write-Log "Error creating batch firewall rule: $_" -EntryType "Warning"
                
                # Fallback to individual rules if batch fails
                foreach ($ip in $batchIPs) {
                    try {
                        $ruleName = "Block_C2_$ip"
                        New-NetFirewallRule -Name $ruleName -DisplayName $ruleName -Direction Outbound -Action Block `
                                           -RemoteAddress $ip -ErrorAction Stop
                        $processedIp++
                        Write-Log "Blocked IP via individual firewall rule: $ip"
                    }
                    catch {
                        Write-Log "Error applying individual firewall rule for ${ip}: $_" -EntryType "Warning"
                    }
                }
            }
        }
    }
    
    Write-Log "Completed applying $processedHash/$hashCount hash-based threats, $processedAsr/$asrCount filename-based threats, and $processedIp/$ipCount Firewall rules."
    
    # Initialize telemetry
    if ($Config.Telemetry.Enabled) {
        $telemetryData = @{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            RulesApplied = @{
                Threats = $processedHash + $processedAsr
                Firewall = $processedIp
            }
            IndicatorCounts = @{
                Total = $Indicators.Count
                ByType = @{
                    Hash = ($Indicators | Where-Object { $_.Type -eq "Hash" }).Count
                    FileName = ($Indicators | Where-Object { $_.Type -eq "FileName" }).Count
                    IP = ($Indicators | Where-Object { $_.Type -eq "IP" }).Count
                    Domain = ($Indicators | Where-Object { $_.Type -eq "Domain" }).Count
                }
            }
        }
        
        $telemetryPath = $Config.Telemetry.Path
        $telemetryDir = Split-Path -Parent $telemetryPath
        
        if (-not (Test-Path $telemetryDir)) {
            New-Item -ItemType Directory -Path $telemetryDir -Force | Out-Null
        }
        
        $telemetryData | ConvertTo-Json -Depth 4 | Out-File -FilePath $telemetryPath -Encoding UTF8
        Write-Log "Saved telemetry data to $telemetryPath"
    }
}

# Monitor processes in real-time
function Start-ProcessMonitor {
    param (
        $Indicators,
        $Config
    )

    Write-Log "Starting process monitoring..."
    $fileNames = $Indicators | Where-Object { $_.Type -eq "FileName" } | ForEach-Object { $_.Value }
    
    if ($fileNames.Count -eq 0) {
        Write-Log "No file indicators to monitor" -EntryType "Warning"
        return
    }
    
    # Create a hashtable for faster lookups
    $fileNameHash = @{}
    foreach ($fileName in $fileNames) {
        $fileNameHash[$fileName.ToLower()] = $true
    }
    
    # Initialize telemetry for blocked processes
    $telemetryDir = "$env:TEMP\security_rules\telemetry"
    $blockedProcessLog = "$telemetryDir\blocked_processes.json"
    
    if (-not (Test-Path $telemetryDir)) {
        New-Item -ItemType Directory -Path $telemetryDir -Force | Out-Null
    }
    
    if (-not (Test-Path $blockedProcessLog)) {
        @{ BlockedProcesses = @() } | ConvertTo-Json | Out-File -FilePath $blockedProcessLog -Encoding UTF8
    }
    
    # Register WMI event for process creation
    Register-WmiEvent -Query "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'" -Action {
        $process = $event.SourceEventArgs.NewEvent.TargetInstance
        $processName = $process.Name.ToLower()
        
        if ($fileNameHash.ContainsKey($processName)) {
            try {
                # Get additional process info before terminating
                $processInfo = @{
                    Name = $process.Name
                    PID = $process.ProcessId
                    Path = $process.ExecutablePath
                    CommandLine = $process.CommandLine
                    ParentPID = $process.ParentProcessId
                    CreationTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
                
                # Terminate the process
                Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop
                
                # Log the blocked process
                $logMessage = "Blocked malicious process: $($process.Name) (PID: $($process.ProcessId), Path: $($process.ExecutablePath))"
                Write-EventLog -LogName "Application" -Source "SecureWindows" -EventId 1001 -EntryType "Warning" -Message $logMessage
                
                # Update telemetry
                $telemetryPath = "$env:TEMP\security_rules\telemetry\blocked_processes.json"
                $telemetry = Get-Content -Path $telemetryPath -Raw | ConvertFrom-Json
                
                $telemetry.BlockedProcesses += $processInfo
                
                # Keep only the most recent events
                if ($telemetry.BlockedProcesses.Count -gt 100) {
                    $telemetry.BlockedProcesses = $telemetry.BlockedProcesses | Select-Object -Last 100
                }
                
                $telemetry | ConvertTo-Json -Depth 4 | Out-File -FilePath $telemetryPath -Encoding UTF8
            }
            catch {
                $errorMessage = "Error blocking process $($process.Name): $_"
                Write-EventLog -LogName "Application" -Source "SecureWindows" -EventId 1002 -EntryType "Error" -Message $errorMessage
            }
        }
    }
    
    Write-Log "Process monitoring started with $($fileNames.Count) file indicators."
}

# Schedule startup and frequent update tasks
function Schedule-Tasks {
    Write-Log "Scheduling tasks..."
    try {
        $scriptPath = $PSCommandPath
        $exePath = $scriptPath -replace '\.ps1$', '.exe'

        $taskName = "SecureWindowsStartup"
        $action = if (Test-Path $exePath) {
            New-ScheduledTaskAction -Execute $exePath -Argument "-Start"
        } else {
            New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`" -Start"
        }
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal `
                              -Description "SecureWindows startup monitoring" -Force -ErrorAction Stop | Out-Null
        Write-Log "Scheduled startup task."

        $taskName = "SecureWindowsUpdate"
        $action = if (Test-Path $exePath) {
            New-ScheduledTaskAction -Execute $exePath
        } else {
            New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$scriptPath`""
        }
        $trigger1 = New-ScheduledTaskTrigger -Daily -At "12:00 AM"
        $trigger2 = New-ScheduledTaskTrigger -Daily -At "12:00 PM"
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger @($trigger1, $trigger2) -Principal $principal `
                              -Description "Twice-daily security rule update" -Force -ErrorAction Stop | Out-Null

        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
        if ($task.State -eq "Paused") {
            $task | Enable-ScheduledTask -ErrorAction Stop
            Write-Log "Unpaused SecureWindowsUpdate task"
        }
        Write-Log "Scheduled twice-daily rule updates."
    }
    catch {
        Write-Log "Error scheduling tasks: $_" -EntryType "Error"
        throw
    }
}

function Harden-PrivilegeRights {
    # Use here-string with proper formatting
    $privilegeSettings = @'
[Privilege Rights]
SeDenyNetworkLogonRight = *S-1-5-21,*S-1-5-32-545,*S-1-5-32-584,*S-1-5-65-1,*S-1-5-13,*S-1-5-32-581,*S-1-5-18,*S-1-18-2,*S-1-5-6,*S-1-5-32-552,*S-1-5-32-580,*S-1-5-14,*S-1-5-32-555,*S-1-5-32-547,*S-1-5-32-558,*S-1-5-32-559,*S-1-3-4,*S-1-5-32-585,*S-1-5-20,*S-1-5-32-556,*S-1-5-2,*S-1-5-19,*S-1-5-114,*S-1-5-113,*S-1-5-17,*S-1-5-4,*S-1-5-32-568,*S-1-5-32-578,*S-1-5-32-546,Guest,*S-1-1-0,*S-1-5-32-573,*S-1-5-32-562,*S-1-5-1,*S-1-5-32-583,*S-1-5-32-569,*S-1-3-0,*S-1-3-1,*S-1-2-1,*S-1-5-3,*S-1-5-32-551,*S-1-18-1,*S-1-5-11,*S-1-5-7,*S-1-15-2-1,*S-1-15-2-2,*S-1-5-32-544,*S-1-5-32-579,*S-1-15-3
SeDenyRemoteInteractiveLogonRight = *S-1-5-21,*S-1-5-32-545,*S-1-5-32-584,*S-1-5-65-1,*S-1-5-13,*S-1-5-32-581,*S-1-5-18,*S-1-18-2,*S-1-5-6,*S-1-5-32-552,*S-1-5-32-580,*S-1-5-14,*S-1-5-32-555,*S-1-5-32-547,*S-1-5-32-558,*S-1-5-32-559,*S-1-3-4,*S-1-5-32-585,*S-1-5-20,*S-1-5-32-556,*S-1-5-2,*S-1-5-19,*S-1-5-114,*S-1-5-113,*S-1-5-17,*S-1-5-4,*S-1-5-32-568,*S-1-5-32-578,*S-1-5-32-546,Guest,*S-1-1-0,*S-1-5-32-573,*S-1-5-32-562,*S-1-5-1,*S-1-5-32-583,*S-1-5-32-569,*S-1-3-0,*S-1-3-1,*S-1-2-1,*S-1-5-3,*S-1-5-32-551,*S-1-18-1,*S-1-5-11,*S-1-5-7,*S-1-15-2-1,*S-1-15-2-2,*S-1-5-32-544,*S-1-5-32-579,*S-1-15-3
SeNetworkLogonRight=
SeRemoteShutdownPrivilege=
SeDebugPrivilege=
SeRemoteInteractiveLogonRight=
'@

    # Consider using a more secure temporary path
    $cfgPath = "$env:TEMP\secpol.cfg"
    
    # Add error handling
    try {
        # Export current security policy
        secedit /export /cfg $cfgPath /quiet
        
        # Append new settings
        $privilegeSettings | Out-File -Append -FilePath $cfgPath -ErrorAction Stop
        
        # Apply configuration
        secedit /configure /db c:\windows\security\local.sdb /cfg $cfgPath /areas USER_RIGHTS /quiet
    }
    catch {
        Write-Error "Error hardening privilege rights: $_"
    }
    finally {
        # Clean up
        if (Test-Path $cfgPath) {
            Remove-Item $cfgPath -Force -ErrorAction SilentlyContinue
        }
    }
}

# Call the function
Harden-PrivilegeRights

# Generate a report of security status
function Get-SecurityReport {
    param (
        $Indicators,
        $Config
    )
    
    $reportDir = "$env:TEMP\security_rules\reports"
    $reportPath = "$reportDir\security_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    
    if (-not (Test-Path $reportDir)) {
        New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
    }
    
    # Get current security status
    $asrRules = Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids -ErrorAction SilentlyContinue
    $firewallRules = Get-NetFirewallRule | Where-Object { $_.Name -like "Block_C2_*" }
    $customThreats = Get-MpThreatDetection | Where-Object { $_.ThreatName -like "GSecurity_*" }
    
    # Generate HTML report
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>GSecurity Status Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2 { color: #333; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .summary { background-color: #e7f3fe; padding: 10px; border-left: 5px solid #2196F3; margin-bottom: 20px; }
    </style>
</head>
<body>
    <h1>GSecurity Status Report</h1>
    <p>Generated on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
    
    <div class="summary">
        <h2>Summary</h2>
        <p>Total Indicators: $($Indicators.Count)</p>
        <p>File Indicators: $($Indicators.Where({ $_.Type -eq "FileName" }).Count)</p>
        <p>IP Indicators: $($Indicators.Where({ $_.Type -eq "IP" }).Count)</p>
        <p>Domain Indicators: $($Indicators.Where({ $_.Type -eq "Domain" }).Count)</p>
        <p>Hash Indicators: $($Indicators.Where({ $_.Type -eq "Hash" }).Count)</p>
        <p>Firewall Rules: $($firewallRules.Count)</p>
        <p>Custom Threats: $($customThreats.Count)</p>
    </div>
    
    <h2>File Indicators</h2>
    <table>
        <tr>
            <th>Filename</th>
            <th>Source</th>
        </tr>
"@
    foreach ($indicator in ($Indicators | Where-Object { $_.Type -eq "FileName" } | Sort-Object -Property Value)) {
        $html += @"
        <tr>
            <td>$($indicator.Value)</td>
            <td>$($indicator.Source)</td>
        </tr>
"@
    }

    $html += @"
    </table>
    
    <h2>IP Indicators</h2>
    <table>
        <tr>
            <th>IP Address</th>
            <th>Source</th>
        </tr>
"@
    foreach ($indicator in ($Indicators | Where-Object { $_.Type -eq "IP" } | Sort-Object -Property Value)) {
        $html += @"
        <tr>
            <td>$($indicator.Value)</td>
            <td>$($indicator.Source)</td>
        </tr>
"@
    }

    $html += @"
    </table>
    
    <h2>System Status</h2>
    <table>
        <tr>
            <th>Component</th>
            <th>Status</th>
        </tr>
        <tr>
            <td>Windows Defender</td>
            <td>$(if ((Get-MpComputerStatus).AntivirusEnabled) { "Enabled" } else { "Disabled" })</td>
        </tr>
        <tr>
            <td>Real-time Protection</td>
            <td>$(if ((Get-MpComputerStatus).RealTimeProtectionEnabled) { "Enabled" } else { "Disabled" })</td>
        </tr>
        <tr>
            <td>ASR Rules</td>
            <td>$(if ($asrRules -contains "e6db77e5-3df2-4cf1-b95a-636979351e5b") { "Configured" } else { "Not Configured" })</td>
        </tr>
        <tr>
            <td>Firewall Rules</td>
            <td>$($firewallRules.Count) rules configured</td>
        </tr>
        <tr>
            <td>Custom Threats</td>
            <td>$($customThreats.Count) threats configured</td>
        </tr>
        <tr>
            <td>Process Monitoring</td>
            <td>$(if ($NoMonitor) { "Disabled" } else { "Active" })</td>
        </tr>
    </table>
</body>
</html>
"@

    $html | Out-File -FilePath $reportPath -Encoding UTF8
    Write-Log "Generated security report at $reportPath"
    return $reportPath
}

# Main
try {
    Write-Log "Starting SecureWindows script (Mode: $(if ($Start) { 'Startup' } else { 'Initial/Update' }))."
    $config = Initialize-Config

    if ($Start) {
        Write-Log "Starting in Startup mode..."
        $tempDir = "$env:TEMP\security_rules"
        if (Test-Path $tempDir) {
            $rules = @{
                Yara = Get-ChildItem -Path @("$tempDir\yara_forge", "$tempDir\yara_rules") -Recurse -Include "*.yar","*.yara" -ErrorAction SilentlyContinue
                Sigma = Get-ChildItem -Path "$tempDir\sigma\sigma-master\rules" -Recurse -Include "*.yml" -ErrorAction SilentlyContinue
                Snort = @("$tempDir\snort_community.rules", "$tempDir\snort_emerging.rules") | Where-Object { Test-Path $_ }
            }
            if ($rules.Yara -or $rules.Sigma -or $rules.Snort) {
                Add-MpPreference -ExclusionPath $tempDir
                $indicators = Parse-Rules -Rules $rules -Config $config
                if (-not $NoMonitor) {
                    Start-ProcessMonitor -Indicators $indicators -Config $config
                    Write-Log "Startup mode: Monitoring active with cached rules."
                    $iteration = 0
                    while ($true) {
                        $ruleCount = ($rules.Yara.Count + $rules.Sigma.Count + $rules.Snort.Count)
                        $firewallRules = (Get-NetFirewallRule | Where-Object { $_.Name -like "Block_C2_*" }).Count
                        $fileIndicators = ($indicators | Where-Object { $_.Type -eq "FileName" }).Count
                        $hashIndicators = ($indicators | Where-Object { $_.Type -eq "Hash" }).Count
                        $ipIndicators = ($indicators | Where-Object { $_.Type -eq "IP" }).Count
                        Write-Log "Monitoring active, iteration $iteration (Rules: $ruleCount, Firewall Rules: $firewallRules, File Indicators: $fileIndicators, Hash Indicators: $hashIndicators, IP Indicators: $ipIndicators, heartbeats every 2 min)..."
                        
                        if ($iteration % 10 -eq 0) {
                            try {
                                $cpuUsage = Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 1
                                if ($cpuUsage.CounterSamples.CookedValue -gt 90) {
                                    Write-Log "High CPU usage detected: $($cpuUsage.CounterSamples.CookedValue)%" -EntryType "Warning"
                                }
                            }
                            catch {
                                Write-Log "Error checking resource usage: $_" -EntryType "Warning"
                            }
                        }
                        
                        Start-Sleep -Seconds 120
                        $iteration++
                    }
                } else {
                    Write-Log "Startup mode: Monitoring disabled."
                    Exit-Script 0 "Startup mode completed without monitoring."
                }
            } else {
                Write-Log "Startup mode: No valid cached rules found." -EntryType "Error"
                Exit-Script 1
            }
        } else {
            Write-Log "Startup mode: Cached rules directory not found." -EntryType "Error"
            Exit-Script 1
        }
    } else {
        Write-Log "Starting in Initial/Update mode..."
        $rules = Get-SecurityRules -Config $config
        $indicators = Parse-Rules -Rules $rules -Config $config
        
        if ($indicators.Count -eq 0) {
            Write-Log "No indicators extracted, forcing rule redownload..." -EntryType "Warning"
            Remove-Item "$env:TEMP\security_rules" -Recurse -Force -ErrorAction SilentlyContinue
            $rules = Get-SecurityRules -Config $config
            $indicators = Parse-Rules -Rules $rules -Config $config
        }
        
        Apply-SecurityRules -Indicators $indicators -Config $config
        Schedule-Tasks
        Harden-PrivilegeRights
        
        # Generate security report
        $reportPath = Get-SecurityReport -Indicators $indicators -Config $config
        Write-Log "Security report available at: $reportPath"
        
        if (-not $NoMonitor) {
            Start-ProcessMonitor -Indicators $indicators -Config $config
            Write-Log "Initial/Update mode: Monitoring active."
            $iteration = 0
            while ($true) {
                $ruleCount = ($rules.Yara.Count + $rules.Sigma.Count + ($rules.Snort | Where-Object { Test-Path $_ }).Count)
                $firewallRules = (Get-NetFirewallRule | Where-Object { $_.Name -like "Block_C2_*" }).Count
                $fileIndicators = ($indicators | Where-Object { $_.Type -eq "FileName" }).Count
                $hashIndicators = ($indicators | Where-Object { $_.Type -eq "Hash" }).Count
                $ipIndicators = ($indicators | Where-Object { $_.Type -eq "IP" }).Count
                Write-Log "Monitoring active, iteration $iteration (Rules: $ruleCount, Firewall Rules: $firewallRules, File Indicators: $fileIndicators, Hash Indicators: $hashIndicators, IP Indicators: $ipIndicators, heartbeats every 2 min)..."
                
                if ($iteration % 10 -eq 0) {
                    try {
                        $cpuUsage = Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 1
                        if ($cpuUsage.CounterSamples.CookedValue -gt 90) {
                            Write-Log "High CPU usage detected: $($cpuUsage.CounterSamples.CookedValue)%" -EntryType "Warning"
                        }
                    }
                    catch {
                        Write-Log "Error checking resource usage: $_" -EntryType "Warning"
                    }
                }
                
                Start-Sleep -Seconds 120
                $iteration++
            }
        } else {
            Write-Log "Initial/Update mode: Monitoring disabled."
            Exit-Script 0 "Initial/Update mode completed without monitoring."
        }
    }
}
catch {
    Write-Log "Fatal error: $_" -EntryType "Error"
    Exit-Script 1
}
finally {
    if (-not $Start) {
        Remove-MpPreference -ExclusionPath "$env:TEMP\security_rules" -ErrorAction SilentlyContinue
    }
}