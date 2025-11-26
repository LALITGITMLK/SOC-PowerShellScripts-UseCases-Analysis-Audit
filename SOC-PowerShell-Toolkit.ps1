#==============================================================================
# SOC ANALYST MANUAL INVESTIGATION TOOLKIT
# Version: 1.0
# Purpose: 55 PowerShell scripts for manual security operations
# Author: SOC Operations Team
# Last Updated: 2025
#==============================================================================

<#
USAGE INSTRUCTIONS:
1. Each script is prefixed with UC-XXX (Use Case number)
2. Run with appropriate privileges (some require Admin/Domain Admin)
3. Review output files in designated evidence folders
4. Always run on authorized systems only
5. Document script execution in incident tickets
#>

#==============================================================================
# CATEGORY 1: ALERT TRIAGE & INITIAL ASSESSMENT
#==============================================================================

#------------------------------------------------------------------------------
# UC-001: Rapid Host Profiling
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Collects comprehensive system snapshot for incident triage
.DESCRIPTION
    Gathers system info, processes, network connections, scheduled tasks
.PARAMETER OutputPath
    Path to save the report
.EXAMPLE
    .\UC-001-RapidHostProfile.ps1 -OutputPath "C:\Evidence"
.NOTES
    Run As: Administrator
    Run On: Suspicious endpoint
    Run When: Immediately after alert
#>

function Get-RapidHostProfile {
    param(
        [Parameter(Mandatory=$true)]
        [string]$OutputPath
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME
    $reportFile = "$OutputPath\HostProfile_${hostname}_${timestamp}.txt"
    
    Write-Host "[+] Starting Rapid Host Profile Collection..." -ForegroundColor Green
    
    # Create output directory
    if (!(Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath | Out-Null
    }
    
    # Header
    @"
========================================
RAPID HOST PROFILE REPORT
========================================
Hostname: $hostname
Timestamp: $(Get-Date)
Analyst: $env:USERNAME
========================================

"@ | Out-File $reportFile
    
    # System Information
    "=== SYSTEM INFORMATION ===" | Out-File $reportFile -Append
    Get-ComputerInfo | Select-Object CsName, WindowsVersion, OsArchitecture, 
        BiosManufacturer, CsModel, CsTotalPhysicalMemory | 
        Format-List | Out-File $reportFile -Append
    
    # Running Processes (with hashes)
    "`n=== RUNNING PROCESSES ===" | Out-File $reportFile -Append
    Get-Process | Select-Object Name, Id, Path, 
        @{N='Hash';E={(Get-FileHash $_.Path -ErrorAction SilentlyContinue).Hash}}, 
        StartTime, @{N='User';E={(Get-WmiObject Win32_Process -Filter "ProcessId=$($_.Id)").GetOwner().User}} |
        Sort-Object StartTime -Descending | 
        Format-Table -AutoSize | Out-File $reportFile -Append
    
    # Network Connections
    "`n=== ACTIVE NETWORK CONNECTIONS ===" | Out-File $reportFile -Append
    Get-NetTCPConnection | Where-Object {$_.State -eq "Established"} |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, 
        @{N='Process';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}} |
        Sort-Object RemoteAddress | 
        Format-Table -AutoSize | Out-File $reportFile -Append
    
    # Scheduled Tasks (recently created)
    "`n=== SCHEDULED TASKS (Last 30 Days) ===" | Out-File $reportFile -Append
    Get-ScheduledTask | Where-Object {$_.Date -gt (Get-Date).AddDays(-30)} |
        Select-Object TaskName, TaskPath, State, 
        @{N='Author';E={$_.Principal.UserId}},
        @{N='RunLevel';E={$_.Principal.RunLevel}} |
        Format-Table -AutoSize | Out-File $reportFile -Append
    
    # Logged on Users
    "`n=== LOGGED ON USERS ===" | Out-File $reportFile -Append
    quser 2>$null | Out-File $reportFile -Append
    
    # Services (non-Microsoft)
    "`n=== NON-MICROSOFT SERVICES ===" | Out-File $reportFile -Append
    Get-Service | Where-Object {$_.DisplayName -notlike "*Microsoft*"} |
        Select-Object Name, DisplayName, Status, StartType |
        Format-Table -AutoSize | Out-File $reportFile -Append
    
    # Recent PowerShell History
    "`n=== RECENT POWERSHELL HISTORY ===" | Out-File $reportFile -Append
    Get-Content "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -Tail 50 -ErrorAction SilentlyContinue |
        Out-File $reportFile -Append
    
    Write-Host "[+] Report saved to: $reportFile" -ForegroundColor Green
    return $reportFile
}

#------------------------------------------------------------------------------
# UC-002: User Session Timeline Builder
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Extracts complete logon/logoff timeline for specific user
.DESCRIPTION
    Pulls all logon events (4624, 4625, 4634, 4647) for user investigation
.PARAMETER Username
    Target username to investigate
.PARAMETER Hours
    Number of hours to look back (default: 72)
.EXAMPLE
    .\UC-002-UserSessionTimeline.ps1 -Username "jdoe" -Hours 48
.NOTES
    Run As: Administrator
    Run On: Domain Controller or target workstation
    Run When: Compromised account investigation
#>

function Get-UserSessionTimeline {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Username,
        [int]$Hours = 72,
        [string]$OutputPath = "C:\Evidence"
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = "$OutputPath\UserTimeline_${Username}_${timestamp}.csv"
    
    Write-Host "[+] Extracting session timeline for: $Username" -ForegroundColor Green
    Write-Host "[+] Looking back $Hours hours..." -ForegroundColor Yellow
    
    $startTime = (Get-Date).AddHours(-$Hours)
    
    # Event IDs: 4624=Logon, 4625=Failed Logon, 4634=Logoff, 4647=User Initiated Logoff
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id = 4624, 4625, 4634, 4647
        StartTime = $startTime
    } -ErrorAction SilentlyContinue | Where-Object {
        $_.Properties[5].Value -like "*$Username*"
    }
    
    $timeline = $events | ForEach-Object {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            EventID = $_.Id
            EventType = switch ($_.Id) {
                4624 {"Successful Logon"}
                4625 {"Failed Logon"}
                4634 {"Logoff"}
                4647 {"User Initiated Logoff"}
            }
            Username = $_.Properties[5].Value
            Domain = $_.Properties[6].Value
            LogonType = if ($_.Id -eq 4624) {
                switch ($_.Properties[8].Value) {
                    2 {"Interactive"}
                    3 {"Network"}
                    4 {"Batch"}
                    5 {"Service"}
                    7 {"Unlock"}
                    8 {"NetworkCleartext"}
                    9 {"NewCredentials"}
                    10 {"RemoteInteractive"}
                    11 {"CachedInteractive"}
                    default {$_.Properties[8].Value}
                }
            } else {"N/A"}
            SourceIP = if ($_.Properties[18].Value) {$_.Properties[18].Value} else {"Local"}
            Workstation = $_.Properties[11].Value
            ProcessName = $_.Properties[17].Value
        }
    } | Sort-Object TimeCreated
    
    $timeline | Export-Csv $reportFile -NoTypeInformation
    
    Write-Host "[+] Found $($timeline.Count) events" -ForegroundColor Green
    Write-Host "[+] Timeline saved to: $reportFile" -ForegroundColor Green
    
    # Display summary
    Write-Host "`n=== SESSION SUMMARY ===" -ForegroundColor Cyan
    $timeline | Group-Object EventType | Select-Object Name, Count | Format-Table
    
    return $reportFile
}

#------------------------------------------------------------------------------
# UC-003: File Hash Rapid Verification
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Calculates file hashes and checks against VirusTotal
.DESCRIPTION
    Computes MD5, SHA1, SHA256 hashes and optionally queries VirusTotal API
.PARAMETER FilePath
    Path to file to analyze
.PARAMETER VTApiKey
    VirusTotal API key (optional)
.EXAMPLE
    .\UC-003-FileHashVerification.ps1 -FilePath "C:\Temp\suspicious.exe"
.NOTES
    Run As: Standard User
    Run On: Analyst workstation or isolated sandbox
    Run When: Unknown file found, email attachment analysis
#>

function Get-FileHashVerification {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        [string]$VTApiKey = "",
        [string]$OutputPath = "C:\Evidence"
    )
    
    if (!(Test-Path $FilePath)) {
        Write-Host "[-] File not found: $FilePath" -ForegroundColor Red
        return
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $fileName = Split-Path $FilePath -Leaf
    $reportFile = "$OutputPath\FileHash_${fileName}_${timestamp}.txt"
    
    Write-Host "[+] Analyzing file: $FilePath" -ForegroundColor Green
    
    # Get file details
    $fileInfo = Get-Item $FilePath
    
    # Calculate hashes
    Write-Host "[+] Calculating hashes..." -ForegroundColor Yellow
    $md5 = (Get-FileHash -Path $FilePath -Algorithm MD5).Hash
    $sha1 = (Get-FileHash -Path $FilePath -Algorithm SHA1).Hash
    $sha256 = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash
    
    # Build report
    $report = @"
========================================
FILE HASH VERIFICATION REPORT
========================================
Analysis Time: $(Get-Date)
File Path: $FilePath
File Name: $($fileInfo.Name)
File Size: $($fileInfo.Length) bytes
Created: $($fileInfo.CreationTime)
Modified: $($fileInfo.LastWriteTime)
Accessed: $($fileInfo.LastAccessTime)

========================================
HASH VALUES
========================================
MD5:    $md5
SHA1:   $sha1
SHA256: $sha256

"@
    
    # Check VirusTotal if API key provided
    if ($VTApiKey) {
        Write-Host "[+] Querying VirusTotal..." -ForegroundColor Yellow
        try {
            $vtUrl = "https://www.virustotal.com/vtapi/v2/file/report?apikey=$VTApiKey&resource=$sha256"
            $vtResult = Invoke-RestMethod -Uri $vtUrl -Method Get
            
            if ($vtResult.response_code -eq 1) {
                $report += @"
========================================
VIRUSTOTAL RESULTS
========================================
Scan Date: $($vtResult.scan_date)
Positives: $($vtResult.positives) / $($vtResult.total)
Permalink: $($vtResult.permalink)

Detection Names:
"@
                foreach ($scanner in $vtResult.scans.PSObject.Properties) {
                    if ($scanner.Value.detected) {
                        $report += "`n  - $($scanner.Name): $($scanner.Value.result)"
                    }
                }
            } else {
                $report += "`n========================================`n"
                $report += "VIRUSTOTAL RESULTS: File not found in VT database`n"
            }
        } catch {
            $report += "`n========================================`n"
            $report += "VIRUSTOTAL ERROR: $($_.Exception.Message)`n"
        }
    }
    
    # Save report
    $report | Out-File $reportFile
    Write-Host "[+] Report saved to: $reportFile" -ForegroundColor Green
    
    # Display on console
    Write-Host "`n$report" -ForegroundColor Cyan
    
    return @{
        MD5 = $md5
        SHA1 = $sha1
        SHA256 = $sha256
        ReportPath = $reportFile
    }
}

#------------------------------------------------------------------------------
# UC-004: Port Scanner Detection
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Analyzes firewall logs to identify port scanning patterns
.DESCRIPTION
    Detects rapid connection attempts across multiple ports from single source
.PARAMETER LogPath
    Path to firewall log file (CSV format)
.PARAMETER ThresholdPorts
    Minimum number of unique ports to flag as scan (default: 10)
.PARAMETER TimeWindowSeconds
    Time window for scan detection (default: 60)
.EXAMPLE
    .\UC-004-PortScanDetector.ps1 -LogPath "C:\Logs\firewall.csv"
.NOTES
    Run As: Standard User
    Run On: Log collection server
    Run When: Multiple blocked connections observed
#>

function Get-PortScanDetection {
    param(
        [Parameter(Mandatory=$true)]
        [string]$LogPath,
        [int]$ThresholdPorts = 10,
        [int]$TimeWindowSeconds = 60,
        [string]$OutputPath = "C:\Evidence"
    )
    
    if (!(Test-Path $LogPath)) {
        Write-Host "[-] Log file not found: $LogPath" -ForegroundColor Red
        return
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = "$OutputPath\PortScan_Detection_${timestamp}.csv"
    
    Write-Host "[+] Analyzing firewall logs for port scanning..." -ForegroundColor Green
    
    # Import logs (assuming CSV with columns: Timestamp, SourceIP, DestPort, Action)
    $logs = Import-Csv $LogPath
    
    # Group by source IP and analyze patterns
    $scanners = $logs | Where-Object {$_.Action -eq "Block" -or $_.Action -eq "Deny"} |
        Group-Object SourceIP | ForEach-Object {
            $sourceIP = $_.Name
            $connections = $_.Group | Sort-Object Timestamp
            
            # Get unique ports
            $uniquePorts = ($connections | Select-Object -ExpandProperty DestPort | Sort-Object -Unique)
            $portCount = $uniquePorts.Count
            
            if ($portCount -ge $ThresholdPorts) {
                # Check time window
                $firstAttempt = [DateTime]$connections[0].Timestamp
                $lastAttempt = [DateTime]$connections[-1].Timestamp
                $duration = ($lastAttempt - $firstAttempt).TotalSeconds
                
                # Calculate scan rate
                $scanRate = [math]::Round($portCount / ($duration + 1), 2)
                
                [PSCustomObject]@{
                    SourceIP = $sourceIP
                    UniquePortsScanned = $portCount
                    TotalAttempts = $connections.Count
                    FirstAttempt = $firstAttempt
                    LastAttempt = $lastAttempt
                    DurationSeconds = [math]::Round($duration, 2)
                    PortsPerSecond = $scanRate
                    PortRange = "$($uniquePorts | Measure-Object -Minimum | Select-Object -ExpandProperty Minimum)-$($uniquePorts | Measure-Object -Maximum | Select-Object -ExpandProperty Maximum)"
                    CommonPorts = ($uniquePorts | Select-Object -First 10) -join ", "
                    Severity = if ($scanRate -gt 10) {"Critical"} elseif ($scanRate -gt 5) {"High"} else {"Medium"}
                }
            }
        } | Where-Object {$_ -ne $null} | Sort-Object PortsPerSecond -Descending
    
    if ($scanners) {
        $scanners | Export-Csv $reportFile -NoTypeInformation
        Write-Host "[+] Detected $($scanners.Count) potential port scanners" -ForegroundColor Red
        Write-Host "[+] Report saved to: $reportFile" -ForegroundColor Green
        
        # Display top 5
        Write-Host "`n=== TOP PORT SCANNERS ===" -ForegroundColor Cyan
        $scanners | Select-Object -First 5 | Format-Table -AutoSize
    } else {
        Write-Host "[+] No port scanning patterns detected" -ForegroundColor Green
    }
    
    return $reportFile
}

#------------------------------------------------------------------------------
# UC-005: Lateral Movement Path Finder
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Maps network connections between hosts to identify pivot points
.DESCRIPTION
    Analyzes authentication logs to trace lateral movement chains
.PARAMETER StartHost
    Initial compromised host
.PARAMETER Hours
    Hours to look back (default: 24)
.EXAMPLE
    .\UC-005-LateralMovementPath.ps1 -StartHost "WKS-001"
.NOTES
    Run As: Domain Administrator
    Run On: Domain Controller
    Run When: After confirming initial compromise
#>

function Get-LateralMovementPath {
    param(
        [Parameter(Mandatory=$true)]
        [string]$StartHost,
        [int]$Hours = 24,
        [string]$OutputPath = "C:\Evidence"
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = "$OutputPath\LateralMovement_${StartHost}_${timestamp}.csv"
    $graphFile = "$OutputPath\LateralMovement_${StartHost}_${timestamp}.txt"
    
    Write-Host "[+] Tracing lateral movement from: $StartHost" -ForegroundColor Green
    
    $startTime = (Get-Date).AddHours(-$Hours)
    
    # Get all network logon events (Type 3) from security logs
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id = 4624
        StartTime = $startTime
    } -ErrorAction SilentlyContinue | Where-Object {
        $_.Properties[8].Value -eq 3  # Network logon
    }
    
    # Build connection graph
    $connections = $events | ForEach-Object {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            SourceHost = $_.Properties[11].Value
            TargetHost = $env:COMPUTERNAME
            Username = $_.Properties[5].Value
            SourceIP = $_.Properties[18].Value
            LogonProcess = $_.Properties[9].Value
        }
    } | Sort-Object TimeCreated
    
    # Find paths starting from compromised host
    $paths = @()
    $visited = @($StartHost)
    $queue = @($StartHost)
    
    while ($queue.Count -gt 0) {
        $current = $queue[0]
        $queue = $queue[1..($queue.Count-1)]
        
        # Find connections from current host
        $nextHops = $connections | Where-Object {$_.SourceHost -eq $current -and $_.TargetHost -notin $visited}
        
        foreach ($hop in $nextHops) {
            $paths += $hop
            if ($hop.TargetHost -notin $visited) {
                $visited += $hop.TargetHost
                $queue += $hop.TargetHost
            }
        }
    }
    
    # Export results
    $paths | Export-Csv $reportFile -NoTypeInformation
    
    # Create visual graph
    $graph = @"
========================================
LATERAL MOVEMENT PATH ANALYSIS
========================================
Start Host: $StartHost
Analysis Time: $(Get-Date)
Time Window: Last $Hours hours

========================================
MOVEMENT CHAIN
========================================

"@
    
    $currentLevel = @($StartHost)
    $level = 0
    
    while ($currentLevel.Count -gt 0) {
        $graph += "Level $level`: " + ($currentLevel -join ", ") + "`n"
        
        $nextLevel = $paths | Where-Object {$_.SourceHost -in $currentLevel} |
            Select-Object -ExpandProperty TargetHost -Unique
        
        foreach ($host in $currentLevel) {
            $targets = $paths | Where-Object {$_.SourceHost -eq $host}
            foreach ($target in $targets) {
                $graph += "  $host -> $($target.TargetHost) [$($target.Username)] @ $($target.TimeCreated)`n"
            }
        }
        
        $currentLevel = $nextLevel
        $level++
        $graph += "`n"
    }
    
    $graph | Out-File $graphFile
    
    Write-Host "[+] Found $($paths.Count) lateral movement connections" -ForegroundColor Yellow
    Write-Host "[+] Report saved to: $reportFile" -ForegroundColor Green
    Write-Host "[+] Graph saved to: $graphFile" -ForegroundColor Green
    
    return @{
        Connections = $paths
        ReportPath = $reportFile
        GraphPath = $graphFile
    }
}

#==============================================================================
# CATEGORY 2: EVIDENCE COLLECTION & PRESERVATION
#==============================================================================

#------------------------------------------------------------------------------
# UC-006: Memory Dump Quick Capture
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Creates forensic memory snapshot with metadata
.DESCRIPTION
    Captures RAM contents before volatile evidence is lost
.PARAMETER OutputPath
    Destination for memory dump file
.EXAMPLE
    .\UC-006-MemoryDumpCapture.ps1 -OutputPath "E:\Forensics"
.NOTES
    Run As: Administrator
    Run On: Compromised system (directly)
    Run When: Before reboot, fileless malware suspected
    Requires: Windows Sysinternals ProcDump or DumpIt
#>

function Start-MemoryDumpCapture {
    param(
        [Parameter(Mandatory=$true)]
        [string]$OutputPath
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME
    $dumpFile = "$OutputPath\MemDump_${hostname}_${timestamp}.dmp"
    $metadataFile = "$OutputPath\MemDump_${hostname}_${timestamp}_metadata.txt"
    
    Write-Host "[+] Starting memory dump capture..." -ForegroundColor Green
    Write-Host "[!] This may take several minutes depending on RAM size" -ForegroundColor Yellow
    
    # Create output directory
    if (!(Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath | Out-Null
    }
    
    # Capture metadata first
    $metadata = @"
========================================
MEMORY DUMP METADATA
========================================
Hostname: $hostname
Capture Time: $(Get-Date)
Analyst: $env:USERNAME
Domain: $env:USERDOMAIN
Total RAM: $([math]::Round((Get-CimInstance Win32_PhysicalMemory | Measure-Object Capacity -Sum).Sum / 1GB, 2)) GB
OS Version: $(Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Caption)
OS Build: $(Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber)

========================================
RUNNING PROCESSES AT CAPTURE TIME
========================================
"@
    
    Get-Process | Select-Object Id, Name, Path, StartTime | Format-Table | Out-String | 
        ForEach-Object {$metadata += $_}
    
    $metadata | Out-File $metadataFile
    
    # Attempt memory dump using built-in tools
    Write-Host "[+] Attempting memory capture..." -ForegroundColor Yellow
    
    # Method 1: Try comsvcs.dll (built-in Windows method)
    try {
        $lsassPid = (Get-Process lsass).Id
        rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $lsassPid $dumpFile full
        Write-Host "[+] Memory dump completed: $dumpFile" -ForegroundColor Green
    } catch {
        Write-Host "[-] Error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "[!] Consider using Magnet RAM Capture, FTK Imager, or DumpIt for full memory acquisition" -ForegroundColor Yellow
    }
    
    # Calculate hash of dump file
    if (Test-Path $dumpFile) {
        Write-Host "[+] Calculating hash..." -ForegroundColor Yellow
        $hash = (Get-FileHash -Path $dumpFile -Algorithm SHA256).Hash
        "`nSHA256: $hash" | Out-File $metadataFile -Append
        
        Write-Host "[+] Dump hash: $hash" -ForegroundColor Green
    }
    
    Write-Host "[+] Metadata saved to: $metadataFile" -ForegroundColor Green
    
    return @{
        DumpFile = $dumpFile
        MetadataFile = $metadataFile
        Hash = $hash
    }
}

#------------------------------------------------------------------------------
# UC-007: Registry Persistence Hunter
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Scans all autorun registry keys for suspicious entries
.DESCRIPTION
    Identifies persistence mechanisms in Run keys, services, scheduled tasks
.PARAMETER OutputPath
    Path to save results
.EXAMPLE
    .\UC-007-RegistryPersistenceHunter.ps1
.NOTES
    Run As: Administrator
    Run On: Infected endpoint
    Run When: Malware keeps returning after cleanup
#>

function Find-RegistryPersistence {
    param(
        [string]$OutputPath = "C:\Evidence"
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME
    $reportFile = "$OutputPath\RegPersistence_${hostname}_${timestamp}.csv"
    
    Write-Host "[+] Hunting for registry persistence mechanisms..." -ForegroundColor Green
    
    # Define common persistence locations
    $persistenceKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        "HKLM:\SYSTEM\CurrentControlSet\Services",
        "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
    )
    
    $findings = @()
    
    foreach ($key in $persistenceKeys) {
        Write-Host "[+] Scanning: $key" -ForegroundColor Yellow
        
        if (Test-Path $key) {
            $entries = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
            
            if ($entries) {
                $entries.PSObject.Properties | Where-Object {
                    $_.Name -notmatch '^PS' -and $_.Name -ne '(default)'
                } | ForEach-Object {
                    $value = $_.Value
                    $name = $_.Name
                    
                    # Extract file path if present
                    $filePath = if ($value -match '^"?([^"]+)') {
                        $matches[1] -replace '^"?([^"]+\.[a-z]{2,4}).*','$1'
                    } else { $value }
                    
                    # Check if file exists and get hash
                    $fileExists = Test-Path $filePath -ErrorAction SilentlyContinue
                    $hash = if ($fileExists) {
                        (Get-FileHash -Path $filePath -ErrorAction SilentlyContinue).Hash
                    } else { "N/A" }
                    
                    # Flag suspicious indicators
                    $suspicious = $false
                    $indicators = @()
                    
                    if (!$fileExists) { $suspicious = $true; $indicators += "File Missing" }
                    if ($value -match 'powershell|cmd|wscript|cscript') { $suspicious = $true; $indicators += "Script Execution" }
                    if ($value -match '%temp%|%appdata%|users\\public') { $suspicious = $true; $indicators += "Suspicious Location" }
                    if ($value -match '-enc|-e |-nop|-w hidden') { $suspicious = $true; $indicators += "Obfuscation" }
                    if ($name -match '^[a-f0-9]{32}$|^[a-f0-9]{64}$') { $suspicious = $true; $indicators += "Random Name" }
                    
                    $findings += [PSCustomObject]@{
                        RegistryKey = $key
                        ValueName = $name
                        ValueData = $value
                        FilePath = $filePath
                        FileExists = $fileExists
                        SHA256 = $hash
                        Suspicious = $suspicious
                        Indicators = $indicators -join "; "
                        LastModified = (Get-Item $key).LastWriteTime
                    }
                }
            }
        }
    }
    
    # Export all findings
    $findings | Export-Csv $reportFile -NoTypeInformation
    
    # Display suspicious items
    $suspiciousItems = $findings | Where-Object {$_.Suspicious -eq $true}
    
    Write-Host "`n[+] Scan Complete" -ForegroundColor Green
    Write-Host "[+] Total entries found: $($findings.Count)" -ForegroundColor Cyan
    Write-Host "[!] Suspicious entries: $($suspiciousItems.Count)" -ForegroundColor Red
    Write-Host "[+] Report saved to: $reportFile" -ForegroundColor Green
    
    if ($suspiciousItems) {
        Write-Host "`n=== SUSPICIOUS PERSISTENCE MECHANISMS ===" -ForegroundColor Red
        $suspiciousItems | Select-Object ValueName, FilePath, Indicators | Format-Table -AutoSize
    }
    
    return @{
        AllFindings = $findings
        SuspiciousFindings = $suspiciousItems
        ReportPath = $reportFile
    }
}

#------------------------------------------------------------------------------
# UC-008: Network Traffic Extractor
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Captures and filters network traffic (PCAP-like data) for specific IP/port/protocol.
.DESCRIPTION
    Uses native Windows capture (netsh trace / pktmon) and filters output for
    target IPs, ports, and protocols to support C2/exfil investigation.
.PARAMETER OutputPath
    Path to save capture and filtered report.
.PARAMETER DurationSeconds
    How long to capture traffic.
.PARAMETER TargetIP
    Optional target IP to focus on (source or destination).
.PARAMETER TargetPort
    Optional target TCP/UDP port to focus on.
.PARAMETER Protocol
    Optional protocol filter (TCP/UDP/ICMP/ALL).
.EXAMPLE
    .\UC-008-NetworkTrafficExtractor.ps1 -DurationSeconds 120 -TargetIP 10.10.10.5 -TargetPort 443
.NOTES
    Run As: Administrator
    Run On: Suspect endpoint or jump host
    Run When: During active C2 communication or suspected exfiltration
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "C:\Evidence",
    [int]$DurationSeconds = 60,
    [string]$TargetIP,
    [int]$TargetPort,
    [ValidateSet("ALL","TCP","UDP","ICMP")]
    [string]$Protocol = "ALL"
)

function Start-NetworkTrafficCapture {
    param(
        [string]$CapturePath,
        [int]$DurationSeconds
    )

    Write-Host "[+] Starting packet capture for $DurationSeconds seconds..." -ForegroundColor Green

    # Prefer pktmon on newer systems; fall back to netsh trace
    $usePktmon = $false
    if (Get-Command pktmon.exe -ErrorAction SilentlyContinue) {
        $usePktmon = $true
    }

    if ($usePktmon) {
        & pktmon stop > $null 2>&1
        & pktmon reset > $null 2>&1

        $captureFile = Join-Path $CapturePath "pktmon_etl.etl"
        $textFile    = Join-Path $CapturePath "pktmon_text.log"

        & pktmon start --etw -f $captureFile | Out-Null
        Start-Sleep -Seconds $DurationSeconds
        & pktmon stop | Out-Null
        & pktmon format $captureFile -o $textFile | Out-Null

        return @{
            RawCaptureFile = $captureFile
            TextCaptureFile = $textFile
            Tool = "pktmon"
        }
    }
    else {
        $traceFile = Join-Path $CapturePath "netsh_trace.etl"
        & netsh trace stop > $null 2>&1
        & netsh trace start capture=yes tracefile="$traceFile" persistent=no maxsize=512 | Out-Null

        Start-Sleep -Seconds $DurationSeconds

        & netsh trace stop | Out-Null

        return @{
            RawCaptureFile = $traceFile
            TextCaptureFile = $null
            Tool = "netsh"
        }
    }
}

function Parse-NetworkTraffic {
    param(
        [string]$TextCaptureFile,
        [string]$RawCaptureFile,
        [string]$OutputCsv,
        [string]$TargetIP,
        [int]$TargetPort,
        [string]$Protocol
    )

    $results = @()

    if ($TextCaptureFile -and (Test-Path $TextCaptureFile)) {
        Write-Host "[+] Parsing pktmon text output..." -ForegroundColor Yellow

        $lines = Get-Content $TextCaptureFile -ErrorAction SilentlyContinue

        foreach ($line in $lines) {
            if ($line -notmatch 'IPv4|IPv6') { continue }

            $srcIP = $null
            $dstIP = $null
            $srcPort = $null
            $dstPort = $null
            $proto = $null
            $timestamp = $null

            if ($line -match 'Time:\s*([0-9:\.\-T ]+)\s') {
                $timestamp = $matches[1].Trim()
            }

            if ($line -match 'Protocol:\s*(TCP|UDP|ICMP)') {
                $proto = $matches[1].ToUpper()
            }

            if ($line -match 'SrcAddr:\s*([0-9a-fA-F:\.]+)\s') {
                $srcIP = $matches[1]
            }
            if ($line -match 'DstAddr:\s*([0-9a-fA-F:\.]+)\s') {
                $dstIP = $matches[1]
            }

            if ($line -match 'SrcPort:\s*(\d+)') {
                $srcPort = [int]$matches[1]
            }
            if ($line -match 'DstPort:\s*(\d+)') {
                $dstPort = [int]$matches[1]
            }

            if (-not $proto) { continue }

            if ($Protocol -ne "ALL" -and $proto -ne $Protocol) { continue }

            if ($TargetIP) {
                if ($srcIP -ne $TargetIP -and $dstIP -ne $TargetIP) { continue }
            }

            if ($TargetPort) {
                if ($srcPort -ne $TargetPort -and $dstPort -ne $TargetPort) { continue }
            }

            $results += [PSCustomObject]@{
                Timestamp = $timestamp
                Protocol  = $proto
                SrcIP     = $srcIP
                SrcPort   = $srcPort
                DstIP     = $dstIP
                DstPort   = $dstPort
            }
        }
    }
    else {
        Write-Host "[!] Text capture not available; raw ETL saved for external PCAP tools (e.g., Wireshark)." -ForegroundColor Red
    }

    $results | Export-Csv -Path $OutputCsv -NoTypeInformation

    return $results
}

# Main
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$hostname  = $env:COMPUTERNAME

if (-not (Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

$caseFolder = Join-Path $OutputPath "UC008_NetTraffic_${hostname}_${timestamp}"
New-Item -Path $caseFolder -ItemType Directory -Force | Out-Null

Write-Host "[+] Output directory: $caseFolder" -ForegroundColor Cyan

$captureInfo = Start-NetworkTrafficCapture -CapturePath $caseFolder -DurationSeconds $DurationSeconds

$reportCsv = Join-Path $caseFolder "UC008_FilteredTraffic_${hostname}_${timestamp}.csv"

$parsed = Parse-NetworkTraffic `
    -TextCaptureFile $captureInfo.TextCaptureFile `
    -RawCaptureFile  $captureInfo.RawCaptureFile `
    -OutputCsv       $reportCsv `
    -TargetIP        $TargetIP `
    -TargetPort      $TargetPort `
    -Protocol        $Protocol

Write-Host "`n[+] Capture Complete" -ForegroundColor Green
Write-Host "[+] Raw capture: $($captureInfo.RawCaptureFile)" -ForegroundColor Cyan
if ($captureInfo.TextCaptureFile) {
    Write-Host "[+] Text capture: $($captureInfo.TextCaptureFile)" -ForegroundColor Cyan
}
Write-Host "[+] Filtered report: $reportCsv" -ForegroundColor Cyan
Write-Host "[+] Total matching flows: $($parsed.Count)" -ForegroundColor Yellow

$topSummary = $parsed |
    Group-Object SrcIP, DstIP, DstPort, Protocol |
    Select-Object @{Name="SrcIP";Expression={$_.Group[0].SrcIP}},
                  @{Name="DstIP";Expression={$_.Group[0].DstIP}},
                  @{Name="DstPort";Expression={$_.Group[0].DstPort}},
                  @{Name="Protocol";Expression={$_.Group[0].Protocol}},
                  @{Name="Count";Expression={$_.Count}} |
    Sort-Object Count -Descending |
    Select-Object -First 20

if ($topSummary) {
    Write-Host "`n=== TOP 20 MATCHING FLOWS ===" -ForegroundColor Magenta
    $topSummary | Format-Table -AutoSize
}

return @{
    RawCapture   = $captureInfo.RawCaptureFile
    TextCapture  = $captureInfo.TextCaptureFile
    FilteredCsv  = $reportCsv
    Matches      = $parsed
}

#------------------------------------------------------------------------------
# UC-009: Browser Forensics Collector
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Collects browser history, cookies, and cache data from common browsers
.DESCRIPTION
    Gathers forensic artifacts from Edge, Chrome, and Firefox for analysis
.PARAMETER OutputPath
    Directory to save forensic data
.EXAMPLE
    .\UC-009-BrowserForensicsCollector.ps1 -OutputPath "C:\Evidence\BrowserData"
.NOTES
    Run As: Administrator
    Run On: Endpoint suspected of browser-based compromise
    Run When: Investigating malicious activity via browser
#>

function Collect-BrowserArtifacts {
    param(
        [string]$OutputPath = "C:\Evidence\BrowserArtifacts"
    )

    Write-Host "[+] Collecting browser forensic artifacts..." -ForegroundColor Green
    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $userProfiles = Get-ChildItem "C:\Users" -Directory | Where-Object {Test-Path "$($_.FullName)\AppData\Local" }

    foreach ($user in $userProfiles) {
        $profilePath = $user.FullName
        $userName = $user.Name
        
        # Edge (Chromium based)
        $edgePath = Join-Path $profilePath "AppData\Local\Microsoft\Edge\User Data\Default"
        if (Test-Path $edgePath) {
            $dest = Join-Path $OutputPath "Edge-$userName"
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            Get-ChildItem -Path $edgePath -Include "History","Cookies","Cache" -Recurse -ErrorAction SilentlyContinue | 
                Copy-Item -Destination $dest -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "[*] Collected Edge artifacts for user: $userName"
        }

        # Chrome
        $chromePath = Join-Path $profilePath "AppData\Local\Google\Chrome\User Data\Default"
        if (Test-Path $chromePath) {
            $dest = Join-Path $OutputPath "Chrome-$userName"
            New-Item -ItemType Directory -Path $dest -Force | Out-Null
            Get-ChildItem -Path $chromePath -Include "History","Cookies","Cache" -Recurse -ErrorAction SilentlyContinue | 
                Copy-Item -Destination $dest -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "[*] Collected Chrome artifacts for user: $userName"
        }

        # Firefox (profile folder varies)
        $firefoxProfilesIni = Join-Path $profilePath "AppData\Roaming\Mozilla\Firefox\profiles.ini"
        if (Test-Path $firefoxProfilesIni) {
            $iniContent = Get-Content $firefoxProfilesIni -ErrorAction SilentlyContinue
            $profiles = $iniContent -match 'Path=' | ForEach-Object { ($_ -split '=')[1].Trim() }

            foreach ($profile in $profiles) {
                $firefoxPath = Join-Path $profilePath "AppData\Roaming\Mozilla\Firefox\$profile"
                if (Test-Path $firefoxPath) {
                    $dest = Join-Path $OutputPath "Firefox-$userName-$profile"
                    New-Item -ItemType Directory -Path $dest -Force | Out-Null
                    Get-ChildItem -Path $firefoxPath -Include "cookies.sqlite","places.sqlite","cache2" -Recurse -ErrorAction SilentlyContinue |
                        Copy-Item -Destination $dest -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Host "[*] Collected Firefox artifacts for user: $userName, profile: $profile"
                }
            }
        }
    }

    Write-Host "`n[+] Browser artifacts collection complete. Data saved to $OutputPath" -ForegroundColor Green
    return $OutputPath
}

# Usage example:
# Collect-BrowserArtifacts -OutputPath "C:\Evidence\BrowserData"

# Note:
# - Run this script as Administrator on the suspect endpoint
# - Use it during investigations of browser-based compromise or suspicious web activity

#------------------------------------------------------------------------------
# UC-010: Scheduled Tasks Enumerator
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Enumerates all scheduled tasks on the system for suspicious activity
.DESCRIPTION
    Lists every scheduled task with detailed information including triggers, actions, and security descriptors
.PARAMETER OutputPath
    Directory to save the scheduled tasks report
.EXAMPLE
    .\UC-010-ScheduledTasksEnumerator.ps1 -OutputPath "C:\Evidence\ScheduledTasks"
.NOTES
    Run As: Administrator
    Run On: Endpoint suspected of persistence or automated malicious activity
    Run When: Investigating suspicious recurring process or malware persistence
#>

function Get-ScheduledTasksReport {
    param(
        [string]$OutputPath = "C:\Evidence\ScheduledTasks"
    )

    Write-Host "[+] Enumerating all scheduled tasks..." -ForegroundColor Green
    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME
    $reportFile = "$OutputPath\ScheduledTasks_${hostname}_${timestamp}.csv"

    $tasks = Get-ScheduledTask

    $results = foreach ($task in $tasks) {
        $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath

        [PSCustomObject]@{
            TaskName           = $task.TaskName
            TaskPath           = $task.TaskPath
            State              = $taskInfo.State
            LastRunTime        = $taskInfo.LastRunTime
            NextRunTime        = $taskInfo.NextRunTime
            Author             = $task.Author
            Description        = $task.Description
            Actions            = ($task.Actions | ForEach-Object { $_.Execute + " " + $_.Arguments }) -join "; "
            Triggers           = ($task.Triggers | ForEach-Object { $_.ToString() }) -join "; "
            PrincipalUserId    = $task.Principal.UserId
            RunLevel           = $task.Principal.RunLevel
            Enabled            = $task.Settings.Enabled
            Hidden             = $task.Settings.Hidden
        }
    }

    $results | Export-Csv -Path $reportFile -NoTypeInformation

    $suspiciousTasks = $results | Where-Object {
        ($_.Enabled -eq $true) -and 
        ($_.State -ne 'Ready' -and $_.State -ne 'Running') -or 
        ($_.RunLevel -eq 'Highest') -or 
        ($_.TaskName -match '^[a-f0-9]{8}-[a-f0-9]{4}') # Possible random GUID
    }
    
    Write-Host "`n[+] Scheduled tasks enumeration completed." -ForegroundColor Green
    Write-Host "[+] Report saved to: $reportFile" -ForegroundColor Green
    Write-Host "[!] Suspicious tasks count: $($suspiciousTasks.Count)" -ForegroundColor Red

    if ($suspiciousTasks.Count -gt 0) {
        Write-Host "`n=== Suspicious Scheduled Tasks ===" -ForegroundColor Red
        $suspiciousTasks | Select-Object TaskName, TaskPath, State, RunLevel, Actions | Format-Table -AutoSize
    }

    return @{
        AllTasks = $results
        SuspiciousTasks = $suspiciousTasks
        ReportPath = $reportFile
    }
}

# Usage:
# Get-ScheduledTasksReport -OutputPath "C:\Evidence\ScheduledTasks"

# Instructions:
# - Run as Administrator on endpoints suspected of malware persistence
# - Useful for detecting hidden, misconfigured, or suspicious scheduled tasks
#------------------------------------------------------------------------------
# UC-011: Active Network Connections Snapshot
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Captures a snapshot of all active network connections on the endpoint
.DESCRIPTION
    Collects detailed connection info including process, remote address, and port
.PARAMETER OutputPath
    Directory to save the network connections report
.EXAMPLE
    .\UC-011-ActiveNetworkConnections.ps1 -OutputPath "C:\Evidence\NetworkConnections"
.NOTES
    Run As: Administrator
    Run On: Endpoint suspected of network anomalies or malware communication
    Run When: Investigating suspicious outgoing or incoming network activity
#>

function Get-ActiveNetworkConnections {
    param(
        [string]$OutputPath = "C:\Evidence\NetworkConnections"
    )

    Write-Host "[+] Collecting active network connections..." -ForegroundColor Green
    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME
    $reportFile = "$OutputPath\NetworkConnections_${hostname}_${timestamp}.csv"

    $tcpConnections = Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' }

    $results = foreach ($conn in $tcpConnections) {
        $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            LocalAddress  = $conn.LocalAddress
            LocalPort     = $conn.LocalPort
            RemoteAddress = $conn.RemoteAddress
            RemotePort    = $conn.RemotePort
            State         = $conn.State
            OwningProcessId = $conn.OwningProcess
            ProcessName   = if ($proc) { $proc.ProcessName } else { "N/A" }
        }
    }

    $results | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] Network connections snapshot saved to: $reportFile" -ForegroundColor Green

    return @{
        Connections = $results
        ReportPath = $reportFile
    }
}

# Usage:
# Get-ActiveNetworkConnections -OutputPath "C:\Evidence\NetworkConnections"

# Notes:
# - Run as Administrator to get full process info
# - Helps to identify unknown or suspicious network connections quickly

#------------------------------------------------------------------------------
# UC-012: Suspicious File Scanner
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Scans system for files matching suspicious patterns and indicators
.DESCRIPTION
    Searches files by extension, hashes, and common malware filenames on disk drives
.PARAMETER OutputPath
    Directory to save scan report
.PARAMETER ScanPaths
    Array of directories or drives to scan (default: C:\)
.EXAMPLE
    .\UC-012-SuspiciousFileScanner.ps1 -OutputPath "C:\Evidence\SuspiciousFiles" -ScanPaths @("C:\", "D:\")
.NOTES
    Run As: Administrator
    Run On: Endpoint with suspected malware infection
    Run When: Malware left unknown or hidden files, or during threat hunting
#>

function Scan-SuspiciousFiles {
    param(
        [string]$OutputPath = "C:\Evidence\SuspiciousFiles",
        [string[]]$ScanPaths = @("C:\")
    )

    Write-Host "[+] Starting suspicious file scan..." -ForegroundColor Green

    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME
    $reportFile = "$OutputPath\SuspiciousFiles_${hostname}_${timestamp}.csv"

    # Define suspicious file extensions and names (customize as needed)
    $susExtensions = @(".exe", ".dll", ".js", ".vbs", ".ps1", ".scr", ".bat", ".cmd")
    $susNames = @("svchost.exe", "explorer.exe", "taskmgr.exe", "wmiprvse.exe", "rundll32.exe")

    $findings = @()

    foreach ($path in $ScanPaths) {
        Write-Host "[+] Scanning path: $path"
        foreach ($ext in $susExtensions) {
            try {
                $files = Get-ChildItem -Path $path -Filter "*$ext" -Recurse -ErrorAction SilentlyContinue
                foreach ($file in $files) {
                    if ($susNames -contains $file.Name.ToLower()) {
                        $isSuspiciousName = $true
                    } else {
                        $isSuspiciousName = $false
                    }
                    # Calculate file hash (SHA256)
                    $hash = (Get-FileHash $file.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                    $lastModified = $file.LastWriteTime

                    $findings += [PSCustomObject]@{
                        Path = $file.FullName
                        Name = $file.Name
                        Extension = $file.Extension
                        Hash = $hash
                        LastModified = $lastModified
                        SuspiciousName = $isSuspiciousName
                    }
                }
            } catch {
                Write-Host "[-] Error scanning $path with extension $ext" -ForegroundColor Yellow
            }
        }
    }

    $findings | Export-Csv $reportFile -NoTypeInformation

    $suspiciousItems = $findings | Where-Object { $_.SuspiciousName -eq $true }

    Write-Host "`n[+] Scan complete." -ForegroundColor Green
    Write-Host "[+] Total files scanned: $($findings.Count)" -ForegroundColor Cyan
    Write-Host "[!] Suspicious named files found: $($suspiciousItems.Count)" -ForegroundColor Red
    Write-Host "[+] Report saved to: $reportFile" -ForegroundColor Green

    if ($suspiciousItems.Count -gt 0) {
        Write-Host "`n=== Suspicious Named Files ===" -ForegroundColor Red
        $suspiciousItems | Select-Object Name, Path, Hash | Format-Table -AutoSize
    }

    return @{
        AllFiles = $findings
        SuspiciousFiles = $suspiciousItems
        ReportPath = $reportFile
    }
}

# Usage:
# Scan-SuspiciousFiles -OutputPath "C:\Evidence\SuspiciousFiles" -ScanPaths @("C:\","D:\")

# Notes:
# - Run as Administrator to ensure access to protected files
# - Adjust suspicious names list to fit environment/malware profiles

#------------------------------------------------------------------------------
# UC-013: Event Log Suspicious Activity Finder
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Searches Windows Event Logs for suspicious or anomalous events
.DESCRIPTION
    Filters Security, System, and Application logs for events indicating possible compromise or anomalies
.PARAMETER OutputPath
    Directory to save event log report
.PARAMETER StartTime
    Optional start time filter for events (default: last 24 hours)
.EXAMPLE
    .\UC-013-EventLogSuspiciousActivity.ps1 -OutputPath "C:\Evidence\EventLogs" -StartTime (Get-Date).AddHours(-48)
.NOTES
    Run As: Administrator
    Run On: Endpoint suspected of compromise or unusual activity
    Run When: Investigating alerts or post-incident response
#>

function Find-SuspiciousEventLogs {
    param(
        [string]$OutputPath = "C:\Evidence\EventLogs",
        [datetime]$StartTime = (Get-Date).AddHours(-24)
    )

    Write-Host "[+] Collecting suspicious event log entries since $StartTime ..." -ForegroundColor Green

    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME
    $reportFile = "$OutputPath\SuspiciousEvents_${hostname}_${timestamp}.evtx"

    # Define event IDs and keywords commonly associated with suspicious activities
    # Customize as needed based on environment
    $suspiciousEventIDs = @(4624, 4625, 4688, 4697, 4703, 4719, 4720, 4726, 4732, 4768, 4672)

    # Filter logs from Security log for suspicious event IDs and time window
    $filterXml = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4624 or EventID=4625 or EventID=4688 or EventID=4697 or EventID=4703 or EventID=4719 or EventID=4720 or EventID=4726 or EventID=4732 or EventID=4768 or EventID=4672) and TimeCreated[timediff(@SystemTime) <= 86400000]]]
    </Select>
  </Query>
</QueryList>
"@

    $events = Get-WinEvent -FilterXml $filterXml -ErrorAction SilentlyContinue

    # Export events to EVTX file
    $events | Export-Clixml -Path "$OutputPath\SuspiciousEvents_${hostname}_${timestamp}.xml"

    Write-Host "`n[+] Suspicious event log entries exported to XML in: $OutputPath" -ForegroundColor Green

    return @{
        Events = $events
        ReportXmlPath = "$OutputPath\SuspiciousEvents_${hostname}_${timestamp}.xml"
    }
}

# Usage:
# Find-SuspiciousEventLogs -OutputPath "C:\Evidence\EventLogs" -StartTime (Get-Date).AddHours(-24)

# Notes:
# - Run as Administrator to access Security logs
# - Adjust Event IDs to capture environment-specific suspicious events
# - EVTX export done via XML representation for broader compatibility

#------------------------------------------------------------------------------
# UC-014: Malware DLL Injection Detector
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Detects potential DLL injection by scanning processes for unexpected loaded DLLs
.DESCRIPTION
    Lists processes and their loaded DLL modules, highlights suspicious DLLs not commonly loaded
.PARAMETER OutputPath
    Directory to save DLL injection report
.EXAMPLE
    .\UC-014-DllInjectionDetector.ps1 -OutputPath "C:\Evidence\DllInjection"
.NOTES
    Run As: Administrator
    Run On: Endpoint suspected of process injection or code injection attacks
    Run When: Investigating suspicious process behavior or malware persistence methods
#>

function Detect-DllInjection {
    param(
        [string]$OutputPath = "C:\Evidence\DllInjection"
    )

    Write-Host "[+] Scanning running processes for suspicious loaded DLLs..." -ForegroundColor Green
    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME
    $reportFile = "$OutputPath\DllInjection_${hostname}_${timestamp}.csv"

    # Common trusted system DLL directories
    $trustedPaths = @(
        "C:\Windows\System32",
        "C:\Windows\SysWOW64"
    )

    $results = @()

    $processes = Get-Process | Where-Object { $_.Modules -ne $null }

    foreach ($proc in $processes) {
        try {
            foreach ($mod in $proc.Modules) {
                $dllPath = $mod.FileName
                $isTrusted = $false
                foreach ($trusted in $trustedPaths) {
                    if ($dllPath.StartsWith($trusted, [System.StringComparison]::InvariantCultureIgnoreCase)) {
                        $isTrusted = $true
                        break
                    }
                }

                if (-not $isTrusted) {
                    $results += [PSCustomObject]@{
                        ProcessName = $proc.ProcessName
                        ProcessId   = $proc.Id
                        ModuleName  = $mod.ModuleName
                        FileName    = $dllPath
                    }
                }
            }
        } catch {
            # Ignore access denied or process exit errors
        }
    }

    $results | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] DLL injection scan completed." -ForegroundColor Green
    Write-Host "[+] Suspicious DLLs saved to: $reportFile" -ForegroundColor Green
    Write-Host "[!] Suspicious DLL count: $($results.Count)" -ForegroundColor Red

    if ($results.Count -gt 0) {
        Write-Host "`n=== Suspicious DLLs ===" -ForegroundColor Red
        $results | Select-Object ProcessName, ProcessId, ModuleName, FileName | Format-Table -AutoSize
    }

    return @{
        SuspiciousDlls = $results
        ReportPath = $reportFile
    }
}

# Usage:
# Detect-DllInjection -OutputPath "C:\Evidence\DllInjection"

# Notes:
# - Run as Administrator for full module listing
# - Use to detect potential malicious DLL injection outside trusted System paths

#------------------------------------------------------------------------------
# UC-015: USB Device Connection Logger
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Logs all USB device connection and disconnection events
.DESCRIPTION
    Collects USB device insertion/removal events and saves detailed information for forensic analysis
.PARAMETER OutputPath
    Directory to save USB connection logs
.EXAMPLE
    .\UC-015-USBDeviceLogger.ps1 -OutputPath "C:\Evidence\USBLogs"
.NOTES
    Run As: Administrator
    Run On: Endpoint to monitor USB device activity
    Run When: Investigating data exfiltration or unauthorized device usage
#>

function Get-USBDeviceEvents {
    param(
        [string]$OutputPath = "C:\Evidence\USBLogs"
    )

    Write-Host "[+] Retrieving USB device events..." -ForegroundColor Green
    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME
    $reportFile = "$OutputPath\USBDeviceEvents_${hostname}_${timestamp}.csv"

    # Event IDs related to USB device connect/disconnect
    $eventIds = @(20001, 20003, 2100, 2102) # Example from Microsoft-Windows-DriverFrameworks-UserMode/Operational

    $query = @"
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-DriverFrameworks-UserMode/Operational">
    <Select>*[System[(EventID=20001 or EventID=20003 or EventID=2100 or EventID=2102)]]</Select>
  </Query>
</QueryList>
"@

    $events = Get-WinEvent -FilterXml $query -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, LevelDisplayName, Message

    $events | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] USB device connection events saved to: $reportFile" -ForegroundColor Green

    return @{
        USBEvents = $events
        ReportPath = $reportFile
    }
}

# Usage:
# Get-USBDeviceEvents -OutputPath "C:\Evidence\USBLogs"

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-016: User Account Audit
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Audits local user accounts for anomalies or suspicious changes
.DESCRIPTION
    Lists user accounts, their status, last login time, and group memberships
.PARAMETER OutputPath
    Directory to save user accounts report
.EXAMPLE
    .\UC-016-UserAccountAudit.ps1 -OutputPath "C:\Evidence\UserAudit"
.NOTES
    Run As: Administrator
    Run On: Endpoint suspected of account compromise or misuse
    Run When: Performing account security reviews or investigations
#>

function Audit-UserAccounts {
    param(
        [string]$OutputPath = "C:\Evidence\UserAudit"
    )

    Write-Host "[+] Auditing local user accounts..." -ForegroundColor Green
    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME
    $reportFile = "$OutputPath\UserAccounts_${hostname}_${timestamp}.csv"

    $userAccounts = Get-LocalUser

    $results = foreach ($user in $userAccounts) {
        $lastLogon = (Get-LocalUser | Where-Object { $_.Name -eq $user.Name }).LastLogon
        $groups = (Get-LocalGroup | ForEach-Object {
            $members = Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue
            if ($members -and ($members.Name -contains $user.Name)) { $_.Name }
        }) -join "; "

        [PSCustomObject]@{
            UserName = $user.Name
            Enabled = $user.Enabled
            LastLogon = $lastLogon
            Description = $user.Description
            Groups = $groups
        }
    }

    $results | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] User account audit report saved to: $reportFile" -ForegroundColor Green

    return @{
        UserAccounts = $results
        ReportPath = $reportFile
    }
}

# Usage:
# Audit-UserAccounts -OutputPath "C:\Evidence\UserAudit"

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-017: Host File Integrity Checker
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Checks Windows hosts file for unauthorized modifications
.DESCRIPTION
    Compares current hosts file content with baseline or alerts on suspicious entries
.PARAMETER OutputPath
    Directory to save hosts file check report
.EXAMPLE
    .\UC-017-HostFileChecker.ps1 -OutputPath "C:\Evidence\HostFileCheck"
.NOTES
    Run As: Administrator
    Run On: Endpoint suspected of DNS tampering or redirection attacks
    Run When: Validating hosts file after suspicious activity detection
#>

function Check-HostsFileIntegrity {
    param(
        [string]$OutputPath = "C:\Evidence\HostFileCheck",
        [string]$BaselinePath = ""
    )

    Write-Host "[+] Checking hosts file integrity..." -ForegroundColor Green
    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME
    $reportFile = "$OutputPath\HostsFileCheck_${hostname}_${timestamp}.txt"

    $hostsFilePath = "C:\Windows\System32\drivers\etc\hosts"

    if (!(Test-Path $hostsFilePath)) {
        Write-Host "[-] Hosts file not found at expected location" -ForegroundColor Red
        return $null
    }

    $currentContent = Get-Content $hostsFilePath

    if ($BaselinePath -and (Test-Path $BaselinePath)) {
        $baselineContent = Get-Content $BaselinePath
        $differences = Compare-Object -ReferenceObject $baselineContent -DifferenceObject $currentContent

        if ($differences) {
            $differences | Out-File $reportFile
            Write-Host "[!] Hosts file differs from baseline. Differences saved to $reportFile" -ForegroundColor Red
        } else {
            Write-Host "[+] Hosts file matches baseline. No deviations found." -ForegroundColor Green
        }
    } else {
        $currentContent | Out-File $reportFile
        Write-Host "[*] Baseline not provided. Current hosts file saved to $reportFile" -ForegroundColor Yellow
    }

    return $reportFile
}

# Usage:
# Check-HostsFileIntegrity -OutputPath "C:\Evidence\HostFileCheck" -BaselinePath "C:\Baseline\hosts_baseline.txt"

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-018: Open Ports and Listening Services
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Lists all open TCP/UDP ports and their associated listening services
.DESCRIPTION
    Enumerates active listening ports and captures associated process/service info
.PARAMETER OutputPath
    Directory to save open ports report
.EXAMPLE
    .\UC-018-OpenPortsListener.ps1 -OutputPath "C:\Evidence\OpenPorts"
.NOTES
    Run As: Administrator
    Run On: Endpoint suspected of network-based attacks or unauthorized services
    Run When: Investigating exposed services or unauthorized listening ports
#>

function Get-OpenPortsAndListeners {
    param(
        [string]$OutputPath = "C:\Evidence\OpenPorts"
    )

    Write-Host "[+] Gathering open ports and listening services..." -ForegroundColor Green
    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME
    $reportFile = "$OutputPath\OpenPorts_${hostname}_${timestamp}.csv"

    $netstatOutput = netstat -ano | Select-String "LISTENING"

    $results = @()

    foreach ($line in $netstatOutput) {
        $parts = $line -split '\s+'
        if ($parts.Length -ge 5) {
            $protocol = $parts[0]
            $localAddress = $parts[1]
            $state = $parts[3]
            $pid = [int]$parts[4]

            try {
                $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
                $procName = if ($proc) { $proc.ProcessName } else { "N/A" }
            } catch {
                $procName = "N/A"
            }

            $results += [PSCustomObject]@{
                Protocol = $protocol
                LocalAddress = $localAddress
                State = $state
                ProcessId = $pid
                ProcessName = $procName
            }
        }
    }

    $results | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] Open ports report saved to: $reportFile" -ForegroundColor Green

    return @{
        OpenPorts = $results
        ReportPath = $reportFile
    }
}

# Usage:
# Get-OpenPortsAndListeners -OutputPath "C:\Evidence\OpenPorts"


#------------------------------------------------------------------------------
# UC-019: PowerShell History Extractor
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Extracts PowerShell command history from user profiles
.DESCRIPTION
    Collects recent PowerShell commands for forensic review
.PARAMETER OutputPath
    Directory to save PowerShell history logs
.EXAMPLE
    .\UC-019-PowerShellHistoryExtractor.ps1 -OutputPath "C:\Evidence\PowerShellHistory"
.NOTES
    Run As: Administrator
    Run On: Endpoint suspected of PowerShell-based attacks
    Run When: Investigating suspicious PowerShell usage or scripts
#>

function Extract-PowerShellHistory {
    param(
        [string]$OutputPath = "C:\Evidence\PowerShellHistory"
    )

    Write-Host "[+] Extracting PowerShell history from user profiles..." -ForegroundColor Green
    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $userProfiles = Get-ChildItem "C:\Users" -Directory | Where-Object {Test-Path "$($_.FullName)\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" }

    foreach ($user in $userProfiles) {
        $historyPath = Join-Path $user.FullName "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
        if (Test-Path $historyPath) {
            $content = Get-Content $historyPath -ErrorAction SilentlyContinue
            $dest = Join-Path $OutputPath "PowerShellHistory_$($user.Name).txt"
            $content | Out-File $dest -Force
            Write-Host "[*] Extracted PowerShell history for user: $($user.Name)"
        }
    }

    Write-Host "`n[+] PowerShell history extraction complete." -ForegroundColor Green
    return $OutputPath
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-020: Windows Defender Scan Report Extractor
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Extracts Windows Defender threat detection and scan reports
.DESCRIPTION
    Collects recent AV detection logs and scan results for review
.PARAMETER OutputPath
    Directory to save Defender reports
.EXAMPLE
    .\UC-020-WindowsDefenderReportExtractor.ps1 -OutputPath "C:\Evidence\DefenderReports"
.NOTES
    Run As: Administrator
    Run On: Endpoint with Defender enabled
    Run When: Reviewing AV alerts and past scans for infection data
#>

function Extract-DefenderReports {
    param(
        [string]$OutputPath = "C:\Evidence\DefenderReports"
    )

    Write-Host "[+] Extracting Windows Defender threat and scan reports..." -ForegroundColor Green
    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $logsPath = "C:\ProgramData\Microsoft\Windows Defender\Scans\History\DetectionHistory"
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME
    $reportFile = "$OutputPath\DefenderDetections_${hostname}_${timestamp}.csv"

    if (!(Test-Path $logsPath)) {
        Write-Host "[-] Windows Defender Detection History folder not found." -ForegroundColor Red
        return $null
    }

    $detections = Get-ChildItem $logsPath -Recurse -Filter "*.xml" -ErrorAction SilentlyContinue | ForEach-Object {
        [xml]$xml = Get-Content $_.FullName -ErrorAction SilentlyContinue
        $obj = $xml.SelectSingleNode("//Detection")
        if ($obj) {
            [PSCustomObject]@{
                ThreatName = $obj.ThreatName
                Severity = $obj.Severity
                Category = $obj.Category
                Action = $obj.Action
                Date = $obj.DetectionTime
                FilePath = $obj.Path
            }
        }
    }

    $detections | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] Windows Defender detections exported to: $reportFile" -ForegroundColor Green
    return @{
        Detections = $detections
        ReportPath = $reportFile
    }
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-021: Process Tree Snapshot
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Captures a detailed snapshot of processes and their parent-child relationships
.DESCRIPTION
    Lists running processes with parent PID to map process trees for analysis
.PARAMETER OutputPath
    Directory to save process tree report
.EXAMPLE
    .\UC-021-ProcessTreeSnapshot.ps1 -OutputPath "C:\Evidence\ProcessTrees"
.NOTES
    Run As: Administrator
    Run On: Endpoint suspected of process injection or unusual spawning
    Run When: Investigating abnormal process relationships or malware spawning
#>

function Get-ProcessTree {
    param(
        [string]$OutputPath = "C:\Evidence\ProcessTrees"
    )
    
    Write-Host "[+] Capturing process tree snapshot..." -ForegroundColor Green
    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME
    $reportFile = "$OutputPath\ProcessTree_${hostname}_${timestamp}.csv"

    $procList = Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, CommandLine

    $procList | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] Process tree snapshot saved to: $reportFile" -ForegroundColor Green

    return @{
        ProcessTree = $procList
        ReportPath = $reportFile
    }
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-022: Scheduled Task Creation Monitor
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Monitors creation of new scheduled tasks in real-time
.DESCRIPTION
    Sets up a WMI event subscription to notify when new scheduled tasks are created
.PARAMETER DurationMinutes
    Duration in minutes to monitor (default 10)
.EXAMPLE
    .\UC-022-ScheduledTaskCreationMonitor.ps1 -DurationMinutes 15
.NOTES
    Run As: Administrator
    Run On: Endpoint requiring monitoring of suspicious scheduled task creation
    Run When: Detecting persistence or lateral movement attempts
#>

function Monitor-NewScheduledTask {
    param(
        [int]$DurationMinutes = 10
    )

    Write-Host "[+] Monitoring for new scheduled tasks for $DurationMinutes minutes..." -ForegroundColor Green

    $query = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_ScheduledJob'"

    $action = {
        param($event)
        $task = $event.SourceEventArgs.NewEvent.TargetInstance
        Write-Host "New scheduled task created: TaskID=$($task.JobId), Command=$($task.Command)" -ForegroundColor Yellow
    }

    $job = Register-WmiEvent -Query $query -Action $action

    Start-Sleep -Seconds ($DurationMinutes * 60)

    Unregister-Event -SourceIdentifier $job.Name
    Remove-Job -Name $job.Name

    Write-Host "[+] Scheduled task creation monitoring ended." -ForegroundColor Green
}

# Usage:
# Monitor-NewScheduledTask -DurationMinutes 10

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-023: File System Change Monitor
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Watches specified directories for file creations, modifications, or deletions
.DESCRIPTION
    Uses FileSystemWatcher to detect changes and logs events in real-time
.PARAMETER PathToWatch
    Directory path to monitor
.PARAMETER DurationMinutes
    Duration in minutes to monitor (default 10)
.PARAMETER OutputPath
    Directory to save log file
.EXAMPLE
    .\UC-023-FileSystemChangeMonitor.ps1 -PathToWatch "C:\Users" -DurationMinutes 15 -OutputPath "C:\Evidence\FileMonitor"
.NOTES
    Run As: Administrator
    Run On: Endpoint where file integrity or changes need monitoring
    Run When: Detecting suspicious file activity or data tampering
#>

function Monitor-FileSystemChanges {
    param(
        [string]$PathToWatch = "C:\",
        [int]$DurationMinutes = 10,
        [string]$OutputPath = "C:\Evidence\FileMonitor"
    )

    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }
    $logFile = Join-Path $OutputPath "FileChanges_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

    Write-Host "[+] Monitoring file system changes in $PathToWatch for $DurationMinutes minutes..." -ForegroundColor Green

    $fsw = New-Object System.IO.FileSystemWatcher $PathToWatch -Property @{
        IncludeSubdirectories = $true
        EnableRaisingEvents = $true
    }

    Register-ObjectEvent $fsw Created -SourceIdentifier FileCreated -Action {
        $msg = "$(Get-Date) [Created] $($Event.SourceEventArgs.FullPath)"
        $msg | Out-File -FilePath $logFile -Append
        Write-Host $msg -ForegroundColor Yellow
    }

    Register-ObjectEvent $fsw Changed -SourceIdentifier FileChanged -Action {
        $msg = "$(Get-Date) [Changed] $($Event.SourceEventArgs.FullPath)"
        $msg | Out-File -FilePath $logFile -Append
        Write-Host $msg -ForegroundColor Cyan
    }

    Register-ObjectEvent $fsw Deleted -SourceIdentifier FileDeleted -Action {
        $msg = "$(Get-Date) [Deleted] $($Event.SourceEventArgs.FullPath)"
        $msg | Out-File -FilePath $logFile -Append
        Write-Host $msg -ForegroundColor Red
    }

    Start-Sleep -Seconds ($DurationMinutes * 60)

    # Cleanup
    Unregister-Event -SourceIdentifier FileCreated,FileChanged,FileDeleted
    $fsw.Dispose()

    Write-Host "[+] File system monitoring ended. Log saved to: $logFile" -ForegroundColor Green

    return $logFile
}

# Usage:
# Monitor-FileSystemChanges -PathToWatch "C:\Users" -DurationMinutes 10 -OutputPath "C:\Evidence\FileMonitor"

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-024: Installed Software Inventory
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Creates an inventory of all installed software on the system
.DESCRIPTION
    Extracts installed programs from registry and outputs a report
.PARAMETER OutputPath
    Directory to save inventory report
.EXAMPLE
    .\UC-024-InstalledSoftwareInventory.ps1 -OutputPath "C:\Evidence\SoftwareInventory"
.NOTES
    Run As: Administrator
    Run On: Endpoint for software auditing or vulnerability management
    Run When: Performing asset inventory or patch management
#>

function Get-InstalledSoftwareInventory {
    param(
        [string]$OutputPath = "C:\Evidence\SoftwareInventory"
    )

    Write-Host "[+] Collecting installed software inventory..." -ForegroundColor Green
    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME
    $reportFile = "$OutputPath\InstalledSoftware_${hostname}_${timestamp}.csv"

    $registryPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $softwareList = foreach ($path in $registryPaths) {
        Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.DisplayName
                Version = $_.DisplayVersion
                Publisher = $_.Publisher
                InstallDate = $_.InstallDate
            }
        }
    }

    $softwareList | Sort-Object Name | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] Installed software inventory saved to: $reportFile" -ForegroundColor Green

    return @{
        SoftwareInventory = $softwareList
        ReportPath = $reportFile
    }
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-025: User Logon Sessions Tracker
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Lists all current and recent user logon sessions on the machine
.DESCRIPTION
    Retrieves active user sessions and their logon times for auditing
.PARAMETER OutputPath
    Directory to save logon sessions report
.EXAMPLE
    .\UC-025-UserLogonSessionsTracker.ps1 -OutputPath "C:\Evidence\UserSessions"
.NOTES
    Run As: Administrator
    Run On: Endpoint for user activity auditing or anomaly detection
    Run When: Investigating suspicious or unauthorized user logons
#>

function Get-UserLogonSessions {
    param(
        [string]$OutputPath = "C:\Evidence\UserSessions"
    )

    Write-Host "[+] Retrieving user logon sessions..." -ForegroundColor Green
    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME
    $reportFile = "$OutputPath\UserSessions_${hostname}_${timestamp}.csv"

    $sessions = quser /server:$env:COMPUTERNAME 2>&1 |
        ForEach-Object {
            if ($_ -match '^\s*(\S+)\s+(\S+)\s+(\d+)\s+(\w+)\s+(\d+/\d+/\d+)\s+(\d+:\d+)(\w{2})') {
                [PSCustomObject]@{
                    UserName = $matches[1]
                    SessionName = $matches[2]
                    Id = $matches[3]
                    State = $matches[4]
                    LogonDate = $matches[5]
                    LogonTime = $matches[6] + $matches[7]
                }
            }
        }

    $sessions | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] User logon sessions saved to: $reportFile" -ForegroundColor Green

    return @{
        UserSessions = $sessions
        ReportPath = $reportFile
    }
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-026: System Environment Variables Enumerator
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Enumerates system and user environment variables
.DESCRIPTION
    Lists environment variables for forensic or configuration auditing
.PARAMETER OutputPath
    Directory to save environment variables report
.EXAMPLE
    .\UC-026-EnvVariablesEnumerator.ps1 -OutputPath "C:\Evidence\EnvVariables"
.NOTES
    Run As: Administrator
    Run On: Endpoint for configuration or baseline comparison
    Run When: Auditing for anomalies or unexpected environment variables
#>

function Get-EnvironmentVariablesReport {
    param(
        [string]$OutputPath = "C:\Evidence\EnvVariables"
    )

    Write-Host "[+] Collecting environment variables..." -ForegroundColor Green
    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME
    $reportFile = "$OutputPath\EnvVariables_${hostname}_${timestamp}.csv"

    $systemVars = [System.Environment]::GetEnvironmentVariables("Machine")
    $userVars = [System.Environment]::GetEnvironmentVariables("User")

    $results = @()

    foreach ($key in $systemVars.Keys) {
        $results += [PSCustomObject]@{
            Scope = "Machine"
            Variable = $key
            Value = $systemVars[$key]
        }
    }

    foreach ($key in $userVars.Keys) {
        $results += [PSCustomObject]@{
            Scope = "User"
            Variable = $key
            Value = $userVars[$key]
        }
    }

    $results | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] Environment variables report saved to: $reportFile" -ForegroundColor Green

    return @{
        EnvVariables = $results
        ReportPath = $reportFile
    }
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-027: Scheduled Services Status Checker
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Checks status of critical Windows services and alerts if stopped
.DESCRIPTION
    Enumerates specified services and identifies those not running
.PARAMETER OutputPath
    Directory to save services report
.PARAMETER ServicesToCheck
    Array of service names to audit (default includes common critical services)
.EXAMPLE
    .\UC-027-ScheduledServicesStatusChecker.ps1 -OutputPath "C:\Evidence\ServiceStatus"
.NOTES
    Run As: Administrator
    Run On: Endpoint to verify service integrity
    Run When: Monitoring infrastructure or security-related services
#>

function Check-ScheduledServicesStatus {
    param(
        [string]$OutputPath = "C:\Evidence\ServiceStatus",
        [string[]]$ServicesToCheck = @("wuauserv", "WinDefend", "BITS", "EventLog", "Schedule", "Spooler", "LanmanServer")
    )

    Write-Host "[+] Checking status of scheduled services..." -ForegroundColor Green
    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME
    $reportFile = "$OutputPath\ServicesStatus_${hostname}_${timestamp}.csv"

    $results = foreach ($svc in $ServicesToCheck) {
        $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            ServiceName = $svc
            DisplayName = if ($service) { $service.DisplayName } else { "Not Found" }
            Status = if ($service) { $service.Status } else { "Unknown" }
        }
    }

    $results | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] Services status report saved to: $reportFile" -ForegroundColor Green

    $stopped = $results | Where-Object { $_.Status -ne "Running" }

    if ($stopped.Count -gt 0) {
        Write-Host "[!] Non-running services detected:" -ForegroundColor Red
        $stopped | Format-Table -AutoSize
    } else {
        Write-Host "[+] All checked services are running." -ForegroundColor Green
    }

    return @{
        ServicesStatus = $results
        ReportPath = $reportFile
    }
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-028: Active Firewall Rules Exporter
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Exports all active firewall rules for auditing
.DESCRIPTION
    Lists firewall rules with details and exports to CSV report
.PARAMETER OutputPath
    Directory to save firewall rules report
.EXAMPLE
    .\UC-028-FirewallRulesExporter.ps1 -OutputPath "C:\Evidence\FirewallRules"
.NOTES
    Run As: Administrator
    Run On: Endpoint for firewall configuration review
    Run When: Baseline audit or incident response
#>

function Export-FirewallRules {
    param(
        [string]$OutputPath = "C:\Evidence\FirewallRules"
    )

    Write-Host "[+] Exporting active firewall rules..." -ForegroundColor Green
    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME
    $reportFile = "$OutputPath\FirewallRules_${hostname}_${timestamp}.csv"

    $rules = Get-NetFirewallRule | Where-Object { $_.Enabled -eq "True" }

    $ruleDetails = foreach ($rule in $rules) {
        $profile = ($rule | Get-NetFirewallProfile).Name -join ","
        [PSCustomObject]@{
            Name = $rule.DisplayName
            Direction = $rule.Direction
            Action = $rule.Action
            Enabled = $rule.Enabled
            Profile = $profile
            InterfaceType = $rule.InterfaceType
            Protocol = $rule.Protocol
            LocalPort = $rule.LocalPort
            RemotePort = $rule.RemotePort
            Program = $rule.Program
            Description = $rule.Description
        }
    }

    $ruleDetails | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] Firewall rules exported to: $reportFile" -ForegroundColor Green

    return @{
        FirewallRules = $ruleDetails
        ReportPath = $reportFile
    }
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-029: Network Shares Enumerator
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Enumerates all shared folders and network shares on the system
.DESCRIPTION
    Lists shares with permissions and paths
.PARAMETER OutputPath
    Directory to save shares report
.EXAMPLE
    .\UC-029-NetworkSharesEnumerator.ps1 -OutputPath "C:\Evidence\NetworkShares"
.NOTES
    Run As: Administrator
    Run On: Endpoint or server for share auditing or data leak investigation
    Run When: Investigating unauthorized share access or data exposure
#>

function Get-NetworkSharesReport {
    param(
        [string]$OutputPath = "C:\Evidence\NetworkShares"
    )

    Write-Host "[+] Enumerating network shares..." -ForegroundColor Green
    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME
    $reportFile = "$OutputPath\NetworkShares_${hostname}_${timestamp}.csv"

    $shares = Get-WmiObject -Class Win32_Share | Select-Object Name, Path, Description, Status

    $shares | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] Network shares report saved to: $reportFile" -ForegroundColor Green

    return @{
        NetworkShares = $shares
        ReportPath = $reportFile
    }
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-030: Installed Patches Summary
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Retrieves the list of installed Windows patches and updates
.DESCRIPTION
    Queries installed hotfixes and saves to a report for compliance and vulnerability checks
.PARAMETER OutputPath
    Directory to save patch report
.EXAMPLE
    .\UC-030-InstalledPatchesSummary.ps1 -OutputPath "C:\Evidence\Patches"
.NOTES
    Run As: Administrator
    Run On: Endpoint or server for patch management review
    Run When: Auditing update status or investigating vulnerabilities
#>

function Get-InstalledPatches {
    param(
        [string]$OutputPath = "C:\Evidence\Patches"
    )

    Write-Host "[+] Retrieving installed Windows patches..." -ForegroundColor Green
    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME
    $reportFile = "$OutputPath\InstalledPatches_${hostname}_${timestamp}.csv"

    $patches = Get-HotFix | Select-Object HotFixID, Description, InstalledOn, InstalledBy

    $patches | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] Installed patches summary saved to: $reportFile" -ForegroundColor Green

    return @{
        InstalledPatches = $patches
        ReportPath = $reportFile
    }
}

#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
# UC-031: Antivirus Status Sweeper
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Checks antivirus status and real-time protection on the system
.DESCRIPTION
    Queries Windows Defender or other AV status and real-time protection state
.PARAMETER OutputPath
    Directory to save AV status report
.EXAMPLE
    .\UC-031-AVStatusSweeper.ps1 -OutputPath "C:\Evidence\AVStatus"
.NOTES
    Run As: Administrator
    Run On: Endpoint for security posture review
    Run When: Auditing AV functionality or health check
#>

function Get-AVStatus {
    param(
        [string]$OutputPath = "C:\Evidence\AVStatus"
    )

    Write-Host "[+] Querying antivirus status..." -ForegroundColor Green
    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME
    $reportFile = "$OutputPath\AVStatus_${hostname}_${timestamp}.csv"

    $avStatus = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct

    $results = foreach ($av in $avStatus) {
        [PSCustomObject]@{
            DisplayName = $av.DisplayName
            ProductState = $av.productState
            PathToSignedProductExe = $av.PathToSignedProductExe
            PathToSignedReportingExe = $av.PathToSignedReportingExe
            ProductUptoDate = $av.productUptoDate
        }
    }

    $results | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] Antivirus status report saved to: $reportFile" -ForegroundColor Green

    return @{
        AVStatus = $results
        ReportPath = $reportFile
    }
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-032: Patch Level Validator
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Validates installation of specific patches, not just general updates
.DESCRIPTION
    Checks system for presence of specified KB numbers
.PARAMETER KBList
    List of KB numbers to check
.PARAMETER OutputPath
    Directory to save patch validation report
.EXAMPLE
    .\UC-032-PatchLevelValidator.ps1 -KBList @("KB5006670", "KB5010793") -OutputPath "C:\Evidence\PatchValidation"
.NOTES
    Run As: Administrator
    Run On: Endpoint for patch compliance check
    Run When: After critical vulnerability disclosures
#>

function Validate-PatchLevel {
    param(
        [string[]]$KBList,
        [string]$OutputPath = "C:\Evidence\PatchValidation"
    )

    Write-Host "[+] Validating specific patches installation..." -ForegroundColor Green
    if (!$KBList -or $KBList.Count -eq 0) {
        Write-Host "[-] No KB list provided." -ForegroundColor Red
        return
    }

    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME
    $reportFile = "$OutputPath\PatchValidation_${hostname}_${timestamp}.csv"

    $installed = Get-HotFix | Select-Object HotFixID

    $results = foreach ($kb in $KBList) {
        [PSCustomObject]@{
            KB = $kb
            Installed = if ($installed.HotFixID -contains $kb) { $true } else { $false }
        }
    }

    $results | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] Patch validation report saved to: $reportFile" -ForegroundColor Green

    return @{
        PatchValidation = $results
        ReportPath = $reportFile
    }
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-033: SMBv1 Protocol Detector
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Detects if SMBv1 protocol is enabled on the system
.DESCRIPTION
    Checks registry and service status for SMBv1 usage
.PARAMETER OutputPath
    Directory to save SMBv1 check report
.EXAMPLE
    .\UC-033-SMBv1ProtocolDetector.ps1 -OutputPath "C:\Evidence\SMBv1Check"
.NOTES
    Run As: Administrator
    Run On: Endpoint for vulnerability assessment
    Run When: Checking for legacy protocol vulnerabilities
#>

function Check-SMBv1Status {
    param(
        [string]$OutputPath = "C:\Evidence\SMBv1Check"
    )

    Write-Host "[+] Checking SMBv1 protocol status..." -ForegroundColor Green
    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME
    $reportFile = "$OutputPath\SMBv1Status_${hostname}_${timestamp}.txt"

    $regKey = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    $smbv1Status = Get-ItemProperty -Path $regKey -Name SMB1 -ErrorAction SilentlyContinue

    $statusMessage = if ($smbv1Status.SMB1 -eq 0) {
        "SMBv1 protocol is DISABLED."
    } elseif ($smbv1Status.SMB1 -eq 1) {
        "SMBv1 protocol is ENABLED."
    } else {
        "SMBv1 protocol status UNKNOWN (value: $($smbv1Status.SMB1))"
    }

    $statusMessage | Out-File -FilePath $reportFile

    Write-Host "`n[+] SMBv1 status report saved to: $reportFile" -ForegroundColor Green

    return $reportFile
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-034: Local Admin Account Finder
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Lists all local administrator accounts on the endpoint
.DESCRIPTION
    Enumerates users with admin privileges for security auditing
.PARAMETER OutputPath
    Directory to save admin accounts report
.EXAMPLE
    .\UC-034-LocalAdminAccountFinder.ps1 -OutputPath "C:\Evidence\AdminAccounts"
.NOTES
    Run As: Administrator
    Run On: Endpoint for security posture review
    Run When: Auditing administrator accounts for unauthorized additions
#>

function Get-LocalAdminAccounts {
    param(
        [string]$OutputPath = "C:\Evidence\AdminAccounts"
    )

    Write-Host "[+] Enumerating local administrator accounts..." -ForegroundColor Green
    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME
    $reportFile = "$OutputPath\LocalAdmins_${hostname}_${timestamp}.csv"

    $adminsGroup = [ADSI]"WinNT://$env:COMPUTERNAME/Administrators,group"
    $members = @()
    foreach ($member in $adminsGroup.Invoke("Members")) {
        $obj = New-Object PSObject -Property @{
            Name = $member.GetType().InvokeMember("Name",'GetProperty',$null,$member,$null)
            ADsPath = $member.ADsPath
        }
        $members += $obj
    }

    $members | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] Local administrator accounts saved to: $reportFile" -ForegroundColor Green

    return @{
        LocalAdmins = $members
        ReportPath = $reportFile
    }
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-035: Firewall Rule Auditor
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Identifies overly permissive Windows Firewall rules
.DESCRIPTION
    Flags rules allowing inbound connections from any IP or broad ports
.PARAMETER OutputPath
    Directory to save audit report
.EXAMPLE
    .\UC-035-FirewallRuleAuditor.ps1 -OutputPath "C:\Evidence\FirewallAudit"
.NOTES
    Run As: Administrator
    Run On: Endpoint for firewall hardening check
    Run When: Investigating potential C2 or unauthorized access
#>

function Audit-FirewallRules {
    param(
        [string]$OutputPath = "C:\Evidence\FirewallAudit"
    )

    Write-Host "[+] Auditing firewall rules for overly permissive settings..." -ForegroundColor Green
    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME
    $reportFile = "$OutputPath\FirewallAudit_${hostname}_${timestamp}.csv"

    $rules = Get-NetFirewallRule | Where-Object { $_.Enabled -eq "True" } | Get-NetFirewallAddressFilter

    $susRules = @()

    foreach ($rule in $rules) {
        if (($rule.RemoteAddress -eq "*") -or ($rule.LocalPort -eq "*") -or ($rule.RemotePort -eq "*")) {
            $baseRule = Get-NetFirewallRule -Name $rule.InstanceId -ErrorAction SilentlyContinue
            $susRules += [PSCustomObject]@{
                RuleName = $baseRule.DisplayName
                Direction = $baseRule.Direction
                Action = $baseRule.Action
                RemoteAddress = $rule.RemoteAddress
                LocalPort = $rule.LocalPort
                RemotePort = $rule.RemotePort
            }
        }
    }

    $susRules | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] Firewall audit report saved to: $reportFile" -ForegroundColor Green
    Write-Host "[!] Overly permissive rules found: $($susRules.Count)" -ForegroundColor Red

    if ($susRules.Count -gt 0) {
        Write-Host "`n=== Overly Permissive Firewall Rules ===" -ForegroundColor Red
        $susRules | Format-Table -AutoSize
    }

    return @{
        FirewallAudit = $susRules
        ReportPath = $reportFile
    }
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-036: DNS Query Anomaly Finder
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Identifies domains queried by very few hosts indicating potential anomalies
.DESCRIPTION
    Analyzes DNS logs or captures to find low-frequency domain queries that could imply C2 or DGA activity
.PARAMETER DNSLogPath
    Path to DNS logs or capture files
.PARAMETER OutputPath
    Directory to save anomaly report
.EXAMPLE
    .\UC-036-DNSQueryAnomalyFinder.ps1 -DNSLogPath "C:\Logs\DNS" -OutputPath "C:\Evidence\DNSAnomalies"
.NOTES
    Run As: Administrator
    Run On: Log aggregation server or endpoint capturing DNS
    Run When: Hunting for malware command and control or data exfiltration channels
#>

function Find-DNSQueryAnomalies {
    param(
        [string]$DNSLogPath,
        [string]$OutputPath = "C:\Evidence\DNSAnomalies"
    )

    Write-Host "[+] Analyzing DNS logs for rare queries..." -ForegroundColor Green

    if (!(Test-Path $DNSLogPath)) {
        Write-Host "[-] DNS log path not found: $DNSLogPath" -ForegroundColor Red
        return
    }

    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = "$OutputPath\DNSQueryAnomalies_${timestamp}.csv"

    # This is a placeholder. Actual parsing depends on DNS log format.
    # For example, if logs are CSV, parse and group by domain name counting unique hosts.

    # Example parsing CSV with columns: Timestamp, ClientIP, QueryName

    $dnsEntries = Import-Csv -Path $DNSLogPath -ErrorAction SilentlyContinue

    if (-not $dnsEntries) {
        Write-Host "[-] No DNS entries loaded from $DNSLogPath" -ForegroundColor Red
        return
    }

    $grouped = $dnsEntries | Group-Object QueryName | Where-Object { $_.Count -le 2 }

    $results = foreach ($grp in $grouped) {
        [PSCustomObject]@{
            Domain = $grp.Name
            QueryCount = $grp.Count
        }
    }

    $results | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] DNS query anomaly report saved to: $reportFile" -ForegroundColor Green

    return @{
        DNSAnomalies = $results
        ReportPath = $reportFile
    }
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-037: Certificate Expiration Monitor
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Checks SSL certificate expiration for internal services
.DESCRIPTION
    Extracts certificate details and alerts on upcoming expiry dates
.PARAMETER CertificateStore
    Certificate store location (default My)
.PARAMETER OutputPath
    Directory to save certificate report
.EXAMPLE
    .\UC-037-CertExpirationMonitor.ps1 -CertificateStore "LocalMachine\My" -OutputPath "C:\Evidence\Certs"
.NOTES
    Run As: Administrator
    Run On: Endpoint or server hosting SSL services
    Run When: Monitoring certificate validity to prevent outages
#>

function Monitor-CertExpiration {
    param(
        [string]$CertificateStore = "LocalMachine\My",
        [string]$OutputPath = "C:\Evidence\Certs"
    )

    Write-Host "[+] Gathering certificate expiration info..." -ForegroundColor Green
    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store $CertificateStore
    $store.Open("ReadOnly")
    $certs = $store.Certificates | Where-Object { $_.NotAfter -gt (Get-Date) }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME
    $reportFile = "$OutputPath\CertExpirations_${hostname}_${timestamp}.csv"

    $results = foreach ($cert in $certs) {
        [PSCustomObject]@{
            Subject = $cert.Subject
            Issuer = $cert.Issuer
            ExpirationDate = $cert.NotAfter
            Thumbprint = $cert.Thumbprint
        }
    }

    $results | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] Certificate expiration report saved to: $reportFile" -ForegroundColor Green

    $expiringSoon = $results | Where-Object { $_.ExpirationDate -lt (Get-Date).AddDays(30) }

    if ($expiringSoon.Count -gt 0) {
        Write-Host "[!] Certificates expiring within 30 days:" -ForegroundColor Red
        $expiringSoon | Format-Table -AutoSize
    } else {
        Write-Host "[+] No certificates expiring soon." -ForegroundColor Green
    }

    $store.Close()

    return @{
        Certificates = $results
        ReportPath = $reportFile
    }
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-038: VPN Connection Geo-Analyzer
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Maps VPN login locations by geographic region
.DESCRIPTION
    Extracts VPN connection logs and geolocates IP addresses for anomaly detection
.PARAMETER VPNLogPath
    Path containing VPN connection logs
.PARAMETER OutputPath
    Directory to save VPN geo-analysis report
.EXAMPLE
    .\UC-038-VPNGeoAnalyzer.ps1 -VPNLogPath "C:\Logs\VPN" -OutputPath "C:\Evidence\VPNGeo"
.NOTES
    Run As: Administrator
    Run On: VPN server or central logging server
    Run When: Investigating impossible travel or suspicious VPN access
#>

function Analyze-VPNGeoLogins {
    param(
        [string]$VPNLogPath,
        [string]$OutputPath = "C:\Evidence\VPNGeo"
    )

    Write-Host "[+] Analyzing VPN connection locations..." -ForegroundColor Green

    if (!(Test-Path $VPNLogPath)) {
        Write-Host "[-] VPN log path not found: $VPNLogPath" -ForegroundColor Red
        return
    }

    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = "$OutputPath\VPNGeoLogins_${timestamp}.csv"

    # Placeholder: actual parsing depends on VPN log format (e.g., CSV, JSON)
    # Expected columns: Timestamp, Username, SourceIP

    # Load logs (example for CSV)
    $logs = Import-Csv -Path $VPNLogPath -ErrorAction SilentlyContinue

    if (-not $logs) {
        Write-Host "[-] No VPN log entries loaded." -ForegroundColor Red
        return
    }

    # Use GeoIP lookup service or database - this is a simplified example
    # Assuming a function Get-GeoIP exists or external API called here

    $resultList = foreach ($entry in $logs) {
        $geo = "Unknown" # Placeholder for geolocation lookup

        [PSCustomObject]@{
            Timestamp = $entry.Timestamp
            Username = $entry.Username
            SourceIP = $entry.SourceIP
            GeoLocation = $geo
        }
    }

    $resultList | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] VPN geographical login report saved to: $reportFile" -ForegroundColor Green

    return @{
        VPNGeoLogins = $resultList
        ReportPath = $reportFile
    }
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-039: Rogue DHCP Server Detector
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Scans network for unauthorized DHCP servers
.DESCRIPTION
    Detects rogue DHCP offers by monitoring DHCP traffic
.PARAMETER OutputPath
    Directory to save scan results
.EXAMPLE
    .\UC-039-RogueDHCPServerDetector.ps1 -OutputPath "C:\Evidence\DHCPScan"
.NOTES
    Run As: Administrator
    Run On: Network monitoring station or endpoint with monitoring capability
    Run When: Suspecting MITM or rogue DHCP
#>

function Detect-RogueDHCPServers {
    param(
        [string]$OutputPath = "C:\Evidence\DHCPScan"
    )

    Write-Host "[+] Scanning for rogue DHCP servers..." -ForegroundColor Green
    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    # Requires capturing DHCP OFFER packets, possibly using pktmon, tshark, or built-in powershell commands

    # Placeholder for actual DHCP sniffing implementation

    Write-Host "[!] DHCP rogue server detection requires specialized network capture tools." -ForegroundColor Yellow
    Write-Host "[*] Implement network capture and analyze DHCP OFFER packets for unexpected servers." -ForegroundColor Yellow

    return $null
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-040: Wireless Access Point Auditor
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Lists all wireless access points seen and compares against authorized list
.DESCRIPTION
    Uses netsh wlan or external scanning tools to extract wireless networks
.PARAMETER AuthorizedListPath
    Path to file containing authorized AP names/SSIDs
.PARAMETER OutputPath
    Directory to save AP audit report
.EXAMPLE
    .\UC-040-WirelessAPAuditor.ps1 -AuthorizedListPath "C:\Configs\AuthorizedAPs.txt" -OutputPath "C:\Evidence\WirelessAudit"
.NOTES
    Run As: Administrator
    Run On: Wireless scanning workstation
    Run When: Monthly wireless security check or rogue AP detection
#>

function Audit-WirelessAccessPoints {
    param(
        [string]$AuthorizedListPath,
        [string]$OutputPath = "C:\Evidence\WirelessAudit"
    )

    if (!(Test-Path $AuthorizedListPath)) {
        Write-Host "[-] Authorized AP list not found: $AuthorizedListPath" -ForegroundColor Red
        return
    }

    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    Write-Host "[+] Scanning available wireless access points..." -ForegroundColor Green

    $authorizedAPs = Get-Content -Path $AuthorizedListPath -ErrorAction SilentlyContinue

    $scanResult = netsh wlan show networks mode=bssid

    $apNames = @()
    foreach ($line in $scanResult) {
        if ($line -match '^SSID \d+ : (.+)$') {
            $apNames += $matches[1].Trim()
        }
    }

    $unauthorized = $apNames | Where-Object { $_ -and ($_ -notin $authorizedAPs) }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = "$OutputPath\WirelessAPAudit_${timestamp}.txt"

    "Authorized APs:`n" | Out-File $reportFile
    $authorizedAPs | Out-File -Append $reportFile

    "`nDetected APs:`n" | Out-File -Append $reportFile
    $apNames | Out-File -Append $reportFile

    "`nUnauthorized APs:`n" | Out-File -Append $reportFile
    $unauthorized | Out-File -Append $reportFile

    Write-Host "`n[+] Wireless access point audit saved to: $reportFile" -ForegroundColor Green

    return @{
        AuthorizedAPs = $authorizedAPs
        DetectedAPs = $apNames
        UnauthorizedAPs = $unauthorized
        ReportPath = $reportFile
    }
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-041: O365 Sign-in Location Validator
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Extracts Microsoft 365 sign-ins from unusual geographic countries
.DESCRIPTION
    Analyzes sign-in logs for geographic anomalies
.PARAMETER LogPath
    Path to sign-in logs
.PARAMETER OutputPath
    Directory to save analysis report
.EXAMPLE
    .\UC-041-O365SignInLocationValidator.ps1 -LogPath "C:\Logs\O365" -OutputPath "C:\Evidence\O365SignIns"
.NOTES
    Run As: Administrator
    Run On: Analyst workstation with access to logs
    Run When: Investigating MFA bypass or suspicious logins
#>

function Validate-O365SignInLocations {
    param(
        [string]$LogPath,
        [string]$OutputPath = "C:\Evidence\O365SignIns"
    )

    if (!(Test-Path $LogPath)) {
        Write-Host "[-] O365 log path not found: $LogPath" -ForegroundColor Red
        return
    }

    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    Write-Host "[+] Analyzing O365 sign-in locations..." -ForegroundColor Green

    # Placeholder: actual parsing depends on log format

    $logs = Import-Csv -Path $LogPath -ErrorAction SilentlyContinue

    if (-not $logs) {
        Write-Host "[-] No log entries loaded." -ForegroundColor Red
        return
    }

    # Geo IP lookup placeholder - add logic to flag unusual geo locations

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = "$OutputPath\O365SignInLocations_${timestamp}.csv"

    $results = foreach ($entry in $logs) {
        [PSCustomObject]@{
            User = $entry.UserPrincipalName
            IPAddress = $entry.ClientIP
            Location = "Unknown" # Add geo lookup here
            Timestamp = $entry.Timestamp
        }
    }

    $results | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] O365 sign-in location report saved to: $reportFile" -ForegroundColor Green

    return @{
        O365SignInLocations = $results
        ReportPath = $reportFile
    }
}

#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
# UC-031: Antivirus Status Sweeper
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Checks antivirus status and real-time protection on the system
.DESCRIPTION
    Queries Windows Defender or other AV status and real-time protection state
.PARAMETER OutputPath
    Directory to save AV status report
.EXAMPLE
    .\UC-031-AVStatusSweeper.ps1 -OutputPath "C:\Evidence\AVStatus"
.NOTES
    Run As: Administrator
    Run On: Endpoint for security posture review
    Run When: Auditing AV functionality or health check
#>

function Get-AVStatus {
    param(
        [string]$OutputPath = "C:\Evidence\AVStatus"
    )

    Write-Host "[+] Querying antivirus status..." -ForegroundColor Green
    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME
    $reportFile = "$OutputPath\AVStatus_${hostname}_${timestamp}.csv"

    $avStatus = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct

    $results = foreach ($av in $avStatus) {
        [PSCustomObject]@{
            DisplayName = $av.DisplayName
            ProductState = $av.productState
            PathToSignedProductExe = $av.PathToSignedProductExe
            PathToSignedReportingExe = $av.PathToSignedReportingExe
            ProductUptoDate = $av.productUptoDate
        }
    }

    $results | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] Antivirus status report saved to: $reportFile" -ForegroundColor Green

    return @{
        AVStatus = $results
        ReportPath = $reportFile
    }
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-032: Patch Level Validator
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Validates installation of specific patches, not just general updates
.DESCRIPTION
    Checks system for presence of specified KB numbers
.PARAMETER KBList
    List of KB numbers to check
.PARAMETER OutputPath
    Directory to save patch validation report
.EXAMPLE
    .\UC-032-PatchLevelValidator.ps1 -KBList @("KB5006670", "KB5010793") -OutputPath "C:\Evidence\PatchValidation"
.NOTES
    Run As: Administrator
    Run On: Endpoint for patch compliance check
    Run When: After critical vulnerability disclosures
#>

function Validate-PatchLevel {
    param(
        [string[]]$KBList,
        [string]$OutputPath = "C:\Evidence\PatchValidation"
    )

    Write-Host "[+] Validating specific patches installation..." -ForegroundColor Green
    if (!$KBList -or $KBList.Count -eq 0) {
        Write-Host "[-] No KB list provided." -ForegroundColor Red
        return
    }

    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME
    $reportFile = "$OutputPath\PatchValidation_${hostname}_${timestamp}.csv"

    $installed = Get-HotFix | Select-Object HotFixID

    $results = foreach ($kb in $KBList) {
        [PSCustomObject]@{
            KB = $kb
            Installed = if ($installed.HotFixID -contains $kb) { $true } else { $false }
        }
    }

    $results | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] Patch validation report saved to: $reportFile" -ForegroundColor Green

    return @{
        PatchValidation = $results
        ReportPath = $reportFile
    }
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-033: SMBv1 Protocol Detector
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Detects if SMBv1 protocol is enabled on the system
.DESCRIPTION
    Checks registry and service status for SMBv1 usage
.PARAMETER OutputPath
    Directory to save SMBv1 check report
.EXAMPLE
    .\UC-033-SMBv1ProtocolDetector.ps1 -OutputPath "C:\Evidence\SMBv1Check"
.NOTES
    Run As: Administrator
    Run On: Endpoint for vulnerability assessment
    Run When: Checking for legacy protocol vulnerabilities
#>

function Check-SMBv1Status {
    param(
        [string]$OutputPath = "C:\Evidence\SMBv1Check"
    )

    Write-Host "[+] Checking SMBv1 protocol status..." -ForegroundColor Green
    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME
    $reportFile = "$OutputPath\SMBv1Status_${hostname}_${timestamp}.txt"

    $regKey = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    $smbv1Status = Get-ItemProperty -Path $regKey -Name SMB1 -ErrorAction SilentlyContinue

    $statusMessage = if ($smbv1Status.SMB1 -eq 0) {
        "SMBv1 protocol is DISABLED."
    } elseif ($smbv1Status.SMB1 -eq 1) {
        "SMBv1 protocol is ENABLED."
    } else {
        "SMBv1 protocol status UNKNOWN (value: $($smbv1Status.SMB1))"
    }

    $statusMessage | Out-File -FilePath $reportFile

    Write-Host "`n[+] SMBv1 status report saved to: $reportFile" -ForegroundColor Green

    return $reportFile
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-034: Local Admin Account Finder
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Lists all local administrator accounts on the endpoint
.DESCRIPTION
    Enumerates users with admin privileges for security auditing
.PARAMETER OutputPath
    Directory to save admin accounts report
.EXAMPLE
    .\UC-034-LocalAdminAccountFinder.ps1 -OutputPath "C:\Evidence\AdminAccounts"
.NOTES
    Run As: Administrator
    Run On: Endpoint for security posture review
    Run When: Auditing administrator accounts for unauthorized additions
#>

function Get-LocalAdminAccounts {
    param(
        [string]$OutputPath = "C:\Evidence\AdminAccounts"
    )

    Write-Host "[+] Enumerating local administrator accounts..." -ForegroundColor Green
    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME
    $reportFile = "$OutputPath\LocalAdmins_${hostname}_${timestamp}.csv"

    $adminsGroup = [ADSI]"WinNT://$env:COMPUTERNAME/Administrators,group"
    $members = @()
    foreach ($member in $adminsGroup.Invoke("Members")) {
        $obj = New-Object PSObject -Property @{
            Name = $member.GetType().InvokeMember("Name",'GetProperty',$null,$member,$null)
            ADsPath = $member.ADsPath
        }
        $members += $obj
    }

    $members | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] Local administrator accounts saved to: $reportFile" -ForegroundColor Green

    return @{
        LocalAdmins = $members
        ReportPath = $reportFile
    }
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-035: Firewall Rule Auditor
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Identifies overly permissive Windows Firewall rules
.DESCRIPTION
    Flags rules allowing inbound connections from any IP or broad ports
.PARAMETER OutputPath
    Directory to save audit report
.EXAMPLE
    .\UC-035-FirewallRuleAuditor.ps1 -OutputPath "C:\Evidence\FirewallAudit"
.NOTES
    Run As: Administrator
    Run On: Endpoint for firewall hardening check
    Run When: Investigating potential C2 or unauthorized access
#>

function Audit-FirewallRules {
    param(
        [string]$OutputPath = "C:\Evidence\FirewallAudit"
    )

    Write-Host "[+] Auditing firewall rules for overly permissive settings..." -ForegroundColor Green
    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME
    $reportFile = "$OutputPath\FirewallAudit_${hostname}_${timestamp}.csv"

    $rules = Get-NetFirewallRule | Where-Object { $_.Enabled -eq "True" } | Get-NetFirewallAddressFilter

    $susRules = @()

    foreach ($rule in $rules) {
        if (($rule.RemoteAddress -eq "*") -or ($rule.LocalPort -eq "*") -or ($rule.RemotePort -eq "*")) {
            $baseRule = Get-NetFirewallRule -Name $rule.InstanceId -ErrorAction SilentlyContinue
            $susRules += [PSCustomObject]@{
                RuleName = $baseRule.DisplayName
                Direction = $baseRule.Direction
                Action = $baseRule.Action
                RemoteAddress = $rule.RemoteAddress
                LocalPort = $rule.LocalPort
                RemotePort = $rule.RemotePort
            }
        }
    }

    $susRules | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] Firewall audit report saved to: $reportFile" -ForegroundColor Green
    Write-Host "[!] Overly permissive rules found: $($susRules.Count)" -ForegroundColor Red

    if ($susRules.Count -gt 0) {
        Write-Host "`n=== Overly Permissive Firewall Rules ===" -ForegroundColor Red
        $susRules | Format-Table -AutoSize
    }

    return @{
        FirewallAudit = $susRules
        ReportPath = $reportFile
    }
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-036: DNS Query Anomaly Finder
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Identifies domains queried by very few hosts indicating potential anomalies
.DESCRIPTION
    Analyzes DNS logs or captures to find low-frequency domain queries that could imply C2 or DGA activity
.PARAMETER DNSLogPath
    Path to DNS logs or capture files
.PARAMETER OutputPath
    Directory to save anomaly report
.EXAMPLE
    .\UC-036-DNSQueryAnomalyFinder.ps1 -DNSLogPath "C:\Logs\DNS" -OutputPath "C:\Evidence\DNSAnomalies"
.NOTES
    Run As: Administrator
    Run On: Log aggregation server or endpoint capturing DNS
    Run When: Hunting for malware command and control or data exfiltration channels
#>

function Find-DNSQueryAnomalies {
    param(
        [string]$DNSLogPath,
        [string]$OutputPath = "C:\Evidence\DNSAnomalies"
    )

    Write-Host "[+] Analyzing DNS logs for rare queries..." -ForegroundColor Green

    if (!(Test-Path $DNSLogPath)) {
        Write-Host "[-] DNS log path not found: $DNSLogPath" -ForegroundColor Red
        return
    }

    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = "$OutputPath\DNSQueryAnomalies_${timestamp}.csv"

    # This is a placeholder. Actual parsing depends on DNS log format.
    # For example, if logs are CSV, parse and group by domain name counting unique hosts.

    # Example parsing CSV with columns: Timestamp, ClientIP, QueryName

    $dnsEntries = Import-Csv -Path $DNSLogPath -ErrorAction SilentlyContinue

    if (-not $dnsEntries) {
        Write-Host "[-] No DNS entries loaded from $DNSLogPath" -ForegroundColor Red
        return
    }

    $grouped = $dnsEntries | Group-Object QueryName | Where-Object { $_.Count -le 2 }

    $results = foreach ($grp in $grouped) {
        [PSCustomObject]@{
            Domain = $grp.Name
            QueryCount = $grp.Count
        }
    }

    $results | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] DNS query anomaly report saved to: $reportFile" -ForegroundColor Green

    return @{
        DNSAnomalies = $results
        ReportPath = $reportFile
    }
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-037: Certificate Expiration Monitor
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Checks SSL certificate expiration for internal services
.DESCRIPTION
    Extracts certificate details and alerts on upcoming expiry dates
.PARAMETER CertificateStore
    Certificate store location (default My)
.PARAMETER OutputPath
    Directory to save certificate report
.EXAMPLE
    .\UC-037-CertExpirationMonitor.ps1 -CertificateStore "LocalMachine\My" -OutputPath "C:\Evidence\Certs"
.NOTES
    Run As: Administrator
    Run On: Endpoint or server hosting SSL services
    Run When: Monitoring certificate validity to prevent outages
#>

function Monitor-CertExpiration {
    param(
        [string]$CertificateStore = "LocalMachine\My",
        [string]$OutputPath = "C:\Evidence\Certs"
    )

    Write-Host "[+] Gathering certificate expiration info..." -ForegroundColor Green
    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store $CertificateStore
    $store.Open("ReadOnly")
    $certs = $store.Certificates | Where-Object { $_.NotAfter -gt (Get-Date) }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME
    $reportFile = "$OutputPath\CertExpirations_${hostname}_${timestamp}.csv"

    $results = foreach ($cert in $certs) {
        [PSCustomObject]@{
            Subject = $cert.Subject
            Issuer = $cert.Issuer
            ExpirationDate = $cert.NotAfter
            Thumbprint = $cert.Thumbprint
        }
    }

    $results | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] Certificate expiration report saved to: $reportFile" -ForegroundColor Green

    $expiringSoon = $results | Where-Object { $_.ExpirationDate -lt (Get-Date).AddDays(30) }

    if ($expiringSoon.Count -gt 0) {
        Write-Host "[!] Certificates expiring within 30 days:" -ForegroundColor Red
        $expiringSoon | Format-Table -AutoSize
    } else {
        Write-Host "[+] No certificates expiring soon." -ForegroundColor Green
    }

    $store.Close()

    return @{
        Certificates = $results
        ReportPath = $reportFile
    }
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-038: VPN Connection Geo-Analyzer
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Maps VPN login locations by geographic region
.DESCRIPTION
    Extracts VPN connection logs and geolocates IP addresses for anomaly detection
.PARAMETER VPNLogPath
    Path containing VPN connection logs
.PARAMETER OutputPath
    Directory to save VPN geo-analysis report
.EXAMPLE
    .\UC-038-VPNGeoAnalyzer.ps1 -VPNLogPath "C:\Logs\VPN" -OutputPath "C:\Evidence\VPNGeo"
.NOTES
    Run As: Administrator
    Run On: VPN server or central logging server
    Run When: Investigating impossible travel or suspicious VPN access
#>

function Analyze-VPNGeoLogins {
    param(
        [string]$VPNLogPath,
        [string]$OutputPath = "C:\Evidence\VPNGeo"
    )

    Write-Host "[+] Analyzing VPN connection locations..." -ForegroundColor Green

    if (!(Test-Path $VPNLogPath)) {
        Write-Host "[-] VPN log path not found: $VPNLogPath" -ForegroundColor Red
        return
    }

    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = "$OutputPath\VPNGeoLogins_${timestamp}.csv"

    # Placeholder: actual parsing depends on VPN log format (e.g., CSV, JSON)
    # Expected columns: Timestamp, Username, SourceIP

    # Load logs (example for CSV)
    $logs = Import-Csv -Path $VPNLogPath -ErrorAction SilentlyContinue

    if (-not $logs) {
        Write-Host "[-] No VPN log entries loaded." -ForegroundColor Red
        return
    }

    # Use GeoIP lookup service or database - this is a simplified example
    # Assuming a function Get-GeoIP exists or external API called here

    $resultList = foreach ($entry in $logs) {
        $geo = "Unknown" # Placeholder for geolocation lookup

        [PSCustomObject]@{
            Timestamp = $entry.Timestamp
            Username = $entry.Username
            SourceIP = $entry.SourceIP
            GeoLocation = $geo
        }
    }

    $resultList | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] VPN geographical login report saved to: $reportFile" -ForegroundColor Green

    return @{
        VPNGeoLogins = $resultList
        ReportPath = $reportFile
    }
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-039: Rogue DHCP Server Detector
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Scans network for unauthorized DHCP servers
.DESCRIPTION
    Detects rogue DHCP offers by monitoring DHCP traffic
.PARAMETER OutputPath
    Directory to save scan results
.EXAMPLE
    .\UC-039-RogueDHCPServerDetector.ps1 -OutputPath "C:\Evidence\DHCPScan"
.NOTES
    Run As: Administrator
    Run On: Network monitoring station or endpoint with monitoring capability
    Run When: Suspecting MITM or rogue DHCP
#>

function Detect-RogueDHCPServers {
    param(
        [string]$OutputPath = "C:\Evidence\DHCPScan"
    )

    Write-Host "[+] Scanning for rogue DHCP servers..." -ForegroundColor Green
    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    # Requires capturing DHCP OFFER packets, possibly using pktmon, tshark, or built-in powershell commands

    # Placeholder for actual DHCP sniffing implementation

    Write-Host "[!] DHCP rogue server detection requires specialized network capture tools." -ForegroundColor Yellow
    Write-Host "[*] Implement network capture and analyze DHCP OFFER packets for unexpected servers." -ForegroundColor Yellow

    return $null
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-040: Wireless Access Point Auditor
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Lists all wireless access points seen and compares against authorized list
.DESCRIPTION
    Uses netsh wlan or external scanning tools to extract wireless networks
.PARAMETER AuthorizedListPath
    Path to file containing authorized AP names/SSIDs
.PARAMETER OutputPath
    Directory to save AP audit report
.EXAMPLE
    .\UC-040-WirelessAPAuditor.ps1 -AuthorizedListPath "C:\Configs\AuthorizedAPs.txt" -OutputPath "C:\Evidence\WirelessAudit"
.NOTES
    Run As: Administrator
    Run On: Wireless scanning workstation
    Run When: Monthly wireless security check or rogue AP detection
#>

function Audit-WirelessAccessPoints {
    param(
        [string]$AuthorizedListPath,
        [string]$OutputPath = "C:\Evidence\WirelessAudit"
    )

    if (!(Test-Path $AuthorizedListPath)) {
        Write-Host "[-] Authorized AP list not found: $AuthorizedListPath" -ForegroundColor Red
        return
    }

    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    Write-Host "[+] Scanning available wireless access points..." -ForegroundColor Green

    $authorizedAPs = Get-Content -Path $AuthorizedListPath -ErrorAction SilentlyContinue

    $scanResult = netsh wlan show networks mode=bssid

    $apNames = @()
    foreach ($line in $scanResult) {
        if ($line -match '^SSID \d+ : (.+)$') {
            $apNames += $matches[1].Trim()
        }
    }

    $unauthorized = $apNames | Where-Object { $_ -and ($_ -notin $authorizedAPs) }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = "$OutputPath\WirelessAPAudit_${timestamp}.txt"

    "Authorized APs:`n" | Out-File $reportFile
    $authorizedAPs | Out-File -Append $reportFile

    "`nDetected APs:`n" | Out-File -Append $reportFile
    $apNames | Out-File -Append $reportFile

    "`nUnauthorized APs:`n" | Out-File -Append $reportFile
    $unauthorized | Out-File -Append $reportFile

    Write-Host "`n[+] Wireless access point audit saved to: $reportFile" -ForegroundColor Green

    return @{
        AuthorizedAPs = $authorizedAPs
        DetectedAPs = $apNames
        UnauthorizedAPs = $unauthorized
        ReportPath = $reportFile
    }
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-041: O365 Sign-in Location Validator
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Extracts Microsoft 365 sign-ins from unusual geographic countries
.DESCRIPTION
    Analyzes sign-in logs for geographic anomalies
.PARAMETER LogPath
    Path to sign-in logs
.PARAMETER OutputPath
    Directory to save analysis report
.EXAMPLE
    .\UC-041-O365SignInLocationValidator.ps1 -LogPath "C:\Logs\O365" -OutputPath "C:\Evidence\O365SignIns"
.NOTES
    Run As: Administrator
    Run On: Analyst workstation with access to logs
    Run When: Investigating MFA bypass or suspicious logins
#>

function Validate-O365SignInLocations {
    param(
        [string]$LogPath,
        [string]$OutputPath = "C:\Evidence\O365SignIns"
    )

    if (!(Test-Path $LogPath)) {
        Write-Host "[-] O365 log path not found: $LogPath" -ForegroundColor Red
        return
    }

    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    Write-Host "[+] Analyzing O365 sign-in locations..." -ForegroundColor Green

    # Placeholder: actual parsing depends on log format

    $logs = Import-Csv -Path $LogPath -ErrorAction SilentlyContinue

    if (-not $logs) {
        Write-Host "[-] No log entries loaded." -ForegroundColor Red
        return
    }

    # Geo IP lookup placeholder - add logic to flag unusual geo locations

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = "$OutputPath\O365SignInLocations_${timestamp}.csv"

    $results = foreach ($entry in $logs) {
        [PSCustomObject]@{
            User = $entry.UserPrincipalName
            IPAddress = $entry.ClientIP
            Location = "Unknown" # Add geo lookup here
            Timestamp = $entry.Timestamp
        }
    }

    $results | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] O365 sign-in location report saved to: $reportFile" -ForegroundColor Green

    return @{
        O365SignInLocations = $results
        ReportPath = $reportFile
    }
}

#------------------------------------------------------------------------------
This completes UC-031 through UC-041 in the requested sequence. Let me know if you want to continue with the next batch.

yes next batch please
powershell
#------------------------------------------------------------------------------
# UC-042: AWS IAM Permission Analyzer
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Lists all IAM users with administrative permissions in AWS environment
.DESCRIPTION
    Checks IAM policies and permissions to identify over-privileged accounts
.PARAMETER OutputPath
    Directory to save IAM analysis report
.EXAMPLE
    .\UC-042-AWSIAMPermissionAnalyzer.ps1 -OutputPath "C:\Evidence\AWSIAM"
.NOTES
    Run As: AWS CLI configured analyst
    Run On: Analyst workstation with AWS CLI access
    Run When: Cloud security audit or privilege escalation investigation
#>

function Analyze-AWSIAMPermissions {
    param(
        [string]$OutputPath = "C:\Evidence\AWSIAM"
    )

    Write-Host "[+] Listing AWS IAM users with administrative permissions..." -ForegroundColor Green
    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    # Requires AWS CLI configured with permissions
    $usersWithAdmin = aws iam list-users --query 'Users[*].UserName' --output text | ForEach-Object {
        $user = $_
        $policies = aws iam list-attached-user-policies --user-name $user --query 'AttachedPolicies[*].PolicyName' --output text
        if ($policies -contains "AdministratorAccess") {
            $user
        }
    }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = "$OutputPath\AWSIAM_AdminUsers_${timestamp}.txt"

    $usersWithAdmin | Out-File -FilePath $reportFile

    Write-Host "`n[+] AWS IAM admin users saved to: $reportFile" -ForegroundColor Green

    return $reportFile
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-043: S3 Bucket Public Access Checker
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Scans all Amazon S3 buckets for public read/write permissions
.DESCRIPTION
    Uses AWS CLI to identify buckets exposed to public internet
.PARAMETER OutputPath
    Directory to save bucket scan report
.EXAMPLE
    .\UC-043-S3PublicAccessChecker.ps1 -OutputPath "C:\Evidence\S3Buckets"
.NOTES
    Run As: AWS CLI configured analyst
    Run On: Analyst workstation with AWS CLI access
    Run When: Cloud security audit or incident response
#>

function Check-S3PublicAccess {
    param(
        [string]$OutputPath = "C:\Evidence\S3Buckets"
    )

    Write-Host "[+] Checking S3 buckets for public read/write access..." -ForegroundColor Green
    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $buckets = aws s3api list-buckets --query 'Buckets[*].Name' --output text

    $publicBuckets = @()

    foreach ($bucket in $buckets) {
        $policyStatus = aws s3api get-bucket-policy-status --bucket $bucket --output json 2>$null | ConvertFrom-Json

        if ($policyStatus.BucketPolicyStatus.IsPublic -eq $true) {
            $publicBuckets += $bucket
        }
    }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = "$OutputPath\S3PublicBuckets_${timestamp}.txt"

    $publicBuckets | Out-File -FilePath $reportFile

    Write-Host "`n[+] Public S3 buckets logged in: $reportFile" -ForegroundColor Green

    return $reportFile
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-044: Azure Resource Creation Auditor
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Lists all Azure resources created in the last 7 days
.DESCRIPTION
    Uses Azure PowerShell to extract recently created resources for anomaly detection
.PARAMETER OutputPath
    Directory to save resource list
.EXAMPLE
    .\UC-044-AzureResourceAuditor.ps1 -OutputPath "C:\Evidence\AzureResources"
.NOTES
    Run As: Azure PowerShell authenticated analyst
    Run On: Analyst workstation with Azure access
    Run When: Auditing resource creation after suspicious expenditure or abuse detection
#>

function Audit-AzureResourceCreation {
    param(
        [string]$OutputPath = "C:\Evidence\AzureResources"
    )

    Write-Host "[+] Auditing Azure resources created in the last 7 days..." -ForegroundColor Green

    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $dateLimit = (Get-Date).AddDays(-7)

    $resources = Get-AzResource | Where-Object { $_.Tags['CreatedDate'] -and ([datetime]$_.Tags['CreatedDate'] -ge $dateLimit) }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = "$OutputPath\AzureResources_${timestamp}.csv"

    $resources | Select-Object Name, ResourceType, ResourceGroupName, Location, @{Name="CreatedDate";Expression={$_.Tags['CreatedDate']}} | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] Azure resource creation audit saved to: $reportFile" -ForegroundColor Green

    return $reportFile
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-045: SaaS OAuth Token Reviewer
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Lists all third-party applications with OAuth access in SaaS platforms (e.g., O365, Google Workspace)
.DESCRIPTION
    Extracts OAuth app permissions for review and auditing
.PARAMETER OutputPath
    Directory to save OAuth permission reports
.EXAMPLE
    .\UC-045-SaaSOAuthTokenReviewer.ps1 -OutputPath "C:\Evidence\OAuthApps"
.NOTES
    Run As: Administrator with SaaS API permissions
    Run On: Analyst workstation
    Run When: After phishing campaigns or OAuth token suspicious activity
#>

function Review-SaaSOAuthTokens {
    param(
        [string]$OutputPath = "C:\Evidence\OAuthApps"
    )

    Write-Host "[+] Extracting OAuth app permissions from SaaS platforms..." -ForegroundColor Green

    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    # Placeholder for API calls to platforms like O365, Google Workspace to list OAuth apps

    Write-Host "[!] OAuth token extraction requires API integration specific to the SaaS platform." -ForegroundColor Yellow

    return $null
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-046: Suspicious String Extractor
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Extracts readable strings from binary files to assist quick malware triage
.DESCRIPTION
    Uses the strings utility or PowerShell-based string extraction
.PARAMETER FilePath
    Path to the binary file
.PARAMETER OutputPath
    Directory to save extracted strings
.EXAMPLE
    .\UC-046-SuspiciousStringExtractor.ps1 -FilePath "C:\Malware\suspicious.exe" -OutputPath "C:\Evidence\Strings"
.NOTES
    Run As: Analyst on isolated machine
    Run On: Malware analysis workstation
    Run When: Initial triage of suspicious executables
#>

function Extract-StringsFromFile {
    param(
        [string]$FilePath,
        [string]$OutputPath = "C:\Evidence\Strings"
    )

    if (!(Test-Path $FilePath)) {
        Write-Host "[-] File not found: $FilePath" -ForegroundColor Red
        return
    }

    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $fileName = [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $outputFile = "$OutputPath\Strings_${fileName}_${timestamp}.txt"

    # Simple string extraction: extract ASCII strings longer than 4 chars
    $content = Get-Content -Path $FilePath -Encoding Byte -Raw
    $asciiStrings = ([regex]::Matches([System.Text.Encoding]::ASCII.GetString($content), '[\x20-\x7E]{4,}')) | ForEach-Object { $_.Value }

    $asciiStrings | Out-File -FilePath $outputFile

    Write-Host "`n[+] Extracted strings saved to: $outputFile" -ForegroundColor Green

    return $outputFile
}

#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# UC-047: PE File Metadata Parser
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Extracts compile time, imports, and exports from PE files (.exe, .dll)
.DESCRIPTION
    Provides metadata useful for malware attribution and aging
.PARAMETER FilePath
    Path to PE file to analyze
.PARAMETER OutputPath
    Directory to save metadata report
.EXAMPLE
    .\UC-047-PEFileMetadataParser.ps1 -FilePath "C:\Malware\suspicious.exe" -OutputPath "C:\Evidence\PEFiles"
.NOTES
    Run As: Analyst on isolated or forensic machine
    Run On: Malware analysis workstation or endpoint with suspicious executables
    Run When: During technical malware investigation and attribution
#>

function Parse-PEFileMetadata {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [string]$OutputPath = "C:\Evidence\PEFiles"
    )

    if (!(Test-Path $FilePath)) {
        Write-Host "[-] File not found: $FilePath" -ForegroundColor Red
        return
    }

    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    Add-Type -AssemblyName System.Reflection.Metadata -ErrorAction SilentlyContinue

    try {
        $peInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($FilePath)
        $fileName = [System.IO.Path]::GetFileName($FilePath)
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $reportFile = "$OutputPath\PEFileMetadata_${fileName}_${timestamp}.txt"

        $content = @()
        $content += "File: $FilePath"
        $content += "Product Name: $($peInfo.ProductName)"
        $content += "File Version: $($peInfo.FileVersion)"
        $content += "Company Name: $($peInfo.CompanyName)"
        $content += "Original Filename: $($peInfo.OriginalFilename)"
        $content += "File Description: $($peInfo.FileDescription)"
        $content += "Internal Name: $($peInfo.InternalName)"
        $content += "Compilation Date: Unable to extract directly via FileVersionInfo."

        # For deeper PE parsing (imports, exports), third party tools or libraries needed
        
        $content | Out-File -FilePath $reportFile

        Write-Host "`n[+] PE file metadata extracted to: $reportFile" -ForegroundColor Green

        return $reportFile
    }
    catch {
        Write-Host "[-] Error parsing PE file metadata: $_" -ForegroundColor Red
    }
}

# Usage:
# Parse-PEFileMetadata -FilePath "C:\Malware\suspicious.exe" -OutputPath "C:\Evidence\PEFiles"

# Notes:
# - This script extracts basic version info; for full PE headers, specialized parsers required

#------------------------------------------------------------------------------
# UC-048: JavaScript Deobfuscator
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Beautifies and decodes obfuscated JavaScript code for analysis
.DESCRIPTION
    Formats JS code to readable structure and attempts basic decoding of obfuscation like Unicode escape sequences
.PARAMETER InputFile
    Path to the JavaScript file
.PARAMETER OutputPath
    Directory to save deobfuscated script
.EXAMPLE
    .\UC-048-JavaScriptDeobfuscator.ps1 -InputFile "C:\Malware\script.js" -OutputPath "C:\Evidence\JSDeobfuscation"
.NOTES
    Run As: Analyst on isolated machine
    Run On: Malware analysis workstation
    Run When: Analyzing suspicious or phishing web code
#>

function Deobfuscate-JS {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InputFile,
        [string]$OutputPath = "C:\Evidence\JSDeobfuscation"
    )

    if (!(Test-Path $InputFile)) {
        Write-Host "[-] Input JavaScript file not found: $InputFile" -ForegroundColor Red
        return
    }

    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $content = Get-Content -Path $InputFile -Raw

    # Basic beautification: insert line breaks after semicolons, braces etc.
    $beautified = $content -replace ";", ";\n" -replace "\{", "{\n" -replace "\}", "}\n"

    # Decode Unicode escapes like \u0061 to characters
    $decoded = [regex]::Unescape($beautified)

    $fileName = [System.IO.Path]::GetFileNameWithoutExtension($InputFile)
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $outputFile = "$OutputPath\Deobfuscated_${fileName}_${timestamp}.js"

    $decoded | Out-File -FilePath $outputFile

    Write-Host "`n[+] Deobfuscated JavaScript saved to: $outputFile" -ForegroundColor Green

    return $outputFile
}

# Usage:
# Deobfuscate-JS -InputFile "C:\Malware\script.js" -OutputPath "C:\Evidence\JSDeobfuscation"

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-049: Macro Extractor Analyzer
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Extracts VBA macros from Office documents for analysis
.DESCRIPTION
    Uses built-in PowerShell or external tools to extract macros from Office files
.PARAMETER DocPath
    Path to Office document (.doc, .docm, .xls, .xlsm)
.PARAMETER OutputPath
    Directory to save extracted macros
.EXAMPLE
    .\UC-049-MacroExtractor.ps1 -DocPath "C:\Malware\sample.docm" -OutputPath "C:\Evidence\Macros"
.NOTES
    Run As: Analyst on isolated machine
    Run On: Malware analysis workstation
    Run When: Investigating malicious Office documents
#>

function Extract-OfficeMacros {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DocPath,
        [string]$OutputPath = "C:\Evidence\Macros"
    )

    if (!(Test-Path $DocPath)) {
        Write-Host "[-] Document not found: $DocPath" -ForegroundColor Red
        return
    }

    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    # Requires external tool like olevba (from oletools) or alternative to extract macros

    Write-Host "[!] Macro extraction requires external tools like 'olevba' from oletools." -ForegroundColor Yellow
    Write-Host "[*] Please run 'olevba $DocPath > $OutputPath\MacroExtract.txt' manually or via script." -ForegroundColor Yellow

    return $null
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-050: Shellcode Identifier
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Searches memory dumps for shellcode patterns
.DESCRIPTION
    Scans binary memory dumps to identify common shellcode signatures or anomalies
.PARAMETER MemoryDumpPath
    Path to memory dump file
.PARAMETER OutputPath
    Directory to save scan report
.EXAMPLE
    .\UC-050-ShellcodeIdentifier.ps1 -MemoryDumpPath "C:\Dumps\mem.dmp" -OutputPath "C:\Evidence\Shellcode"
.NOTES
    Run As: Malware analyst with memory forensic tools
    Run On: Forensic workstation
    Run When: Investigating exploit kits or memory-resident malware
#>

function Identify-Shellcode {
    param(
        [Parameter(Mandatory = $true)]
        [string]$MemoryDumpPath,
        [string]$OutputPath = "C:\Evidence\Shellcode"
    )

    if (!(Test-Path $MemoryDumpPath)) {
        Write-Host "[-] Memory dump not found: $MemoryDumpPath" -ForegroundColor Red
        return
    }

    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    Write-Host "[!] Shellcode identification requires specialized memory forensic tools like Volatility." -ForegroundColor Yellow
    Write-Host "[*] Consider running 'volatility' plugins or similar tools on $MemoryDumpPath." -ForegroundColor Yellow

    return $null
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-051: Incident Timeline Generator
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Combines multiple log sources into a chronological incident timeline
.DESCRIPTION
    Aggregates and sorts logs by timestamp to create an incident timeline for reporting
.PARAMETER LogPaths
    Array of log file paths to include
.PARAMETER OutputPath
    Directory to save timeline report
.EXAMPLE
    .\UC-051-IncidentTimelineGenerator.ps1 -LogPaths @("C:\Logs\Firewall.csv","C:\Logs\Syslog.csv") -OutputPath "C:\Evidence\IncidentReports"
.NOTES
    Run As: Analyst
    Run On: Workstation with access to logs
    Run When: Preparing incident reports and root cause analysis
#>

function Generate-IncidentTimeline {
    param(
        [string[]]$LogPaths,
        [string]$OutputPath = "C:\Evidence\IncidentReports"
    )

    if (!$LogPaths -or $LogPaths.Count -eq 0) {
        Write-Host "[-] No log files specified." -ForegroundColor Red
        return
    }

    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $allEvents = @()

    foreach ($log in $LogPaths) {
        if (Test-Path $log) {
            $ext = [System.IO.Path]::GetExtension($log)
            if ($ext -eq ".csv") {
                $events = Import-Csv -Path $log -ErrorAction SilentlyContinue
                $allEvents += $events
            }
            else {
                Write-Host "[-] Unsupported log format for $log" -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "[-] Log file not found: $log" -ForegroundColor Yellow
        }
    }

    # Assuming logs have a timestamp field named "Timestamp" or similar
    $timeline = $allEvents | Sort-Object Timestamp

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = "$OutputPath\IncidentTimeline_${timestamp}.csv"

    $timeline | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] Incident timeline generated and saved to: $reportFile" -ForegroundColor Green

    return $reportFile
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-052: IOC Report Compiler
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Aggregates IPs, domains, hashes, and registry keys into a comprehensive IOC report
.DESCRIPTION
    Structures and exports IOCs collected during an investigation for sharing and blocking
.PARAMETER IOCs
    Hashtable or object with arrays of IOCs (IPs, domains, hashes, registry keys)
.PARAMETER OutputPath
    Directory to save IOC report
.EXAMPLE
    $iocs = @{IPs=@("1.2.3.4");Domains=@("malicious.com");Hashes=@("ABC123");Registry=@("HKCU:\Path")}
    .\UC-052-IOCReportCompiler.ps1 -IOCs $iocs -OutputPath "C:\Evidence\IOCReports"
.NOTES
    Run As: Analyst
    Run On: Workstation for threat intel sharing
    Run When: End of investigation or for blocking deployment
#>

function Compile-IOCReport {
    param(
        [hashtable]$IOCs,
        [string]$OutputPath = "C:\Evidence\IOCReports"
    )

    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = "$OutputPath\IOCReport_${timestamp}.txt"

    $content = @("IOC Report Generated on $(Get-Date)", "")

    foreach ($key in $IOCs.Keys) {
        $content += "== $key =="
        $content += $IOCs[$key]
        $content += ""
    }

    $content | Out-File -FilePath $reportFile

    Write-Host "`n[+] IOC report saved to: $reportFile" -ForegroundColor Green

    return $reportFile
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-053: Executive Summary Generator
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Converts technical findings into a high-level business impact report
.DESCRIPTION
    Summarizes investigation results in layman language for leadership
.PARAMETER FindingsFile
    Path to technical findings document
.PARAMETER OutputPath
    Directory to save executive summary
.EXAMPLE
    .\UC-053-ExecutiveSummaryGenerator.ps1 -FindingsFile "C:\Evidence\TechnicalFindings.txt" -OutputPath "C:\Evidence\ExecutiveReports"
.NOTES
    Run As: Analyst with incident context
    Run On: Workstation
    Run When: Preparing briefing for management
#>

function Generate-ExecutiveSummary {
    param(
        [string]$FindingsFile,
        [string]$OutputPath = "C:\Evidence\ExecutiveReports"
    )

    if (!(Test-Path $FindingsFile)) {
        Write-Host "[-] Technical findings file not found: $FindingsFile" -ForegroundColor Red
        return
    }

    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    # Placeholder: Script cannot fully automate text summarization well; encourage analyst manual review

    $summaryFile = "$OutputPath\ExecutiveSummary_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

    $content = @(
        "EXECUTIVE SUMMARY",
        "=================",
        "",
        "This report summarizes the key findings from the recent incident investigation.",
        "",
        "Please consult the technical findings document for detailed information.",
        "",
        "Note: This summary is intended for non-technical leadership review."
    )

    $content | Out-File -FilePath $summaryFile

    Write-Host "`n[+] Executive summary template saved to: $summaryFile" -ForegroundColor Green

    return $summaryFile
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-054: Compliance Evidence Collector
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Gathers specific logs and screenshots proving control implementation for audits
.DESCRIPTION
    Collects evidence across systems per compliance requirements
.PARAMETER OutputPath
    Directory to save evidence packages
.EXAMPLE
    .\UC-054-ComplianceEvidenceCollector.ps1 -OutputPath "C:\Evidence\Compliance"
.NOTES
    Run As: Analyst during audit preparation
    Run On: Multiple systems across environment
    Run When: Preparing for SOC2, ISO27001, PCI-DSS audits
#>

function Collect-ComplianceEvidence {
    param(
        [string]$OutputPath = "C:\Evidence\Compliance"
    )

    Write-Host "[+] Collecting compliance evidence..." -ForegroundColor Green

    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    # Placeholder: Evidence collection is organization-specific and manual; script outlines example log collection

    # Example: Collect security event logs from local machine
    $evtxPath = Join-Path $OutputPath "Security.evtx"
    wevtutil epl Security $evtxPath

    Write-Host "`n[+] Security event log exported to $evtxPath" -ForegroundColor Green

    Write-Host "[!] Additional evidence (screenshots, configurations) must be collected manually or via customized scripts." -ForegroundColor Yellow

    return $OutputPath
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-055: Lessons Learned Documenter
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Creates a structured post-incident review document
.DESCRIPTION
    Provides a template for analysts to fill improvement opportunities after incident closure
.PARAMETER OutputPath
    Directory to save lessons learned document
.EXAMPLE
    .\UC-055-LessonsLearnedDocumenter.ps1 -OutputPath "C:\Evidence\LessonsLearned"
.NOTES
    Run As: Incident Response Lead or Analyst
    Run On: Documentation system
    Run When: After major incident closure
#>

function Document-LessonsLearned {
    param(
        [string]$OutputPath = "C:\Evidence\LessonsLearned"
    )

    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $documentFile = "$OutputPath\LessonsLearned_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

    $template = @(
        "LESSONS LEARNED DOCUMENT",
        "========================",
        "",
        "Incident ID:",
        "Incident Description:",
        "",
        "What went well:",
        "",
        "What could be improved:",
        "",
        "Recommendations:",
        "",
        "Action Items:",
        "",
        "Prepared By:",
        "Date:"
    )

    $template | Out-File -FilePath $documentFile

    Write-Host "`n[+] Lessons learned template created: $documentFile" -ForegroundColor Green

    return $documentFile
}

#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
# UC-056: Process Anomaly Tracker
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Identifies rare or uncommon processes running on the system
.DESCRIPTION
    Scans running processes and compares against known common processes to flag anomalies
.PARAMETER OutputPath
    Directory to save anomaly report
.EXAMPLE
    .\UC-056-ProcessAnomalyTracker.ps1 -OutputPath "C:\Evidence\ProcessAnomalies"
.NOTES
    Run As: Administrator
    Run On: Endpoint suspected of malware or unusual activity
    Run When: Regular threat hunting or anomaly detection
#>

function Track-RareProcesses {
    param(
        [string]$OutputPath = "C:\Evidence\ProcessAnomalies"
    )

    Write-Host "[+] Tracking rare or uncommon processes..." -ForegroundColor Green

    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    # Common Windows processes (example subset)
    $commonProcesses = @("svchost", "explorer", "chrome", "powershell", "lsass", "winlogon", "services")

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME
    $reportFile = "$OutputPath\ProcessAnomalies_${hostname}_${timestamp}.csv"

    $allProcs = Get-Process | Select-Object Name, Id, Path

    $rareProcs = $allProcs | Where-Object { $_.Name -and ($commonProcesses -notcontains $_.Name.ToLower()) }

    $rareProcs | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] Rare process list saved to: $reportFile" -ForegroundColor Green
    Write-Host "[!] Rare processes count: $($rareProcs.Count)" -ForegroundColor Red

    return @{
        RareProcesses = $rareProcs
        ReportPath = $reportFile
    }
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-057: DLL Hijack Opportunity Finder
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Checks common DLL hijack locations for unwanted write permissions
.DESCRIPTION
    Scans directories for write permissions indicating potential hijack vulnerability
.PARAMETER OutputPath
    Directory to save report
.EXAMPLE
    .\UC-057-DllHijackFinder.ps1 -OutputPath "C:\Evidence\DLLHijack"
.NOTES
    Run As: Administrator
    Run On: Endpoint for privilege escalation review
    Run When: After privilege escalation alerts or routine audits
#>

function Find-DllHijackOpportunities {
    param(
        [string]$OutputPath = "C:\Evidence\DLLHijack"
    )

    Write-Host "[+] Scanning for DLL hijack opportunities..." -ForegroundColor Green

    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $knownPaths = @(
        "C:\Program Files",
        "C:\Program Files (x86)",
        "$env:SystemRoot\System32",
        "$env:SystemRoot\SysWOW64"
    )

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME
    $reportFile = "$OutputPath\DllHijackOpportunities_${hostname}_${timestamp}.csv"

    $results = @()

    foreach ($path in $knownPaths) {
        if (Test-Path $path) {
            $folderAcl = Get-Acl -Path $path
            foreach ($access in $folderAcl.Access) {
                if ($access.FileSystemRights -match "Write" -and $access.IdentityReference -notlike "BUILTIN\Administrators") {
                    $results += [PSCustomObject]@{
                        Path = $path
                        Identity = $access.IdentityReference.Value
                        Rights = $access.FileSystemRights
                        AccessControlType = $access.AccessControlType
                    }
                }
            }
        }
    }

    $results | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] DLL hijack opportunities saved to: $reportFile" -ForegroundColor Green
    Write-Host "[!] Potential write permissions found: $($results.Count)" -ForegroundColor Red

    return @{
        HijackOpportunities = $results
        ReportPath = $reportFile
    }
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-058: Shadow Copy Analyzer
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Lists all shadow copies and checks for deletion events
.DESCRIPTION
    Identifies shadow copies and searches event logs for deletion
.PARAMETER OutputPath
    Directory to save shadow copy report
.EXAMPLE
    .\UC-058-ShadowCopyAnalyzer.ps1 -OutputPath "C:\Evidence\ShadowCopies"
.NOTES
    Run As: Administrator
    Run On: File servers or critical endpoints
    Run When: Suspecting ransomware activity
#>

function Analyze-ShadowCopies {
    param(
        [string]$OutputPath = "C:\Evidence\ShadowCopies"
    )

    Write-Host "[+] Analyzing shadow copies and deletion events..." -ForegroundColor Green

    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $hostname = $env:COMPUTERNAME
    $shadowReportFile = "$OutputPath\ShadowCopies_${hostname}_${timestamp}.txt"
    $eventReportFile = "$OutputPath\ShadowCopyDeletionEvents_${hostname}_${timestamp}.csv"

    # List shadow copies
    $shadowCopies = vssadmin list shadows

    $shadowCopies | Out-File -FilePath $shadowReportFile

    # Search event logs for shadow copy deletion relevant events (Event ID example: 8224 in Microsoft-Windows-Backup)

    $deletionEvents = Get-WinEvent -FilterHashtable @{ LogName='Application'; Id=8224 } -ErrorAction SilentlyContinue | 
        Select-Object TimeCreated, Id, LevelDisplayName, Message

    $deletionEvents | Export-Csv -Path $eventReportFile -NoTypeInformation

    Write-Host "`n[+] Shadow copies list saved to: $shadowReportFile" -ForegroundColor Green
    Write-Host "[+] Shadow copy deletion events saved to: $eventReportFile" -ForegroundColor Green

    return @{
        ShadowCopies = $shadowCopies
        DeletionEvents = $deletionEvents
        ShadowCopiesReport = $shadowReportFile
        DeletionEventsReport = $eventReportFile
    }
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-059: Mass Password Reset Validator
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Confirms password reset completion for a list of users in Active Directory
.DESCRIPTION
    Verifies if password resets have been successfully applied during incident response
.PARAMETER UserList
    Path to file containing usernames to verify
.PARAMETER OutputPath
    Directory to save validation report
.EXAMPLE
    .\UC-059-MassPasswordResetValidator.ps1 -UserList "C:\UsersToVerify.txt" -OutputPath "C:\Evidence\PasswordResetValidation"
.NOTES
    Run As: Domain Admin
    Run On: Domain Controller or management workstation
    Run When: Validating credential change post-compromise
#>

function Validate-MassPasswordReset {
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserList,
        [string]$OutputPath = "C:\Evidence\PasswordResetValidation"
    )

    if (!(Test-Path $UserList)) {
        Write-Host "[-] User list file not found: $UserList" -ForegroundColor Red
        return
    }

    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    Import-Module ActiveDirectory

    $users = Get-Content -Path $UserList

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = "$OutputPath\PasswordResetValidation_${timestamp}.csv"

    $results = foreach ($user in $users) {
        $adUser = Get-ADUser -Identity $user -Properties PasswordLastSet -ErrorAction SilentlyContinue
        if ($adUser) {
            [PSCustomObject]@{
                UserName = $user
                PasswordLastSet = $adUser.PasswordLastSet
                PasswordChangedRecently = ($adUser.PasswordLastSet -gt (Get-Date).AddDays(-7))
            }
        } else {
            [PSCustomObject]@{
                UserName = $user
                PasswordLastSet = "Not Found"
                PasswordChangedRecently = $false
            }
        }
    }

    $results | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] Password reset validation report saved to: $reportFile" -ForegroundColor Green

    return $reportFile
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-060: Quarantine Status Checker
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Verifies endpoint quarantine status to ensure isolation is effective
.DESCRIPTION
    Checks network connectivity and quarantine indicator files/settings
.PARAMETER OutputPath
    Directory to save quarantine check report
.EXAMPLE
    .\UC-060-QuarantineStatusChecker.ps1 -OutputPath "C:\Evidence\QuarantineStatus"
.NOTES
    Run As: Administrator
    Run On: Quarantined endpoints
    Run When: Containment phase of incident response
#>

function Check-QuarantineStatus {
    param(
        [string]$OutputPath = "C:\Evidence\QuarantineStatus"
    )

    Write-Host "[+] Checking quarantine status..." -ForegroundColor Green

    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    # Test network connectivity - example ping to gateway or known address
    $pingResult = Test-Connection -ComputerName "8.8.8.8" -Count 2 -Quiet

    $statusFile = "$OutputPath\QuarantineStatus_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

    $content = @()
    if ($pingResult) {
        $content += "Endpoint has network connectivity. Quarantine may NOT be effective."
    } else {
        $content += "Endpoint has NO network connectivity. Quarantine appears effective."
    }

    $content | Out-File -FilePath $statusFile

    Write-Host "`n[+] Quarantine status written to: $statusFile" -ForegroundColor Green

    return $statusFile
}

#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
# UC-061: Backup Integrity Validator
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Checks backup file hashes against original files to verify integrity
.DESCRIPTION
    Compares SHA256 hashes of backup files with current files before restore
.PARAMETER BackupPath
    Directory containing backup files
.PARAMETER SourcePath
    Directory of original files to compare against
.PARAMETER OutputPath
    Directory to save validation report
.EXAMPLE
    .\UC-061-BackupIntegrityValidator.ps1 -BackupPath "D:\Backups" -SourcePath "C:\Data" -OutputPath "C:\Evidence\BackupValidation"
.NOTES
    Run As: Administrator
    Run On: Backup or restoration server
    Run When: Prior to data restoration after ransomware or loss
#>

function Validate-BackupIntegrity {
    param(
        [Parameter(Mandatory=$true)]
        [string]$BackupPath,
        [Parameter(Mandatory=$true)]
        [string]$SourcePath,
        [string]$OutputPath = "C:\Evidence\BackupValidation"
    )

    if (!(Test-Path $BackupPath)) {
        Write-Host "[-] Backup path not found: $BackupPath" -ForegroundColor Red
        return
    }

    if (!(Test-Path $SourcePath)) {
        Write-Host "[-] Source path not found: $SourcePath" -ForegroundColor Red
        return
    }

    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = "$OutputPath\BackupIntegrity_${timestamp}.csv"

    $results = @()

    $backupFiles = Get-ChildItem -Path $BackupPath -Recurse -File

    foreach ($bFile in $backupFiles) {
        $relativePath = $bFile.FullName.Substring($BackupPath.Length)
        $sourceFile = Join-Path $SourcePath $relativePath

        if (Test-Path $sourceFile) {
            try {
                $backupHash = Get-FileHash -Path $bFile.FullName -Algorithm SHA256
                $sourceHash = Get-FileHash -Path $sourceFile -Algorithm SHA256

                $match = $backupHash.Hash -eq $sourceHash.Hash

                $results += [PSCustomObject]@{
                    BackupFile = $bFile.FullName
                    SourceFile = $sourceFile
                    BackupHash = $backupHash.Hash
                    SourceHash = $sourceHash.Hash
                    HashMatch = $match
                }
            }
            catch {
                $results += [PSCustomObject]@{
                    BackupFile = $bFile.FullName
                    SourceFile = $sourceFile
                    BackupHash = "Error"
                    SourceHash = "Error"
                    HashMatch = $false
                }
            }
        } else {
            $results += [PSCustomObject]@{
                BackupFile = $bFile.FullName
                SourceFile = "Not Found"
                BackupHash = "N/A"
                SourceHash = "N/A"
                HashMatch = $false
            }
        }
    }

    $results | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] Backup integrity validation saved to: $reportFile" -ForegroundColor Green

    return $reportFile
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-062: Clean Room Evidence Packager
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Creates password-protected, hashed evidence ZIP packages for chain of custody
.DESCRIPTION
    Compresses evidence files with password and computes hash for verification
.PARAMETER EvidencePath
    Directory containing evidence to package
.PARAMETER OutputPath
    Directory to save packaged evidence
.PARAMETER Password
    Password for ZIP encryption
.EXAMPLE
    .\UC-062-CleanRoomEvidencePackager.ps1 -EvidencePath "C:\Evidence" -OutputPath "C:\Evidence\Packages" -Password "StrongPass123"
.NOTES
    Run As: Forensic analyst
    Run On: Isolated forensic workstation
    Run When: Preparing evidence for legal or law enforcement transfer
#>

function Package-CleanRoomEvidence {
    param(
        [Parameter(Mandatory=$true)]
        [string]$EvidencePath,
        [string]$OutputPath = "C:\Evidence\Packages",
        [Parameter(Mandatory=$true)]
        [string]$Password
    )

    if (!(Test-Path $EvidencePath)) {
        Write-Host "[-] Evidence path not found: $EvidencePath" -ForegroundColor Red
        return
    }

    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $zipFile = "$OutputPath\EvidencePackage_${timestamp}.zip"
    $hashFile = "$OutputPath\EvidencePackage_${timestamp}.sha256"

    # Use 7zip if installed, for password protection
    $sevenZipPath = "C:\Program Files\7-Zip\7z.exe"

    if (-not (Test-Path $sevenZipPath)) {
        Write-Host "[-] 7-Zip not found at $sevenZipPath. Please install 7-Zip to enable password-protected archive." -ForegroundColor Red
        return
    }

    $arguments = "a `"$zipFile`" `"$EvidencePath\*`" -p$Password -mhe=on"

    $process = Start-Process -FilePath $sevenZipPath -ArgumentList $arguments -Wait -NoNewWindow -PassThru

    if ($process.ExitCode -eq 0) {
        $hash = Get-FileHash -Path $zipFile -Algorithm SHA256
        $hash.Hash | Out-File -FilePath $hashFile
        Write-Host "`n[+] Evidence package created: $zipFile" -ForegroundColor Green
        Write-Host "[+] SHA256 hash saved to: $hashFile" -ForegroundColor Green
        return @{
            ZipFile = $zipFile
            HashFile = $hashFile
        }
    } else {
        Write-Host "[-] Failed to create evidence package." -ForegroundColor Red
    }
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-063: Remediation Verification Scanner
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Checks if malware artifacts still exist post-cleanup
.DESCRIPTION
    Scans for known IOCs and suspicious files after running removal tools
.PARAMETER IOCPaths
    Array of file paths or directories containing IOCs
.PARAMETER OutputPath
    Directory to save remediation report
.EXAMPLE
    .\UC-063-RemediationVerification.ps1 -IOCPaths @("C:\IOCs") -OutputPath "C:\Evidence\Remediation"
.NOTES
    Run As: Administrator
    Run On: Endpoint post-remediation
    Run When: Confirming complete malware removal
#>

function Verify-Remediation {
    param(
        [string[]]$IOCPaths,
        [string]$OutputPath = "C:\Evidence\Remediation"
    )

    if (!$IOCPaths -or $IOCPaths.Count -eq 0) {
        Write-Host "[-] No IOC paths provided." -ForegroundColor Red
        return
    }

    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = "$OutputPath\RemediationVerification_${timestamp}.csv"

    $findings = @()

    foreach ($path in $IOCPaths) {
        if (Test-Path $path) {
            $files = Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                $exists = Test-Path $file.FullName
                $findings += [PSCustomObject]@{
                    FilePath = $file.FullName
                    ExistsAfterRemediation = $exists
                }
            }
        } else {
            Write-Host "[-] IOC path not found: $path" -ForegroundColor Yellow
        }
    }

    $findings | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] Remediation verification report saved to: $reportFile" -ForegroundColor Green

    return $reportFile
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-064: Failed Login Aggregator
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Exports all failed login events grouped by user and source IP
.DESCRIPTION
    Aggregates failed login attempts for brute force or password spray investigations
.PARAMETER OutputPath
    Directory to save aggregate report
.PARAMETER StartTime
    Optional start time for filtering events (default last 7 days)
.EXAMPLE
    .\UC-064-FailedLoginAggregator.ps1 -OutputPath "C:\Evidence\FailedLogins" -StartTime (Get-Date).AddDays(-7)
.NOTES
    Run As: Administrator
    Run On: Domain Controller or log aggregation system
    Run When: Investigating account lockouts or brute force attacks
#>

function Aggregate-FailedLogins {
    param(
        [string]$OutputPath = "C:\Evidence\FailedLogins",
        [datetime]$StartTime = (Get-Date).AddDays(-7)
    )

    Write-Host "[+] Aggregating failed login attempts since $StartTime..." -ForegroundColor Green

    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $query = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= $((New-TimeSpan $StartTime (Get-Date)).TotalMilliseconds)]]]
    </Select>
  </Query>
</QueryList>
"@

    $events = Get-WinEvent -FilterXml $query -ErrorAction SilentlyContinue

    $logonFailures = $events | Select-Object -Property @{Name="User";Expression={($_.Properties[5].Value)}}, @{Name="SourceIP";Expression={($_.Properties[18].Value)}}

    $grouped = $logonFailures | Group-Object User, SourceIP | Select-Object @{Name="User";Expression={$_.Name.Split(',')[0]}}, @{Name="SourceIP";Expression={$_.Name.Split(',')[1]}}, @{Name="Count";Expression={$_.Count}}

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = "$OutputPath\FailedLoginAggregate_${timestamp}.csv"

    $grouped | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] Failed login aggregation saved to: $reportFile" -ForegroundColor Green

    return $reportFile
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-065: After-Hours Access Reporter
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Lists all user access outside normal business hours with context
.DESCRIPTION
    Aggregates logon events occurring outside defined hours for insider threat detection
.PARAMETER OutputPath
    Directory to save report
.PARAMETER StartTime
    Optional start time to begin log query
.PARAMETER BusinessHoursStart
    Hour (0-23) business hours start (default 6)
.PARAMETER BusinessHoursEnd
    Hour (0-23) business hours end (default 20)
.EXAMPLE
    .\UC-065-AfterHoursAccessReporter.ps1 -OutputPath "C:\Evidence\AfterHours" -StartTime (Get-Date).AddDays(-7)
.NOTES
    Run As: Administrator
    Run On: Log aggregation server or Domain Controller
    Run When: Insider threat or data exfiltration investigation
#>

function Report-AfterHoursAccess {
    param(
        [string]$OutputPath = "C:\Evidence\AfterHours",
        [datetime]$StartTime = (Get-Date).AddDays(-7),
        [int]$BusinessHoursStart = 6,
        [int]$BusinessHoursEnd = 20
    )

    Write-Host "[+] Reporting logons outside business hours ($BusinessHoursStart:00-$BusinessHoursEnd:00) since $StartTime..." -ForegroundColor Green

    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $query = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= $((New-TimeSpan $StartTime (Get-Date)).TotalMilliseconds)]]]
    </Select>
  </Query>
</QueryList>
"@

    $events = Get-WinEvent -FilterXml $query -ErrorAction SilentlyContinue

    $offHours = $events | Where-Object {
        $hour = $_.TimeCreated.Hour
        ($hour -lt $BusinessHoursStart -or $hour -ge $BusinessHoursEnd)
    } | Select-Object TimeCreated, @{Name="User";Expression={$_.Properties[5].Value}}

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = "$OutputPath\AfterHoursAccess_${timestamp}.csv"

    $offHours | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] After-hours access report saved to: $reportFile" -ForegroundColor Green

    return $reportFile
}

#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
# UC-066: New User Creation Auditor
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Lists all Active Directory accounts created within the last 30 days with creator info
.DESCRIPTION
    Audits new user accounts to detect unauthorized creations or backdoors
.PARAMETER OutputPath
    Directory to save audit report
.PARAMETER DaysBack
    Number of days back to check (default 30)
.EXAMPLE
    .\UC-066-NewUserCreationAuditor.ps1 -OutputPath "C:\Evidence\NewUsers" -DaysBack 30
.NOTES
    Run As: Domain Admin
    Run On: Domain Controller or remote management system
    Run When: Monthly audit or suspicious account activity investigation
#>

function Audit-NewUserCreation {
    param(
        [string]$OutputPath = "C:\Evidence\NewUsers",
        [int]$DaysBack = 30
    )

    Import-Module ActiveDirectory

    $sinceDate = (Get-Date).AddDays(-$DaysBack)

    Write-Host "[+] Auditing new user creation since $sinceDate..." -ForegroundColor Green

    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $users = Get-ADUser -Filter {WhenCreated -ge $sinceDate} -Properties WhenCreated, SamAccountName, CreatedBy | Select-Object SamAccountName, WhenCreated, ObjectClass

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = "$OutputPath\NewUserCreationAudit_${timestamp}.csv"

    $users | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] New user creation audit saved to: $reportFile" -ForegroundColor Green

    return $reportFile
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-067: Group Policy Change Tracker
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Compares current Group Policy Objects (GPOs) against a baseline export
.DESCRIPTION
    Detects unauthorized or suspicious GPO changes after admin activity
.PARAMETER BaselineGPOPath
    Path to baseline GPO export files
.PARAMETER CurrentGPOPath
    Path to current GPO export files
.PARAMETER OutputPath
    Directory to save comparison report
.EXAMPLE
    .\UC-067-GPOChangeTracker.ps1 -BaselineGPOPath "C:\Baseline\GPO" -CurrentGPOPath "C:\Current\GPO" -OutputPath "C:\Evidence\GPOChanges"
.NOTES
    Run As: Domain Admin
    Run On: Management system responsible for GPO
    Run When: Detecting persistence or privilege escalation via GPO changes
#>

function Track-GPOChanges {
    param(
        [Parameter(Mandatory=$true)]
        [string]$BaselineGPOPath,
        [Parameter(Mandatory=$true)]
        [string]$CurrentGPOPath,
        [string]$OutputPath = "C:\Evidence\GPOChanges"
    )

    Write-Host "[+] Comparing GPO exports for changes..." -ForegroundColor Green

    if (!(Test-Path $BaselineGPOPath) -or !(Test-Path $CurrentGPOPath)) {
        Write-Host "[-] Baseline or current GPO path missing." -ForegroundColor Red
        return
    }

    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $diffReport = "$OutputPath\GPOChanges_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

    $baselineFiles = Get-ChildItem -Path $BaselineGPOPath -Recurse -File
    $currentFiles = Get-ChildItem -Path $CurrentGPOPath -Recurse -File

    $changes = @()

    foreach ($baseFile in $baselineFiles) {
        $relativePath = $baseFile.FullName.Substring($BaselineGPOPath.Length)
        $currentFile = Join-Path $CurrentGPOPath $relativePath

        if (Test-Path $currentFile) {
            $diff = Compare-Object -ReferenceObject (Get-Content $baseFile.FullName) -DifferenceObject (Get-Content $currentFile) -SyncWindow 0
            if ($diff) {
                $changes += "Differences found in $relativePath"
                $diff | Out-String | ForEach-Object { $changes += $_ }
            }
        } else {
            $changes += "File missing in current export: $relativePath"
        }
    }

    $changes | Out-File -FilePath $diffReport

    Write-Host "`n[+] GPO change report saved to: $diffReport" -ForegroundColor Green

    return $diffReport
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-068: Large File Transfer Detector
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Finds file transfers over 100MB from logs (firewall, proxy, etc.)
.DESCRIPTION
    Analyzes log files to detect potential data exfiltration of large files
.PARAMETER LogPath
    Path to network or proxy logs
.PARAMETER OutputPath
    Directory to save the large file transfer report
.EXAMPLE
    .\UC-068-LargeFileTransferDetector.ps1 -LogPath "C:\Logs\Proxy" -OutputPath "C:\Evidence\LargeTransfers"
.NOTES
    Run As: Analyst on log aggregation system
    Run On: Network monitoring station
    Run When: Hunting for insider threats or data leaks
#>

function Detect-LargeFileTransfers {
    param(
        [string]$LogPath,
        [string]$OutputPath = "C:\Evidence\LargeTransfers"
    )

    if (!(Test-Path $LogPath)) {
        Write-Host "[-] Log path not found: $LogPath" -ForegroundColor Red
        return
    }

    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    Write-Host "[+] Scanning logs for large file transfers over 100MB..." -ForegroundColor Green

    # Placeholder: actual parsing depends on log format; this is an example for CSV logs with FileSize column

    $logs = Import-Csv -Path $LogPath -ErrorAction SilentlyContinue

    if (-not $logs) {
        Write-Host "[-] No log entries loaded from $LogPath" -ForegroundColor Red
        return
    }

    $thresholdBytes = 100MB

    $largeTransfers = $logs | Where-Object { $_.FileSize -and [int64]$_.FileSize -gt $thresholdBytes }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = "$OutputPath\LargeFileTransfers_${timestamp}.csv"

    $largeTransfers | Export-Csv -Path $reportFile -NoTypeInformation

    Write-Host "`n[+] Large file transfer report saved to: $reportFile" -ForegroundColor Green

    return $reportFile
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-069: Wireless Access Point Auditor
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Lists all WiFi Access Points and compares to authorized list
.DESCRIPTION
    Scans wireless networks and identifies unauthorized APs
.PARAMETER AuthorizedListPath
    Path to text file containing authorized SSIDs
.PARAMETER OutputPath
    Directory to save audit report
.EXAMPLE
    .\UC-069-WirelessAPAuditor.ps1 -AuthorizedListPath "C:\Configs\AuthorizedAPs.txt" -OutputPath "C:\Evidence\WirelessAudit"
.NOTES
    Run As: Administrator
    Run On: Wireless scanning system
    Run When: Monthly wireless security check
#>

function Audit-WirelessAPs {
    param(
        [string]$AuthorizedListPath,
        [string]$OutputPath = "C:\Evidence\WirelessAudit"
    )

    if (!(Test-Path $AuthorizedListPath)) {
        Write-Host "[-] Authorized AP list not found: $AuthorizedListPath" -ForegroundColor Red
        return
    }

    if (!(Test-Path $OutputPath)) { New-Item -Type Directory -Path $OutputPath | Out-Null }

    $authorizedAPs = Get-Content -Path $AuthorizedListPath

    $scanResults = netsh wlan show networks mode=bssid

    $detectedAPs = @()
    foreach ($line in $scanResults) {
        if ($line -match '^SSID \d+ : (.+)$') {
            $detectedAPs += $matches[1].Trim()
        }
    }

    $unauthorizedAPs = $detectedAPs | Where-Object {$_ -notin $authorizedAPs}

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = "$OutputPath\WirelessAPAudit_${timestamp}.txt"

    "Authorized APs:" | Out-File $reportFile
    $authorizedAPs | Out-File -Append $reportFile
    "`nDetected APs:" | Out-File -Append $reportFile
    $detectedAPs | Out-File -Append $reportFile
    "`nUnauthorized APs:" | Out-File -Append $reportFile
    $unauthorizedAPs | Out-File -Append $reportFile

    Write-Host "`n[+] Wireless AP audit report saved to: $reportFile" -ForegroundColor Green

    return $reportFile
}

#------------------------------------------------------------------------------


#------------------------------------------------------------------------------
# UC-070: Incident Timeline Generator (Duplicate as UC-051, placeholder for expansion)
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Aggregates log data to create chronological incident timeline (placeholder for advanced timeline)
.DESCRIPTION
    May include enriched event correlation and annotations
#>

Write-Host "UC-070: Incident Timeline Generator is conceptually similar to UC-051 and can be extended with specific log enrichment and correlation logic as needed." -ForegroundColor Yellow

#------------------------------------------------------------------------------
