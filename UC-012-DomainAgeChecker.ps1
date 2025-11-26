#------------------------------------------------------------------------------
# UC-012: Domain Age & Registration Checker
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Checks domain creation date, registrar, and age – perfect for phishing triage
.DESCRIPTION
    Uses public WHOIS (via crt.sh-style API fallback) and DNS lookup
.PARAMETER Domain
    Domain to check (e.g. malicious-site.com)
.PARAMETER OutputPath
    Where to save the report (default C:\Evidence)
.EXAMPLE
    .\UC-012-DomainAgeChecker.ps1 -Domain "evilcorp-login.com"
.NOTES
    Run As: Standard user
    Run On: Analyst workstation
    Run When: Investigating suspicious domain in phishing email
#>

param(
    [Parameter(Mandatory=$true)][string]$Domain,
    [string]$OutputPath = "C:\Evidence"
)

Write-Host "[+] Checking domain: $Domain" -ForegroundColor Green

# Create output folder
if(!(Test-Path $OutputPath)){ New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$report = "$OutputPath\UC012_DomainReport_$Domain`_$timestamp.txt"

# Try public WHOIS API (no key needed)
try {
    $uri = "https://whoisds.com/whois/$Domain"
    $data = Invoke-RestMethod -Uri $uri -TimeoutSec 10
    $created = ($data.whois.creation_date -split 'T')[0]
    $ageDays = if($created){ ((Get-Date) - [datetime]$created).Days } else { "Unknown" }
} catch { $created = "Failed to retrieve"; $ageDays = "Unknown" }

# DNS records
$dns = Resolve-DnsName -Name $Domain -ErrorAction SilentlyContinue | Select-Object Name,Type,IPAddress -Unique

# Build report
@"
DOMAIN AGE & REGISTRATION REPORT
================================
Domain       : $Domain
Checked      : $(Get-Date)
Creation Date: $created
Age (days)   : $ageDays $(if($ageDays -is [int] -and $ageDays -lt 30){" [!] VERY RECENT – HIGH RISK"}else{""})

DNS RECORDS
===========
$($dns | Format-Table | Out-String)
"@ | Out-File -FilePath $report -Encoding UTF8

Write-Host "[+] Report saved → $report" -ForegroundColor Green
if($ageDays -is [int] -and $ageDays -lt 30){ Write-Host "[!] SUSPICIOUS: Domain registered less than 30 days ago!" -ForegroundColor Red }