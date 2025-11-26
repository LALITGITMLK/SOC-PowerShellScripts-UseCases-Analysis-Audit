#------------------------------------------------------------------------------
# UC-013: Certificate Transparency Log Scanner
#------------------------------------------------------------------------------
<#
.SYNOPSIS
    Scans public CT logs (crt.sh) for certificates issued to your domains
.DESCRIPTION
    Finds new/rogue certs – great for detecting phishing sites early
.PARAMETER Domains
    One or more domains (or wildcards) to monitor
.PARAMETER DaysBack
    How many days back to search (default 30)
.PARAMETER OutputPath
    Where to save CSV report
.EXAMPLE
    .\UC-013-CertTransparencyScanner.ps1 -Domains "yourcompany.com","mail.yourcompany.com"
.NOTES
    Run As: Standard user
    Run On: Analyst workstation or scheduled weekly
    Run When: Proactive domain protection / phishing prevention
#>

param(
    [Parameter(Mandatory=$true)][string[]]$Domains,
    [int]$DaysBack = 30,
    [string]$OutputPath = "C:\Evidence"
)

Write-Host "[+] Scanning Certificate Transparency logs for $($Domains -join ', ')" -ForegroundColor Green

if(!(Test-Path $OutputPath)){ New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

$allCerts = @()
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$report = "$OutputPath\UC013_CT_Results_$timestamp.csv"

foreach($domain in $Domains){
    Write-Host "[*] Querying crt.sh for $domain ..." -ForegroundColor Yellow
    try{
        $url = "https://crt.sh/?q=%25$domain&output=json"
        $data = Invoke-RestMethod -Uri $url -TimeoutSec 20
        $recent = $data | Where-Object { [datetime]$_.not_before -gt (Get-Date).AddDays(-$DaysBack) }
        
        foreach($cert in $recent){
            $allCerts += [PSCustomObject]@{
                Domain       = $domain
                CommonName   = $cert.name_value -split "`n" -join "; "
                Issuer       = $cert.issuer_name -replace 'C=.*?, ','' -replace 'O=',''
                NotBefore    = $cert.not_before
                NotAfter     = $cert.not_after
                Serial       = $cert.serial_number
                Log          = "crt.sh"
            }
        }
    }catch{
        Write-Host "[-] Failed for $domain : $($_.Exception.Message)" -ForegroundColor Red
    }
}

$allCerts | Sort-Object NotBefore -Descending | Export-Csv $report -NoTypeInformation

Write-Host "`n[+] Scan complete! Found $($allCerts.Count) certificates in last $DaysBack days" -ForegroundColor Green
Write-Host "[+] Report → $report" -ForegroundColor Cyan

if($allCerts.Count -gt 0){
    Write-Host "`n=== RECENT CERTIFICATES ===" -ForegroundColor Magenta
    $allCerts | Select-Object Domain,CommonName,Issuer,NotBefore | Format-Table -AutoSize
}

if($allCerts.Count -eq 0){
    Write-Host "[+] No new certificates found – all good!" -ForegroundColor Green
}