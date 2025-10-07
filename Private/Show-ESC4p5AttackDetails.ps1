function Show-ESC4p5AttackDetails {
    <#
        .SYNOPSIS
        Shows attack details for ESC4p5Combo vulnerabilities.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [array]$Results
    )

    Write-Host "=== ESC4p5: Combined Template Control Attack ===" -ForegroundColor Red
    Write-Host ""
    Write-Host "Attack Description:" -ForegroundColor Yellow
    Write-Host "The principal can control both disabled certificate templates AND enrollment services." -ForegroundColor White
    Write-Host "This combination allows enabling vulnerable templates and controlling their deployment." -ForegroundColor White
    Write-Host ""
    Write-Host "Attack Steps:" -ForegroundColor Yellow
    Write-Host "1. Modify the identified certificate template to match ESC1 requirements:`n  - Subject Alternative Name (SAN) allowed`n  - Client Authentication EKU`n  - No Manager Approval`n  - Enrollment Rights Assigned" -ForegroundColor Gray
    Write-Host "2. Enable the certificate template" -ForegroundColor Gray
    Write-Host "3. Request a certificate with the SAN of a privileged account" -ForegroundColor Gray
    Write-Host "4. Use the certificate to authenticate as the privileged account" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Risk Level: CRITICAL - Multi-stage attack with full template control" -ForegroundColor Red
}