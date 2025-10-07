function Show-ESC5p5AttackDetails {
    <#
        .SYNOPSIS
        Shows attack details for ESC5p5Combo vulnerabilities.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [array]$Results
    )

    Write-Host "=== ESC5p5: Full PKI Infrastructure Control ===" -ForegroundColor Red
    Write-Host ""
    Write-Host "Attack Description:" -ForegroundColor Yellow
    Write-Host "The principal has comprehensive control over PKI infrastructure including both" -ForegroundColor White
    Write-Host "certificate template containers AND enrollment services." -ForegroundColor White
    Write-Host ""
    Write-Host "Attack Steps:" -ForegroundColor Yellow
    Write-Host "1. Create a new blank certificate template" -ForegroundColor Gray
    Write-Host "2. Modify the blank certificate template to match ESC1 requirements:`n  - Subject Alternative Name (SAN) allowed`n  - Client Authentication EKU`n  - No Manager Approval`n  - Enrollment Rights Assigned" -ForegroundColor Gray
    Write-Host "3. Enable the new certificate template" -ForegroundColor Gray
    Write-Host "4. Request a certificate with the SAN of a privileged account" -ForegroundColor Gray
    Write-Host "5. Use the certificate to authenticate as the privileged account" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Risk Level: CRITICAL - Complete PKI infrastructure compromise" -ForegroundColor Red
}