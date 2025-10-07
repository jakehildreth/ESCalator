function Show-ESC4e1AttackDetails {
    <#
        .SYNOPSIS
        Shows attack details for ESC4e1 vulnerabilities.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [array]$Results
    )

    Write-Host "=== ESC4e1: Immediate Template Modification Attack ===" -ForegroundColor Red
    Write-Host ""
    Write-Host "Attack Description:" -ForegroundColor Yellow
    Write-Host "The principal can immediately modify certificate templates that are enabled on Certificate Authorities." -ForegroundColor White
    Write-Host "This allows for instant privilege escalation by changing template properties to make them vulnerable." -ForegroundColor White
    Write-Host ""
    
    # Display affected templates and rights
    Write-Host "Affected Templates and Rights:" -ForegroundColor Yellow
    foreach ($result in $Results) {
        Write-Host "  Principal: $($result.PrincipalName)" -ForegroundColor Cyan
        
        if ($result.VulnerableTemplates -and $result.VulnerableTemplates.Count -gt 0) {
            foreach ($template in $result.VulnerableTemplates) {
                Write-Host "    - Template: $template" -ForegroundColor White
                
                # Find issues for this template to get specific rights
                $templateIssues = $result.ESC4e1Issues | Where-Object { 
                    $_.DirectoryEntry -and $_.DirectoryEntry.Properties['name'].Value -eq $template 
                }
                
                if ($templateIssues) {
                    $uniqueRights = $templateIssues | ForEach-Object { $_.ActiveDirectoryRights } | Sort-Object -Unique
                    Write-Host "    - Rights: $($uniqueRights -join ', ')" -ForegroundColor Gray
                }
            }
        }
        Write-Host ""
    }
    
    Write-Host "Attack Steps:" -ForegroundColor Yellow
    Write-Host "1. Modify the identified certificate template to match ESC1 requirements:`n  - Subject Alternative Name (SAN) allowed`n  - Client Authentication EKU`n  - No Manager Approval`n  - Enrollment Rights Assigned" -ForegroundColor Gray
    Write-Host "2. Request a certificate with a SAN of a privileged account" -ForegroundColor Gray
    Write-Host "3. Use the certificate to authenticate as the privileged account" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Risk Level: CRITICAL - Immediate exploitation possible" -ForegroundColor Red
}