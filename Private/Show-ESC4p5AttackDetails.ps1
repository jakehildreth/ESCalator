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
    
    # Display affected templates, enrollment services, and rights
    Write-Host "Affected Templates and Enrollment Services:" -ForegroundColor Yellow
    foreach ($result in $Results) {
        Write-Host "  Principal: $($result.PrincipalName)" -ForegroundColor Cyan
        
        # Display vulnerable templates
        if ($result.VulnerableTemplates -and $result.VulnerableTemplates.Count -gt 0) {
            Write-Host "    Vulnerable Templates:" -ForegroundColor White
            foreach ($template in $result.VulnerableTemplates) {
                Write-Host "      - Template: $template" -ForegroundColor White
                
                # Find issues for this template to get specific rights
                $templateIssues = $result.ESC4dIssues | Where-Object { 
                    $_.DirectoryEntry -and $_.DirectoryEntry.Properties['name'].Value -eq $template 
                }
                
                if ($templateIssues) {
                    $uniqueRights = $templateIssues | ForEach-Object { $_.ActiveDirectoryRights } | Sort-Object -Unique
                    $uniqueSubtypes = $templateIssues | ForEach-Object { $_.Subtype } | Sort-Object -Unique
                    Write-Host "      - Rights: $($uniqueRights -join ', ')" -ForegroundColor Gray
                    Write-Host "      - Subtypes: $($uniqueSubtypes -join ', ')" -ForegroundColor Gray
                }
            }
        }
        
        # Display enrollment services
        if ($result.EnrollmentServices -and $result.EnrollmentServices.Count -gt 0) {
            Write-Host "    Controlled Enrollment Services:" -ForegroundColor White
            foreach ($service in $result.EnrollmentServices) {
                Write-Host "      - Service: $service" -ForegroundColor White
                
                # Find issues for this service to get specific rights
                $serviceIssues = $result.ESC5EnrollmentIssues | Where-Object { $_.Name -eq $service }
                
                if ($serviceIssues) {
                    $uniqueRights = $serviceIssues | ForEach-Object { $_.ActiveDirectoryRights } | Sort-Object -Unique
                    $uniqueSubtypes = $serviceIssues | ForEach-Object { $_.Subtype } | Sort-Object -Unique
                    Write-Host "      - Rights: $($uniqueRights -join ', ')" -ForegroundColor Gray
                    Write-Host "      - Subtypes: $($uniqueSubtypes -join ', ')" -ForegroundColor Gray
                }
            }
        }
        Write-Host ""
    }
    
    Write-Host "Attack Steps:" -ForegroundColor Yellow
    Write-Host "1. Modify the identified certificate template to match ESC1 requirements:`n  - Subject Alternative Name (SAN) allowed`n  - Client Authentication EKU`n  - No Manager Approval`n  - Enrollment Rights Assigned" -ForegroundColor Gray
    Write-Host "2. Enable the certificate template" -ForegroundColor Gray
    Write-Host "3. Request a certificate with the SAN of a privileged account" -ForegroundColor Gray
    Write-Host "4. Use the certificate to authenticate as the privileged account" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Risk Level: CRITICAL - Multi-stage attack with full template control" -ForegroundColor Red
}