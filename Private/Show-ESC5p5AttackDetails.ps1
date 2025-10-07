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
    
    # Display affected certificate template containers and enrollment services
    Write-Host "Affected Certificate Template Containers and Enrollment Services:" -ForegroundColor Yellow
    foreach ($result in $Results) {
        Write-Host "  Principal: $($result.PrincipalName)" -ForegroundColor Cyan
        
        # Display certificate template containers
        if ($result.CertTemplatesContainers -and $result.CertTemplatesContainers.Count -gt 0) {
            Write-Host "    Certificate Template Containers:" -ForegroundColor White
            foreach ($container in $result.CertTemplatesContainers) {
                Write-Host "      - Container: $container" -ForegroundColor White
                
                # Find issues for this container to get specific rights
                $containerIssues = $result.ESC5CertTemplatesIssues | Where-Object { $_.Name -eq $container }
                
                if ($containerIssues) {
                    $uniqueRights = $containerIssues | ForEach-Object { $_.ActiveDirectoryRights } | Sort-Object -Unique
                    $uniqueSubtypes = $containerIssues | ForEach-Object { $_.Subtype } | Sort-Object -Unique
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
    Write-Host "1. Create a new blank certificate template" -ForegroundColor Gray
    Write-Host "2. Modify the blank certificate template to match ESC1 requirements:`n  - Subject Alternative Name (SAN) allowed`n  - Client Authentication EKU`n  - No Manager Approval`n  - Enrollment Rights Assigned" -ForegroundColor Gray
    Write-Host "3. Enable the new certificate template" -ForegroundColor Gray
    Write-Host "4. Request a certificate with the SAN of a privileged account" -ForegroundColor Gray
    Write-Host "5. Use the certificate to authenticate as the privileged account" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Risk Level: CRITICAL - Complete PKI infrastructure compromise" -ForegroundColor Red
}