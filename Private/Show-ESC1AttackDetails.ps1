function Show-ESC1AttackDetails {
    <#
        .SYNOPSIS
        Shows ESC1 attack details and offers attack execution.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [array]$Results,

        [Parameter()]
        [object]$Principal
    )

    Write-Host "=== ESC1: SAN Spoofing Attack ===" -ForegroundColor Red
    Write-Host ""
    Write-Host "Attack Description:" -ForegroundColor Yellow
    Write-Host "The principal can request certificates with arbitrary Subject Alternative Names" -ForegroundColor White
    Write-Host "from templates that allow enrollee-supplied subjects and have Client Authentication EKU." -ForegroundColor White
    Write-Host "This enables impersonation of any user or computer in the domain." -ForegroundColor White
    Write-Host ""

    # Collect all vulnerable templates from all results
    $allTemplates = @()
    foreach ($result in $Results) {
        if ($result.ESC1Issues -and $result.ESC1Issues.Count -gt 0) {
            foreach ($issue in $result.ESC1Issues) {
                $templateName = if ($issue.DirectoryEntry -and $issue.DirectoryEntry.Properties['name'].Value) {
                    $issue.DirectoryEntry.Properties['name'].Value
                } else {
                    "Unknown Template"
                }

                $allTemplates += [PSCustomObject]@{
                    TemplateName = $templateName
                    PrincipalName = $result.PrincipalName
                    Issue = $issue
                    Result = $result
                }
            }
        }
    }

    $uniqueTemplates = @($allTemplates | Group-Object TemplateName | ForEach-Object {
        [PSCustomObject]@{
            TemplateName = $_.Name
            Issues = $_.Group
            IssueCount = $_.Count
        }
    })

    if ($uniqueTemplates.Count -eq 0) {
        Write-Host "No vulnerable templates found." -ForegroundColor Red
        return
    }

    Write-Host "Vulnerable Templates:" -ForegroundColor Yellow
    Write-Host ""

    for ($i = 0; $i -lt $uniqueTemplates.Count; $i++) {
        $template = $uniqueTemplates[$i]
        Write-Host "  $($i + 1). $($template.TemplateName)" -ForegroundColor White
    }

    Write-Host ""
    Write-Host "Attack Steps:" -ForegroundColor Yellow
    Write-Host "1. Request a certificate from a vulnerable template with a SAN of a privileged account" -ForegroundColor Gray
    Write-Host "2. Use the certificate to authenticate as the privileged account (PKINIT)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Risk Level: CRITICAL - Immediate exploitation possible" -ForegroundColor Red
    Write-Host ""

    # Offer attack execution for current user
    if (-not $Principal) {
        Write-Host "Do you want to execute the ESC1 attack now? (y/N): " -NoNewline -ForegroundColor Yellow
        $response = Read-Host
        if ($response.Trim().ToLower() -eq 'y') {
            foreach ($result in $Results) {
                Invoke-ESC1Attack -TemplateObject $result.ESC1Issues[0].DirectoryEntry
            }
        }
    }
}
