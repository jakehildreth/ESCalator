function Show-ESC4e1AttackDetails {
    <#
        .SYNOPSIS
        Shows an interactive menu for selecting and attacking ESC4e1 vulnerable templates.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [array]$Results,
        
        [Parameter()]
        [object]$Principal
    )

    # PowerShell 5.1 has no `e escape; use the ESC character directly for ANSI sequences.
    $esc = [char]0x1b

    Write-Host "=== ESC4e1: Immediate Template Modification Attack ===" -ForegroundColor Red
    Write-Host ""
    Write-Host "Attack Description:" -ForegroundColor Yellow
    Write-Host "The principal can immediately modify certificate templates that are enabled on Certificate Authorities." -ForegroundColor White
    Write-Host "This allows for instant privilege escalation by changing template properties to make them vulnerable." -ForegroundColor White
    Write-Host ""
    
    # Collect all vulnerable templates from all results
    $allTemplates = @()
    foreach ($result in $Results) {
        if ($result.ESC4e1Issues -and $result.ESC4e1Issues.Count -gt 0) {
            foreach ($issue in $result.ESC4e1Issues) {
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
    
    # Group templates by name to remove duplicates
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
    
    do {
        Write-Host "Available Vulnerable Templates:" -ForegroundColor Yellow
        Write-Host ""
        
        for ($i = 0; $i -lt $uniqueTemplates.Count; $i++) {
            $template = $uniqueTemplates[$i]
            $optionNumber = $i + 1
            Write-Host "$optionNumber. $($template.TemplateName) ($($template.IssueCount) issue(s))" -ForegroundColor White
        }
        
        Write-Host ""
        Write-Host "q. Back to main menu" -ForegroundColor Red
        Write-Host ""

        # Get user choice
        Write-Host "${esc}[1mSelect a template to analyze${esc}[0m" -NoNewline
        Write-Host " (1-$($uniqueTemplates.Count), q=quit): " -NoNewline
        $choice = Read-Host

        $choice = $choice.Trim().ToLower()

        if ($choice -eq 'q') {
            return
        }

        # Try to parse as integer
        $numericChoice = 0
        if ([int]::TryParse($choice, [ref]$numericChoice)) {
            if ($numericChoice -ge 1 -and $numericChoice -le $uniqueTemplates.Count) {
                $selectedTemplate = $uniqueTemplates[$numericChoice - 1]
                
                Write-Host ""
                Show-TemplateDetails -Template $selectedTemplate -Principal $Principal
                Write-Host ""
                Read-Host "Press Enter to continue"
            } else {
                Write-Host "${esc}[38;5;196m[x] Invalid choice. Please enter a number between 1 and $($uniqueTemplates.Count) or 'q' to quit.${esc}[0m" -ForegroundColor Red
                Write-Host ""
            }
        } else {
            Write-Host "${esc}[38;5;196m[x] Invalid input. Please enter a number (1-$($uniqueTemplates.Count)) or 'q' to quit.${esc}[0m" -ForegroundColor Red
            Write-Host ""
        }

    } while ($choice -ne 'q')
}

function Show-TemplateDetails {
    <#
        .SYNOPSIS
        Shows detailed information for a specific template and offers attack execution.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$Template,
        
        [Parameter()]
        [object]$Principal
    )
    
    Write-Host "=== Template Details: $($Template.TemplateName) ===" -ForegroundColor Cyan
    Write-Host ""
    
    # Show template information
    $firstIssue = $Template.Issues[0].Issue
    if ($firstIssue.DirectoryEntry -and $firstIssue.DirectoryEntry.Properties['distinguishedName'].Value) {
        $dn = $firstIssue.DirectoryEntry.Properties['distinguishedName'].Value
        Write-Host "Location: $dn" -ForegroundColor Gray
    }
    
    # Show rights and subtypes
    $uniqueRights = $Template.Issues | ForEach-Object { $_.Issue.ActiveDirectoryRights } | Sort-Object -Unique
    $uniqueSubtypes = $Template.Issues | ForEach-Object { $_.Issue.Subtype } | Sort-Object -Unique
    
    Write-Host "Rights: $($uniqueRights -join ', ')" -ForegroundColor Yellow
    Write-Host "Subtypes: $($uniqueSubtypes -join ', ')" -ForegroundColor Yellow
    
    # Show which CAs have this template enabled
    $enabledCAs = $Template.Issues | ForEach-Object { 
        if ($_.Issue.Issue -match "enabled on CA '([^']+)'") {
            $matches[1]
        }
    } | Sort-Object -Unique
    
    if ($enabledCAs) {
        Write-Host "Enabled on CAs: $($enabledCAs -join ', ')" -ForegroundColor Green
    }
    
    Write-Host ""
    Write-Host "Attack Steps:" -ForegroundColor Yellow
    Write-Host "1. Modify the certificate template to match ESC1 requirements:" -ForegroundColor Gray
    Write-Host "   - Subject Alternative Name (SAN) allowed" -ForegroundColor Gray
    Write-Host "   - Client Authentication EKU" -ForegroundColor Gray
    Write-Host "   - No Manager Approval" -ForegroundColor Gray
    Write-Host "   - Enrollment Rights Assigned" -ForegroundColor Gray
    Write-Host "2. Request a certificate with a SAN of a privileged account" -ForegroundColor Gray
    Write-Host "3. Use the certificate to authenticate as the privileged account" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Risk Level: CRITICAL - Immediate exploitation possible" -ForegroundColor Red
    
    # Offer attack execution for current user
    if (-not $Principal) {
        # Build a result scoped to ONLY the selected template so the attack
        # converts/enrolls just this one, not every vulnerable template.
        $sourceResult = $Template.Issues[0].Result
        $selectedIssues = @($Template.Issues | ForEach-Object { $_.Issue })
        $templateResult = [PSCustomObject]@{
            PSTypeName          = 'ESC4e1_Result'
            PrincipalSID        = $sourceResult.PrincipalSID
            PrincipalName       = $sourceResult.PrincipalName
            ESC4e1Count         = $selectedIssues.Count
            ESC4e1Issues        = $selectedIssues
            VulnerableTemplates = @($Template.TemplateName)
        }
        Invoke-InteractiveAttack -AttackType "ESC4e1" -AttackResult $templateResult -Principal $Principal
    }
}