function Show-ESC2AttackDetails {
    <#
        .SYNOPSIS
        Shows an interactive menu for selecting and attacking ESC2 vulnerable templates.
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

    Write-Host "=== ESC2: Any Purpose EKU / No EKU (Enroll On Behalf Of) Attack ===" -ForegroundColor Red
    Write-Host ""
    Write-Host "Attack Description:" -ForegroundColor Yellow
    Write-Host "The principal can enroll in a template that has the Any Purpose EKU (or no EKU" -ForegroundColor White
    Write-Host "restriction). A certificate issued from such a template can act as a Certificate" -ForegroundColor White
    Write-Host "Request Agent, allowing the principal to Enroll On Behalf Of (EOBO) another user" -ForegroundColor White
    Write-Host "against an agent-protected template and impersonate them." -ForegroundColor White
    Write-Host ""

    # Collect all vulnerable templates from all results
    $allTemplates = @()
    foreach ($result in $Results) {
        if ($result.ESC2Issues -and $result.ESC2Issues.Count -gt 0) {
            foreach ($issue in $result.ESC2Issues) {
                $templateName = if ($issue.DirectoryEntry -and $issue.DirectoryEntry.Properties['name'].Value) {
                    $issue.DirectoryEntry.Properties['name'].Value
                } else {
                    "Unknown Template"
                }

                $allTemplates += [PSCustomObject]@{
                    TemplateName  = $templateName
                    PrincipalName = $result.PrincipalName
                    Issue         = $issue
                    Result        = $result
                }
            }
        }
    }

    # Group templates by name to remove duplicates. Wrap in @() so a single
    # group still yields an array (PS 5.1 unrolls single-element pipelines).
    $uniqueTemplates = @($allTemplates | Group-Object TemplateName | ForEach-Object {
        [PSCustomObject]@{
            TemplateName = $_.Name
            Issues       = $_.Group
            IssueCount   = $_.Count
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

        Write-Host "${esc}[1mSelect a template to analyze${esc}[0m" -NoNewline
        Write-Host " (1-$($uniqueTemplates.Count), q=quit): " -NoNewline
        $choice = Read-Host

        $choice = $choice.Trim().ToLower()

        if ($choice -eq 'q') {
            return
        }

        $numericChoice = 0
        if ([int]::TryParse($choice, [ref]$numericChoice)) {
            if ($numericChoice -ge 1 -and $numericChoice -le $uniqueTemplates.Count) {
                $selectedTemplate = $uniqueTemplates[$numericChoice - 1]

                Write-Host ""
                Show-ESC2TemplateDetails -Template $selectedTemplate -Principal $Principal
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

function Show-ESC2TemplateDetails {
    <#
        .SYNOPSIS
        Shows detailed information for a specific ESC2 template and offers attack execution.
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

    # Show template location
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

    Write-Host ""
    Write-Host "Attack Steps:" -ForegroundColor Yellow
    Write-Host "1. Enroll a certificate from this template (Any Purpose / no EKU) to act as a Certificate Request Agent" -ForegroundColor Gray
    Write-Host "2. Build a request for a target user and co-sign it with the agent certificate (EOBO)" -ForegroundColor Gray
    Write-Host "3. Submit for an agent-protected template, then authenticate as the target (PKINIT)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Risk Level: HIGH - Privilege escalation via Enroll On Behalf Of" -ForegroundColor Red

    # Offer attack execution for current user, targeting only the selected template
    if (-not $Principal) {
        Write-Host ""
        Write-Host "Do you want to execute the ESC2 (EOBO) attack using '$($Template.TemplateName)' now? (y/N): " -NoNewline -ForegroundColor Yellow
        $response = Read-Host
        if ($response.Trim().ToLower() -eq 'y') {
            Invoke-EOBOAttack -AgentTemplateObject $Template.Issues[0].Issue.DirectoryEntry
        }
    }
}
