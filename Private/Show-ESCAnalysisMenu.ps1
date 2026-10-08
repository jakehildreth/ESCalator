function Show-ESCAnalysisMenu {
    <#
        .SYNOPSIS
        Displays ESC vulnerability analysis results in a simple menu format.

        .DESCRIPTION
        This function accepts ESCalator issue objects, runs Find-ESC4e1, Find-ESC4p5Combo, and Find-ESC5p5Combo
        analysis functions, and presents the results in a menu showing attack descriptions.

        .PARAMETER Issues
        Mandatory array of one or more ESCalatorIssue objects to analyze.

        .PARAMETER Principal
        Optional DirectoryEntry object representing a specific security principal to analyze.
        If not provided, analyzes for the current user.

        .INPUTS
        ESCalatorIssue[] - Array of ESCalatorIssue objects
        System.DirectoryServices.DirectoryEntry - Optional principal object

        .OUTPUTS
        None - Interactive menu display

        .EXAMPLE
        Show-ESCAnalysisMenu -Issues $AllIssues
        
        Analyzes all issues for the current user and displays results menu.

        .EXAMPLE
        Show-ESCAnalysisMenu -Issues $AllIssues -Principal $userPrincipal
        
        Analyzes all issues for a specific principal and displays results menu.

        .NOTES
        This function provides a simplified interface for ESC vulnerability analysis,
        focusing on attack descriptions rather than detailed technical information.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [object[]]$Issues,
        
        [Parameter()]
        [System.DirectoryServices.DirectoryEntry]$Principal
    )

    # PowerShell 5.1 has no `e escape; use the ESC character directly for ANSI sequences.
    $esc = [char]0x1b


    Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Starting $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."

    # Initialize result collections
    $esc1Results = @()
    $esc4e1Results = @()
    $esc4p5ComboResults = @()
    $esc5p5ComboResults = @()

    try {
        # Run Find-ESC1
        Write-Verbose "Running Find-ESC1..."
        if ($Principal) {
            $esc1Results = @(Find-ESC1 -Issues $Issues -Principal $Principal)
        } else {
            $esc1Results = @(Find-ESC1 -Issues $Issues)
        }
        Write-Verbose "Find-ESC1 found $($esc1Results.Count) results"

        # Run Find-ESC4e1
        Write-Verbose "Running Find-ESC4e1..."
        if ($Principal) {
            $esc4e1Results = @(Find-ESC4e1 -Issues $Issues -Principal $Principal)
        } else {
            $esc4e1Results = @(Find-ESC4e1 -Issues $Issues)
        }
        Write-Verbose "Find-ESC4e1 found $($esc4e1Results.Count) results"

        # Run Find-ESC4p5Combo
        Write-Verbose "Running Find-ESC4p5Combo..."
        if ($Principal) {
            $esc4p5ComboResults = @(Find-ESC4p5Combo -Issues $Issues -Principal $Principal)
        } else {
            $esc4p5ComboResults = @(Find-ESC4p5Combo -Issues $Issues)
        }
        Write-Verbose "Find-ESC4p5Combo found $($esc4p5ComboResults.Count) results"

        # Run Find-ESC5p5Combo
        Write-Verbose "Running Find-ESC5p5Combo..."
        if ($Principal) {
            $esc5p5ComboResults = @(Find-ESC5p5Combo -Issues $Issues -Principal $Principal)
        } else {
            $esc5p5ComboResults = @(Find-ESC5p5Combo -Issues $Issues)
        }
        Write-Verbose "Find-ESC5p5Combo found $($esc5p5ComboResults.Count) results"

    } catch {
        Write-Error "Error occurred during ESC analysis: $($_.Exception.Message)"
        return
    }

    # Calculate totals
    $totalVulnerabilities = $esc1Results.Count + $esc4e1Results.Count + $esc4p5ComboResults.Count + $esc5p5ComboResults.Count

    # Display analysis header
    Write-Host ""
    Write-Host "=== ESC Vulnerability Analysis Results ===" -ForegroundColor Cyan
    
    if ($Principal) {
        $principalName = $null
        if ($Principal.Properties['sAMAccountName'].Value) {
            $principalName = $Principal.Properties['sAMAccountName'].Value
        } elseif ($Principal.Properties['name'].Value) {
            $principalName = $Principal.Properties['name'].Value
        } else {
            $principalName = "Unknown Principal"
        }
        Write-Host "Principal: $principalName" -ForegroundColor White
    } else {
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        Write-Host "Principal: $($currentUser.Name) (Current User)" -ForegroundColor White
    }
    
    Write-Host "Analysis Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host ""

    # Check if any vulnerabilities were found
    if ($totalVulnerabilities -eq 0) {
        Write-Host "[+] No ESC vulnerabilities found for this principal!" -ForegroundColor Green
        Write-Host ""
        Write-Host "The analyzed principal does not have any of the following vulnerability combinations:" -ForegroundColor Gray
        Write-Host "  - ESC1: SAN Spoofing (enabled templates with enrollee-supplied subject)" -ForegroundColor Gray
        Write-Host "  - ESC4e1: ESC4 (enabled templates)" -ForegroundColor Gray
        Write-Host "  - ESC4p5: ESC4 (disabled templates) + ESC5 (pKIEnrollmentService certificateTemplates attribute) combinations" -ForegroundColor Gray
        Write-Host "  - ESC5p5: ESC5 (Certificate Templates container) + ESC5 (pKIEnrollmentService certificateTemplates attribute) combinations" -ForegroundColor Gray
        Write-Host ""
        Read-Host "Press Enter to continue"
        return
    }

    # Build attack menu dynamically: each entry has a label and an action key
    $attackMenu = @()

    if ($esc1Results.Count -gt 0) {
        $attackMenu += [PSCustomObject]@{
            Key = 'ESC1'
            Label = "ESC1: SAN spoofing attack`n  - Can request certificates with arbitrary Subject Alternative Names from enabled templates"
        }
    }

    if ($esc4e1Results.Count -gt 0) {
        $attackMenu += [PSCustomObject]@{
            Key = 'ESC4e1'
            Label = "ESC4e1: Immediate template modification attack`n  - Can modify one or more enabled certificate templates for instant privilege escalation"
        }
    }

    if ($esc4p5ComboResults.Count -gt 0) {
        $attackMenu += [PSCustomObject]@{
            Key = 'ESC4p5'
            Label = "ESC4p5: Combined template control attack`n  - Can modify one or more disabled certificate templates AND enable disabled templates"
        }
    }

    if ($esc5p5ComboResults.Count -gt 0) {
        $attackMenu += [PSCustomObject]@{
            Key = 'ESC5p5'
            Label = "ESC5p5: Full PKI infrastructure control`n  - Can create new certificate templates AND enabled disabled templates"
        }
    }

    do {
        # Display attack descriptions
        Write-Host "Available Attacks:" -ForegroundColor Yellow
        Write-Host ""

        for ($i = 0; $i -lt $attackMenu.Count; $i++) {
            $optionNumber = $i + 1
            Write-Host "$optionNumber. $($attackMenu[$i].Label)" -ForegroundColor White
        }

        Write-Host ""
        Write-Host "q. Quit" -ForegroundColor Red
        Write-Host ""

        # Get user choice
        Write-Host "${esc}[1mSelect an attack to explore${esc}[0m" -NoNewline
        Write-Host " (1-$($attackMenu.Count), q=quit): " -NoNewline
        $choice = Read-Host

        $choice = $choice.Trim().ToLower()

        if ($choice -eq 'q') {
            Write-Host ""
            Write-Host "Goodbye!" -ForegroundColor Green
            return
        }

        # Try to parse as integer
        $numericChoice = 0
        if ([int]::TryParse($choice, [ref]$numericChoice)) {
            if ($numericChoice -ge 1 -and $numericChoice -le $attackMenu.Count) {
                Write-Host ""
                $selectedAttack = $attackMenu[$numericChoice - 1].Key

                switch ($selectedAttack) {
                    'ESC1' {
                        Show-ESC1AttackDetails -Results $esc1Results -Principal $Principal
                    }
                    'ESC4e1' {
                        Show-ESC4e1AttackDetails -Results $esc4e1Results -Principal $Principal
                    }
                    'ESC4p5' {
                        Show-ESC4p5AttackDetails -Results $esc4p5ComboResults
                        Invoke-InteractiveAttack -AttackType "ESC4p5" -AttackResult $esc4p5ComboResults[0] -Principal $Principal
                    }
                    'ESC5p5' {
                        Show-ESC5p5AttackDetails -Results $esc5p5ComboResults
                        Invoke-InteractiveAttack -AttackType "ESC5p5" -AttackResult $esc5p5ComboResults[0] -Principal $Principal
                    }
                }
                Write-Host ""
                Read-Host "Press Enter to continue"
            } else {
                Write-Host "${esc}[38;5;196m[x] Invalid choice. Please enter a number between 1 and $($attackMenu.Count) or 'q' to quit.${esc}[0m" -ForegroundColor Red
                Write-Host ""
            }
        } else {
            Write-Host "${esc}[38;5;196m[x] Invalid input. Please enter a number (1-$($attackMenu.Count)) or 'q' to quit.${esc}[0m" -ForegroundColor Red
            Write-Host ""
        }

    } while ($choice -ne 'q')

    Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Finishing $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
}