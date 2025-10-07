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

    #requires -Version 7.4

    Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Starting $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."

    # Initialize result collections
    $esc4e1Results = @()
    $esc4p5ComboResults = @()
    $esc5p5ComboResults = @()

    try {
        # Run Find-ESC4e1
        Write-Verbose "Running Find-ESC4e1..."
        if ($Principal) {
            $esc4e1Results = Find-ESC4e1 -Issues $Issues -Principal $Principal
        } else {
            $esc4e1Results = Find-ESC4e1 -Issues $Issues 
        }
        Write-Verbose "Find-ESC4e1 found $($esc4e1Results.Count) results"

        # Run Find-ESC4p5Combo
        Write-Verbose "Running Find-ESC4p5Combo..."
        if ($Principal) {
            $esc4p5ComboResults = Find-ESC4p5Combo -Issues $Issues -Principal $Principal
        } else {
            $esc4p5ComboResults = Find-ESC4p5Combo -Issues $Issues
        }
        Write-Verbose "Find-ESC4p5Combo found $($esc4p5ComboResults.Count) results"

        # Run Find-ESC5p5Combo
        Write-Verbose "Running Find-ESC5p5Combo..."
        if ($Principal) {
            $esc5p5ComboResults = Find-ESC5p5Combo -Issues $Issues -Principal $Principal
        } else {
            $esc5p5ComboResults = Find-ESC5p5Combo -Issues $Issues
        }
        Write-Verbose "Find-ESC5p5Combo found $($esc5p5ComboResults.Count) results"

    } catch {
        Write-Error "Error occurred during ESC analysis: $($_.Exception.Message)"
        return
    }

    # Calculate totals
    $totalVulnerabilities = $esc4e1Results.Count + $esc4p5ComboResults.Count + $esc5p5ComboResults.Count

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
        Write-Host "  • ESC4e1: Critical ESC4 with enabled templates" -ForegroundColor Gray
        Write-Host "  • ESC4p5: ESC4 (disabled templates) + ESC5 (EnrollmentService) combinations" -ForegroundColor Gray
        Write-Host "  • ESC5p5: ESC5 CertTemplatesContainer + EnrollmentService combinations" -ForegroundColor Gray
        Write-Host ""
        Read-Host "Press Enter to continue"
        return
    }

    # Build attack description menu
    $attackDescriptions = @()

    if ($esc4e1Results.Count -gt 0) {
        $attackDescriptions += "ESC4e1: Immediate template modification attack - Can modify enabled certificate templates for instant privilege escalation"
    }

    if ($esc4p5ComboResults.Count -gt 0) {
        $attackDescriptions += "ESC4p5: Combined template control attack - Can enable disabled templates AND control enrollment services"
    }

    if ($esc5p5ComboResults.Count -gt 0) {
        $attackDescriptions += "ESC5p5: Full PKI infrastructure control - Can control both certificate template containers AND enrollment services"
    }

    Write-Host "Total Attack Vectors Found: $totalVulnerabilities" -ForegroundColor Red
    Write-Host ""

    do {
        # Display attack descriptions
        Write-Host "Available Attack Vectors:" -ForegroundColor Yellow
        Write-Host ""
        
        for ($i = 0; $i -lt $attackDescriptions.Count; $i++) {
            $optionNumber = $i + 1
            Write-Host "$optionNumber. $($attackDescriptions[$i])" -ForegroundColor White
        }
        
        Write-Host ""
        Write-Host "q. Quit" -ForegroundColor Red
        Write-Host ""

        # Get user choice
        Write-Host "`e[1mSelect an attack vector to explore`e[0m" -NoNewline
        Write-Host " (1-$($attackDescriptions.Count), q=quit): " -NoNewline
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
            if ($numericChoice -ge 1 -and $numericChoice -le $attackDescriptions.Count) {
                Write-Host ""
                # Show detailed information based on selection
                switch ($numericChoice) {
                    1 {
                        if ($esc4e1Results.Count -gt 0) {
                            Show-ESC4e1AttackDetails -Results $esc4e1Results
                        }
                    }
                    2 {
                        if ($esc4p5ComboResults.Count -gt 0) {
                            Show-ESC4p5AttackDetails -Results $esc4p5ComboResults
                        } elseif ($esc5p5ComboResults.Count -gt 0) {
                            Show-ESC5p5AttackDetails -Results $esc5p5ComboResults
                        }
                    }
                    3 {
                        if ($esc5p5ComboResults.Count -gt 0) {
                            Show-ESC5p5AttackDetails -Results $esc5p5ComboResults
                        }
                    }
                }
                Write-Host ""
                Read-Host "Press Enter to continue"
            } else {
                Write-Host "`e[38;5;196m[x] Invalid choice. Please enter a number between 1 and $($attackDescriptions.Count) or 'q' to quit.`e[0m" -ForegroundColor Red
                Write-Host ""
            }
        } else {
            Write-Host "`e[38;5;196m[x] Invalid input. Please enter a number (1-$($attackDescriptions.Count)) or 'q' to quit.`e[0m" -ForegroundColor Red
            Write-Host ""
        }

    } while ($choice -ne 'q')

    Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Finishing $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
}

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
    Write-Host "Attack Steps:" -ForegroundColor Yellow
    Write-Host "1. Modify the identified certificate template to match ESC1 requirements:`n  - Subject Alternative Name (SAN) allowed`n  - Client Authentication EKU`n  - No Manager Approval`n  - Enrollment Rights Assigned" -ForegroundColor Gray
    Write-Host "2. Request a certificate with a SAN of a privileged account" -ForegroundColor Gray
    Write-Host "3. Use the certificate to authenticate as the privileged account" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Risk Level: CRITICAL - Immediate exploitation possible" -ForegroundColor Red
}

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