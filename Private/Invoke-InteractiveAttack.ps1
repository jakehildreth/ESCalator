function Invoke-InteractiveAttack {
    <#
        .SYNOPSIS
        Provides interactive attack execution for ESC vulnerabilities with current user confirmation.

        .DESCRIPTION
        This helper function consolidates the common attack execution logic for ESC4e1, ESC4p5, 
        and ESC5p5 attacks. It handles user prompting, attack invocation, result processing, 
        and formatted output display.

        .PARAMETER AttackType
        The type of attack being executed (ESC4e1, ESC4p5, or ESC5p5).

        .PARAMETER AttackResult
        The vulnerability result object to pass to the attack function.

        .PARAMETER Principal
        The principal being analyzed. If null, indicates current user analysis.

        .EXAMPLE
        Invoke-InteractiveAttack -AttackType "ESC4e1" -AttackResult $esc4e1Results[0] -Principal $null

        .EXAMPLE  
        Invoke-InteractiveAttack -AttackType "ESC4p5" -AttackResult $esc4p5ComboResults[0] -Principal $null
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("ESC4e1", "ESC4p5", "ESC5p5")]
        [string]$AttackType,

        [Parameter(Mandatory = $true)]
        [object]$AttackResult,

        [Parameter(Mandatory = $false)]
        [object]$Principal
    )

    Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Starting $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."

    # Only offer attack execution for current user analysis
    if ($Principal) {
        Write-Verbose "Principal specified - skipping interactive attack for non-current user analysis"
        return
    }

    Write-Host ""
    Write-Host "=== Attack Execution ===" -ForegroundColor Red
    Write-Host ""
    Write-Host "This $AttackType vulnerability can be exploited immediately since you have the required permissions." -ForegroundColor Yellow
    Write-Host ""
    $executeChoice = Read-Host "Do you want to execute the $AttackType attack now? (y/N)"
    
    if ($executeChoice -notmatch '^y|yes$') {
        Write-Host ""
        Write-Host "[*] Attack execution cancelled by user." -ForegroundColor Yellow
        return
    }

    Write-Host ""
    
    try {
        # Execute the appropriate attack function based on attack type
        $result = switch ($AttackType) {
            "ESC4e1" { 
                Invoke-ESC4e1Attack -ESC4e1Result $AttackResult 
            }
            "ESC4p5" { 
                Invoke-ESC4p5Attack -ESC4p5Result $AttackResult 
            }
            "ESC5p5" { 
                Invoke-ESC5p5Attack -ESC5p5Result $AttackResult 
            }
        }
        
        if ($result -and $result.Success) {
            Write-Host "[+] $AttackType attack completed successfully!" -ForegroundColor Green
            Write-Host ""
            Write-Host "Attack Summary:" -ForegroundColor Cyan
            
            # Display attack-specific result information
            switch ($AttackType) {
                "ESC4e1" {
                    Write-Host "- Template Modified: $($result.TemplateName)" -ForegroundColor White
                    Write-Host "- Certificate Requested: $($result.CertificateRequested)" -ForegroundColor White
                }
                "ESC4p5" {
                    Write-Host "- Template Modified: $($result.TemplateName)" -ForegroundColor White
                    Write-Host "- Template Enabled: $($result.TemplateEnabled)" -ForegroundColor White
                    Write-Host "- Certificate Requested: $($result.CertificateRequested)" -ForegroundColor White
                }
                "ESC5p5" {
                    Write-Host "- Template Created: $($result.TemplateName)" -ForegroundColor White
                    Write-Host "- Template Configured: $($result.TemplateConfigured)" -ForegroundColor White
                    Write-Host "- Template Enabled: $($result.TemplateEnabled)" -ForegroundColor White
                    Write-Host "- Certificate Requested: $($result.CertificateRequested)" -ForegroundColor White
                }
            }
            
            # Common result information
            if ($result.KirbiFile) {
                Write-Host "- Ticket Generated: $($result.KirbiFile)" -ForegroundColor White
            }
        } else {
            if ($result.Error) {
                Write-Host "Error: $($result.Error)" -ForegroundColor Red
            }
        }
    } catch {
        Write-Host "[-] $AttackType attack failed with exception: $($_.Exception.Message)" -ForegroundColor Red
    }

    Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Finishing $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
}