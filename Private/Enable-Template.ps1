function Enable-Template {
    <#
        .SYNOPSIS
        Enables certificate templates for enrollment by adding them to Certificate Authority configurations.

        .DESCRIPTION
        This function takes one or more certificate template names and enables them for enrollment
        by adding their names to the certificateTemplates attribute on all Certificate Authorities
        in the current forest. This allows clients to request certificates based on these templates.

        The function uses DirectoryEntry objects to modify the CA configurations without requiring
        the ActiveDirectory PowerShell module.

        .PARAMETER Template
        One or more certificate template DirectoryEntry objects to enable for enrollment.
        These should be DirectoryEntry objects representing pKICertificateTemplate objects
        from Active Directory.

        .PARAMETER CertificateAuthority
        Optional. Specific Certificate Authority objects to modify. If not provided, the function
        will discover and modify all CAs in the current forest.

        .PARAMETER WhatIf
        Shows what changes would be made without actually performing them.

        .INPUTS
        System.DirectoryServices.DirectoryEntry[]
        Certificate template DirectoryEntry objects to enable.

        .OUTPUTS
        PSCustomObject[]
        Returns result objects indicating success/failure for each CA modification.

        .EXAMPLE
        $Templates = Get-AdcsObjects | Where-Object { $_.ObjectClass -eq 'pKICertificateTemplate' }
        $UserTemplate = $Templates | Where-Object { $_.Properties['name'].Value -eq 'User' }
        Enable-Template -Template $UserTemplate

        .EXAMPLE
        $Templates = Get-AdcsObjects | Where-Object { $_.ObjectClass -eq 'pKICertificateTemplate' }
        $Templates | Enable-Template -WhatIf

        .EXAMPLE
        $CAs = Get-AdcsObjects | Where-Object { $_.ObjectClass -eq 'pKIEnrollmentService' }
        $Template = Get-AdcsObjects | Where-Object { $_.Properties['name'].Value -eq 'WebServer' }
        Enable-Template -Template $Template -CertificateAuthority $CAs

        .LINK
        https://docs.microsoft.com/en-us/windows-server/networking/core-network-guide/cncg/server-certs/configure-the-server-certificate-template

        .NOTES
        Requires appropriate permissions to modify Certificate Authority objects in Active Directory.
        The function will skip templates that are already enabled on each CA.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNull()]
        [System.DirectoryServices.DirectoryEntry[]]$Template,
        
        [Parameter()]
        [System.DirectoryServices.DirectoryEntry[]]$CertificateAuthority,
        
        [Parameter()]
        [switch]$PassThru
    )


    begin {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Starting $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
        
        # Initialize results array
        $results = @()
        
        # If no specific CAs provided, discover all CAs in the forest
        if (-not $CertificateAuthority) {
            Write-Verbose "No specific CAs provided, discovering all CAs in forest..."
            
            try {
                # Get the current forest
                $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
                Write-Verbose "Forest: $($forest.Name)"
                
                # Search for Certificate Authorities (pKIEnrollmentService objects)
                $configContext = "CN=Configuration," + $forest.RootDomain.GetDirectoryEntry().Properties['distinguishedName'].Value
                $searcher = [System.DirectoryServices.DirectorySearcher]::new()
                $searcher.SearchRoot = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$configContext")
                $searcher.Filter = "(objectClass=pKIEnrollmentService)"
                $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
                
                $caResults = $searcher.FindAll()
                $CertificateAuthority = @()
                
                foreach ($result in $caResults) {
                    $CertificateAuthority += $result.GetDirectoryEntry()
                }
                
                Write-Verbose "Found $($CertificateAuthority.Count) Certificate Authorities"
                
                # Clean up
                $searcher.Dispose()
                $caResults.Dispose()
                
            } catch {
                Write-Error "Failed to discover Certificate Authorities: $($_.Exception.Message)"
                return
            }
        }
        
        if ($CertificateAuthority.Count -eq 0) {
            Write-Warning "No Certificate Authorities found or provided"
            return
        }
    }

    process {
        foreach ($templateObj in $Template) {
            # Validate that this is a certificate template
            if ($templateObj.SchemaClassName -ne 'pKICertificateTemplate') {
                Write-Warning "Object is not a certificate template (SchemaClassName: $($templateObj.SchemaClassName))"
                continue
            }
            
            # Get the template name for enrollment
            $templateName = $templateObj.Properties['name'].Value
            Write-Verbose "Processing template: $templateName"
            
            foreach ($ca in $CertificateAuthority) {
                try {
                    # Refresh the CA object to get current values
                    $ca.RefreshCache()
                    
                    $caName = $ca.Properties['name'].Value
                    $caDN = $ca.Properties['distinguishedName'].Value
                    
                    Write-Verbose "Processing CA: $caName"
                    Write-Verbose "CA DN: $caDN"
                    
                    # Get current certificate templates
                    $currentTemplates = @()
                    if ($ca.Properties['certificateTemplates'].Count -gt 0) {
                        $currentTemplates = @($ca.Properties['certificateTemplates'].Value)
                    }
                    
                    Write-Verbose "Current templates on $caName : $($currentTemplates -join ', ')"
                    
                    # Check if template is already enabled
                    if ($templateName -in $currentTemplates) {
                        Write-Verbose "Template '$templateName' is already enabled on CA '$caName'"
                        
                        $results += [PSCustomObject]@{
                            Success = $true
                            CertificateAuthority = $caName
                            CertificateAuthorityDN = $caDN
                            TemplateName = $templateName
                            TemplateDistinguishedName = $templateObj.Properties['distinguishedName'].Value
                            Action = "Already Enabled"
                            Error = $null
                        }
                        
                        continue
                    }
                    
                    # Add the template to the certificateTemplates attribute
                    if ($PSCmdlet.ShouldProcess("$caName", "Enable template '$templateName'")) {
                        # Add the new template to the list
                        $null = $ca.Properties['certificateTemplates'].Add($templateName)
                        
                        # Commit the changes
                        $ca.CommitChanges()
                        
                        Write-Verbose "Successfully enabled template '$templateName' on CA '$caName'"
                        
                        $results += [PSCustomObject]@{
                            Success = $true
                            CertificateAuthority = $caName
                            CertificateAuthorityDN = $caDN
                            TemplateName = $templateName
                            TemplateDistinguishedName = $templateObj.Properties['distinguishedName'].Value
                            Action = "Enabled"
                            Error = $null
                        }
                    } else {
                        # WhatIf scenario
                        $results += [PSCustomObject]@{
                            Success = $true
                            CertificateAuthority = $caName
                            CertificateAuthorityDN = $caDN
                            TemplateName = $templateName
                            TemplateDistinguishedName = $templateObj.Properties['distinguishedName'].Value
                            Action = "Would Enable"
                            Error = $null
                        }
                    }
                    
                } catch {
                    $errorMsg = "Failed to enable template '$templateName' on CA '$caName': $($_.Exception.Message)"
                    Write-Warning $errorMsg
                    
                    $results += [PSCustomObject]@{
                        Success = $false
                        CertificateAuthority = $caName
                        CertificateAuthorityDN = $caDN
                        TemplateName = $templateName
                        TemplateDistinguishedName = $templateObj.Properties['distinguishedName'].Value
                        Action = "Failed"
                        Error = $errorMsg
                    }
                }
            }
        }
    }

    end {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Finishing $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
        
        if ($PassThru -or $WhatIfPreference) {
            Write-Output $results
        }
        
        # Summary
        $successful = $results | Where-Object { $_.Success -and $_.Action -eq "Enabled" }
        $alreadyEnabled = $results | Where-Object { $_.Success -and $_.Action -eq "Already Enabled" }
        $failed = $results | Where-Object { -not $_.Success }
        
        Write-Verbose "Summary:"
        Write-Verbose "  Templates enabled: $($successful.Count)"
        Write-Verbose "  Templates already enabled: $($alreadyEnabled.Count)"
        Write-Verbose "  Failed operations: $($failed.Count)"
    }
}
