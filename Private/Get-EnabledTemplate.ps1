function Get-EnabledTemplate {
    <#
        .SYNOPSIS
        Gets all certificate templates that are enabled for enrollment across Certificate Authorities.

        .DESCRIPTION
        This function reads the certificateTemplates attribute from all pKIEnrollmentService objects 
        (Certificate Authorities) in the provided DirectoryEntry objects and returns information about
        which templates are enabled on which Certificate Authorities.

        .PARAMETER AdcsObjects
        DirectoryEntry objects representing AD CS infrastructure objects, typically obtained from Get-AdcsObjects.

        .INPUTS
        System.DirectoryServices.DirectoryEntry[]

        .OUTPUTS
        PSCustomObject[] - Array of objects with Template name and CertificateAuthorities properties

        .EXAMPLE
        $AdcsObjects = Get-AdcsObjects
        $EnabledTemplates = Get-EnabledTemplate -AdcsObjects $AdcsObjects
        
        Gets all enabled certificate templates and the CAs they're enabled on.

        .EXAMPLE
        $AdcsObjects = Get-AdcsObjects
        $EnabledTemplates = Get-EnabledTemplate -AdcsObjects $AdcsObjects
        $EnabledTemplates | Where-Object { $_.Template -eq 'User' }
        
        Gets information about the 'User' template and which CAs it's enabled on.

        .LINK
        https://docs.microsoft.com/en-us/windows/win32/adschema/a-certificatetemplates
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.DirectoryServices.DirectoryEntry[]]$AdcsObjects
    )

    begin {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Starting $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
        $TemplateCAMapping = @{}
    }

    process {
        foreach ($AdcsObject in $AdcsObjects) {
            try {
                # Check if this is a pKIEnrollmentService object (Certificate Authority)
                if ($AdcsObject.objectClass -contains 'pKIEnrollmentService') {
                    $CAName = $AdcsObject.Name.ToString()
                    Write-Verbose "Processing pKIEnrollmentService: $CAName"
                    
                    # Get the certificateTemplates attribute
                    if ($AdcsObject.Properties['certificateTemplates']) {
                        $CertificateTemplates = $AdcsObject.Properties['certificateTemplates']
                        
                        foreach ($Template in $CertificateTemplates) {
                            if ($Template -and $Template -ne '') {
                                Write-Verbose "Found enabled template: $Template on CA: $CAName"
                                
                                # Build the mapping of templates to CAs
                                if (-not $TemplateCAMapping.ContainsKey($Template)) {
                                    $TemplateCAMapping[$Template] = @()
                                }
                                $TemplateCAMapping[$Template] += $CAName
                            }
                        }
                    } else {
                        Write-Verbose "No certificateTemplates attribute found for $CAName"
                    }
                }
            }
            catch {
                Write-Warning "Error processing AD CS object $($AdcsObject.Name): $($_.Exception.Message)"
            }
        }
    }

    end {
        # Create objects with template names and their associated CAs
        $EnabledTemplateObjects = @()
        
        foreach ($TemplateName in ($TemplateCAMapping.Keys | Sort-Object)) {
            $CertificateAuthorities = $TemplateCAMapping[$TemplateName] | Sort-Object -Unique
            
            $TemplateObject = [PSCustomObject]@{
                Template = $TemplateName
                CertificateAuthorities = $CertificateAuthorities
                CACount = $CertificateAuthorities.Count
            }
            
            $EnabledTemplateObjects += $TemplateObject
            Write-Verbose "Template '$TemplateName' enabled on $($CertificateAuthorities.Count) CA(s): $($CertificateAuthorities -join ', ')"
        }
        
        Write-Verbose "Found $($EnabledTemplateObjects.Count) unique enabled certificate templates across all CAs"
        return $EnabledTemplateObjects
    }
}


