function Set-EnabledTemplateStatus {
    <#
        .SYNOPSIS
        Sets the Enabled status attribute on certificate template DirectoryEntry objects.

        .DESCRIPTION
        This function takes DirectoryEntry objects and a list of enabled templates, then filters for 
        pKICertificateTemplate objects and adds an "Enabled" attribute to each template based on 
        whether it appears in the enabled templates list.

        .PARAMETER AdcsObjects
        DirectoryEntry objects representing AD CS infrastructure objects, typically obtained from Get-AdcsObjects.

        .PARAMETER EnabledTemplates
        Array of template objects with Template and CertificateAuthorities properties, typically obtained from Get-EnabledTemplate.

        .INPUTS
        System.DirectoryServices.DirectoryEntry[]
        PSCustomObject[]

        .OUTPUTS
        System.DirectoryServices.DirectoryEntry[] - Certificate template objects with Enabled and EnabledOn attributes added

        .EXAMPLE
        $AdcsObjects = Get-AdcsObjects
        $EnabledTemplates = Get-EnabledTemplate -AdcsObjects $AdcsObjects
        $TemplatesWithStatus = Set-EnabledTemplateStatus -AdcsObjects $AdcsObjects -EnabledTemplates $EnabledTemplates
        
        Sets the Enabled status and EnabledOn information on all certificate templates.

        .EXAMPLE
        $AdcsObjects = Get-AdcsObjects
        $EnabledTemplates = $AdcsObjects | Get-EnabledTemplate
        $TemplatesWithStatus = $AdcsObjects | Set-EnabledTemplateStatus -EnabledTemplates $EnabledTemplates
        
        Uses pipeline to process certificate templates and set their enabled status and CA information.

        .LINK
        https://docs.microsoft.com/en-us/windows/win32/adschema/c-pkicertificatetemplate
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.DirectoryServices.DirectoryEntry[]]$AdcsObjects,
        
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]$EnabledTemplates
    )


    begin {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Starting $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
        $ProcessedTemplates = @()
    }

    process {
        foreach ($AdcsObject in $AdcsObjects) {
            try {
                # Check if this is a pKICertificateTemplate object
                if ($AdcsObject.objectClass -contains 'pKICertificateTemplate') {
                    Write-Verbose "Processing certificate template: $($AdcsObject.Name)"
                    
                    # Get the template name - could be in Name or displayName property
                    $TemplateName = if ($AdcsObject.Name) { 
                        $AdcsObject.Name.ToString() 
                    } elseif ($AdcsObject.Properties['name']) { 
                        $AdcsObject.Properties['name'][0].ToString()
                    } elseif ($AdcsObject.Properties['displayName']) {
                        $AdcsObject.Properties['displayName'][0].ToString()
                    } else {
                        $AdcsObject.Properties['cn'][0].ToString()
                    }
                    
                    # Find the template object in the enabled templates list
                    $EnabledTemplateObject = $EnabledTemplates | Where-Object { $_.Template -eq $TemplateName }
                    $IsEnabled = $null -ne $EnabledTemplateObject
                    $EnabledOn = if ($EnabledTemplateObject) { 
                        $EnabledTemplateObject.CertificateAuthorities 
                    } else { 
                        "None" 
                    }
                    
                    Write-Verbose "Template '$TemplateName' enabled status: $IsEnabled"
                    if ($IsEnabled) {
                        Write-Verbose "Template '$TemplateName' enabled on: $($EnabledOn -join ', ')"
                    }
                    
                    # Add the Enabled and EnabledOn attributes to the DirectoryEntry object
                    try {
                        # Add as note properties to the object
                        Add-Member -InputObject $AdcsObject -MemberType NoteProperty -Name 'Enabled' -Value $IsEnabled -Force
                        Add-Member -InputObject $AdcsObject -MemberType NoteProperty -Name 'EnabledOn' -Value $EnabledOn -Force
                        Write-Verbose "Successfully added Enabled and EnabledOn attributes to template '$TemplateName'"
                    }
                    catch {
                        Write-Warning "Failed to add attributes to template '$TemplateName': $($_.Exception.Message)"
                    }
                    
                    $ProcessedTemplates += $AdcsObject
                }
            }
            catch {
                Write-Warning "Error processing AD CS object $($AdcsObject.Name): $($_.Exception.Message)"
            }
        }
    }

    end {
        Write-Verbose "Processed $($ProcessedTemplates.Count) certificate templates"
        return $ProcessedTemplates
    }
}
