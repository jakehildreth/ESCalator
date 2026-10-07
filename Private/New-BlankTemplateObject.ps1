function New-BlankTemplateObject {
    <#
        .SYNOPSIS
        Creates a new blank certificate template object in Active Directory.

        .DESCRIPTION
        This function creates a new blank certificate template object by adding a new pKICertificateTemplate
        object to the Certificate Templates container in the Active Directory Configuration partition.
        The template is created with minimal properties and must be further configured before use.

        This function uses System.DirectoryServices to directly interact with Active Directory without
        requiring additional PowerShell modules. It automatically discovers the Configuration partition
        and creates templates in the standard Certificate Templates container.

        .PARAMETER TemplateName
        The name(s) of the certificate template(s) to create. Must be valid LDAP common names.
        Multiple template names can be provided via pipeline input.

        .PARAMETER Server
        Optional. The domain controller to use for the operation. If not specified, the function
        will use the default domain controller for the current domain.

        .INPUTS
        System.String[]
        Template names can be provided via pipeline input.

        .OUTPUTS
        System.DirectoryServices.DirectoryEntry[]
        Returns the newly created certificate template DirectoryEntry objects.

        .EXAMPLE
        New-BlankTemplateObject -TemplateName "MyCustomTemplate"
        Creates a single blank certificate template named "MyCustomTemplate".

        .EXAMPLE
        "Template1", "Template2", "Template3" | New-BlankTemplateObject
        Creates multiple blank certificate templates using pipeline input.

        .EXAMPLE
        New-BlankTemplateObject -TemplateName "TestTemplate" -Server "dc01.contoso.com"
        Creates a blank template using a specific domain controller.

        .LINK
        https://docs.microsoft.com/en-us/windows/win32/adschema/c-pkicertificatetemplate

        .NOTES
        Requires permissions to create objects in the Certificate Templates container.
        The created templates will be blank and require additional configuration before use.
        
        WARNING: This function creates skeleton template objects that are not immediately usable.
        Additional properties must be configured before enabling templates for enrollment.
    #>
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$TemplateName,
        
        [Parameter()]
        [string]$Server
    )


    begin {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Starting $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
        
        # Load System.DirectoryServices assembly
        try {
            Add-Type -AssemblyName System.DirectoryServices
            Write-Verbose "System.DirectoryServices assembly loaded successfully"
        } catch {
            Write-Error "Failed to load System.DirectoryServices assembly: $($_.Exception.Message)"
            return
        }

        # Get the Configuration partition automatically via RootDSE
        try {
            if ($Server) {
                $rootDSE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Server/RootDSE")
                Write-Verbose "Connected to domain controller: $Server"
            } else {
                $rootDSE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
                Write-Verbose "Connected to default domain controller"
            }
            
            $configurationPartition = $rootDSE.configurationNamingContext
            Write-Verbose "Configuration Naming Context: $configurationPartition"
            
            $templatesContainer = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configurationPartition"
            Write-Verbose "Templates Container: $templatesContainer"
            
            if ($Server) {
                $templatePath = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Server/$templatesContainer")
            } else {
                $templatePath = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$templatesContainer")
            }
            
            Write-Verbose "Successfully connected to Certificate Templates container"
        } catch {
            Write-Error "Failed to connect to Active Directory or locate Certificate Templates container: $($_.Exception.Message)"
            return
        }
    }

    process {
        foreach ($name in $TemplateName) {
            Write-Verbose "Creating certificate template: $name"
            
            $success = $false
            $currentName = $name
            $createdTemplate = $null
            
            while (-not $success) {
                try {
                    # Validate template name format
                    if ([string]::IsNullOrWhiteSpace($currentName)) {
                        throw "Template name cannot be null, empty, or whitespace"
                    }
                    
                    # Check if template already exists
                    try {
                        $existingTemplate = $templatePath.Children.Find("CN=$currentName", "pKICertificateTemplate")
                        if ($existingTemplate) {
                            throw "A certificate template named '$currentName' already exists"
                        }
                    } catch [System.DirectoryServices.DirectoryServicesCOMException] {
                        # Template doesn't exist - this is expected, continue with creation
                        Write-Verbose "Confirmed template '$currentName' does not exist"
                    }
                    
                    # Create the new template object
                    Write-Verbose "Adding new pKICertificateTemplate object: CN=$currentName"
                    $newTemplate = $templatePath.Children.Add("CN=$currentName", "pKICertificateTemplate")
                    
                    # Commit the changes to Active Directory
                    Write-Verbose "Committing template '$currentName' to Active Directory"
                    $newTemplate.CommitChanges()
                    
                    # Refresh the object to get updated properties
                    $newTemplate.RefreshCache()
                    
                    $createdTemplate = $newTemplate
                    $success = $true
                    
                    Write-Verbose "Successfully created certificate template: $currentName"
                    
                } catch [System.DirectoryServices.DirectoryServicesCOMException] {
                    $comError = $_.Exception
                    Write-Error "Failed to create template '$currentName': $($comError.Message) (HRESULT: 0x$($comError.ErrorCode.ToString('X8')))"
                    
                    # If running interactively, prompt for a new name
                    if ($Host.UI.RawUI.KeyAvailable -or $env:TERM_PROGRAM -eq "vscode") {
                        Write-Warning "Template name '$currentName' is invalid or already exists. Please enter a new name."
                        do {
                            $currentName = Read-Host -Prompt "New Template Name"
                        } while ([string]::IsNullOrWhiteSpace($currentName))
                    } else {
                        # Non-interactive mode - skip this template
                        Write-Error "Cannot create template '$currentName' in non-interactive mode. Skipping."
                        break
                    }
                    
                } catch {
                    Write-Error "Unexpected error creating template '$currentName': $($_.Exception.Message)"
                    break
                }
            }
            
            # Output the created template if successful
            if ($createdTemplate) {
                Write-Output $createdTemplate
            }
        }
    }

    end {
        # Clean up DirectoryEntry objects
        if ($templatePath) {
            $templatePath.Dispose()
            Write-Verbose "Disposed of templatePath DirectoryEntry object"
        }
        if ($rootDSE) {
            $rootDSE.Dispose()
            Write-Verbose "Disposed of rootDSE DirectoryEntry object"
        }
        
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Finishing $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
    }
}