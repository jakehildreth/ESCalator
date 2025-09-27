function Find-ESC4 {
    <#
        .SYNOPSIS
        Identifies Active Directory Certificate Services (AD CS) certificate templates vulnerable to ESC4 attacks by analyzing permissions on template objects.

        .DESCRIPTION
        This function analyzes Active Directory Certificate Services (ADCS) objects to identify ESC4 vulnerabilities.
        ESC4 occurs when non-administrative principals have dangerous permissions (like GenericAll, WriteProperty, 
        WriteOwner, WriteDacl) on certificate templates, allowing them to modify templates into ESC1/ESC2/ESC3 templates.

        .PARAMETER AdcsObjects
        Array of AD CS objects from Get-AdcsObjects. The function will filter for certificate templates.

        .PARAMETER DangerousRights
        Array of dangerous Active Directory rights to check for. Defaults to common dangerous rights.

        .PARAMETER SafeOwners
        Regex pattern of SIDs for principals that are safe to own certificate templates.

        .PARAMETER SafeObjectTypes
        Array of object type GUIDs that are safe when granted specific permissions (Enroll, AutoEnroll).

        .INPUTS
        System.DirectoryServices.DirectoryEntry[]

        .OUTPUTS
        PSCustomObject[]
        Returns objects describing ESC4 vulnerabilities found.

        .EXAMPLE
        $ADCSObjects = Get-AdcsObjects
        $ESC4Issues = Find-ESC4 -AdcsObjects $ADCSObjects
        $ESC4Issues | Format-Table Name, IdentityReference, ActiveDirectoryRights

        .EXAMPLE
        $Issues = Find-ESC4 -AdcsObjects $ADCSObjects | Where-Object { $_.Name -eq "User" }

        .LINK
        https://posts.specterops.io/certified-pre-owned-d95910965cd2
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [System.DirectoryServices.DirectoryEntry[]]$AdcsObjects,
        
        [Parameter()]
        [string[]]$DangerousRights = @('GenericAll', 'WriteProperty', 'WriteOwner', 'WriteDacl'),
        
        [Parameter()]
        [string]$SafeOwners = '-519$',
        
        [Parameter()]
        [string[]]$SafeObjectTypes = @('0e10c968-78fb-11d2-90d4-00c04f79dc55', 'a05b8cc2-17bc-4802-a710-e7c15ab866a2')
    )

    #requires -Version 5

    begin {
        Write-Verbose "Starting ESC4 template vulnerability scan"
        Write-Verbose "Dangerous Rights: $($DangerousRights -join ', ')"
        Write-Verbose "Safe Owners Pattern: $SafeOwners"
    }

    process {
        # Filter for certificate templates only
        $Templates = $AdcsObjects | Where-Object { $_.objectClass -contains 'pKICertificateTemplate' }
        
        Write-Verbose "Processing $($Templates.Count) certificate templates"

        foreach ($Template in $Templates) {
            $templateName = $Template.Name.Value
            $templateDN = $Template.distinguishedName.Value
            
            Write-Verbose "Analyzing template: $templateName"
            
            try {
                $security = $Template.ObjectSecurity
                
                # Extract forest name from DN
                $forestName = if ($templateDN) {
                    $parts = $templateDN -split ',DC='
                    if ($parts.Count -gt 1) { 
                        $parts[1..($parts.Count-1)] -join '.' 
                    } else { 
                        'Unknown' 
                    }
                } else { 
                    'Unknown' 
                }

                # Check owner for ESC4 vulnerability
                if ($security.Owner) {
                    Write-Verbose "Template owner: $($security.Owner)"
                    
                    # Convert owner to SID if needed
                    try {
                        if ($security.Owner -match '^S-1-') {
                            $ownerSID = $security.Owner
                        } else {
                            $ownerPrincipal = New-Object System.Security.Principal.NTAccount($security.Owner)
                            $ownerSID = $ownerPrincipal.Translate([System.Security.Principal.SecurityIdentifier]).Value
                        }
                        
                        # Check if owner is unsafe
                        if ($ownerSID -notmatch $SafeOwners) {
                            Write-Verbose "Found dangerous owner: $($security.Owner)"
                            
                            [PSCustomObject]@{
                                Forest                = $forestName
                                Name                  = $templateName
                                DistinguishedName     = $templateDN
                                IdentityReference     = $security.Owner
                                IdentityReferenceSID  = $ownerSID
                                ActiveDirectoryRights = 'Owner'
                                Issue                 = "$($security.Owner) has Owner rights on this template and can modify it into a template that can create ESC1, ESC2, and ESC3 templates."
                                Technique             = 'ESC4'
                            }
                        }
                    }
                    catch {
                        Write-Warning "Failed to process owner '$($security.Owner)' for template $templateName : $_"
                    }
                }

                # Check Access Control Entries for dangerous permissions
                if ($security.Access) {
                    foreach ($ace in $security.Access) {
                        try {
                            # Convert identity to SID if needed
                            if ($ace.IdentityReference -match '^S-1-') {
                                $aceSID = $ace.IdentityReference.Value
                            } else {
                                try {
                                    $acePrincipal = New-Object System.Security.Principal.NTAccount($ace.IdentityReference)
                                    $aceSID = $acePrincipal.Translate([System.Security.Principal.SecurityIdentifier]).Value
                                }
                                catch {
                                    Write-Verbose "Could not translate identity $($ace.IdentityReference) to SID, skipping"
                                    continue
                                }
                            }

                            # Check for dangerous conditions
                            $hasDangerousRights = $false
                            foreach ($right in $DangerousRights) {
                                if ($ace.ActiveDirectoryRights -match $right) {
                                    $hasDangerousRights = $true
                                    break
                                }
                            }
                            
                            # Check if this is a safe object type (like Enroll/AutoEnroll only)
                            $isSafeObjectType = $false
                            if ($ace.ObjectType -and $ace.ObjectType.Guid) {
                                $isSafeObjectType = $ace.ObjectType.Guid -in $SafeObjectTypes
                            }

                            if (($ace.AccessControlType -eq 'Allow') -and
                                $hasDangerousRights -and
                                -not $isSafeObjectType) {
                                
                                Write-Verbose "Found dangerous permission: $($ace.IdentityReference) has $($ace.ActiveDirectoryRights)"

                                [PSCustomObject]@{
                                    Forest                = $forestName
                                    Name                  = $templateName
                                    DistinguishedName     = $templateDN
                                    IdentityReference     = $ace.IdentityReference.Value
                                    IdentityReferenceSID  = $aceSID
                                    ActiveDirectoryRights = $ace.ActiveDirectoryRights.ToString()
                                    Issue                 = "$($ace.IdentityReference) has been granted $($ace.ActiveDirectoryRights) rights on this template."
                                    Technique             = 'ESC4'
                                }
                            }
                        }
                        catch {
                            Write-Warning "Failed to process ACE for identity $($ace.IdentityReference) on template $templateName : $_"
                        }
                    }
                }
            }
            catch {
                Write-Warning "Failed to analyze security for template $templateName : $_"
            }
        }
    }

    end {
        Write-Verbose "ESC4 template vulnerability scan completed"
    }
}
