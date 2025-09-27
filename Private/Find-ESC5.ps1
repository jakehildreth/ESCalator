function Find-ESC5 {
    <#
        .SYNOPSIS
        Identifies Active Directory Certificate Services (AD CS) objects and containers vulnerable to ESC5 attacks by analyzing permissions on AD CS objects.

        .DESCRIPTION
        This function analyzes Active Directory Certificate Services (ADCS) objects to identify ESC5 vulnerabilities.
        ESC5 occurs when non-administrative principals have dangerous permissions (like GenericAll, WriteProperty, 
        WriteOwner, WriteDacl) on AD CS objects and containers.

        .PARAMETER AdcsObjects
        Array of ADCS objects from Get-AdcsObjects. The function will filter for AD CS objects and containers.

        .PARAMETER DangerousRights
        Array of dangerous Active Directory rights to check for. Defaults to common dangerous rights.

        .PARAMETER SafeOwners
        Regex pattern of SIDs for principals that are safe to own AD CS objects and containers.

        .PARAMETER SafeObjectTypes
        Array of object type GUIDs that are safe when granted specific permissions (Enroll, AutoEnroll).

        .INPUTS
        System.DirectoryServices.DirectoryEntry[]

        .OUTPUTS
        PSCustomObject[]
        Returns objects describing ESC5 vulnerabilities found.

        .EXAMPLE
        $ADCSObjects = Get-AdcsObjects
        $ESC5Issues = Find-ESC5 -AdcsObjects $ADCSObjects
        $ESC5Issues | Format-Table Name, IdentityReference, ActiveDirectoryRights

        .EXAMPLE
        $Issues = Find-ESC5 -AdcsObjects $ADCSObjects | Where-Object { $_.Name -eq "User" }

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
        Write-Verbose "Starting ESC5 object vulnerability scan"
        Write-Verbose "Dangerous Rights: $($DangerousRights -join ', ')"
        Write-Verbose "Safe Owners Pattern: $SafeOwners"
    }

    process {
        # Filter out certificate objects
        $Objects = $AdcsObjects | Where-Object { $_.objectClass -notcontains 'pKICertificateTemplate' }
        
        Write-Verbose "Processing $($Objects.Count) AD CS objects and containers"

        foreach ($Object in $Objects) {
            $ObjectName = $Object.Name.Value
            $ObjectDN = $Object.distinguishedName.Value
            
            Write-Verbose "Analyzing object: $ObjectName"
            
            try {
                $security = $Object.ObjectSecurity
                
                # Extract forest name from DN
                $forestName = if ($ObjectDN) {
                    $parts = $ObjectDN -split ',DC='
                    if ($parts.Count -gt 1) { 
                        $parts[1..($parts.Count - 1)] -join '.' 
                    } else { 
                        'Unknown' 
                    }
                } else { 
                    'Unknown' 
                }

                # Check owner for ESC5 vulnerability
                if ($security.Owner) {
                    Write-Verbose "Object owner: $($security.Owner)"
                    
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
                                Name                  = $ObjectName
                                DistinguishedName     = $ObjectDN
                                IdentityReference     = $security.Owner
                                IdentityReferenceSID  = $ownerSID
                                ActiveDirectoryRights = 'Owner'
                                Issue                 = "$($security.Owner) has Owner rights on this object and can modify it into a object that can create ESC1, ESC2, and ESC3 objects."
                                Technique             = 'ESC5'
                            }
                        }
                    } catch {
                        Write-Warning "Failed to process owner '$($security.Owner)' for object $ObjectName : $_"
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
                                } catch {
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
                                    Name                  = $ObjectName
                                    DistinguishedName     = $ObjectDN
                                    IdentityReference     = $ace.IdentityReference.Value
                                    IdentityReferenceSID  = $aceSID
                                    ActiveDirectoryRights = $ace.ActiveDirectoryRights.ToString()
                                    Issue                 = "$($ace.IdentityReference) has been granted $($ace.ActiveDirectoryRights) rights on this object."
                                    Technique             = 'ESC5'
                                }
                            }
                        } catch {
                            Write-Warning "Failed to process ACE for identity $($ace.IdentityReference) on object $ObjectName : $_"
                        }
                    }
                }
            } catch {
                Write-Warning "Failed to analyze security for object $ObjectName : $_"
            }
        }
    }

    end {
        Write-Verbose "ESC5 object vulnerability scan completed"
    }
}
