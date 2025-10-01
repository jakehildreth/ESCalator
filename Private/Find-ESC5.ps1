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
        Returns objects describing ESC5 vulnerabilities found, including the DirectoryEntry object.

        Each output object contains:
        - Forest: Forest name where object was found
        - Name: AD CS object name
        - DistinguishedName: Object distinguished name
        - IdentityReference: Principal with dangerous permissions
        - IdentityReferenceSID: SID of the principal
        - ActiveDirectoryRights: Specific permissions granted
        - Issue: Detailed description of the vulnerability
        - Technique: Always 'ESC5'
        - Subtype: Specific ESC5 subtype classification
        - ObjectType: GUID of the object type being granted permissions on (if applicable)
        - DirectoryEntry: The actual DirectoryEntry object for the AD CS object

        ESC5 Subtypes:
        - CreateChild-CertTemplates-GenericAll: GenericAll on Certificate Templates container
        - CreateChild-CertTemplates-AllObjects: CreateChild for All Objects on Certificate Templates container  
        - CreateChild-CertTemplates-PKICertTemplate: CreateChild for pKICertificateTemplate objects
        - WriteProperty-EnrollmentService-GenericAll: GenericAll on pKIEnrollmentService objects
        - WriteProperty-EnrollmentService-AllObjects: WriteProperty for All Objects on pKIEnrollmentService
        - WriteProperty-EnrollmentService-CertTemplatesAttr: WriteProperty on certificateTemplates attribute
        - General: Other dangerous permissions on ADCS objects

        .EXAMPLE
        $ADCSObjects = Get-AdcsObjects
        $ESC5Issues = Find-ESC5 -AdcsObjects $ADCSObjects
        $ESC5Issues | Format-Table Name, IdentityReference, ActiveDirectoryRights

        .EXAMPLE
        $Issues = Find-ESC5 -AdcsObjects $ADCSObjects | Where-Object { $_.Name -eq "User" }

        .EXAMPLE
        # Filter by specific ESC5 subtypes
        $CertTemplateCreationIssues = Find-ESC5 -AdcsObjects $ADCSObjects | Where-Object { $_.Subtype -like "*CreateChild-CertTemplates*" }
        $EnrollmentServiceIssues = Find-ESC5 -AdcsObjects $ADCSObjects | Where-Object { $_.Subtype -like "*WriteProperty-EnrollmentService*" }

        .EXAMPLE
        # Access the DirectoryEntry object for additional properties
        $ESC5Issues = Find-ESC5 -AdcsObjects $ADCSObjects
        $ESC5Issues[0].DirectoryEntry.Properties
        
        # Use DirectoryEntry for further analysis
        $ESC5Issues | ForEach-Object {
            Write-Host "Object: $($_.Name) [Subtype: $($_.Subtype)]"
            Write-Host "  Object Class: $($_.DirectoryEntry.objectClass)"
            Write-Host "  Created: $($_.DirectoryEntry.whenCreated)"
        }

        .LINK
        https://posts.specterops.io/certified-pre-owned-d95910965cd2
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [System.DirectoryServices.DirectoryEntry[]]$AdcsObjects,
        
        [Parameter()]
        [string[]]$DangerousRights = @('GenericAll', 'WriteProperty', 'WriteOwner', 'WriteDacl', 'CreateChild'),
        
        [Parameter()]
        [string]$SafeOwners = '-519$',
        
        [Parameter()]
        [string[]]$SafeObjectTypes = @('0e10c968-78fb-11d2-90d4-00c04f79dc55', 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'),
        
        [Parameter()]
        [string]$PKICertificateTemplateGUID = 'e5209ca2-3bba-11d2-90cc-00c04fd91ab1',
        
        [Parameter()]
        [string]$CertificateTemplatesAttributeGUID = 'd15b0dec-d0a0-4e47-a0d7-1cf18d63f0d1'
    )

    #requires -Version 5 -Modules Microsoft.PowerShell.Security

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
                                DirectoryEntry        = $Object
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

                                # Determine ESC5 subtype and create detailed issue description
                                $subtype = "General"
                                $detailedIssue = "$($ace.IdentityReference) has been granted $($ace.ActiveDirectoryRights) rights on this object."
                                
                                # ESC5 Subtype 1: CreateChild on Certificate Templates container
                                if ($Object.Name.Value -eq "Certificate Templates" -and 
                                    ($ace.ActiveDirectoryRights -match 'CreateChild' -or $ace.ActiveDirectoryRights -match 'GenericAll')) {
                                    
                                    if ($ace.ActiveDirectoryRights -match 'GenericAll') {
                                        $subtype = "CreateChild-CertTemplates-GenericAll"
                                        $detailedIssue = "$($ace.IdentityReference) has GenericAll rights on the Certificate Templates container, allowing them to create new certificate templates."
                                    } elseif (-not $ace.ObjectType -or $ace.ObjectType.Guid -eq '00000000-0000-0000-0000-000000000000') {
                                        $subtype = "CreateChild-CertTemplates-AllObjects"  
                                        $detailedIssue = "$($ace.IdentityReference) has CreateChild rights for All Objects on the Certificate Templates container, allowing them to create new certificate templates."
                                    } elseif ($ace.ObjectType.Guid -eq $PKICertificateTemplateGUID) {
                                        $subtype = "CreateChild-CertTemplates-PKICertTemplate"
                                        $detailedIssue = "$($ace.IdentityReference) has CreateChild rights specifically for pKICertificateTemplate objects on the Certificate Templates container, allowing them to create new certificate templates."
                                    }
                                }
                                
                                # ESC5 Subtype 2: WriteProperty on certificateTemplates attribute of pKIEnrollmentService
                                elseif ($Object.objectClass -contains 'pKIEnrollmentService' -and 
                                        ($ace.ActiveDirectoryRights -match 'WriteProperty' -or $ace.ActiveDirectoryRights -match 'GenericAll')) {
                                    
                                    if ($ace.ActiveDirectoryRights -match 'GenericAll') {
                                        $subtype = "WriteProperty-EnrollmentService-GenericAll"
                                        $detailedIssue = "$($ace.IdentityReference) has GenericAll rights on the pKIEnrollmentService object '$ObjectName', allowing them to modify the certificateTemplates attribute and control which templates are published."
                                    } elseif (-not $ace.ObjectType -or $ace.ObjectType.Guid -eq '00000000-0000-0000-0000-000000000000') {
                                        $subtype = "WriteProperty-EnrollmentService-AllObjects"
                                        $detailedIssue = "$($ace.IdentityReference) has WriteProperty rights for All Objects on the pKIEnrollmentService object '$ObjectName', allowing them to modify the certificateTemplates attribute and control which templates are published."
                                    } elseif ($ace.ObjectType.Guid -eq $CertificateTemplatesAttributeGUID) {
                                        $subtype = "WriteProperty-EnrollmentService-CertTemplatesAttr"
                                        $detailedIssue = "$($ace.IdentityReference) has WriteProperty rights specifically for the certificateTemplates attribute on the pKIEnrollmentService object '$ObjectName', allowing them to control which templates are published."
                                    }
                                }

                                [PSCustomObject]@{
                                    Forest                = $forestName
                                    Name                  = $ObjectName
                                    DistinguishedName     = $ObjectDN
                                    IdentityReference     = $ace.IdentityReference.Value
                                    IdentityReferenceSID  = $aceSID
                                    ActiveDirectoryRights = $ace.ActiveDirectoryRights.ToString()
                                    Issue                 = $detailedIssue
                                    Technique             = 'ESC5'
                                    Subtype               = $subtype
                                    ObjectType            = if ($ace.ObjectType) { $ace.ObjectType.Guid } else { $null }
                                    DirectoryEntry        = $Object
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
