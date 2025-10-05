function Find-ESC5Issue {
    <#
        .SYNOPSIS
        I        .EXAMPLE
        $AdcsObjects = Get-AdcsObjects
        $ESC5Issues = Find-ESC5Issue -AdcsObjects $AdcsObjects
        $ESC5Issues | Format-Table Name, IdentityReference, ActiveDirectoryRights

        .EXAMPLE
        $Issues = Find-ESC5Issue -AdcsObjects $AdcsObjects | Where-Object { $_.Name -eq "User" }

        .EXAMPLE
        # Filter for specific ESC5 subtypes
        $CertTemplateCreationIssues = Find-ESC5Issue -AdcsObjects $AdcsObjects | Where-Object { $_.Subtype -like "*CertTemplatesContainer*" }
        $EnrollmentServiceIssues = Find-ESC5Issue -AdcsObjects $AdcsObjects | Where-Object { $_.Subtype -like "*EnrollmentService*" }

        .EXAMPLE
        # Access the DirectoryEntry object for additional properties
        $ESC5Issues = Find-ESC5Issue -AdcsObjects $AdcsObjects Directory Certificate Services (AD CS) objects and containers vulnerable to ESC5 attacks by analyzing permissions on AD CS objects.

        .DESCRIPTION
        This function analyzes Active Directory Certificate Services (AD CS) objects to identify ESC5 vulnerabilities.
        ESC5 occurs when non-administrative principals have dangerous permissions (like GenericAll, WriteProperty, 
        WriteOwner, WriteDacl) on AD CS objects and containers.

        .PARAMETER AdcsObjects
        Array of AD CS objects from Get-AdcsObjects. The function will filter for AD CS objects and containers.

        .PARAMETER DangerousRights
        Array of dangerous Active Directory rights to check for. Defaults to common dangerous rights.

        .PARAMETER SafeOwners
        Regex pattern of SIDs for principals that are safe to own AD CS objects and containers.

        .PARAMETER SafeUsers
        Regex pattern of SIDs for principals that are considered safe and should be excluded from vulnerability findings.
        Defaults to common administrative and system account SIDs.

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
        - Subtype: Specific ESC5 subtype classification
        - ObjectType: GUID of the object type being granted permissions on (if applicable)
        - ExpandedFromGroup: Group this principal was expanded from (null for original issues)
        - ExpandedFromGroupSID: SID of the group this principal was expanded from (null for original issues)
        - MemberType: Type of expanded member (null for original issues)
        - Issue: Detailed description of the vulnerability
        - Technique: Always 'ESC5'
        - DirectoryEntry: The actual DirectoryEntry object for the AD CS object

        ESC5 Subtypes:
        - CertTemplatesContainer-GenericAll: GenericAll rights on Certificate Templates container
        - CertTemplatesContainer-GenericWrite: GenericWrite rights on Certificate Templates container
        - CertTemplatesContainer-CreateChild-AllObjects: CreateChild for All Objects on Certificate Templates container  
        - CertTemplatesContainer-CreateChild-PKICertTemplate: CreateChild for pKICertificateTemplate objects
        - CertTemplatesContainer-WriteDacl: WriteDacl on Certificate Templates container
        - CertTemplatesContainer-WriteOwner: WriteOwner on Certificate Templates container
        - CertTemplatesContainer-Owner: Principal owns the Certificate Templates container
        - EnrollmentService-GenericAll: GenericAll on pKIEnrollmentService objects
        - EnrollmentService-GenericWrite: GenericWrite on pKIEnrollmentService objects
        - EnrollmentService-WriteProperty-AllObjects: WriteProperty for All Objects on pKIEnrollmentService
        - EnrollmentService-WriteProperty-CertTemplatesAttr: WriteProperty on certificateTemplates attribute
        - EnrollmentService-WriteDacl: WriteDacl on pKIEnrollmentService objects
        - EnrollmentService-WriteOwner: WriteOwner on pKIEnrollmentService objects
        - EnrollmentService-Owner: Principal owns a pKIEnrollmentService object
        - General: Other dangerous permissions on AD CS objects
        - Object-Owner: Principal owns other AD CS objects

        .EXAMPLE
        $AdcsObjects = Get-AdcsObjects
        $ESC5Issues = Find-ESC5 -AdcsObjects $AdcsObjects
        $ESC5Issues | Format-Table Name, IdentityReference, ActiveDirectoryRights

        .EXAMPLE
        $Issues = Find-ESC5 -AdcsObjects $AdcsObjects | Where-Object { $_.Name -eq "User" }

        .EXAMPLE
        # Use expanded SafeUsers pattern to reduce false positives
        $ExpandedSafeUsers = Expand-SafeUsers -AdcsObjects $AdcsObjects
        $ESC5Issues = Find-ESC5Issue -AdcsObjects $AdcsObjects -SafeUsers $ExpandedSafeUsers
        $ESC5Issues | Format-Table Name, IdentityReference, ActiveDirectoryRights

        .EXAMPLE
        # Filter by specific ESC5 subtypes
        $CertTemplateCreationIssues = Find-ESC5 -AdcsObjects $AdcsObjects | Where-Object { $_.Subtype -like "*CertTemplatesContainer*" }
        $EnrollmentServiceIssues = Find-ESC5 -AdcsObjects $AdcsObjects | Where-Object { $_.Subtype -like "*EnrollmentService*" }

        .EXAMPLE
        # Access the DirectoryEntry object for additional properties
        $ESC5Issues = Find-ESC5 -AdcsObjects $AdcsObjects
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
        [string[]]$DangerousRights = @('GenericAll', 'GenericWrite', 'WriteProperty', 'WriteOwner', 'WriteDacl', 'CreateChild'),
        
        [Parameter()]
        [string]$SafeOwners = '-519$',
        
        [Parameter()]
        [string]$SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-521$|-498$|-9$|-526$|-527$|S-1-5-10',
        
        [Parameter()]
        [string[]]$SafeObjectTypes = @('0e10c968-78fb-11d2-90d4-00c04f79dc55', 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'),
        
        [Parameter()]
        [string]$PKICertificateTemplateGUID = 'e5209ca2-3bba-11d2-90cc-00c04fd91ab1',
        
        [Parameter()]
        [string]$CertificateTemplatesAttributeGUID = 'd15b0dec-d0a0-4e47-a0d7-1cf18d63f0d1'
    )

    #requires -Version 7.4 -Modules Microsoft.PowerShell.Security

    begin {
        # Load the ESCalatorIssue class
        . "$PSScriptRoot\ESCalatorIssue.ps1"
        
        Write-Verbose "Starting ESC5 object vulnerability scan"
        Write-Verbose "Dangerous Rights: $($DangerousRights -join ', ')"
        Write-Verbose "Safe Owners Pattern: $SafeOwners"
        Write-Verbose "Safe Users Pattern: $SafeUsers"
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
                        
                        # Check if owner is unsafe (not in SafeOwners and not in SafeUsers)
                        if ($ownerSID -notmatch $SafeOwners -and $ownerSID -notmatch $SafeUsers) {
                            Write-Verbose "Found dangerous owner: $($security.Owner)"
                            
                            # Determine specific owner subtype based on object type
                            $ownerSubtype = if ($ObjectName -eq "Certificate Templates") {
                                "CertTemplatesContainer-Owner"
                            } elseif ($Object.objectClass -contains 'pKIEnrollmentService') {
                                "EnrollmentService-Owner"
                            } else {
                                "Object-Owner"
                            }
                            
                            [ESCalatorIssue]::CreateOriginalIssue(
                                $forestName,                                    # Forest
                                $ObjectName,                                    # Name
                                $ObjectDN,                                      # DistinguishedName
                                $security.Owner,                                # IdentityReference
                                $ownerSID,                                      # IdentityReferenceSID
                                'Owner',                                        # ActiveDirectoryRights
                                'ESC5',                                         # Technique
                                $ownerSubtype,                                  # Subtype
                                "$($security.Owner) has Owner rights on this object and can modify it into a object that can create ESC1, ESC2, and ESC3 objects.", # Issue
                                'High',                                         # Severity
                                $null,                                          # ObjectType
                                $Object                                         # DirectoryEntry
                            )
                        } else {
                            Write-Verbose "Owner $($security.Owner) is considered safe, skipping"
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
                                -not $isSafeObjectType -and
                                ($aceSID -notmatch $SafeOwners) -and
                                ($aceSID -notmatch $SafeUsers)) {
                                
                                Write-Verbose "Found dangerous permission: $($ace.IdentityReference) has $($ace.ActiveDirectoryRights)"

                                # Determine ESC5 subtype and create detailed issue description
                                $subtype = "General"
                                $detailedIssue = "$($ace.IdentityReference) has been granted $($ace.ActiveDirectoryRights) rights on this object."
                                
                                # ESC5 Subtype 1: CreateChild on Certificate Templates container
                                if ($Object.Name.Value -eq "Certificate Templates" -and 
                                    ($ace.ActiveDirectoryRights -match 'CreateChild' -or $ace.ActiveDirectoryRights -match 'GenericAll' -or $ace.ActiveDirectoryRights -match 'GenericWrite')) {
                                    
                                    if ($ace.ActiveDirectoryRights -match 'GenericAll') {
                                        $subtype = "CertTemplatesContainer-GenericAll"
                                        $detailedIssue = "$($ace.IdentityReference) has GenericAll rights on the Certificate Templates container, allowing them to create new certificate templates."
                                    } elseif ($ace.ActiveDirectoryRights -match 'GenericWrite') {
                                        $subtype = "CertTemplatesContainer-GenericWrite"
                                        $detailedIssue = "$($ace.IdentityReference) has GenericWrite rights on the Certificate Templates container, allowing them to create new certificate templates."
                                    } elseif (-not $ace.ObjectType -or $ace.ObjectType.Guid -eq '00000000-0000-0000-0000-000000000000') {
                                        $subtype = "CertTemplatesContainer-CreateChild-AllObjects"  
                                        $detailedIssue = "$($ace.IdentityReference) has CreateChild rights for All Objects on the Certificate Templates container, allowing them to create new certificate templates."
                                    } elseif ($ace.ObjectType.Guid -eq $PKICertificateTemplateGUID) {
                                        $subtype = "CertTemplatesContainer-CreateChild-PKICertTemplate"
                                        $detailedIssue = "$($ace.IdentityReference) has CreateChild rights specifically for pKICertificateTemplate objects on the Certificate Templates container, allowing them to create new certificate templates."
                                    }
                                }
                                
                                # ESC5 Subtype 2: WriteProperty on certificateTemplates attribute of pKIEnrollmentService
                                elseif ($Object.objectClass -contains 'pKIEnrollmentService' -and 
                                        ($ace.ActiveDirectoryRights -match 'WriteProperty' -or $ace.ActiveDirectoryRights -match 'GenericAll' -or $ace.ActiveDirectoryRights -match 'GenericWrite')) {
                                    
                                    if ($ace.ActiveDirectoryRights -match 'GenericAll') {
                                        $subtype = "EnrollmentService-GenericAll"
                                        $detailedIssue = "$($ace.IdentityReference) has GenericAll rights on the pKIEnrollmentService object '$ObjectName', allowing them to modify the certificateTemplates attribute and control which templates are enabled."
                                    } elseif ($ace.ActiveDirectoryRights -match 'GenericWrite') {
                                        $subtype = "EnrollmentService-GenericWrite"
                                        $detailedIssue = "$($ace.IdentityReference) has GenericWrite rights on the pKIEnrollmentService object '$ObjectName', allowing them to modify the certificateTemplates attribute and control which templates are enabled."
                                    } elseif (-not $ace.ObjectType -or $ace.ObjectType.Guid -eq '00000000-0000-0000-0000-000000000000') {
                                        $subtype = "EnrollmentService-WriteProperty-AllObjects"
                                        $detailedIssue = "$($ace.IdentityReference) has WriteProperty rights for All Objects on the pKIEnrollmentService object '$ObjectName', allowing them to modify the certificateTemplates attribute and control which templates are enabled."
                                    } elseif ($ace.ObjectType.Guid -eq $CertificateTemplatesAttributeGUID) {
                                        $subtype = "EnrollmentService-WriteProperty-CertTemplatesAttr"
                                        $detailedIssue = "$($ace.IdentityReference) has WriteProperty rights specifically for the certificateTemplates attribute on the pKIEnrollmentService object '$ObjectName', allowing them to control which templates are enabled."
                                    }
                                }
                                
                                # ESC5 Subtype 3: WriteDacl on Certificate Templates container
                                elseif ($Object.Name.Value -eq "Certificate Templates" -and $ace.ActiveDirectoryRights -match 'WriteDacl') {
                                    $subtype = "CertTemplatesContainer-WriteDacl"
                                    $detailedIssue = "$($ace.IdentityReference) has WriteDacl rights on the Certificate Templates container, allowing them to modify permissions and potentially grant themselves CreateChild rights to create new certificate templates."
                                }
                                
                                # ESC5 Subtype 4: WriteDacl on pKIEnrollmentService
                                elseif ($Object.objectClass -contains 'pKIEnrollmentService' -and $ace.ActiveDirectoryRights -match 'WriteDacl') {
                                    $subtype = "EnrollmentService-WriteDacl"
                                    $detailedIssue = "$($ace.IdentityReference) has WriteDacl rights on the pKIEnrollmentService object '$ObjectName', allowing them to modify permissions and potentially grant themselves WriteProperty rights on the certificateTemplates attribute."
                                }
                                
                                # ESC5 Subtype 5: WriteOwner on Certificate Templates container
                                elseif ($Object.Name.Value -eq "Certificate Templates" -and $ace.ActiveDirectoryRights -match 'WriteOwner') {
                                    $subtype = "CertTemplatesContainer-WriteOwner"
                                    $detailedIssue = "$($ace.IdentityReference) has WriteOwner rights on the Certificate Templates container, allowing them to take ownership and then modify permissions to grant themselves CreateChild rights."
                                }
                                
                                # ESC5 Subtype 6: WriteOwner on pKIEnrollmentService
                                elseif ($Object.objectClass -contains 'pKIEnrollmentService' -and $ace.ActiveDirectoryRights -match 'WriteOwner') {
                                    $subtype = "EnrollmentService-WriteOwner"
                                    $detailedIssue = "$($ace.IdentityReference) has WriteOwner rights on the pKIEnrollmentService object '$ObjectName', allowing them to take ownership and then modify permissions to control which templates are enabled."
                                }
                                
                                # Determine ObjectType
                                $objectTypeGuid = if ($ace.ObjectType) { $ace.ObjectType.Guid } else { $null }

                                # Determine severity based on subtype
                                $severity = switch ($subtype) {
                                    'CertTemplatesContainer-GenericAll' { 'Critical' }
                                    'CertTemplatesContainer-CreateChild-AllObjects' { 'Critical' }
                                    'CertTemplatesContainer-CreateChild-PKICertTemplate' { 'Critical' }
                                    'EnrollmentService-GenericAll' { 'Critical' }
                                    'EnrollmentService-GenericWrite' { 'Critical' }
                                    'EnrollmentService-WriteProperty-AllObjects' { 'Critical' }
                                    'EnrollmentService-WriteProperty-CertTemplatesAttr' { 'Critical' }
                                    'CertTemplatesContainer-Owner' { 'High' }
                                    'EnrollmentService-Owner' { 'High' }
                                    'Object-Owner' { 'High' }
                                    'CertTemplatesContainer-WriteDacl' { 'High' }
                                    'EnrollmentService-WriteDacl' { 'High' }
                                    'CertTemplatesContainer-WriteOwner' { 'High' }
                                    'EnrollmentService-WriteOwner' { 'High' }
                                    'CertTemplatesContainer-GenericWrite' { 'Medium' }
                                    'General' { 'Low' }
                                    default { 'Medium' }
                                }

                                [ESCalatorIssue]::CreateOriginalIssue(
                                    $forestName,                            # Forest
                                    $ObjectName,                            # Name
                                    $ObjectDN,                              # DistinguishedName
                                    $ace.IdentityReference.Value,           # IdentityReference
                                    $aceSID,                                # IdentityReferenceSID
                                    $ace.ActiveDirectoryRights.ToString(), # ActiveDirectoryRights
                                    'ESC5',                                 # Technique
                                    $subtype,                               # Subtype
                                    $detailedIssue,                         # Issue
                                    $severity,                              # Severity
                                    $objectTypeGuid,                        # ObjectType
                                    $Object                                 # DirectoryEntry
                                )
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