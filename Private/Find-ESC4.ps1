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
        Returns objects describing ESC4 vulnerabilities found, including the DirectoryEntry object.

        Each output object contains:
        - Forest: Forest name where template was found
        - Name: Certificate template name
        - DistinguishedName: Template distinguished name
        - IdentityReference: Principal with dangerous permissions
        - IdentityReferenceSID: SID of the principal
        - ActiveDirectoryRights: Specific permissions granted
        - Subtype: Specific ESC4 vulnerability subtype
        - ObjectType: GUID of the object type being granted permissions on
        - ExpandedFromGroup: Group this principal was expanded from (null for original issues)
        - ExpandedFromGroupSID: SID of the group this principal was expanded from (null for original issues)
        - MemberType: Type of expanded member (null for original issues)
        - Issue: Description of the vulnerability
        - Technique: Always 'ESC4'
        - DirectoryEntry: The actual DirectoryEntry object for the template

        ESC4 Subtypes:
        - Owner-Template: Principal owns the certificate template
        - GenericAll-Template: GenericAll rights on certificate template
        - GenericWrite-Template: GenericWrite rights on certificate template
        - WriteProperty-Template-AllObjects: WriteProperty for All Objects on template
        - WriteProperty-Template-PKIExtendedKeyUsage: WriteProperty on pkiExtendedKeyUsage attribute
        - WriteProperty-Template-CertNameFlag: WriteProperty on msPKI-Certificate-Name-Flag attribute
        - WriteProperty-Template-EnrollmentFlag: WriteProperty on msPKI-Enrollment-Flag attribute
        - WriteProperty-Template-RASignature: WriteProperty on msPKI-RA-Signature attribute
        - WriteOwner-Template: WriteOwner rights on certificate template
        - WriteDacl-Template: WriteDacl rights on certificate template

        .EXAMPLE
        $ADCSObjects = Get-AdcsObjects
        $ESC4Issues = Find-ESC4 -AdcsObjects $ADCSObjects
        $ESC4Issues | Format-Table Name, IdentityReference, ActiveDirectoryRights

        .EXAMPLE
        $Issues = Find-ESC4 -AdcsObjects $ADCSObjects | Where-Object { $_.Name -eq "User" }

        .EXAMPLE
        # Filter for specific ESC4 subtypes
        $ESC4Issues = Find-ESC4 -AdcsObjects $ADCSObjects
        $ESC4Issues | Format-Table Name, Subtype, IdentityReference, ActiveDirectoryRights

        # Find template ownership issues
        $OwnershipIssues = $ESC4Issues | Where-Object { $_.Subtype -eq 'Owner-Template' }

        # Find critical attribute modification vulnerabilities
        $CriticalAttrIssues = $ESC4Issues | Where-Object { 
            $_.Subtype -like '*CertNameFlag*' -or 
            $_.Subtype -like '*EnrollmentFlag*' -or 
            $_.Subtype -like '*PKIExtendedKeyUsage*' 
        }

        .EXAMPLE
        # Access the DirectoryEntry object for additional properties
        $ESC4Issues = Find-ESC4 -AdcsObjects $ADCSObjects
        $ESC4Issues[0].DirectoryEntry.Properties
        
        # Use DirectoryEntry for further analysis
        $ESC4Issues | ForEach-Object {
            Write-Host "Template: $($_.Name) [Subtype: $($_.Subtype)]"
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
        [string[]]$DangerousRights = @('GenericAll', 'GenericWrite', 'WriteProperty', 'WriteOwner', 'WriteDacl'),
        
        [Parameter()]
        [string]$SafeOwners = '-519$',
        
        [Parameter()]
        [string[]]$SafeObjectTypes = @('0e10c968-78fb-11d2-90d4-00c04f79dc55', 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'),
        
        [Parameter()]
        [string]$AllObjectsGUID = '00000000-0000-0000-0000-000000000000',
        
        [Parameter()]
        [string]$PKIExtendedKeyUsageGUID = 'bf967a0a-0de6-11d0-a285-00aa003049e2',
        
        [Parameter()]
        [string]$MSPKICertificateNameFlagGUID = 'b7ff5a38-0818-42b0-8110-d3d154c97f24',
        
        [Parameter()]
        [string]$MSPKIEnrollmentFlagGUID = 'fe17e862-1f75-4d8e-affe-2bf7cb5d3ac0',
        
        [Parameter()]
        [string]$MSPKIRASignatureGUID = 'd15ef7d8-f226-46db-ae79-b34e560bd12c'
    )

    #requires -Version 5 -Modules Microsoft.PowerShell.Security

    begin {
        # Load the ESCalatorIssue class
        . "$PSScriptRoot\ESCalatorIssue.ps1"
        
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
                        $parts[1..($parts.Count - 1)] -join '.' 
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
                            
                            [ESCalatorIssue]::CreateOriginalIssue(
                                $forestName,                                    # Forest
                                $templateName,                                  # Name
                                $templateDN,                                    # DistinguishedName
                                $security.Owner,                                # IdentityReference
                                $ownerSID,                                      # IdentityReferenceSID
                                'Owner',                                        # ActiveDirectoryRights
                                'ESC4',                                         # Technique
                                'Owner-Template',                               # Subtype
                                "$($security.Owner) has Owner rights on this template and can modify it into a template that can create ESC1, ESC2, and ESC3 templates.", # Issue
                                $null,                                          # ObjectType
                                $Template                                       # DirectoryEntry
                            )
                        }
                    } catch {
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
                                } catch {
                                    Write-Verbose "Could not translate identity $($ace.IdentityReference) to SID, skipping"
                                    continue
                                }
                            }

                            # Check if this is a safe object type (like Enroll/AutoEnroll only)
                            $isSafeObjectType = $false
                            if ($ace.ObjectType -and $ace.ObjectType.Guid) {
                                $isSafeObjectType = $ace.ObjectType.Guid -in $SafeObjectTypes
                            }

                            if (($ace.AccessControlType -eq 'Allow') -and -not $isSafeObjectType -and ($aceSID -notmatch $SafeOwners)) {
                                
                                $subtype = $null
                                $objectTypeGuid = if ($ace.ObjectType) { $ace.ObjectType.Guid } else { $null }
                                $issue = $null
                                $includeIssue = $false

                                # Determine ESC4 subtype based on permissions and object type
                                if ($ace.ActiveDirectoryRights -match 'GenericAll') {
                                    $subtype = 'GenericAll-Template'
                                    $issue = "$($ace.IdentityReference) has GenericAll rights on this certificate template, allowing complete modification of template settings to create ESC1, ESC2, and ESC3 vulnerabilities."
                                    $includeIssue = $true
                                }
                                elseif ($ace.ActiveDirectoryRights -match 'GenericWrite') {
                                    $subtype = 'GenericWrite-Template'
                                    $issue = "$($ace.IdentityReference) has GenericWrite rights on this certificate template, allowing modification of template settings to create ESC1, ESC2, and ESC3 vulnerabilities."
                                    $includeIssue = $true
                                }
                                elseif ($ace.ActiveDirectoryRights -match 'WriteProperty') {
                                    if ($objectTypeGuid -eq $AllObjectsGUID -or $null -eq $objectTypeGuid) {
                                        $subtype = 'WriteProperty-Template-AllObjects'
                                        $issue = "$($ace.IdentityReference) has WriteProperty rights for All Objects on this certificate template, allowing modification of critical template settings to create ESC1, ESC2, and ESC3 vulnerabilities."
                                        $includeIssue = $true
                                    }
                                    elseif ($objectTypeGuid -eq $PKIExtendedKeyUsageGUID) {
                                        $subtype = 'WriteProperty-Template-PKIExtendedKeyUsage'
                                        $issue = "$($ace.IdentityReference) can modify the pkiExtendedKeyUsage attribute, potentially allowing addition of Client Authentication EKU to create ESC1 vulnerabilities."
                                        $includeIssue = $true
                                    }
                                    elseif ($objectTypeGuid -eq $MSPKICertificateNameFlagGUID) {
                                        $subtype = 'WriteProperty-Template-CertNameFlag'
                                        $issue = "$($ace.IdentityReference) can modify the msPKI-Certificate-Name-Flag attribute, potentially enabling subject name spoofing to create ESC1 vulnerabilities."
                                        $includeIssue = $true
                                    }
                                    elseif ($objectTypeGuid -eq $MSPKIEnrollmentFlagGUID) {
                                        $subtype = 'WriteProperty-Template-EnrollmentFlag'
                                        $issue = "$($ace.IdentityReference) can modify the msPKI-Enrollment-Flag attribute, potentially disabling security features like manager approval to create ESC1 vulnerabilities."
                                        $includeIssue = $true
                                    }
                                    elseif ($objectTypeGuid -eq $MSPKIRASignatureGUID) {
                                        $subtype = 'WriteProperty-Template-RASignature'
                                        $issue = "$($ace.IdentityReference) can modify the msPKI-RA-Signature attribute, potentially disabling registration authority signature requirements to create ESC1 vulnerabilities."
                                        $includeIssue = $true
                                    }
                                }
                                elseif ($ace.ActiveDirectoryRights -match 'WriteOwner') {
                                    $subtype = 'WriteOwner-Template'
                                    $issue = "$($ace.IdentityReference) has WriteOwner rights on this certificate template, allowing them to take ownership and then modify template settings to create ESC1, ESC2, and ESC3 vulnerabilities."
                                    $includeIssue = $true
                                }
                                elseif ($ace.ActiveDirectoryRights -match 'WriteDacl') {
                                    $subtype = 'WriteDacl-Template'
                                    $issue = "$($ace.IdentityReference) has WriteDacl rights on this certificate template, allowing them to grant themselves additional permissions to modify template settings and create ESC1, ESC2, and ESC3 vulnerabilities."
                                    $includeIssue = $true
                                }

                                if ($includeIssue -and $subtype) {
                                    Write-Verbose "Found ESC4 issue: $subtype - $($ace.IdentityReference) on $templateName"

                                    [ESCalatorIssue]::CreateOriginalIssue(
                                        $forestName,                            # Forest
                                        $templateName,                          # Name
                                        $templateDN,                            # DistinguishedName
                                        $ace.IdentityReference.Value,           # IdentityReference
                                        $aceSID,                                # IdentityReferenceSID
                                        $ace.ActiveDirectoryRights.ToString(), # ActiveDirectoryRights
                                        'ESC4',                                 # Technique
                                        $subtype,                               # Subtype
                                        $issue,                                 # Issue
                                        $objectTypeGuid,                        # ObjectType
                                        $Template                               # DirectoryEntry
                                    )
                                }
                            }
                        } catch {
                            Write-Warning "Failed to process ACE for identity $($ace.IdentityReference) on template $templateName : $_"
                        }
                    }
                }
            } catch {
                Write-Warning "Failed to analyze security for template $templateName : $_"
            }
        }
    }

    end {
        Write-Verbose "ESC4 template vulnerability scan completed"
    }
}
