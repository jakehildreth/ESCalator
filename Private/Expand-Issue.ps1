function Expand-Issue {
    <#
        .SYNOPSIS
        Expands ESCalatorIssue objects by recursively enumerating group members when the identity is a group.

        .DESCRIPTION
        This function takes ESCalatorIssue objects and checks if the IdentityReference represents a group.
        If it's a group, the function recursively enumerates all group members and creates individual
        ESCalatorIssue objects for each principal (user/computer) in the group. Non-group identities
        are returned unchanged.

        .PARAMETER Issue
        ESCalatorIssue objects to expand. If the IdentityReference is a group, it will be expanded
        to individual member principals.

        .PARAMETER Recursive
        Whether to recursively expand nested groups. Default is $true.

        .INPUTS
        ESCalatorIssue[]
        ESCalatorIssue objects with IdentityReference properties to expand.

        .OUTPUTS
        ESCalatorIssue[]
        Returns expanded ESCalatorIssue objects with individual principals instead of groups,
        plus any non-group issues unchanged.

        .EXAMPLE
        $Issues = Find-ESC4 -AdcsObjects $AdcsObjects
        $ExpandedIssues = $Issues | Expand-Issue
        $ExpandedIssues | Where-Object { $_.IsExpanded() } | Format-Table

        .EXAMPLE
        $ESC5Issues = Find-ESC5 -AdcsObjects $AdcsObjects
        $AllExpanded = $ESC5Issues | Expand-Issue -Recursive $true
        Write-Host "Original issues: $($ESC5Issues.Count), Expanded: $($AllExpanded.Count)"

        .EXAMPLE
        # Expand only specific group issues
        $GroupIssues = $AllIssues | Where-Object { $_.IdentityReferenceSID -match '^S-1-5-.*-5[0-9][0-9]$' }
        $ExpandedGroupIssues = $GroupIssues | Expand-Issue

        .LINK
        https://posts.specterops.io/certified-pre-owned-d95910965cd2
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        $Issue,
        
        [Parameter()]
        [bool]$Recursive = $true
    )

    #requires -Version 5

    begin {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Starting $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
        Add-Type -AssemblyName 'System.DirectoryServices.AccountManagement'
        
        # Load ESCalatorIssue class if not already loaded
        if (-not ([System.Management.Automation.PSTypeName]'ESCalatorIssue').Type) {
            $escalatorIssuePath = Join-Path $PSScriptRoot "ESCalatorIssue.ps1"
            if (Test-Path $escalatorIssuePath) {
                . $escalatorIssuePath
            } else {
                throw "ESCalatorIssue class not found. Please ensure ESCalatorIssue.ps1 is available."
            }
        }
    }

    process {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Processing $($Issue.Count) issue(s) for group expansion..."
        
        # Handle array flattening - support multiple array syntax like ($Array1, $Array2)
        $FlattenedIssues = @()
        foreach ($IssueSet in $Issue) {
            if ($null -ne $IssueSet) {
                # Check if this is a single ESCalatorIssue object
                if ($IssueSet.PSObject.TypeNames[0] -eq 'ESCalatorIssue') {
                    $FlattenedIssues += $IssueSet
                }
                # Check if this is an array (could be array of ESCalatorIssue or nested arrays)
                elseif ($IssueSet -is [System.Array] -or $IssueSet -is [System.Collections.IEnumerable]) {
                    foreach ($SubItem in $IssueSet) {
                        if ($null -ne $SubItem) {
                            # Recursively handle nested arrays
                            if ($SubItem.PSObject.TypeNames[0] -eq 'ESCalatorIssue') {
                                $FlattenedIssues += $SubItem
                            } elseif ($SubItem -is [System.Array] -or $SubItem -is [System.Collections.IEnumerable]) {
                                foreach ($NestedItem in $SubItem) {
                                    if ($null -ne $NestedItem -and $NestedItem.PSObject.TypeNames[0] -eq 'ESCalatorIssue') {
                                        $FlattenedIssues += $NestedItem
                                    } else {
                                        Write-Warning "Skipping non-ESCalatorIssue object in nested array: $($NestedItem.GetType().Name)"
                                    }
                                }
                            } else {
                                Write-Warning "Skipping non-ESCalatorIssue object in array: $($SubItem.GetType().Name)"
                            }
                        }
                    }
                } else {
                    Write-Warning "Skipping non-ESCalatorIssue object: $($IssueSet.GetType().Name)"
                }
            }
        }
        
        Write-Verbose "Processing $($FlattenedIssues.Count) flattened issues for expansion..."
        
        foreach ($IssueObject in $FlattenedIssues) {
            Write-Verbose "Processing issue for $($IssueObject.Name) - Identity: $($IssueObject.IdentityReference)"
            
            try {
                # Skip if this is already an expanded issue to avoid infinite recursion
                if ($IssueObject.IsExpanded()) {
                    Write-Verbose "Issue is already expanded from group: $($IssueObject.ExpandedFromGroup), skipping"
                    Write-Output $IssueObject
                    continue
                }
                
                # Extract domain from the forest or try to determine from SID
                $domain = $IssueObject.Forest
                if (-not $domain -or $domain -eq 'Unknown') {
                    # Try to extract domain from DN if available
                    if ($IssueObject.DistinguishedName) {
                        $parts = $IssueObject.DistinguishedName -split ',DC='
                        if ($parts.Count -gt 1) {
                            $domain = $parts[1..($parts.Count-1)] -join '.'
                        }
                    }
                }
                
                # Try to resolve the SID to determine if it's a group
                $sid = $IssueObject.IdentityReferenceSID
                if ($sid -match '^S-1-') {
                    Write-Verbose "Attempting to resolve SID: $sid in domain: $domain"
                    
                    $PrincipalContext = $null
                    $Principal = $null
                    $GroupPrincipal = $null
                    
                    try {
                        $PrincipalContext = [System.DirectoryServices.AccountManagement.PrincipalContext]::New('Domain', $domain)
                        $Principal = [System.DirectoryServices.AccountManagement.Principal]::FindByIdentity($PrincipalContext, 'Sid', $sid)
                        
                        if ($Principal -and $Principal.GetType().Name -eq 'GroupPrincipal') {
                            Write-Verbose "Found group: $($Principal.Name), expanding members..."
                            
                            # Get group members
                            $GroupPrincipal = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($PrincipalContext, 'Sid', $sid)
                            if ($GroupPrincipal) {
                                $members = $GroupPrincipal.GetMembers($Recursive)  # Use parameter for recursive expansion
                                
                                if ($members) {
                                    $memberCount = 0
                                    foreach ($member in $members) {
                                        $memberCount++
                                        Write-Verbose "Expanding member $memberCount : $($member.SamAccountName) ($($member.GetType().Name))"
                                        
                                        # Construct domain\username format consistent with original issues
                                        # Extract NetBIOS domain name from the original issue's IdentityReference
                                        $netbiosDomain = if ($IssueObject.IdentityReference -match '^([^\\]+)\\') {
                                            $matches[1]
                                        } elseif ($member.Context.Name) {
                                            # Fallback: try to get NetBIOS name from context
                                            $member.Context.Name
                                        } elseif ($domain) {
                                            # Last resort: use first part of FQDN
                                            $domain.Split('.')[0]
                                        } else {
                                            $null
                                        }
                                        
                                        $memberIdentity = if ($netbiosDomain) {
                                            "$netbiosDomain\$($member.SamAccountName)"
                                        } else {
                                            $member.SamAccountName
                                        }
                                        
                                        # Create expanded issue using ESCalatorIssue class method
                                        $expandedIssue = [ESCalatorIssue]::CreateExpandedIssue(
                                            $IssueObject.Forest,                               # Forest
                                            $IssueObject.Name,                                  # Name
                                            $IssueObject.DistinguishedName,                    # DistinguishedName
                                            $memberIdentity,                                    # IdentityReference (with NetBIOS domain)
                                            $member.Sid.Value,                                  # IdentityReferenceSID
                                            $IssueObject.ActiveDirectoryRights,                # ActiveDirectoryRights
                                            $IssueObject.Technique,                            # Technique
                                            $IssueObject.Subtype,                              # Subtype
                                            ($IssueObject.Issue -replace [regex]::Escape($IssueObject.IdentityReference), $memberIdentity), # Issue (updated with NetBIOS format)
                                            $IssueObject.ObjectType,                           # ObjectType
                                            $IssueObject.DirectoryEntry,                       # DirectoryEntry
                                            $IssueObject.IdentityReference,                    # ExpandedFromGroup
                                            $IssueObject.IdentityReferenceSID,                 # ExpandedFromGroupSID
                                            $member.GetType().Name                              # MemberType
                                        )
                                        
                                        Write-Output $expandedIssue
                                    }
                                    
                                    Write-Verbose "Successfully expanded group $($Principal.Name) into $memberCount members"
                                } else {
                                    Write-Verbose "Group $($Principal.Name) has no members"
                                    # Output original issue with note that group is empty
                                    $emptyGroupIssue = $IssueObject.CreateCopy()
                                    $emptyGroupIssue | Add-Member -NotePropertyName "GroupExpansionNote" -NotePropertyValue "Group has no members" -Force
                                    Write-Output $emptyGroupIssue
                                }
                            } else {
                                Write-Warning "Could not cast principal to GroupPrincipal for SID: $sid"
                                Write-Output $IssueObject
                            }
                        } else {
                            Write-Verbose "SID $sid is not a group or could not be resolved, outputting original issue"
                            # Not a group, output original issue
                            Write-Output $IssueObject
                        }
                    }
                    catch {
                        Write-Warning "Failed to expand group membership for SID $sid in domain $domain : $_"
                        # Output original issue with error note
                        $errorIssue = $IssueObject.CreateCopy()
                        $errorIssue | Add-Member -NotePropertyName "GroupExpansionError" -NotePropertyValue $_.Exception.Message -Force
                        Write-Output $errorIssue
                    }
                    finally {
                        # Clean up resources
                        if ($GroupPrincipal) { $GroupPrincipal.Dispose() }
                        if ($Principal) { $Principal.Dispose() }
                        if ($PrincipalContext) { $PrincipalContext.Dispose() }
                    }
                } else {
                    Write-Verbose "IdentityReferenceSID '$sid' is not a valid SID format, outputting original issue"
                    Write-Output $IssueObject
                }
            }
            catch {
                Write-Warning "Failed to process issue object for $($IssueObject.Name): $_"
                Write-Output $IssueObject
            }
        }
    }

    end {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Finishing $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."    
    }
}
