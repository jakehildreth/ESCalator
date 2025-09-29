function Expand-GroupMembership {
    <#
        .SYNOPSIS
        Expands group membership for Issue objects from Find-ESC4 and Find-ESC5 functions.

        .DESCRIPTION
        This function takes Issue objects (PSCustomObjects) from Find-ESC4 or Find-ESC5 functions and expands
        any IdentityReferenceSID that represents a group into its individual member principals. This helps
        identify all users and computers that might be affected by the ESC4/ESC5 vulnerability through
        group membership inheritance.

        .PARAMETER Issue
        Issue objects from Find-ESC4 or Find-ESC5 functions containing IdentityReferenceSID properties to expand.

        .INPUTS
        PSCustomObject[]
        Issue objects with IdentityReferenceSID properties.

        .OUTPUTS
        PSCustomObject[]
        Returns expanded Issue objects with individual principals instead of group SIDs.

        .EXAMPLE
        $ESC4Issues = Find-ESC4 -AdcsObjects $ADCSObjects
        $ExpandedIssues = $ESC4Issues | Expand-GroupMembership
        $ExpandedIssues | Format-Table Name, IdentityReference, ActiveDirectoryRights

        .EXAMPLE
        Find-ESC5 -AdcsObjects $ADCSObjects | Expand-GroupMembership | Where-Object { $_.IdentityReference -like "*user*" }

        .LINK
        https://posts.specterops.io/certified-pre-owned-d95910965cd2
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject[]]$Issue
    )

    #requires -Version 5

    begin {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Starting $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
        Add-Type -AssemblyName 'System.DirectoryServices.AccountManagement'
    }

    process {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Processing $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
        
        foreach ($IssueObject in $Issue) {
            Write-Verbose "Processing issue for $($IssueObject.Name) - Identity: $($IssueObject.IdentityReference)"
            
            try {
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
                    
                    try {
                        $PrincipalContext = [System.DirectoryServices.AccountManagement.PrincipalContext]::New('Domain', $domain)
                        $Principal = [System.DirectoryServices.AccountManagement.Principal]::FindByIdentity($PrincipalContext, 'Sid', $sid)
                        
                        if ($Principal -and $Principal.GetType().Name -eq 'GroupPrincipal') {
                            Write-Verbose "Found group: $($Principal.Name), expanding members..."
                            
                            # Get group members
                            $GroupPrincipal = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($PrincipalContext, 'Sid', $sid)
                            $members = $GroupPrincipal.GetMembers($true)  # $true for recursive expansion
                            
                            if ($members) {
                                foreach ($member in $members) {
                                    # Create a new issue object for each member
                                    $expandedIssue = $IssueObject.PSObject.Copy()
                                    $expandedIssue.IdentityReference = $member.SamAccountName
                                    $expandedIssue.IdentityReferenceSID = $member.Sid.Value
                                    $expandedIssue.Issue = $expandedIssue.Issue -replace [regex]::Escape($IssueObject.IdentityReference), $member.SamAccountName
                                    
                                    # Add additional properties about the member
                                    $expandedIssue | Add-Member -NotePropertyName MemberType -NotePropertyValue $member.GetType().Name -Force
                                    $expandedIssue | Add-Member -NotePropertyName ExpandedFromGroup -NotePropertyValue $IssueObject.IdentityReference -Force
                                    $expandedIssue | Add-Member -NotePropertyName ExpandedFromGroupSID -NotePropertyValue $IssueObject.IdentityReferenceSID -Force
                                    
                                    Write-Output $expandedIssue
                                }
                            } else {
                                Write-Verbose "Group $($Principal.Name) has no members"
                                # Output original issue with note that group is empty
                                $IssueObject | Add-Member -NotePropertyName GroupExpansionNote -NotePropertyValue "Group has no members" -Force
                                Write-Output $IssueObject
                            }
                        } else {
                            Write-Verbose "SID $sid is not a group or could not be resolved, outputting original issue"
                            # Not a group, output original issue
                            Write-Output $IssueObject
                        }
                        
                        if ($Principal) { $Principal.Dispose() }
                        if ($PrincipalContext) { $PrincipalContext.Dispose() }
                    }
                    catch {
                        Write-Warning "Failed to expand group membership for SID $sid in domain $domain : $_"
                        # Output original issue with error note
                        $IssueObject | Add-Member -NotePropertyName GroupExpansionError -NotePropertyValue $_.Exception.Message -Force
                        Write-Output $IssueObject
                    }
                } else {
                    Write-Verbose "IdentityReferenceSID is not a valid SID format, outputting original issue"
                    Write-Output $IssueObject
                }
            }
            catch {
                Write-Warning "Failed to process issue object: $_"
                Write-Output $IssueObject
            }
        }
    }

    end {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Finishing $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."    
    }
}
