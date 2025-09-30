function Get-IndividualPrincipals {
    <#
        .SYNOPSIS
        Extracts DirectoryEntry objects for all individual principals identified in ESC4/ESC5 issues.

        .DESCRIPTION
        This function takes Issue objects from Find-ESC4, Find-ESC5, or expanded from Expand-GroupMembership
        and returns DirectoryEntry objects for each unique individual principal (users, computers) that has
        been identified with permissions on ADCS objects.

        .PARAMETER Issues
        Array of Issue objects from Find-ESC4, Find-ESC5, or other vulnerability scanning functions.
        Can include both original issues and expanded group membership issues.

        .PARAMETER IncludeGroups
        Switch to include group principals in the output. By default, only individual users and computers are included.

        .INPUTS
        PSCustomObject[]
        Issue objects with IdentityReference and IdentityReferenceSID properties.

        .OUTPUTS
        System.DirectoryServices.DirectoryEntry[]
        DirectoryEntry objects for each unique individual principal.

        .EXAMPLE
        $ADCSObjects = Get-AdcsObjects
        $AllIssues = @(Find-ESC4 -AdcsObjects $ADCSObjects; Find-ESC5 -AdcsObjects $ADCSObjects)
        $ObjectsWithIssues = Add-Issue -AdcsObjects $ADCSObjects -Issues $AllIssues
        $AllIndividualMemberIssues = $ObjectsWithIssues | ForEach-Object { $_.IndividualMemberIssues }
        $IndividualPrincipals = Get-IndividualPrincipals -Issues $AllIndividualMemberIssues
        $IndividualPrincipals | Select-Object Name, samAccountName, objectClass

        .EXAMPLE
        # Include groups in the output
        $AllPrincipals = Get-IndividualPrincipals -Issues $AllIndividualMemberIssues -IncludeGroups

        .LINK
        https://posts.specterops.io/certified-pre-owned-d95910965cd2
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject[]]$Issues,
        
        [Parameter()]
        [switch]$IncludeGroups
    )

    #requires -Version 5

    begin {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Starting $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
        $principalSIDs = @{}
    }

    process {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Processing $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
        
        foreach ($issue in $Issues) {
            Write-Verbose "Processing issue for principal: $($issue.IdentityReference)"
            
            try {
                # Skip groups if not requested
                if (-not $IncludeGroups -and $issue.MemberType -eq 'GroupPrincipal') {
                    Write-Verbose "Skipping group principal: $($issue.IdentityReference)"
                    continue
                }
                
                # Collect unique SIDs
                if ($issue.IdentityReferenceSID -and -not $principalSIDs.ContainsKey($issue.IdentityReferenceSID)) {
                    $principalSIDs[$issue.IdentityReferenceSID] = $issue.IdentityReference
                }
                
            } catch {
                Write-Warning "Failed to process issue for principal $($issue.IdentityReference): $_"
            }
        }
    }

    end {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Processing final results for $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
        Write-Verbose "Found $($principalSIDs.Count) unique principals"
        
        $directoryEntries = @()
        
        foreach ($sid in $principalSIDs.Keys) {
            try {
                Write-Verbose "Creating DirectoryEntry for SID: $sid ($($principalSIDs[$sid]))"
                
                # Create DirectoryEntry using the SID
                $searcher = New-Object System.DirectoryServices.DirectorySearcher
                $searcher.Filter = "(objectSid=$sid)"
                $searcher.PropertiesToLoad.AddRange(@('distinguishedName', 'samAccountName', 'name', 'objectClass', 'objectSid'))
                
                $result = $searcher.FindOne()
                if ($result) {
                    $directoryEntry = $result.GetDirectoryEntry()
                    $directoryEntries += $directoryEntry
                    Write-Verbose "Successfully created DirectoryEntry for: $($directoryEntry.Name)"
                } else {
                    Write-Warning "Could not find AD object for SID: $sid ($($principalSIDs[$sid]))"
                }
                
            } catch {
                Write-Warning "Failed to create DirectoryEntry for SID $sid ($($principalSIDs[$sid])): $_"
            }
        }
        
        Write-Verbose "Returning $($directoryEntries.Count) DirectoryEntry objects"
        Write-Output $directoryEntries
        
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Finishing $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
    }
}