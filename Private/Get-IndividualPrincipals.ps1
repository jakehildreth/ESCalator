function Get-IndividualPrincipals {
    <#
        .SYNOPSIS
        Extracts a consolidated list of all individual principals identified in ESC4/ESC5 issues.

        .DESCRIPTION
        This function takes Issue objects from Find-ESC4, Find-ESC5, or expanded from Expand-GroupMembership
        and creates a consolidated list of all individual principals (users, computers, groups) that have
        been identified with permissions on ADCS objects. This helps provide a comprehensive view of
        all accounts that may pose a security risk in the ADCS environment.

        .PARAMETER Issues
        Array of Issue objects from Find-ESC4, Find-ESC5, or other vulnerability scanning functions.
        Can include both original issues and expanded group membership issues.

        .PARAMETER IncludeGroups
        Switch to include group principals in the output. By default, only individual users and computers are included.

        .PARAMETER UniqueOnly
        Switch to return only unique principals (deduplicated by IdentityReferenceSID). Default behavior.

        .INPUTS
        PSCustomObject[]
        Issue objects with IdentityReference and IdentityReferenceSID properties.

        .OUTPUTS
        PSCustomObject[]
        Returns objects describing individual principals with aggregated information about their permissions.

        .EXAMPLE
        $ADCSObjects = Get-AdcsObjects
        $AllIssues = @(Find-ESC4 -AdcsObjects $ADCSObjects; Find-ESC5 -AdcsObjects $ADCSObjects)
        $ExpandedIssues = $AllIssues | Expand-GroupMembership
        $IndividualPrincipals = Get-IndividualPrincipals -Issues $ExpandedIssues
        $IndividualPrincipals | Format-Table IdentityReference, PrincipalType, IssueCount, Techniques

        .EXAMPLE
        # Include groups in the output
        $AllPrincipals = Get-IndividualPrincipals -Issues $ExpandedIssues -IncludeGroups
        
        .EXAMPLE
        # Get from Add-Issue results
        $ObjectsWithIssues = Get-AdcsObjects | Add-Issue -Issues $AllIssues
        $AllIndividualMemberIssues = $ObjectsWithIssues | ForEach-Object { $_.IndividualMemberIssues }
        $IndividualPrincipals = Get-IndividualPrincipals -Issues $AllIndividualMemberIssues

        .LINK
        https://posts.specterops.io/certified-pre-owned-d95910965cd2
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject[]]$Issues,
        
        [Parameter()]
        [switch]$IncludeGroups,
        
        [Parameter()]
        [switch]$UniqueOnly
    )

    #requires -Version 5

    begin {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Starting $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
        $allPrincipals = @()
    }

    process {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Processing $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
        
        foreach ($issue in $Issues) {
            Write-Verbose "Processing issue for principal: $($issue.IdentityReference)"
            
            try {
                # Determine principal type
                $principalType = if ($issue.MemberType) {
                    # This is from expanded group membership
                    switch ($issue.MemberType) {
                        'UserPrincipal' { 'User' }
                        'ComputerPrincipal' { 'Computer' }
                        'GroupPrincipal' { 'Group' }
                        default { 'Unknown' }
                    }
                } elseif ($issue.ExpandedFromGroup) {
                    # This is an expanded member but MemberType might be missing
                    'ExpandedMember'
                } else {
                    # This is an original issue - try to determine type from identity reference
                    if ($issue.IdentityReference -match '\$$') {
                        'Computer'
                    } elseif ($issue.IdentityReference -match '\\.*\s') {
                        'Group'  # Groups often have spaces in names
                    } else {
                        'Principal'  # Generic term for original issues
                    }
                }
                
                # Skip groups if not requested
                if (-not $IncludeGroups -and ($principalType -eq 'Group' -or $principalType -eq 'GroupPrincipal')) {
                    Write-Verbose "Skipping group principal: $($issue.IdentityReference)"
                    continue
                }
                
                # Create principal object
                $principal = [PSCustomObject]@{
                    IdentityReference = $issue.IdentityReference
                    IdentityReferenceSID = $issue.IdentityReferenceSID
                    PrincipalType = $principalType
                    ExpandedFromGroup = $issue.ExpandedFromGroup
                    ExpandedFromGroupSID = $issue.ExpandedFromGroupSID
                    Technique = $issue.Technique
                    ActiveDirectoryRights = $issue.ActiveDirectoryRights
                    TargetObject = $issue.Name
                    TargetDistinguishedName = $issue.DistinguishedName
                    Forest = $issue.Forest
                    Issue = $issue.Issue
                    IsExpanded = [bool]$issue.ExpandedFromGroup
                    IsHighRisk = $issue.ActiveDirectoryRights -match 'GenericAll|FullControl|WriteOwner|WriteDacl'
                }
                
                $allPrincipals += $principal
                
            } catch {
                Write-Warning "Failed to process issue for principal $($issue.IdentityReference): $_"
            }
        }
    }

    end {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Processing final results for $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
        
        # Default to unique behavior unless explicitly disabled
        $shouldDeduplicate = -not $PSBoundParameters.ContainsKey('UniqueOnly') -or $UniqueOnly
        
        if ($shouldDeduplicate) {
            Write-Verbose "Deduplicating principals by IdentityReferenceSID..."
            # Group by SID and create aggregated objects
            $groupedPrincipals = $allPrincipals | Group-Object IdentityReferenceSID
            
            $uniquePrincipals = foreach ($group in $groupedPrincipals) {
                $firstPrincipal = $group.Group[0]
                $allIssues = $group.Group
                
                # Aggregate information
                $techniques = $allIssues | Select-Object -ExpandProperty Technique -Unique
                $rights = $allIssues | Select-Object -ExpandProperty ActiveDirectoryRights -Unique
                $targetObjects = $allIssues | Select-Object -ExpandProperty TargetObject -Unique
                $expandedFromGroups = $allIssues | Where-Object { $_.ExpandedFromGroup } | Select-Object -ExpandProperty ExpandedFromGroup -Unique
                $isHighRisk = $allIssues | Where-Object { $_.IsHighRisk } | Measure-Object | Select-Object -ExpandProperty Count
                
                # Create aggregated principal object
                [PSCustomObject]@{
                    IdentityReference = $firstPrincipal.IdentityReference
                    IdentityReferenceSID = $firstPrincipal.IdentityReferenceSID
                    PrincipalType = $firstPrincipal.PrincipalType
                    IssueCount = $group.Count
                    Techniques = $techniques -join ', '
                    ActiveDirectoryRights = $rights -join ', '
                    TargetObjects = $targetObjects -join ', '
                    TargetObjectCount = $targetObjects.Count
                    ExpandedFromGroups = $expandedFromGroups -join ', '
                    ExpandedFromGroupCount = $expandedFromGroups.Count
                    Forest = $firstPrincipal.Forest
                    IsExpanded = $firstPrincipal.IsExpanded
                    HighRiskIssueCount = $isHighRisk
                    IsHighRisk = $isHighRisk -gt 0
                    RiskLevel = if ($isHighRisk -gt 0) { 
                        if ($isHighRisk -ge 3) { 'Critical' } 
                        elseif ($isHighRisk -ge 2) { 'High' } 
                        else { 'Medium' } 
                    } else { 'Low' }
                }
            }
            
            Write-Verbose "Found $($allPrincipals.Count) total principal entries, consolidated to $($uniquePrincipals.Count) unique principals"
            Write-Output $uniquePrincipals | Sort-Object @{Expression='IsHighRisk'; Descending=$true}, @{Expression='IssueCount'; Descending=$true}, IdentityReference
            
        } else {
            Write-Verbose "Returning all $($allPrincipals.Count) principal entries (no deduplication)"
            Write-Output $allPrincipals | Sort-Object @{Expression='IsHighRisk'; Descending=$true}, IdentityReference
        }
        
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Finishing $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
    }
}