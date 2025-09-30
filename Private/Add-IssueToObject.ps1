function Add-IssueToObject {
    <#
        .SYNOPSIS
        Adds Issue objects as properties to DirectoryEntry objects from ADCS scans.

        .DESCRIPTION
        This function takes DirectoryEntry objects from Get-AdcsObjects and attaches security issues
        found by Find-ESC4, Find-ESC5, and other vulnerability scanning functions as properties.
        The function automatically expands group memberships while keeping both the original group 
        issues and the expanded individual member issues for comprehensive analysis.

        .PARAMETER AdcsObjects
        Array of objects from Get-AdcsObjects to attach issues to. Typically DirectoryEntry objects but can accept any objects with Name and distinguishedName properties.

        .PARAMETER Issues
        Array of Issue objects from Find-ESC4, Find-ESC5, or other vulnerability scanning functions.
        Group memberships will be automatically expanded while keeping original group issues.

        .INPUTS
        Object[]
        Objects with Name and distinguishedName properties (typically DirectoryEntry objects)
        PSCustomObject[] (Issue objects)

        .OUTPUTS
        Object[]
        Returns the original objects with additional issue-related properties added.

        .EXAMPLE
        $ADCSObjects = Get-AdcsObjects
        $ESC4Issues = Find-ESC4 -AdcsObjects $ADCSObjects
        $ESC5Issues = Find-ESC5 -AdcsObjects $ADCSObjects
        $AllIssues = @($ESC4Issues; $ESC5Issues)
        $ObjectsWithIssues = Add-Issue -AdcsObjects $ADCSObjects -Issues $AllIssues

        .EXAMPLE
        $ADCSObjects = Get-AdcsObjects
        $Issues = @(Find-ESC4 -AdcsObjects $ADCSObjects; Find-ESC5 -AdcsObjects $ADCSObjects)
        $ObjectsWithIssues = Add-Issue -AdcsObjects $ADCSObjects -Issues $Issues
        $VulnerableObjects = $ObjectsWithIssues | Where-Object { $_.HasIssues }
        # Groups are automatically expanded, so you get both group and individual member issues

        .EXAMPLE
        # Pipeline usage - automatic group expansion
        Get-AdcsObjects | Add-Issue -Issues $AllIssues | Where-Object { $_.RiskLevel -eq "High" }

        .LINK
        https://posts.specterops.io/certified-pre-owned-d95910965cd2
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [object[]]$AdcsObjects,
        
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [PSCustomObject[]]$Issues
    )

    #requires -Version 5

    begin {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Starting $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
        
        # Always expand groups but keep both original and expanded issues

        $ExpandedIssues = @()
        $AllIssues = @()
        
        if ($Issues) {
            Write-Verbose "Expanding group memberships in issues (keeping both original and expanded)..."
            try {
                # Load the Expand-GroupMembership function if available
                if (-not (Get-Command Expand-GroupMembership -ErrorAction SilentlyContinue)) {
                    $expandGroupPath = Join-Path $PSScriptRoot "Expand-GroupMembership.ps1"
                    if (Test-Path $expandGroupPath) {
                        . $expandGroupPath
                    } else {
                        Write-Warning "Expand-GroupMembership function not found. Using original issues only."
                        $AllIssues = $Issues
                    }
                }
                
                if (Get-Command Expand-GroupMembership -ErrorAction SilentlyContinue) {
                    # Expand the issues
                    $ExpandedIssues = $Issues | Expand-GroupMembership
                    
                    # Combine original and expanded issues, avoiding duplicates of non-group issues
                    $AllIssues = @()
                    
                    # Add all original issues first (including groups)
                    $AllIssues += $Issues
                    
                    # Add only the expanded issues (those that came from groups)
                    $NewExpandedIssues = $ExpandedIssues | Where-Object { $_.ExpandedFromGroup }
                    $AllIssues += $NewExpandedIssues
                    
                    Write-Verbose "Original issues: $($Issues.Count)"
                    Write-Verbose "Expanded issues from groups: $($NewExpandedIssues.Count)" 
                    Write-Verbose "Total combined issues: $($AllIssues.Count)"
                } else {
                    $AllIssues = $Issues
                }
            }
            catch {
                Write-Warning "Failed to expand group memberships: $_"
                $AllIssues = $Issues
            }
        } else {
            $AllIssues = @()
        }
        
        Write-Verbose "Processing $($AllIssues.Count) total issues (original + expanded) for attachment to ADCS objects"
    }

    process {
        foreach ($AdcsObject in $AdcsObjects) {
            # Handle different object types and property access patterns
            $objectName = if ($AdcsObject.Name.Value) { 
                $AdcsObject.Name.Value 
            } elseif ($AdcsObject.Name) { 
                $AdcsObject.Name 
            } else { 
                "Unknown" 
            }
            
            $objectDN = if ($AdcsObject.distinguishedName.Value) { 
                $AdcsObject.distinguishedName.Value 
            } elseif ($AdcsObject.distinguishedName) { 
                $AdcsObject.distinguishedName 
            } else { 
                $null 
            }
            
            Write-Verbose "Processing ADCS object: $objectName"
            
            try {
                # Find issues related to this object
                $relatedIssues = $AllIssues | Where-Object { 
                    $_.Name -eq $objectName -or 
                    $_.DistinguishedName -eq $objectDN 
                }
                
                Write-Verbose "Found $($relatedIssues.Count) issues for object: $objectName"
                
                # Group issues by technique for easier analysis
                $issuesByTechnique = $relatedIssues | Group-Object Technique -AsHashTable -AsString
                
                # Calculate risk level based on issue count and techniques
                $riskLevel = if ($relatedIssues.Count -eq 0) { 
                    "None" 
                } elseif ($relatedIssues.Count -le 2) { 
                    "Low" 
                } elseif ($relatedIssues.Count -le 5) { 
                    "Medium" 
                } else { 
                    "High" 
                }
                
                # Get unique techniques and affected principals
                $techniques = $relatedIssues | Select-Object -ExpandProperty Technique -Unique
                $affectedPrincipals = $relatedIssues | Select-Object -ExpandProperty IdentityReference -Unique
                
                # Analyze issue types - separate original, group, expanded, and direct issues
                $originalIssues = $relatedIssues | Where-Object { -not $_.ExpandedFromGroup }
                $originalGroupIssues = $originalIssues | Where-Object { 
                    $_.IdentityReferenceSID -match '^S-1-5-.*-5[0-9][0-9]$|^S-1-5-32-' 
                } # Heuristic to identify group SIDs
                
                $expandedMemberIssues = $relatedIssues | Where-Object { $_.ExpandedFromGroup }
                $directPrincipalIssues = $originalIssues | Where-Object { 
                    -not ($_.IdentityReferenceSID -match '^S-1-5-.*-5[0-9][0-9]$|^S-1-5-32-')
                }
                
                $expandedFromGroups = $expandedMemberIssues | Select-Object -ExpandProperty ExpandedFromGroup -Unique
                $memberTypes = $expandedMemberIssues | Where-Object { $_.MemberType } | Select-Object -ExpandProperty MemberType -Unique
                
                # Add comprehensive issue information as properties
                $AdcsObject | Add-Member -NotePropertyName "SecurityIssues" -NotePropertyValue $relatedIssues -Force
                $AdcsObject | Add-Member -NotePropertyName "IssueCount" -NotePropertyValue $relatedIssues.Count -Force
                $AdcsObject | Add-Member -NotePropertyName "HasIssues" -NotePropertyValue ($relatedIssues.Count -gt 0) -Force
                $AdcsObject | Add-Member -NotePropertyName "IssuesByTechnique" -NotePropertyValue $issuesByTechnique -Force
                $AdcsObject | Add-Member -NotePropertyName "VulnerableTechniques" -NotePropertyValue $techniques -Force
                $AdcsObject | Add-Member -NotePropertyName "RiskLevel" -NotePropertyValue $riskLevel -Force
                $AdcsObject | Add-Member -NotePropertyName "AffectedPrincipals" -NotePropertyValue $affectedPrincipals -Force
                $AdcsObject | Add-Member -NotePropertyName "AffectedPrincipalCount" -NotePropertyValue $affectedPrincipals.Count -Force
                
                # Add enhanced group expansion analysis properties
                $AdcsObject | Add-Member -NotePropertyName "OriginalIssues" -NotePropertyValue $originalIssues -Force
                $AdcsObject | Add-Member -NotePropertyName "GroupIssues" -NotePropertyValue $originalGroupIssues -Force
                $AdcsObject | Add-Member -NotePropertyName "IndividualMemberIssues" -NotePropertyValue $expandedMemberIssues -Force
                $AdcsObject | Add-Member -NotePropertyName "NonGroupIssues" -NotePropertyValue $directPrincipalIssues -Force
                $AdcsObject | Add-Member -NotePropertyName "ExpandedFromGroups" -NotePropertyValue $expandedFromGroups -Force
                $AdcsObject | Add-Member -NotePropertyName "MemberTypes" -NotePropertyValue $memberTypes -Force
                $AdcsObject | Add-Member -NotePropertyName "OriginalIssueCount" -NotePropertyValue $originalIssues.Count -Force
                $AdcsObject | Add-Member -NotePropertyName "GroupIssueCount" -NotePropertyValue $originalGroupIssues.Count -Force
                $AdcsObject | Add-Member -NotePropertyName "IndividualMemberIssueCount" -NotePropertyValue $expandedMemberIssues.Count -Force
                $AdcsObject | Add-Member -NotePropertyName "NonGroupIssueCount" -NotePropertyValue $directPrincipalIssues.Count -Force
                $AdcsObject | Add-Member -NotePropertyName "GroupCount" -NotePropertyValue $expandedFromGroups.Count -Force
                
                # Add convenience methods for common operations
                $AdcsObject | Add-Member -MemberType ScriptMethod -Name "GetIssuesByTechnique" -Value {
                    param([string]$Technique)
                    return $this.SecurityIssues | Where-Object { $_.Technique -eq $Technique }
                } -Force
                
                $AdcsObject | Add-Member -MemberType ScriptMethod -Name "GetHighRiskIssues" -Value {
                    return $this.SecurityIssues | Where-Object { 
                        $_.ActiveDirectoryRights -match 'GenericAll|FullControl|WriteOwner|WriteDacl' 
                    }
                } -Force
                
                $AdcsObject | Add-Member -MemberType ScriptMethod -Name "GetGroupExpansionSummary" -Value {
                    $summary = [PSCustomObject]@{
                        TotalIssues = $this.IssueCount
                        OriginalGroups = $this.OriginalGroupCount
                        ExpandedMembers = $this.ExpandedMemberCount
                        DirectPrincipals = $this.DirectPrincipalCount
                        GroupsInvolved = $this.GroupCount
                        MemberTypes = $this.MemberTypes -join ', '
                        ExpandedFromGroups = $this.ExpandedFromGroups -join ', '
                    }
                    return $summary
                } -Force
                
                $AdcsObject | Add-Member -MemberType ScriptMethod -Name "GetIssueSummary" -Value {
                    $objName = if ($this.Name.Value) { $this.Name.Value } elseif ($this.Name) { $this.Name } else { "Unknown" }
                    $summary = [PSCustomObject]@{
                        ObjectName               = $objName
                        TotalIssues              = $this.IssueCount
                        OriginalIssues           = $this.OriginalIssueCount
                        GroupIssues              = $this.GroupIssueCount
                        IndividualMemberIssues   = $this.IndividualMemberIssueCount
                        NonGroupIssues           = $this.NonGroupIssueCount
                        RiskLevel                = $this.RiskLevel
                        Techniques               = $this.VulnerableTechniques -join ', '
                        AffectedPrincipals       = $this.AffectedPrincipalCount
                        GroupsInvolved           = $this.GroupCount
                    }
                    return $summary
                } -Force
                
                Write-Output $AdcsObject
            } catch {
                Write-Warning "Failed to process ADCS object $objectName : $_"
                # Still output the object even if issue attachment failed
                Write-Output $AdcsObject
            }
        }
    }

    end {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Finishing $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
    }
}
