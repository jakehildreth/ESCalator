function Add-IssueToObject {
    <#
        .SYNOPSIS
        Adds Issue objects as properties to DirectoryEntry objects from AD CS scans.

        .DESCRIPTION
        This function takes DirectoryEntry objects from Get-AdcsObjects and attaches security issues
        found by Find-ESC4Issue, Find-ESC5Issue, and other vulnerability scanning functions as properties.

        .PARAMETER AdcsObjects
        Array of DirectoryEntry objects from Get-AdcsObjects to attach issues to.

        .PARAMETER Issues
        Array of ESCalatorIssue objects from Find-ESC4Issue, Find-ESC5Issue, or other vulnerability scanning functions.
        Supports multiple arrays that will be automatically flattened.

        .INPUTS
        System.DirectoryServices.DirectoryEntry[]
        DirectoryEntry objects from Get-AdcsObjects
        ESCalatorIssue[]
        ESCalatorIssue objects from Find-ESC4Issue, Find-ESC5Issue, or other vulnerability scanning functions.
        Supports multiple arrays that will be automatically flattened.

        .OUTPUTS
        Object[]
        Returns the original objects with additional issue-related properties added.

        .EXAMPLE
        $AdcsObjects = Get-AdcsObjects
        $ESC4Issues = Find-ESC4Issue -AdcsObjects $AdcsObjects
        $ESC5Issues = Find-ESC5Issue -AdcsObjects $AdcsObjects
        $AllIssues = @($ESC4Issues; $ESC5Issues)
        $ObjectsWithIssues = Add-Issue -AdcsObjects $AdcsObjects -Issues $AllIssues

        .EXAMPLE
        $AdcsObjects = Get-AdcsObjects
        $Issues = @(Find-ESC4Issue -AdcsObjects $AdcsObjects; Find-ESC5Issue -AdcsObjects $AdcsObjects)
        $ObjectsWithIssues = Add-Issue -AdcsObjects $AdcsObjects -Issues $Issues
        $VulnerableObjects = $ObjectsWithIssues | Where-Object { $_.HasIssues }

        .EXAMPLE
        # Pipeline usage
        Get-AdcsObjects | Add-Issue -Issues $AllIssues | Where-Object { $_.HasIssues }

        .LINK
        https://posts.specterops.io/certified-pre-owned-d95910965cd2
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [System.DirectoryServices.DirectoryEntry[]]$AdcsObjects,
        
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Issues
    )


    begin {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Starting $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
        
        # Load ESCalatorIssue class if not already loaded
        if (-not ([System.Management.Automation.PSTypeName]'ESCalatorIssue').Type) {
            $escalatorIssuePath = Join-Path $PSScriptRoot "ESCalatorIssue.ps1"
            if (Test-Path $escalatorIssuePath) {
                . $escalatorIssuePath
            } else {
                throw "ESCalatorIssue class not found. Please ensure ESCalatorIssue.ps1 is available."
            }
        }
        
        # Flatten any nested arrays and validate all items are ESCalatorIssue objects
        $AllIssues = @()
        $NonESCalatorIssues = @()
        
        $Issues | ForEach-Object { 
            if ($_.PSObject.TypeNames[0] -eq 'ESCalatorIssue') { 
                $AllIssues += $_ 
            } elseif ($_ -is [Array]) {
                # Recursively flatten nested arrays
                $_ | ForEach-Object { 
                    if ($_.PSObject.TypeNames[0] -eq 'ESCalatorIssue') { 
                        $AllIssues += $_ 
                    } else {
                        $NonESCalatorIssues += $_
                    }
                }
            } else {
                $NonESCalatorIssues += $_
            }
        }
        
        # Warn about non-ESCalatorIssue objects but continue processing
        if ($NonESCalatorIssues.Count -gt 0) {
            Write-Warning "Found $($NonESCalatorIssues.Count) non-ESCalatorIssue objects that will be ignored. Expected ESCalatorIssue objects."
        }
        
        Write-Verbose "Processing $($AllIssues.Count) ESCalatorIssue objects for attachment to AD CS objects"
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
            
            Write-Verbose "Processing AD CS object: $objectName"
            
            try {
                # Find issues related to this object
                $relatedIssues = $AllIssues | Where-Object { 
                    $_.Name -eq $objectName -or 
                    $_.DistinguishedName -eq $objectDN 
                }
                
                Write-Verbose "Found $($relatedIssues.Count) issues for object: $objectName"
                
                # Group issues by technique for easier analysis
                $issuesByTechnique = $relatedIssues | Group-Object Technique -AsHashTable -AsString
                
                # Get unique techniques and affected principals
                $techniques = $relatedIssues | Select-Object -ExpandProperty Technique -Unique
                $affectedPrincipals = $relatedIssues | Select-Object -ExpandProperty IdentityReference -Unique
                
                # Add comprehensive issue information as properties
                $AdcsObject | Add-Member -NotePropertyName "SecurityIssues" -NotePropertyValue $relatedIssues -Force
                $AdcsObject | Add-Member -NotePropertyName "IssueCount" -NotePropertyValue $relatedIssues.Count -Force
                $AdcsObject | Add-Member -NotePropertyName "HasIssues" -NotePropertyValue ($relatedIssues.Count -gt 0) -Force
                $AdcsObject | Add-Member -NotePropertyName "IssuesByTechnique" -NotePropertyValue $issuesByTechnique -Force
                $AdcsObject | Add-Member -NotePropertyName "VulnerableTechniques" -NotePropertyValue $techniques -Force
                $AdcsObject | Add-Member -NotePropertyName "AffectedPrincipals" -NotePropertyValue $affectedPrincipals -Force
                $AdcsObject | Add-Member -NotePropertyName "AffectedPrincipalCount" -NotePropertyValue $affectedPrincipals.Count -Force
                
                # Add convenience methods for common operations
                $AdcsObject | Add-Member -MemberType ScriptMethod -Name "GetIssuesByTechnique" -Value {
                    param([string]$Technique)
                    return $this.SecurityIssues | Where-Object { $_.Technique -eq $Technique }
                } -Force
                
                $AdcsObject | Add-Member -MemberType ScriptMethod -Name "GetIssueSummary" -Value {
                    $objName = if ($this.Name.Value) { $this.Name.Value } elseif ($this.Name) { $this.Name } else { "Unknown" }
                    $summary = [PSCustomObject]@{
                        ObjectName          = $objName
                        TotalIssues         = $this.IssueCount
                        Techniques          = $this.VulnerableTechniques -join ', '
                        AffectedPrincipals  = $this.AffectedPrincipalCount
                    }
                    return $summary
                } -Force
                
                Write-Output $AdcsObject
            } catch {
                Write-Warning "Failed to process AD CS object $objectName : $_"
                # Still output the object even if issue attachment failed
                Write-Output $AdcsObject
            }
        }
    }

    end {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Finishing $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
    }
}
