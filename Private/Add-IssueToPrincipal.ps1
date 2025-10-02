function Add-IssueToPrincipal {
    <#
        .SYNOPSIS
        Adds Issue objects as properties to AD principal objects (users, groups, computers).

        .DESCRIPTION
        This function takes AD principal objects (DirectoryEntry or similar) and attaches 
        security issues where they are the affected principal. Unlike Add-Issue which 
        focuses on AD CS objects, this function focuses on the principals themselves.

        .PARAMETER Principals
        Array of AD principal objects (users, groups, computers) to attach issues to.

        .PARAMETER Issues
        Array of ESCalatorIssue objects where these principals are mentioned.
        Supports multiple arrays that will be automatically flattened.

        .INPUTS
        System.DirectoryServices.DirectoryEntry[]
        ESCalatorIssue[]
        ESCalatorIssue objects from Find-ESC4Issue, Find-ESC5Issue, or other vulnerability scanning functions.
        Supports multiple arrays that will be automatically flattened.

        .OUTPUTS
        System.DirectoryServices.DirectoryEntry[]
        Returns the principal objects with additional issue-related properties.

        .EXAMPLE
        $AllPrincipals = Get-IndividualPrincipals -Issues $AllIssues
        $PrincipalsWithIssues = Add-PrincipalIssue -Principals $AllPrincipals -Issues $AllIssues

        .EXAMPLE
        # Get specific users and attach their issues
        $Users = Get-ADUser -Filter * | Get-ADObject
        $UsersWithIssues = Add-PrincipalIssue -Principals $Users -Issues $AllExpandedIssues
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [object[]]$Principals,
        
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Issues
    )

    begin {
        Write-Verbose "Starting principal issue attachment..."
        
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
        
        Write-Verbose "Processing $($AllIssues.Count) ESCalatorIssue objects for principal attachment"
    }

    process {
        foreach ($Principal in $Principals) {
            $principalName = if ($Principal.samAccountName.Value) { 
                $Principal.samAccountName.Value 
            } elseif ($Principal.samAccountName) { 
                $Principal.samAccountName 
            } else { 
                $Principal.Name 
            }
            
            $principalSID = if ($Principal.objectSid.Value) {
                (New-Object System.Security.Principal.SecurityIdentifier($Principal.objectSid.Value, 0)).Value
            } elseif ($Principal.Sid) {
                $Principal.Sid.Value
            } else {
                $null
            }

            # Find issues where this principal is involved
            $principalIssues = $AllIssues | Where-Object { 
                $_.IdentityReference -eq $principalName -or 
                $_.IdentityReferenceSID -eq $principalSID
            }

            # Categorize issues
            $directIssues = $principalIssues | Where-Object { -not $_.ExpandedFromGroup }
            $inheritedIssues = $principalIssues | Where-Object { $_.ExpandedFromGroup }
            
            # Calculate impact metrics
            $affectedObjects = $principalIssues | Select-Object -ExpandProperty Name -Unique
            $techniques = $principalIssues | Select-Object -ExpandProperty Technique -Unique
            $inheritedFromGroups = $inheritedIssues | Select-Object -ExpandProperty ExpandedFromGroup -Unique

            # Add properties specific to principals
            $Principal | Add-Member -NotePropertyName "SecurityIssues" -NotePropertyValue $principalIssues -Force
            $Principal | Add-Member -NotePropertyName "IssueCount" -NotePropertyValue $principalIssues.Count -Force
            $Principal | Add-Member -NotePropertyName "HasIssues" -NotePropertyValue ($principalIssues.Count -gt 0) -Force
            $Principal | Add-Member -NotePropertyName "DirectIssues" -NotePropertyValue $directIssues -Force
            $Principal | Add-Member -NotePropertyName "InheritedIssues" -NotePropertyValue $inheritedIssues -Force
            $Principal | Add-Member -NotePropertyName "DirectIssueCount" -NotePropertyValue $directIssues.Count -Force
            $Principal | Add-Member -NotePropertyName "InheritedIssueCount" -NotePropertyValue $inheritedIssues.Count -Force
            $Principal | Add-Member -NotePropertyName "AffectedObjects" -NotePropertyValue $affectedObjects -Force
            $Principal | Add-Member -NotePropertyName "AffectedObjectCount" -NotePropertyValue $affectedObjects.Count -Force
            $Principal | Add-Member -NotePropertyName "VulnerableTechniques" -NotePropertyValue $techniques -Force
            $Principal | Add-Member -NotePropertyName "InheritedFromGroups" -NotePropertyValue $inheritedFromGroups -Force
            
            # Principal-specific methods
            $Principal | Add-Member -MemberType ScriptMethod -Name "GetIssuesByObject" -Value {
                param([string]$ObjectName)
                return $this.SecurityIssues | Where-Object { $_.Name -eq $ObjectName }
            } -Force

            $Principal | Add-Member -MemberType ScriptMethod -Name "GetPrincipalSummary" -Value {
                $name = if ($this.samAccountName.Value) { $this.samAccountName.Value } else { $this.samAccountName }
                return [PSCustomObject]@{
                    PrincipalName = $name
                    PrincipalType = $this.objectClass -join ','
                    TotalIssues = $this.IssueCount
                    DirectIssues = $this.DirectIssueCount
                    InheritedIssues = $this.InheritedIssueCount
                    AffectedObjects = $this.AffectedObjectCount
                    InheritedFromGroups = $this.InheritedFromGroups -join ', '
                }
            } -Force

            Write-Output $Principal
        }
    }

    end {
        Write-Verbose "Completed principal issue attachment"
    }
}