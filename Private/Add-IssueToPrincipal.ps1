function Add-IssueToPrincipal {
    <#
        .SYNOPSIS
        Adds Issue objects as properties to AD principal objects (users, groups, computers).

        .DESCRIPTION
        This function takes AD principal objects (DirectoryEntry or similar) and attaches 
        security issues where they are the affected principal. Unlike Add-Issue which 
        focuses on ADCS objects, this function focuses on the principals themselves.

        .PARAMETER Principals
        Array of AD principal objects (users, groups, computers) to attach issues to.

        .PARAMETER Issues
        Array of Issue objects where these principals are mentioned.

        .INPUTS
        System.DirectoryServices.DirectoryEntry[]
        PSCustomObject[] (Issue objects)

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
        [PSCustomObject[]]$Issues
    )

    begin {
        Write-Verbose "Starting principal issue attachment for $($Issues.Count) issues"
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
            $principalIssues = $Issues | Where-Object { 
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
            
            # Principal-specific risk assessment
            $riskLevel = if ($principalIssues.Count -eq 0) { "None" }
                        elseif ($directIssues.Count -gt 0 -and $inheritedIssues.Count -gt 3) { "Critical" }
                        elseif ($directIssues.Count -gt 0) { "High" }
                        elseif ($inheritedIssues.Count -gt 5) { "High" }
                        elseif ($inheritedIssues.Count -gt 2) { "Medium" }
                        else { "Low" }
            
            $Principal | Add-Member -NotePropertyName "RiskLevel" -NotePropertyValue $riskLevel -Force

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
                    RiskLevel = $this.RiskLevel
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