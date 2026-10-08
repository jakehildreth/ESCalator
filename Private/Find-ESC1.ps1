function Find-ESC1 {
    <#
        .SYNOPSIS
        Filters ESC1 issues to those that apply to a specific principal or the current user.

        .DESCRIPTION
        Takes ESCalatorIssue objects from Find-ESC1Issue (already filtered for Critical,
        enabled templates with SAN + Client Auth) and further filters to issues that apply
        to the target principal. ESC1 issues are directly exploitable — no combo needed.

        .PARAMETER Issues
        Array of ESCalatorIssue objects from Find-ESC1Issue (after Expand-Issue).

        .PARAMETER Principal
        Optional DirectoryEntry for a specific principal. Defaults to current user.

        .INPUTS
        ESCalatorIssue[]

        .OUTPUTS
        PSCustomObject[] grouped by principal with ESC1 issue details.

        .EXAMPLE
        $ESC1Issues = Find-ESC1Issue -AdcsObjects $AdcsObjects
        $ExpandedIssues = $ESC1Issues | Expand-Issue
        $ApplicableESC1 = Find-ESC1 -Issues ($ESC1Issues + $ExpandedIssues)

        .LINK
        https://posts.specterops.io/certified-pre-owned-d95910965cd2
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNull()]
        [object[]]$Issues,

        [Parameter()]
        [System.DirectoryServices.DirectoryEntry]$Principal
    )

    begin {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Starting $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."

        $matchedIssues = @()

        if ($Principal) {
            $targetSid = $null
            $targetName = $null
            if ($Principal.Properties['objectSid'].Value) {
                $targetSid = (New-Object System.Security.Principal.SecurityIdentifier($Principal.Properties['objectSid'].Value, 0)).Value
            }
            if ($Principal.Properties['sAMAccountName'].Value) {
                $targetName = $Principal.Properties['sAMAccountName'].Value
            } elseif ($Principal.Properties['name'].Value) {
                $targetName = $Principal.Properties['name'].Value
            }
            Write-Verbose "Analyzing ESC1 issues for principal: $targetName"
        } else {
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $targetSid = $currentUser.User.Value
            $targetName = $currentUser.Name
            Write-Verbose "Analyzing ESC1 issues for current user: $targetName"
        }
    }

    process {
        foreach ($issue in $Issues) {
            if ($issue.PSObject.TypeNames[0] -ne 'ESCalatorIssue') { continue }
            if ($issue.Technique -ne 'ESC1') { continue }
            if ($issue.Severity -ne 'Critical') { continue }

            # Check if issue applies to target principal
            $applies = $false

            # Check by SID
            if ($targetSid -and $issue.IdentityReferenceSID -eq $targetSid) {
                $applies = $true
            }

            # Check by name
            if (-not $applies -and $targetName -and $issue.IdentityReference) {
                $shortName = $targetName -replace '^.*\\', ''
                if ($issue.IdentityReference -like "*$targetName*" -or $issue.IdentityReference -like "*$shortName*") {
                    $applies = $true
                }
            }

            # Well-known implicit-membership SIDs
            if (-not $applies -and $issue.IdentityReferenceSID -in @('S-1-5-11', 'S-1-1-0')) {
                $applies = $true
            }

            if ($applies) {
                Write-Verbose "ESC1 issue applies: $($issue.Name) - $($issue.IdentityReference)"
                $matchedIssues += $issue
            }
        }
    }

    end {
        Write-Verbose "Found $($matchedIssues.Count) applicable ESC1 issue(s)"

        # Group by principal
        $principalGroups = @{}
        foreach ($issue in $matchedIssues) {
            $key = $issue.IdentityReferenceSID -or $issue.IdentityReference -or "Unknown"
            if (-not $principalGroups[$key]) {
                $principalGroups[$key] = @{
                    PrincipalSID = $issue.IdentityReferenceSID
                    PrincipalName = $issue.IdentityReference
                    Issues = @()
                }
            }
            $principalGroups[$key].Issues += $issue
        }

        $results = @()
        foreach ($key in $principalGroups.Keys) {
            $group = $principalGroups[$key]
            $results += [PSCustomObject]@{
                PSTypeName = 'ESC1_Result'
                PrincipalSID = $group.PrincipalSID
                PrincipalName = $group.PrincipalName
                ESC1Count = $group.Issues.Count
                ESC1Issues = $group.Issues
                VulnerableTemplates = ($group.Issues | ForEach-Object {
                    if ($_.DirectoryEntry -and $_.DirectoryEntry.Properties['name'].Value) {
                        $_.DirectoryEntry.Properties['name'].Value
                    }
                } | Sort-Object -Unique)
                RiskLevel = "Critical"
                Attack = "SAN Spoofing (ESC1)"
                Technique = "ESC1"
            }
        }

        return $results
    }
}
