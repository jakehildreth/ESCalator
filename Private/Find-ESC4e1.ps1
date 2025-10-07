function Find-ESC4e1 {
    <#
        .SYNOPSIS
        Finds Critical ESC4 vulnerabilities with templates that are enabled on one or more CAs for a specific principal or current user.

        .DESCRIPTION
        This function analyzes ESCalatorIssue objects to identify Critical ESC4 (Vulnerable Certificate Template Access Control)
        vulnerabilities where the vulnerable templates are enabled on one or more Certificate Authorities.

        If no principal is provided, the function will analyze Critical ESC4 issues that apply to the current user.
        If a specific principal DirectoryEntry is provided, it will analyze issues for that principal instead.

        The function filters for Critical severity ESC4 issues and additionally verifies that the affected certificate
        templates are actually enabled/published on at least one Certificate Authority, making them actively exploitable.

        .PARAMETER Issues
        An array of ESCalatorIssue objects to analyze. These should be the output from Find-ESC4Issue
        function that has been processed and expanded.

        .PARAMETER Principal
        Optional. A DirectoryEntry object representing a specific security principal to analyze. If provided, the function
        will only return Critical ESC4 issues that apply to this principal. If not provided, returns Critical
        ESC4 issues that apply to the current user.

        .INPUTS
        ESCalatorIssue[]
        Array of ESCalatorIssue objects from ESC4 vulnerability scans.

        .OUTPUTS
        PSCustomObject[]
        Returns an array of custom objects representing Critical ESC4 vulnerabilities with enabled templates.
        Each object contains details about the vulnerability, affected principal, and enabled templates.

        .EXAMPLE
        # Analyze Critical ESC4 issues with enabled templates for current user (no principal specified)
        $esc4Issues = Find-ESC4Issue -AdcsObjects $AdcsObjects
        $expandedIssues = $esc4Issues | Expand-Issue
        $enabledESC4 = Find-ESC4e1 -Issues $expandedIssues

        .EXAMPLE
        # Analyze Critical ESC4 issues with enabled templates for a specific user
        $userPrincipal = Get-AdcsObjects | Where-Object { $_.Properties['sAMAccountName'].Value -eq 'testuser' }
        $enabledESC4 = Find-ESC4e1 -Issues $expandedIssues -Principal $userPrincipal

        .EXAMPLE
        # Pipeline usage
        $expandedIssues | Find-ESC4e1

        .LINK
        https://posts.specterops.io/certified-pre-owned-d95910965cd2

        .NOTES
        This function focuses specifically on Critical severity ESC4 issues where the vulnerable certificate
        templates are enabled on one or more CAs, representing actively exploitable vulnerabilities.
        
        The function requires that issues have been properly expanded using Expand-Issue to ensure
        individual principal analysis is possible.
        
        Templates must be enabled/published on at least one CA to be considered exploitable, as disabled
        templates cannot be used for certificate enrollment attacks.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNull()]
        [object[]]$Issues,
        
        [Parameter()]
        [System.DirectoryServices.DirectoryEntry]$Principal
    )

    #requires -Version 7.4

    begin {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Starting $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
        
        # Initialize results array
        $enabledESC4Issues = @()
        
        # Determine target principal for analysis
        if ($Principal) {
            # Get the principal name properly
            $principalDisplayName = $null
            if ($Principal.Properties['sAMAccountName'].Value) {
                $principalDisplayName = $Principal.Properties['sAMAccountName'].Value
            } elseif ($Principal.Properties['name'].Value) {
                $principalDisplayName = $Principal.Properties['name'].Value
            } elseif ($Principal.Properties['distinguishedName'].Value) {
                $principalDisplayName = $Principal.Properties['distinguishedName'].Value
            } else {
                $principalDisplayName = "Unknown"
            }
            Write-Verbose "Analyzing Critical ESC4 issues with enabled templates for specific principal: $principalDisplayName"
        } else {
            # No principal specified - analyze for current user
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $currentUserSid = $currentUser.User.Value
            $currentUserName = $currentUser.Name
            Write-Verbose "No principal specified - analyzing Critical ESC4 issues with enabled templates for current user: $currentUserName (SID: $currentUserSid)"
            
            # Store current user info for comparison
            $targetUserSid = $currentUserSid
            $targetUserName = $currentUserName
        }
    }

    process {
        # Process all issues in the current pipeline input
        foreach ($issue in $Issues) {
            # Validate that this is an ESCalatorIssue object
            if ($issue.PSObject.TypeNames[0] -ne 'ESCalatorIssue') {
                Write-Warning "Skipping non-ESCalatorIssue object: $($issue.GetType().Name)"
                continue
            }
            
            # Filter for Critical ESC4 issues only
            if ($issue.Technique -ne 'ESC4') {
                Write-Verbose "Skipping non-ESC4 issue: $($issue.Technique)"
                continue
            }
            
            if ($issue.Severity -ne 'Critical') {
                Write-Verbose "Skipping non-Critical ESC4 issue: $($issue.Severity) severity"
                continue
            }
            
            # Check if the template is enabled on one or more CAs
            $templateEnabled = $false
            if ($issue.DirectoryEntry -and $issue.DirectoryEntry.SchemaClassName -eq 'pKICertificateTemplate') {
                try {
                    # Check if the template has the Enabled property set by Set-EnabledTemplateStatus
                    $templateName = $issue.DirectoryEntry.Properties['name'].Value
                    
                    if ($issue.DirectoryEntry.PSObject.Properties['Enabled']) {
                        $templateEnabled = $issue.DirectoryEntry.Enabled
                        if ($templateEnabled) {
                            Write-Verbose "Template '$templateName' is enabled on one or more CAs"
                        } else {
                            Write-Verbose "Template '$templateName' is not enabled on any CAs, skipping"
                            continue
                        }
                    } else {
                        Write-Warning "Template '$templateName' does not have Enabled property set - ensure Set-EnabledTemplateStatus was called"
                        continue
                    }
                } catch {
                    Write-Warning "Failed to check template enabled status: $($_.Exception.Message)"
                    continue
                }
            } else {
                Write-Verbose "Issue does not target a certificate template, skipping"
                continue
            }
            
            # Filter for issues that apply to the target principal (specific principal or current user)
            if ($Principal) {
                # Specific principal provided - use existing logic
                $principalSid = $null
                $principalName = $null
                
                # Get principal identifiers for comparison
                if ($Principal.Properties['objectSid'].Value) {
                    $principalSid = (New-Object System.Security.Principal.SecurityIdentifier($Principal.Properties['objectSid'].Value, 0)).Value
                }
                
                # Fix the boolean issue with -or operator
                $principalName = $null
                if ($Principal.Properties['sAMAccountName'].Value) {
                    $principalName = $Principal.Properties['sAMAccountName'].Value
                } elseif ($Principal.Properties['name'].Value) {
                    $principalName = $Principal.Properties['name'].Value
                }
                
                $principalDN = $Principal.Properties['distinguishedName'].Value
                
                Write-Verbose "Checking issue against principal - SID: $principalSid, Name: $principalName, DN: $principalDN"
                Write-Verbose "Issue details - Principal: '$($issue.Principal)', IdentityReferenceSID: '$($issue.IdentityReferenceSID)'"
                
                # Check if the issue applies to this principal
                $appliesToPrincipal = $false
                
                # Check by SID if available
                if ($principalSid -and $issue.IdentityReferenceSID) {
                    if ($issue.IdentityReferenceSID -eq $principalSid) {
                        $appliesToPrincipal = $true
                        Write-Verbose "Issue matches principal by SID: $principalSid"
                    }
                }
                
                # Check by name if SID match fails
                if (-not $appliesToPrincipal -and $principalName -and $issue.Principal) {
                    if ($issue.Principal -like "*$principalName*" -or $issue.Principal -eq $principalName) {
                        $appliesToPrincipal = $true
                        Write-Verbose "Issue matches principal by name: $principalName"
                    }
                }
                
                # Check by DN if other matches fail
                if (-not $appliesToPrincipal -and $principalDN -and $issue.Principal) {
                    if ($issue.Principal -eq $principalDN) {
                        $appliesToPrincipal = $true
                        Write-Verbose "Issue matches principal by DN: $principalDN"
                    }
                }
                
                # Skip if this issue doesn't apply to the specified principal
                if (-not $appliesToPrincipal) {
                    Write-Verbose "Issue does not apply to specified principal, skipping"
                    continue
                }
            } else {
                # No principal specified - check if issue applies to current user
                $appliesToCurrentUser = $false
                
                # Check by SID if available
                if ($issue.IdentityReferenceSID -and $issue.IdentityReferenceSID -eq $targetUserSid) {
                    $appliesToCurrentUser = $true
                    Write-Verbose "Issue matches current user by SID: $targetUserSid"
                }
                
                # Check by name if SID match fails
                if (-not $appliesToCurrentUser -and $issue.Principal) {
                    # Extract just the username from domain\username format
                    $currentUserShortName = $targetUserName -replace '^.*\\', ''
                    if ($issue.Principal -like "*$currentUserShortName*" -or $issue.Principal -like "*$targetUserName*") {
                        $appliesToCurrentUser = $true
                        Write-Verbose "Issue matches current user by name: $targetUserName"
                    }
                }
                
                # Skip if this issue doesn't apply to the current user
                if (-not $appliesToCurrentUser) {
                    Write-Verbose "Issue does not apply to current user, skipping"
                    continue
                }
            }
            
            # This is a Critical ESC4 issue with an enabled template that matches our criteria
            Write-Verbose "Found Critical ESC4 issue with enabled template: $($issue.Name) - $($issue.Principal)"
            $enabledESC4Issues += $issue
        }
    }

    end {
        Write-Verbose "Found $($enabledESC4Issues.Count) Critical ESC4 issue(s) with enabled templates"
        
        # Group issues by principal and create structured objects
        $principalGroups = @{}
        $structuredResults = @()
        
        # Group issues by principal
        foreach ($issue in $enabledESC4Issues) {
            $principalKey = $issue.IdentityReferenceSID -or $issue.IdentityReference -or "Unknown"
            if (-not $principalGroups[$principalKey]) {
                $principalGroups[$principalKey] = @{
                    PrincipalSID = $issue.IdentityReferenceSID
                    PrincipalName = $issue.IdentityReference
                    Issues = @()
                }
            }
            $principalGroups[$principalKey].Issues += $issue
        }
        
        # Create structured objects for each principal
        foreach ($principalKey in $principalGroups.Keys) {
            $group = $principalGroups[$principalKey]
            $structuredObject = [PSCustomObject]@{
                PSTypeName = 'ESC4e1_Result'
                PrincipalSID = $group.PrincipalSID
                PrincipalName = $group.PrincipalName
                ESC4e1Count = $group.Issues.Count
                ESC4e1Issues = $group.Issues
                VulnerableTemplates = ($group.Issues | ForEach-Object {
                    if ($_.DirectoryEntry -and $_.DirectoryEntry.Properties['name'].Value) {
                        $_.DirectoryEntry.Properties['name'].Value
                    }
                } | Sort-Object -Unique)
                EnabledTemplateCount = ($group.Issues | ForEach-Object {
                    if ($_.DirectoryEntry -and $_.DirectoryEntry.Properties['name'].Value) {
                        $_.DirectoryEntry.Properties['name'].Value
                    }
                } | Sort-Object -Unique | Measure-Object).Count
                RiskLevel = "Critical"
                Attack = "Template Modification (ESC4e1)"
                Technique = "ESC4"
                EnabledStatus = "Enabled"
            }
            
            $structuredResults += $structuredObject
            Write-Verbose "Created ESC4e1 result for principal: $($group.PrincipalName) (Issues: $($group.Issues.Count), Templates: $($structuredObject.EnabledTemplateCount))"
        }
        
        if ($structuredResults.Count -gt 0) {
            $totalIssues = ($structuredResults | Measure-Object -Property ESC4e1Count -Sum).Sum
            $uniquePrincipals = ($structuredResults | Select-Object -ExpandProperty PrincipalName | Sort-Object -Unique).Count
            $allTemplates = $structuredResults | ForEach-Object { $_.VulnerableTemplates } | Sort-Object -Unique
            
            Write-Verbose "  Total ESC4e1 issues: $totalIssues"
            Write-Verbose "  Affected principals: $uniquePrincipals"
            if ($allTemplates) {
                Write-Verbose "  Enabled vulnerable templates: $($allTemplates -join ', ')"
            }
        }
        
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Finishing $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
        
        # Return the structured results
        return $structuredResults
    }
}