function Find-ESC4p5Combo {
    <#
        .SYNOPSIS
        Finds Critical ESC4 and ESC5 vulnerability combinations for a specific principal or all principals.

        .DESCRIPTION
        This function analyzes ESCalatorIssue objects to identify Critical ESC4 (Vulnerable Certificate Template Access Control)
        and ESC5 (Vulnerable PKI Object Access Control) vulnerabilities that apply to a specific security principal.

        If no principal is provided, the function will analyze Critical ESC4 and ESC5 issues that apply to the current user.
        If a specific principal DirectoryEntry is provided, it will analyze issues for that principal instead.

        The function filters for Critical severity ESC4 and ESC5 issues and returns combinations that represent
        high-impact vulnerabilities where principals have dangerous permissions on certificate templates or PKI objects.

        .PARAMETER Issues
        An array of ESCalatorIssue objects to analyze. These should be the output from Find-ESC4Issue and Find-ESC5Issue
        functions that have been processed and expanded.

        .PARAMETER Principal
        Optional. A DirectoryEntry object representing a specific security principal to analyze. If provided, the function
        will only return Critical ESC4 and ESC5 issues that apply to this principal. If not provided, returns Critical
        ESC4 and ESC5 issues that apply to the current user.

        .INPUTS
        ESCalatorIssue[]
        Array of ESCalatorIssue objects from ESC4 and ESC5 vulnerability scans.

        .OUTPUTS
        ESCalatorIssue[]
        Returns an array of ESCalatorIssue objects representing Critical ESC4 and ESC5 vulnerabilities.

        .EXAMPLE
        # Analyze Critical ESC4/ESC5 issues for current user (no principal specified)
        $allIssues = @()
        $allIssues += Find-ESC4Issue -AdcsObjects $AdcsObjects
        $allIssues += Find-ESC5Issue -AdcsObjects $AdcsObjects
        $expandedIssues = $allIssues | Expand-Issue
        $criticalCombos = Find-ESC4p5Combo -Issues $expandedIssues

        .EXAMPLE
        # Analyze Critical ESC4/ESC5 issues for a specific user
        $userPrincipal = Get-AdcsObjects | Where-Object { $_.Properties['sAMAccountName'].Value -eq 'testuser' }
        $criticalCombos = Find-ESC4p5Combo -Issues $expandedIssues -Principal $userPrincipal

        .EXAMPLE
        # Pipeline usage
        $expandedIssues | Find-ESC4p5Combo

        .LINK
        https://posts.specterops.io/certified-pre-owned-d95910965cd2

        .NOTES
        This function focuses specifically on Critical severity ESC4 and ESC5 issues as these represent
        the highest risk combinations for privilege escalation via certificate services.
        
        The function requires that issues have been properly expanded using Expand-Issue to ensure
        individual principal analysis is possible.
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
        $criticalCombos = @()
        
        # Determine target principal for analysis
        if ($Principal) {
            $principalName = $Principal.Properties['sAMAccountName'].Value -or $Principal.Properties['name'].Value -or $Principal.Properties['distinguishedName'].Value
            Write-Verbose "Analyzing Critical ESC4/ESC5 combinations for specific principal: $principalName"
        } else {
            # No principal specified - analyze for current user
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $currentUserSid = $currentUser.User.Value
            $currentUserName = $currentUser.Name
            Write-Verbose "No principal specified - analyzing Critical ESC4/ESC5 combinations for current user: $currentUserName (SID: $currentUserSid)"
            
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
            
            # Filter for Critical ESC4 and ESC5 issues only
            if ($issue.Technique -notin @('ESC4', 'ESC5')) {
                Write-Verbose "Skipping non-ESC4/ESC5 issue: $($issue.Technique)"
                continue
            }
            
            if ($issue.Severity -ne 'Critical') {
                Write-Verbose "Skipping non-Critical $($issue.Technique) issue: $($issue.Severity) severity"
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
                $principalName = $Principal.Properties['sAMAccountName'].Value -or $Principal.Properties['name'].Value
                $principalDN = $Principal.Properties['distinguishedName'].Value
                
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
            
            # This is a Critical ESC4 or ESC5 issue that matches our criteria
            Write-Verbose "Found Critical $($issue.Technique) issue: $($issue.Name) - $($issue.Principal)"
            $criticalCombos += $issue
        }
    }

    end {
        Write-Verbose "Found $($criticalCombos.Count) Critical ESC4/ESC5 combination(s)"
        
        # Log summary by technique
        $esc4Count = ($criticalCombos | Where-Object { $_.Technique -eq 'ESC4' }).Count
        $esc5Count = ($criticalCombos | Where-Object { $_.Technique -eq 'ESC5' }).Count
        
        Write-Verbose "  ESC4 Critical issues: $esc4Count"
        Write-Verbose "  ESC5 Critical issues: $esc5Count"
        
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Finishing $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
        
        # Return the results
        return $criticalCombos
    }
}
