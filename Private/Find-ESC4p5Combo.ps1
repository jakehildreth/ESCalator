function Find-ESC4p5Combo {
    <#
        .SYNOPSIS
        Finds Critical ESC4 (disabled templates) and ESC5 (EnrollmentService subtypes) vulnerability combinations for a specific principal or current user.

        .DESCRIPTION
        This function analyzes ESCalatorIssue objects to identify dangerous combinations of:
        1. Critical ESC4 vulnerabilities with disabled templates (templates NOT enabled on CAs)
        2. Critical ESC5 vulnerabilities with EnrollmentService subtypes
        
        When a principal has both types of vulnerabilities, it represents a potential future attack path where
        the principal could enable vulnerable templates and then exploit them through controlled enrollment services.

        If no principal is provided, the function will analyze combinations that apply to the current user.
        If a specific principal DirectoryEntry is provided, it will analyze combinations for that principal instead.

        .PARAMETER Issues
        An array of ESCalatorIssue objects to analyze. These should be the output from Find-ESC4Issue and Find-ESC5Issue
        functions that have been processed and expanded.

        .PARAMETER Principal
        Optional. A DirectoryEntry object representing a specific security principal to analyze. If provided, the function
        will only return combinations that apply to this principal. If not provided, returns combinations
        that apply to the current user.

        .INPUTS
        ESCalatorIssue[]
        Array of ESCalatorIssue objects from ESC4 and ESC5 vulnerability scans.

        .OUTPUTS
        PSCustomObject[]
        Returns an array of custom objects representing dangerous ESC4d + ESC5 EnrollmentService combinations.
        Each object contains details about both vulnerabilities and the affected principal.

        .EXAMPLE
        # Analyze ESC4d/ESC5 combinations for current user (no principal specified)
        $allIssues = @()
        $allIssues += Find-ESC4Issue -AdcsObjects $AdcsObjects
        $allIssues += Find-ESC5Issue -AdcsObjects $AdcsObjects
        $expandedIssues = $allIssues | Expand-Issue
        $dangerousCombos = Find-ESC4p5Combo -Issues $expandedIssues

        .EXAMPLE
        # Analyze ESC4d/ESC5 combinations for a specific user
        $userPrincipal = Get-DirectoryEntryByUsername -Username "testuser"
        $dangerousCombos = Find-ESC4p5Combo -Issues $expandedIssues -Principal $userPrincipal

        .EXAMPLE
        # Pipeline usage
        $expandedIssues | Find-ESC4p5Combo

        .LINK
        https://posts.specterops.io/certified-pre-owned-d95910965cd2

        .NOTES
        This function focuses on potential future vulnerability combinations:
        - ESC4 vulnerabilities with disabled templates (dormant certificate template control)
        - ESC5 vulnerabilities with EnrollmentService subtypes (CA/enrollment service control)
        
        The combination of these vulnerabilities allows an attacker to potentially enable and modify certificate templates
        and control the enrollment services, representing a critical security risk.
        
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
        $dangerousCombinations = @()
        
        # Get principal display name for logging
        if ($Principal) {
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
            Write-Verbose "Analyzing Critical ESC4d/ESC5 combinations for specific principal: $principalDisplayName"
        } else {
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $currentUserName = $currentUser.Name
            Write-Verbose "No principal specified - analyzing Critical ESC4d/ESC5 combinations for current user: $currentUserName"
        }
    }

    process {
        # Step 1: Find Critical ESC4 issues with disabled templates (NOT enabled on CAs)
        Write-Verbose "Step 1: Finding Critical ESC4 issues with disabled templates..."
        $esc4dIssues = @()
        
        # Get principal info for ESC4 filtering
        $targetPrincipalSid = $null
        $targetPrincipalName = $null
        
        if ($Principal) {
            if ($Principal.Properties['objectSid'].Value) {
                $targetPrincipalSid = (New-Object System.Security.Principal.SecurityIdentifier($Principal.Properties['objectSid'].Value, 0)).Value
            }
            if ($Principal.Properties['sAMAccountName'].Value) {
                $targetPrincipalName = $Principal.Properties['sAMAccountName'].Value
            } elseif ($Principal.Properties['name'].Value) {
                $targetPrincipalName = $Principal.Properties['name'].Value
            }
        } else {
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $targetPrincipalSid = $currentUser.User.Value
            $targetPrincipalName = $currentUser.Name
        }
        
        # Filter for Critical ESC4 issues with templates that are NOT enabled
        foreach ($issue in $Issues) {
            # Skip non-ESCalatorIssue objects
            if ($issue.PSObject.TypeNames[0] -ne 'ESCalatorIssue') {
                continue
            }
            
            # Filter for Critical ESC4 issues only
            if ($issue.Technique -ne 'ESC4' -or $issue.Severity -ne 'Critical') {
                continue
            }
            
            # Check if template is NOT enabled (disabled)
            $templateEnabled = $false
            if ($issue.DirectoryEntry -and $issue.DirectoryEntry.Properties['Enabled']) {
                $templateEnabled = $issue.DirectoryEntry.Properties['Enabled'].Value
            }
            
            if ($templateEnabled) {
                Write-Verbose "Skipping ESC4 issue with enabled template: $($issue.DirectoryEntry.Properties['name'].Value)"
                continue
            }
            
            Write-Verbose "Template '$($issue.DirectoryEntry.Properties['name'].Value)' is disabled on CAs"
            
            # Check if issue applies to target principal
            $appliesToPrincipal = $false
            
            # Check by SID
            if ($targetPrincipalSid -and $issue.IdentityReferenceSID -eq $targetPrincipalSid) {
                $appliesToPrincipal = $true
                Write-Verbose "ESC4 issue matches principal by SID: $targetPrincipalSid"
            }
            
            # Check by name if SID match fails
            if (-not $appliesToPrincipal -and $targetPrincipalName -and $issue.Principal) {
                $shortName = $targetPrincipalName -replace '^.*\\', ''
                if ($issue.Principal -like "*$targetPrincipalName*" -or $issue.Principal -like "*$shortName*") {
                    $appliesToPrincipal = $true
                    Write-Verbose "ESC4 issue matches principal by name: $targetPrincipalName"
                }
            }
            
            if ($appliesToPrincipal) {
                $esc4dIssues += $issue
                Write-Verbose "Found Critical ESC4 issue with disabled template: $($issue.DirectoryEntry.Properties['name'].Value) - $($issue.Principal)"
            }
        }
        
        Write-Verbose "Found $($esc4dIssues.Count) Critical ESC4 issue(s) with disabled templates"
        
        # Step 2: Find Critical ESC5 issues with EnrollmentService subtypes
        Write-Verbose "Step 2: Finding Critical ESC5 issues with EnrollmentService subtypes..."
        $esc5EnrollmentIssues = @()
        
        # Filter for Critical ESC5 issues with EnrollmentService subtypes
        foreach ($issue in $Issues) {
            # Skip non-ESCalatorIssue objects
            if ($issue.PSObject.TypeNames[0] -ne 'ESCalatorIssue') {
                continue
            }
            
            # Filter for Critical ESC5 issues only
            if ($issue.Technique -ne 'ESC5' -or $issue.Severity -ne 'Critical') {
                continue
            }
            
            # Filter for EnrollmentService subtypes
            if ($issue.Subtype -notlike "EnrollmentService*") {
                Write-Verbose "Skipping ESC5 issue with non-EnrollmentService subtype: $($issue.Subtype)"
                continue
            }
            
            # Check if issue applies to target principal
            $appliesToPrincipal = $false
            
            # Check by SID
            if ($targetPrincipalSid -and $issue.IdentityReferenceSID -eq $targetPrincipalSid) {
                $appliesToPrincipal = $true
                Write-Verbose "ESC5 issue matches principal by SID: $targetPrincipalSid"
            }
            
            # Check by name if SID match fails
            if (-not $appliesToPrincipal -and $targetPrincipalName -and $issue.Principal) {
                $shortName = $targetPrincipalName -replace '^.*\\', ''
                if ($issue.Principal -like "*$targetPrincipalName*" -or $issue.Principal -like "*$shortName*") {
                    $appliesToPrincipal = $true
                    Write-Verbose "ESC5 issue matches principal by name: $targetPrincipalName"
                }
            }
            
            if ($appliesToPrincipal) {
                $esc5EnrollmentIssues += $issue
                Write-Verbose "Found Critical ESC5 EnrollmentService issue: $($issue.Name) - $($issue.Subtype)"
            }
        }
        
        Write-Verbose "Found $($esc5EnrollmentIssues.Count) Critical ESC5 EnrollmentService issue(s)"
        
        # Step 3: Create combination objects if both types exist
        if ($esc4dIssues.Count -gt 0 -and $esc5EnrollmentIssues.Count -gt 0) {
            Write-Verbose "Step 3: Creating dangerous combination objects..."
            
            # Group issues by principal for combination analysis
            $principalCombinations = @{}
            
            # Add ESC4d issues to combinations
            foreach ($esc4Issue in $esc4dIssues) {
                $principalKey = $esc4Issue.IdentityReferenceSID -or $esc4Issue.Principal -or "Unknown"
                if (-not $principalCombinations[$principalKey]) {
                    $principalCombinations[$principalKey] = @{
                        PrincipalSID = $esc4Issue.IdentityReferenceSID
                        PrincipalName = $esc4Issue.IdentityReference
                        ESC4dIssues = @()
                        ESC5EnrollmentIssues = @()
                    }
                }
                $principalCombinations[$principalKey].ESC4dIssues += $esc4Issue
            }
            
            # Add ESC5 enrollment issues to combinations
            foreach ($esc5Issue in $esc5EnrollmentIssues) {
                $principalKey = $esc5Issue.IdentityReferenceSID -or $esc5Issue.Principal -or "Unknown"
                if ($principalCombinations[$principalKey]) {
                    $principalCombinations[$principalKey].ESC5EnrollmentIssues += $esc5Issue
                }
            }
            
            # Create combination objects for principals with both types
            foreach ($principalKey in $principalCombinations.Keys) {
                $combo = $principalCombinations[$principalKey]
                if ($combo.ESC4dIssues.Count -gt 0 -and $combo.ESC5EnrollmentIssues.Count -gt 0) {
                    $combinationObject = [PSCustomObject]@{
                        PSTypeName = 'ESC4d_ESC5_Combination'
                        PrincipalSID = $combo.PrincipalSID
                        PrincipalName = $combo.PrincipalName
                        ESC4dCount = $combo.ESC4dIssues.Count
                        ESC5EnrollmentCount = $combo.ESC5EnrollmentIssues.Count
                        ESC4dIssues = $combo.ESC4dIssues
                        ESC5EnrollmentIssues = $combo.ESC5EnrollmentIssues
                        VulnerableTemplates = ($combo.ESC4dIssues | ForEach-Object { 
                            if ($_.DirectoryEntry -and $_.DirectoryEntry.Properties['name'].Value) {
                                $_.DirectoryEntry.Properties['name'].Value
                            }
                        } | Sort-Object -Unique)
                        EnrollmentServices = ($combo.ESC5EnrollmentIssues | ForEach-Object { $_.Name } | Sort-Object -Unique)
                        RiskLevel = "Critical"
                        AttackPath = "Template Modification (ESC4) + Template Enablement (ESC5)"
                    }
                    
                    $dangerousCombinations += $combinationObject
                    Write-Verbose "Created dangerous combination for principal: $($combo.PrincipalName) (ESC4d: $($combo.ESC4dIssues.Count), ESC5: $($combo.ESC5EnrollmentIssues.Count))"
                }
            }
        } else {
            Write-Verbose "Step 3: No dangerous combinations found (ESC4d: $($esc4dIssues.Count), ESC5 EnrollmentService: $($esc5EnrollmentIssues.Count))"
        }
    }

    end {
        Write-Verbose "Found $($dangerousCombinations.Count) dangerous ESC4d/ESC5 combination(s)"
        
        if ($dangerousCombinations.Count -gt 0) {
            $totalESC4d = ($dangerousCombinations | Measure-Object -Property ESC4dCount -Sum).Sum
            $totalESC5 = ($dangerousCombinations | Measure-Object -Property ESC5EnrollmentCount -Sum).Sum
            $uniquePrincipals = ($dangerousCombinations | Select-Object -ExpandProperty PrincipalName | Sort-Object -Unique).Count
            
            Write-Verbose "  Total ESC4d issues: $totalESC4d"
            Write-Verbose "  Total ESC5 EnrollmentService issues: $totalESC5"
            Write-Verbose "  Affected principals: $uniquePrincipals"
            
            # Log vulnerable templates and services
            $allTemplates = $dangerousCombinations | ForEach-Object { $_.VulnerableTemplates } | Sort-Object -Unique
            $allServices = $dangerousCombinations | ForEach-Object { $_.EnrollmentServices } | Sort-Object -Unique
            
            if ($allTemplates) {
                Write-Verbose "  Vulnerable templates: $($allTemplates -join ', ')"
            }
            if ($allServices) {
                Write-Verbose "  Compromised enrollment services: $($allServices -join ', ')"
            }
        }
        
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Finishing $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
        
        # Return the combination objects
        return $dangerousCombinations
    }
}
