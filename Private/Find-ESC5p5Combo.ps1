function Find-ESC5p5Combo {
    <#
        .SYNOPSIS
        Find Critical ESC5 (CertTemplatesContainer and EnrollmentService subtypes) vulnerability combinations.

        .DESCRIPTION
        This function analyzes ESCalatorIssue objects to identify dangerous combinations of Critical ESC5 vulnerabilities
        where a principal has both CertTemplatesContainer and EnrollmentService subtype vulnerabilities.
        
        CertTemplatesContainer subtypes allow modification of certificate template containers, while EnrollmentService
        subtypes allow control over enrollment services. Having both provides comprehensive control over the
        certificate infrastructure.

        .PARAMETER Issues
        An array of ESCalatorIssue objects to analyze for Critical ESC5 combinations.

        .PARAMETER Principal
        Optional. A DirectoryEntry object representing a specific principal to analyze. If not provided,
        analyzes combinations for the current user context.

        .INPUTS
        System.Object[] - Array of ESCalatorIssue objects
        System.DirectoryServices.DirectoryEntry - Optional principal object

        .OUTPUTS
        PSCustomObject[] - Array of ESC5_Combination objects containing detailed information about
        Critical ESC5 CertTemplatesContainer and EnrollmentService combinations.

        .EXAMPLE
        Find-ESC5p5Combo -Issues $AllIssues
        
        Finds Critical ESC5 combinations for the current user.

        .EXAMPLE
        Find-ESC5p5Combo -Issues $AllIssues -Principal $horsePrincipal -Verbose
        
        Finds Critical ESC5 combinations for a specific principal with verbose output.

        .NOTES
        This function specifically looks for:
        - Critical ESC5 issues with subtypes starting with "CertTemplatesContainer"
        - Critical ESC5 issues with subtypes starting with "EnrollmentService" 
        - Creates combination objects when a principal has both types
        
        Requires PowerShell 7.4 or later.

        .LINK
        https://github.com/jakehildreth/ESCalator
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
            Write-Verbose "Analyzing Critical ESC5 CertTemplatesContainer/EnrollmentService combinations for specific principal: $principalDisplayName"
        } else {
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $currentUserName = $currentUser.Name
            Write-Verbose "No principal specified - analyzing Critical ESC5 CertTemplatesContainer/EnrollmentService combinations for current user: $currentUserName"
        }
    }

    process {
        # Step 1: Find Critical ESC5 issues with CertTemplatesContainer subtypes
        Write-Verbose "Step 1: Finding Critical ESC5 issues with CertTemplatesContainer subtypes..."
        $esc5CertTemplatesIssues = @()
        
        # Step 2: Find Critical ESC5 issues with EnrollmentService subtypes
        Write-Verbose "Step 2: Finding Critical ESC5 issues with EnrollmentService subtypes..."
        $esc5EnrollmentIssues = @()
        
        # Get principal info for ESC5 filtering
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
        
        # Filter for Critical ESC5 issues with CertTemplatesContainer and EnrollmentService subtypes
        foreach ($issue in $Issues) {
            # Skip non-ESCalatorIssue objects
            if ($issue.PSObject.TypeNames[0] -ne 'ESCalatorIssue') {
                continue
            }
            
            # Filter for Critical ESC5 issues only
            if ($issue.Technique -ne 'ESC5' -or $issue.Severity -ne 'Critical') {
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
                # Check for CertTemplatesContainer subtypes
                if ($issue.Subtype -like "CertTemplatesContainer*") {
                    $esc5CertTemplatesIssues += $issue
                    Write-Verbose "Found Critical ESC5 CertTemplatesContainer issue: $($issue.Name) - $($issue.Subtype)"
                }
                
                # Check for EnrollmentService subtypes
                if ($issue.Subtype -like "EnrollmentService*") {
                    $esc5EnrollmentIssues += $issue
                    Write-Verbose "Found Critical ESC5 EnrollmentService issue: $($issue.Name) - $($issue.Subtype)"
                }
            }
        }
        
        Write-Verbose "Found $($esc5CertTemplatesIssues.Count) Critical ESC5 CertTemplatesContainer issue(s)"
        Write-Verbose "Found $($esc5EnrollmentIssues.Count) Critical ESC5 EnrollmentService issue(s)"
        
        # Step 3: Create combination objects if both types exist
        if ($esc5CertTemplatesIssues.Count -gt 0 -and $esc5EnrollmentIssues.Count -gt 0) {
            Write-Verbose "Step 3: Creating dangerous combination objects..."
            
            # Group issues by principal for combination analysis
            $principalCombinations = @{}
            
            # Add ESC5 CertTemplatesContainer issues to combinations
            foreach ($certTemplatesIssue in $esc5CertTemplatesIssues) {
                $principalKey = $certTemplatesIssue.IdentityReferenceSID -or $certTemplatesIssue.Principal -or "Unknown"
                if (-not $principalCombinations[$principalKey]) {
                    $principalCombinations[$principalKey] = @{
                        PrincipalSID = $certTemplatesIssue.IdentityReferenceSID
                        PrincipalName = $certTemplatesIssue.Principal
                        ESC5CertTemplatesIssues = @()
                        ESC5EnrollmentIssues = @()
                    }
                }
                $principalCombinations[$principalKey].ESC5CertTemplatesIssues += $certTemplatesIssue
            }
            
            # Add ESC5 enrollment issues to combinations
            foreach ($enrollmentIssue in $esc5EnrollmentIssues) {
                $principalKey = $enrollmentIssue.IdentityReferenceSID -or $enrollmentIssue.Principal -or "Unknown"
                if ($principalCombinations[$principalKey]) {
                    $principalCombinations[$principalKey].ESC5EnrollmentIssues += $enrollmentIssue
                }
            }
            
            # Create combination objects for principals with both types
            foreach ($principalKey in $principalCombinations.Keys) {
                $combo = $principalCombinations[$principalKey]
                if ($combo.ESC5CertTemplatesIssues.Count -gt 0 -and $combo.ESC5EnrollmentIssues.Count -gt 0) {
                    $combinationObject = [PSCustomObject]@{
                        PSTypeName = 'ESC5_Combination'
                        PrincipalSID = $combo.PrincipalSID
                        PrincipalName = $combo.PrincipalName
                        ESC5CertTemplatesCount = $combo.ESC5CertTemplatesIssues.Count
                        ESC5EnrollmentCount = $combo.ESC5EnrollmentIssues.Count
                        ESC5CertTemplatesIssues = $combo.ESC5CertTemplatesIssues
                        ESC5EnrollmentIssues = $combo.ESC5EnrollmentIssues
                        CertTemplatesContainers = ($combo.ESC5CertTemplatesIssues | ForEach-Object { $_.Name } | Sort-Object -Unique)
                        EnrollmentServices = ($combo.ESC5EnrollmentIssues | ForEach-Object { $_.Name } | Sort-Object -Unique)
                        CertTemplatesSubtypes = ($combo.ESC5CertTemplatesIssues | ForEach-Object { $_.Subtype } | Sort-Object -Unique)
                        EnrollmentSubtypes = ($combo.ESC5EnrollmentIssues | ForEach-Object { $_.Subtype } | Sort-Object -Unique)
                        RiskLevel = "Critical"
                        AttackPath = "Certificate Templates Container Control (ESC5) + Enrollment Service Control (ESC5)"
                    }
                    
                    $dangerousCombinations += $combinationObject
                    Write-Verbose "Created dangerous combination for principal: $($combo.PrincipalName) (CertTemplates: $($combo.ESC5CertTemplatesIssues.Count), EnrollmentService: $($combo.ESC5EnrollmentIssues.Count))"
                }
            }
        } else {
            Write-Verbose "Step 3: No dangerous combinations found (CertTemplatesContainer: $($esc5CertTemplatesIssues.Count), EnrollmentService: $($esc5EnrollmentIssues.Count))"
        }
    }

    end {
        Write-Verbose "Found $($dangerousCombinations.Count) dangerous ESC5 combination(s)"
        
        if ($dangerousCombinations.Count -gt 0) {
            $totalCertTemplates = ($dangerousCombinations | Measure-Object -Property ESC5CertTemplatesCount -Sum).Sum
            $totalEnrollment = ($dangerousCombinations | Measure-Object -Property ESC5EnrollmentCount -Sum).Sum
            $uniquePrincipals = ($dangerousCombinations | Select-Object -ExpandProperty PrincipalName | Sort-Object -Unique).Count
            
            Write-Verbose "  Total ESC5 CertTemplatesContainer issues: $totalCertTemplates"
            Write-Verbose "  Total ESC5 EnrollmentService issues: $totalEnrollment"
            Write-Verbose "  Affected principals: $uniquePrincipals"
            
            # Log containers and services
            $allContainers = $dangerousCombinations | ForEach-Object { $_.CertTemplatesContainers } | Sort-Object -Unique
            $allServices = $dangerousCombinations | ForEach-Object { $_.EnrollmentServices } | Sort-Object -Unique
            
            if ($allContainers) {
                Write-Verbose "  Vulnerable certificate template containers: $($allContainers -join ', ')"
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
