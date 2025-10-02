function Find-IssueCombinations {
    <#
        .SYNOPSIS
        Identifies principals capable of creating ESC1 vulnerable certificate templates through AD CS issue combinations.

        .DESCRIPTION
        This function analyzes ESC4 and ESC5 vulnerabilities to identify complete issue combinations that enable
        principals to create ESC1 vulnerable certificate templates. It loads issue combination definitions from
        JSON configuration files and matches principal capabilities against required prerequisites.

        .PARAMETER Issues
        Array of ESCalatorIssue objects from Find-ESC4 and Find-ESC5 scans.
        Supports multiple arrays that will be automatically flattened.

        .PARAMETER ConfigPath
        Path to the ESC1 issue combinations configuration file. Defaults to IssueCombinations directory.

        .PARAMETER IncludePartialChains
        Include principals with partial issue combination capabilities (may require additional access).

        .INPUTS
        ESCalatorIssue[]
        Objects from Find-ESC4 and Find-ESC5 vulnerability scans.

        .OUTPUTS
        PSCustomObject[]
        Returns objects describing principals with ESC1 issue combination capabilities.

        Each output object contains:
        - PrincipalName: The principal (user/group) name
        - PrincipalSID: The principal's security identifier
        - IssueCombinationId: ID of the issue combination the principal can execute
        - IssueCombinationName: Descriptive name of the issue combination
        - ESC4Capabilities: Array of ESC4 capabilities the principal has
        - ESC5Capabilities: Array of ESC5 capabilities the principal has
        - AffectedTemplates: Certificate templates the principal can modify
        - AffectedCAs: Certificate Authorities the principal can control
        - Steps: Detailed steps for this combination
        - IsExpandedFromGroup: Whether this represents a group member
        - ExpandedFromGroup: Original group if expanded

        .EXAMPLE
        $AllIssues = @(Find-ESC4 -AdcsObjects $AdcsObjects; Find-ESC5 -AdcsObjects $AdcsObjects)
        $IssueCombinations = Find-IssueCombinations -Issues $AllIssues
        $IssueCombinations | Format-Table PrincipalName, IssueCombinationName
        
        .EXAMPLE
        # Include partial capabilities
        $AllCombinations = Find-IssueCombinations -Issues $AllIssues -IncludePartialChains

        .EXAMPLE
        # Analyze specific principal's capabilities
        $UserCombinations = Find-IssueCombinations -Issues $AllIssues | Where-Object { $_.PrincipalName -like "*john.doe*" }
        $UserCombinations | Select-Object IssueCombinationName, ESC4Capabilities, ESC5Capabilities, Steps

        .LINK
        https://posts.specterops.io/certified-pre-owned-d95910965cd2
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowEmptyCollection()]
        [object[]]$Issues,
        
        [Parameter()]
        [string]$ConfigPath = (Join-Path $PSScriptRoot "ComboDefinitions"),
        
        [Parameter()]
        [switch]$IncludePartialChains
    )

    begin {
        Write-Verbose "Starting ESC1 issue combination analysis..."
        
        # Load shared configuration
        $SharedConfigPath = Join-Path $ConfigPath "SharedConfig.json"
        if (-not (Test-Path $SharedConfigPath)) {
            throw "Shared configuration file not found: $SharedConfigPath"
        }
        
        try {
            $SharedConfig = Get-Content $SharedConfigPath -Raw | ConvertFrom-Json
            Write-Verbose "Loaded shared configuration version $($SharedConfig.metadata.version)"
        } catch {
            throw "Failed to load shared configuration: $_"
        }
        
        # Load individual issue combination files
        $IssueCombinationFiles = Get-ChildItem -Path $ConfigPath -Filter "EC*.json"
        if ($IssueCombinationFiles.Count -eq 0) {
            throw "No issue combination files found in: $ConfigPath"
        }
        
        $IssueCombinations = @()
        foreach ($File in $IssueCombinationFiles) {
            try {
                $Combination = Get-Content $File.FullName -Raw | ConvertFrom-Json
                $IssueCombinations += $Combination
                Write-Verbose "Loaded issue combination: $($Combination.id) - $($Combination.name)"
            } catch {
                Write-Warning "Failed to load issue combination file $($File.Name): $_"
            }
        }
        
        if ($IssueCombinations.Count -eq 0) {
            throw "No valid issue combination configurations loaded"
        }
        
        Write-Verbose "Loaded $($IssueCombinations.Count) issue combination configurations"
        
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
            Write-Warning "Found $($NonESCalatorIssues.Count) non-ESCalatorIssue objects that will be ignored."
        }
        
        Write-Verbose "Processing $($AllIssues.Count) ESCalatorIssue objects for attack chain analysis"
    }

    process {
        # Group issues by principal
        $PrincipalGroups = $AllIssues | Group-Object IdentityReference
        
        Write-Verbose "Analyzing $($PrincipalGroups.Count) unique principals for attack chain capabilities"
        
        foreach ($PrincipalGroup in $PrincipalGroups) {
            $PrincipalName = $PrincipalGroup.Name
            $PrincipalIssues = $PrincipalGroup.Group
            
            # Get principal SID (use first available)
            $PrincipalSID = ($PrincipalIssues | Where-Object { $_.IdentityReferenceSID } | Select-Object -First 1).IdentityReferenceSID
            
            # Separate ESC4 and ESC5 issues
            $ESC4Issues = $PrincipalIssues | Where-Object { $_.Technique -eq 'ESC4' }
            $ESC5Issues = $PrincipalIssues | Where-Object { $_.Technique -eq 'ESC5' }
            
            # Extract capabilities
            $ESC4Capabilities = @($ESC4Issues | Select-Object -ExpandProperty Subtype -Unique)
            $ESC5Capabilities = @($ESC5Issues | Select-Object -ExpandProperty Subtype -Unique)
            
            # Get affected objects
            $AffectedTemplates = $ESC4Issues | Select-Object -ExpandProperty Name -Unique
            $AffectedCAs = $ESC5Issues | Where-Object { $_.Subtype -like "*EnrollmentService*" } | Select-Object -ExpandProperty Name -Unique
            
            # Check expansion info
            $IsExpanded = $PrincipalIssues | Where-Object { $_.ExpandedFromGroup } | Select-Object -First 1
            $IsExpandedFromGroup = $null -ne $IsExpanded
            $ExpandedFromGroup = if ($IsExpanded) { $IsExpanded.ExpandedFromGroup } else { $null }
            
            Write-Verbose "Analyzing principal $PrincipalName with $($ESC4Capabilities.Count) ESC4 and $($ESC5Capabilities.Count) ESC5 capabilities"
            
            # Test each issue combination
            foreach ($IssueCombination in $IssueCombinations) {
                $CanExecuteChain = Test-IssueCombinationCapabilities -IssueCombination $IssueCombination -ESC4Capabilities $ESC4Capabilities -ESC5Capabilities $ESC5Capabilities -IncludePartialChains:$IncludePartialChains
                
                if ($CanExecuteChain.CanExecute) {
                    Write-Verbose "Principal $PrincipalName can execute issue combination $($IssueCombination.id): $($IssueCombination.name)"
                    
                    [PSCustomObject]@{
                        PrincipalName = $PrincipalName
                        PrincipalSID = $PrincipalSID
                        IssueCombinationId = $IssueCombination.id
                        IssueCombinationName = $IssueCombination.name
                        IssueCombinationDescription = $IssueCombination.description
                        ESC4Capabilities = $ESC4Capabilities
                        ESC5Capabilities = $ESC5Capabilities
                        AffectedTemplates = $AffectedTemplates
                        AffectedCAs = $AffectedCAs
                        Steps = $IssueCombination.steps
                        IsExpandedFromGroup = $IsExpandedFromGroup
                        ExpandedFromGroup = $ExpandedFromGroup
                        CapabilityAnalysis = $CanExecuteChain.Analysis
                        RequiredCapabilities = $IssueCombination.requiredCapabilities
                    }
                }
            }
        }
    }

    end {
        Write-Verbose "Completed ESC1 issue combination analysis"
    }
}

function Test-IssueCombinationCapabilities {
    <#
        .SYNOPSIS
        Tests if a principal has the required capabilities for a specific issue combination.
        
        .DESCRIPTION
        Helper function that evaluates whether given ESC4/ESC5 capabilities satisfy
        the requirements for a specific issue combination definition.
    #>
    param (
        [Parameter(Mandatory)]
        [object]$IssueCombination,
        
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$ESC4Capabilities,
        
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$ESC5Capabilities,
        
        [Parameter()]
        [switch]$IncludePartialChains
    )
    
    $Analysis = @{
        ESC4Requirements = @()
        ESC5Requirements = @()
        MissingCapabilities = @()
        SatisfiedRequirements = 0
        TotalRequirements = 0
    }
    
    $AllRequirementsMet = $true
    
    # Check ESC4 requirements
    if ($IssueCombination.requiredCapabilities.esc4) {
        foreach ($Requirement in $IssueCombination.requiredCapabilities.esc4) {
            $Analysis.TotalRequirements++
            $RequirementMet = $false
            
            if ($Requirement.anyOf) {
                # Check if principal has any of the required capabilities
                $MatchingCapabilities = $ESC4Capabilities | Where-Object { $_ -in $Requirement.anyOf }
                if ($MatchingCapabilities) {
                    $RequirementMet = $true
                    $Analysis.SatisfiedRequirements++
                    $Analysis.ESC4Requirements += [PSCustomObject]@{
                        Type = 'anyOf'
                        Required = $Requirement.anyOf
                        Satisfied = $MatchingCapabilities
                        Description = $Requirement.description
                    }
                } else {
                    $Analysis.MissingCapabilities += "ESC4: Need any of [$($Requirement.anyOf -join ', ')]"
                }
            }
            
            if ($Requirement.allOf) {
                # Check if principal has all required capability groups
                $AllGroupsMet = $true
                $SatisfiedGroups = @()
                
                foreach ($Group in $Requirement.allOf) {
                    $GroupMet = $false
                    if ($Group.anyOf) {
                        $MatchingInGroup = $ESC4Capabilities | Where-Object { $_ -in $Group.anyOf }
                        if ($MatchingInGroup) {
                            $GroupMet = $true
                            $SatisfiedGroups += $MatchingInGroup
                        }
                    }
                    
                    if (-not $GroupMet) {
                        $AllGroupsMet = $false
                        $Analysis.MissingCapabilities += "ESC4: Need any of [$($Group.anyOf -join ', ')]"
                    }
                }
                
                if ($AllGroupsMet) {
                    $RequirementMet = $true
                    $Analysis.SatisfiedRequirements++
                    $Analysis.ESC4Requirements += [PSCustomObject]@{
                        Type = 'allOf'
                        Required = $Requirement.allOf
                        Satisfied = $SatisfiedGroups
                        Description = $Requirement.description
                    }
                }
            }
            
            if (-not $RequirementMet) {
                $AllRequirementsMet = $false
            }
        }
    }
    
    # Check ESC5 requirements
    if ($IssueCombination.requiredCapabilities.esc5) {
        foreach ($Requirement in $IssueCombination.requiredCapabilities.esc5) {
            $Analysis.TotalRequirements++
            $RequirementMet = $false
            
            if ($Requirement.anyOf) {
                # Check if principal has any of the required capabilities
                $MatchingCapabilities = $ESC5Capabilities | Where-Object { $_ -in $Requirement.anyOf }
                if ($MatchingCapabilities) {
                    $RequirementMet = $true
                    $Analysis.SatisfiedRequirements++
                    $Analysis.ESC5Requirements += [PSCustomObject]@{
                        Type = 'anyOf'
                        Required = $Requirement.anyOf
                        Satisfied = $MatchingCapabilities
                        Description = $Requirement.description
                    }
                } else {
                    $Analysis.MissingCapabilities += "ESC5: Need any of [$($Requirement.anyOf -join ', ')]"
                }
            }
            
            if (-not $RequirementMet) {
                $AllRequirementsMet = $false
            }
        }
    }
    
    # Determine if chain can be executed
    $CanExecute = $AllRequirementsMet
    
    # If including partial chains, allow execution if majority of requirements are met
    if (-not $CanExecute -and $IncludePartialChains -and $Analysis.TotalRequirements -gt 0) {
        $CompletionPercentage = ($Analysis.SatisfiedRequirements / $Analysis.TotalRequirements) * 100
        $CanExecute = $CompletionPercentage -ge 50  # Allow if 50% or more requirements are met
    }
    
    return [PSCustomObject]@{
        CanExecute = $CanExecute
        Analysis = $Analysis
    }
}