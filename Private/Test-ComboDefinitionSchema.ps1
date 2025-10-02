function Test-ComboDefinitionSchema {
    <#
        .SYNOPSIS
        Validates ESC Issue Combination JSON definitions against the standard schema.

        .DESCRIPTION
        This function validates ESC Issue Combination JSON files against the standardized schema
        to ensure consistency and completeness of combo definitions.

        .PARAMETER Path
        Path to the JSON file to validate, or directory containing JSON files.

        .PARAMETER SchemaPath
        Path to the JSON schema file. Defaults to schema.json in the same directory.

        .PARAMETER Detailed
        Return detailed validation results including all errors and warnings.

        .INPUTS
        String
        File or directory path for validation.

        .OUTPUTS
        PSCustomObject
        Validation results with status, errors, and warnings.

        .EXAMPLE
        Test-ComboDefinitionSchema -Path "C:\ESCalator\ComboDefinitions\EC000-EnabledTemplateModification.json"

        .EXAMPLE
        Test-ComboDefinitionSchema -Path "C:\ESCalator\ComboDefinitions" -Detailed

        .LINK
        https://json-schema.org/
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Path,
        
        [Parameter()]
        [string]$SchemaPath,
        
        [Parameter()]
        [switch]$Detailed
    )

    begin {
        # Set default schema path if not provided
        if (-not $SchemaPath) {
            $SchemaPath = Join-Path $PSScriptRoot "ComboDefinitions\schema.json"
        }
        
        # Verify schema file exists
        if (-not (Test-Path $SchemaPath)) {
            throw "Schema file not found: $SchemaPath"
        }
        
        Write-Verbose "Loading schema from: $SchemaPath"
        try {
            $Schema = Get-Content $SchemaPath -Raw | ConvertFrom-Json
        } catch {
            throw "Failed to load schema: $_"
        }
    }

    process {
        $results = @()
        
        # Determine if path is file or directory
        if (Test-Path $Path -PathType Container) {
            $jsonFiles = Get-ChildItem -Path $Path -Filter "EC*.json" -File
            Write-Verbose "Found $($jsonFiles.Count) combo definition files to validate"
        } elseif (Test-Path $Path -PathType Leaf) {
            $jsonFiles = @(Get-Item $Path)
        } else {
            throw "Path not found: $Path"
        }
        
        foreach ($file in $jsonFiles) {
            Write-Verbose "Validating: $($file.Name)"
            
            $result = [PSCustomObject]@{
                FileName = $file.Name
                FilePath = $file.FullName
                IsValid = $false
                Errors = @()
                Warnings = @()
                ValidationTime = Get-Date
            }
            
            try {
                # Load and parse JSON
                $jsonContent = Get-Content $file.FullName -Raw
                $definition = $jsonContent | ConvertFrom-Json
                
                # Basic structure validation
                $result.Errors += Test-RequiredProperties -Definition $definition -Schema $Schema
                $result.Warnings += Test-RecommendedProperties -Definition $definition
                
                # Validate specific fields
                $result.Errors += Test-IdFormat -Definition $definition
                $result.Errors += Test-CapabilityFormat -Definition $definition
                $result.Errors += Test-Prerequisites -Definition $definition
                $result.Warnings += Test-AttackChainCompleteness -Definition $definition
                
                # Schema-specific validations
                $result.Errors += Test-MetadataValidation -Definition $definition
                $result.Warnings += Test-TemplateModificationConsistency -Definition $definition
                
                # Determine overall validity
                $result.IsValid = ($result.Errors.Count -eq 0)
                
            } catch {
                $result.Errors += "JSON parsing failed: $_"
                $result.IsValid = $false
            }
            
            $results += $result
        }
        
        return $results
    }
}

function Test-RequiredProperties {
    param($Definition, $Schema)
    
    $errors = @()
    $requiredProps = $Schema.required
    
    foreach ($prop in $requiredProps) {
        if (-not $Definition.PSObject.Properties[$prop]) {
            $errors += "Missing required property: $prop"
        }
    }
    
    return $errors
}

function Test-RecommendedProperties {
    param($Definition)
    
    $warnings = @()
    $recommended = @('templateModifications', 'validation')
    
    foreach ($prop in $recommended) {
        if (-not $Definition.PSObject.Properties[$prop]) {
            $warnings += "Missing recommended property: $prop"
        }
    }
    
    return $warnings
}

function Test-IdFormat {
    param($Definition)
    
    $errors = @()
    
    if ($Definition.id -notmatch '^EC\d{3}$') {
        $errors += "Invalid ID format: $($Definition.id). Expected: EC000-EC999"
    }
    
    return $errors
}

function Test-CapabilityFormat {
    param($Definition)
    
    $errors = @()
    $validCapabilityPattern = '^(GenericAll|GenericWrite|WriteProperty|WriteOwner|WriteDacl|CreateChild|Owner)-(Template|EnrollmentService|CertTemplates|Object)(-(AllObjects|[A-Za-z0-9]+))?$'
    
    if ($Definition.requiredCapabilities) {
        foreach ($escType in @('esc4', 'esc5')) {
            if ($Definition.requiredCapabilities.$escType) {
                foreach ($requirement in $Definition.requiredCapabilities.$escType) {
                    if ($requirement.capabilities) {
                        foreach ($capability in $requirement.capabilities) {
                            if ($capability -notmatch $validCapabilityPattern) {
                                $errors += "Invalid capability format in $escType`: $capability"
                            }
                        }
                    }
                }
            }
        }
    }
    
    return $errors
}

function Test-Prerequisites {
    param($Definition)
    
    $errors = @()
    
    if ($Definition.prerequisites) {
        $prereq = $Definition.prerequisites
        
        # Check templateState
        if ($prereq.templateState -and $prereq.templateState -notin @('enabled', 'disabled', 'any')) {
            $errors += "Invalid templateState: $($prereq.templateState). Expected: enabled, disabled, or any"
        }
        
        # Ensure arrays are actually arrays
        foreach ($arrayProp in @('principalRequirements', 'infrastructureRequirements')) {
            if ($prereq.$arrayProp -and $prereq.$arrayProp -isnot [array]) {
                $errors += "Property $arrayProp must be an array"
            }
        }
    }
    
    return $errors
}

function Test-AttackChainCompleteness {
    param($Definition)
    
    $warnings = @()
    
    if ($Definition.attackChain -and $Definition.attackChain.phases) {
        foreach ($phase in $Definition.attackChain.phases) {
            if (-not $phase.actions -or $phase.actions.Count -eq 0) {
                $warnings += "Phase '$($phase.name)' has no actions defined"
            }
            
            if ($phase.actions) {
                foreach ($action in $phase.actions) {
                    if (-not $action.powershellCommand) {
                        $warnings += "Action '$($action.action)' missing PowerShell command example"
                    }
                }
            }
        }
    } else {
        $warnings += "No attack chain phases defined"
    }
    
    return $warnings
}

function Test-MetadataValidation {
    param($Definition)
    
    $errors = @()
    
    if ($Definition.metadata) {
        $meta = $Definition.metadata
        
        # Version format
        if ($meta.version -and $meta.version -notmatch '^\d+\.\d+(\.\d+)?$') {
            $errors += "Invalid version format: $($meta.version). Expected: X.Y or X.Y.Z"
        }
        
        # Date format
        if ($meta.lastUpdated -and $meta.lastUpdated -notmatch '^\d{4}-\d{2}-\d{2}$') {
            $errors += "Invalid date format: $($meta.lastUpdated). Expected: YYYY-MM-DD"
        }
        
        # Valid enums
        $validCategories = @('Template Modification', 'Template Creation', 'Infrastructure Control', 'Privilege Escalation')
        if ($meta.category -and $meta.category -notin $validCategories) {
            $errors += "Invalid category: $($meta.category). Expected: $($validCategories -join ', ')"
        }
        
        $validDifficulties = @('Low', 'Medium', 'High', 'Expert')
        if ($meta.difficulty -and $meta.difficulty -notin $validDifficulties) {
            $errors += "Invalid difficulty: $($meta.difficulty). Expected: $($validDifficulties -join ', ')"
        }
        
        $validRiskLevels = @('Low', 'Medium', 'High', 'Critical')
        if ($meta.riskLevel -and $meta.riskLevel -notin $validRiskLevels) {
            $errors += "Invalid riskLevel: $($meta.riskLevel). Expected: $($validRiskLevels -join ', ')"
        }
    }
    
    return $errors
}

function Test-TemplateModificationConsistency {
    param($Definition)
    
    $warnings = @()
    
    if ($Definition.templateModifications) {
        $validAttributes = @(
            'msPKI-Certificate-Application-Policy',
            'msPKI-Certificate-Name-Flag', 
            'msPKI-Enrollment-Flag',
            'msPKI-Template-Security-Descriptor',
            'msPKI-RA-Signature',
            'pkiExtendedKeyUsage',
            'displayName',
            'msPKI-Template-Schema-Version'
        )
        
        foreach ($mod in $Definition.templateModifications) {
            if ($mod.attribute -and $mod.attribute -notin $validAttributes) {
                $warnings += "Uncommon template attribute: $($mod.attribute)"
            }
            
            if (-not $mod.requiredCapability) {
                $warnings += "Template modification missing required capability mapping: $($mod.attribute)"
            }
        }
    }
    
    return $warnings
}

# Export the main function
Export-ModuleMember -Function Test-ComboDefinitionSchema