function Get-IssueCombinationReport {
    <#
        .SYNOPSIS
        Generates comprehensive reports from ESC issue combination analysis results.

        .DESCRIPTION
        This function takes ESC issue combination analysis results and generates various report formats
        including summary statistics, detailed principal analysis, and capability breakdowns.

        .PARAMETER IssueCombinations
        Array of issue combination objects from Find-IssueCombinations.

        .PARAMETER ReportType
        Type of report to generate. Valid values: Summary, Detailed, PrincipalFocus, Steps.

        .PARAMETER GroupByPrincipal
        Group results by principal rather than by issue combination.

        .PARAMETER IncludeStatistics
        Include statistical analysis in the report.

        .PARAMETER ExportPath
        Optional path to export the report as JSON, CSV, or HTML.

        .EXAMPLE
        $IssueCombinations = Find-IssueCombinations -Issues $AllIssues
        Get-IssueCombinationReport -IssueCombinations $IssueCombinations -ReportType Summary

        .EXAMPLE
        Get-IssueCombinationReport -IssueCombinations $IssueCombinations -ReportType Detailed -GroupByPrincipal -IncludeStatistics

        .EXAMPLE
        Get-IssueCombinationReport -IssueCombinations $IssueCombinations -ReportType Summary -ExportPath "C:\Reports\ESC-Analysis.json"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [object[]]$IssueCombinations,
        
        [Parameter()]
        [ValidateSet('Summary', 'Detailed', 'PrincipalFocus', 'Steps')]
        [string]$ReportType = 'Summary',
        
        [Parameter()]
        [switch]$GroupByPrincipal,
        
        [Parameter()]
        [switch]$IncludeStatistics,
        
        [Parameter()]
        [string]$ExportPath
    )

    begin {
        $AllCombinations = @()
    }

    process {
        $AllCombinations += $IssueCombinations
    }

    end {
        Write-Verbose "Generating $ReportType report for $($AllCombinations.Count) issue combinations"
        
        $Report = switch ($ReportType) {
            'Summary' { 
                Get-SummaryReport -IssueCombinations $AllCombinations -IncludeStatistics:$IncludeStatistics
            }
            'Detailed' { 
                Get-DetailedReport -IssueCombinations $AllCombinations -GroupByPrincipal:$GroupByPrincipal
            }
            'PrincipalFocus' { 
                Get-PrincipalFocusReport -IssueCombinations $AllCombinations
            }
            'Steps' { 
                Get-StepsReport -IssueCombinations $AllCombinations
            }
        }
        
        if ($ExportPath) {
            Export-Report -Report $Report -Path $ExportPath
        }
        
        return $Report
    }
}

function Get-SummaryReport {
    param ($IssueCombinations, [switch]$IncludeStatistics)
    
    $Summary = [PSCustomObject]@{
        ReportType = 'ESC Issue Combination Summary'
        GeneratedDate = Get-Date
        TotalIssueCombinations = $IssueCombinations.Count
        UniquePrincipals = ($IssueCombinations | Select-Object PrincipalName -Unique).Count
        UniqueIssueCombinationTypes = ($IssueCombinations | Select-Object IssueCombinationId -Unique).Count
    }
    
    # Top issue combinations by frequency
    $TopIssueCombinations = $IssueCombinations | Group-Object IssueCombinationName | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object {
        [PSCustomObject]@{
            IssueCombinationName = $_.Name
            Count = $_.Count
            UniquePrincipals = ($_.Group | Select-Object PrincipalName -Unique).Count
        }
    }
    
    $Summary | Add-Member -NotePropertyName "TopIssueCombinations" -NotePropertyValue $TopIssueCombinations
    
    # Most vulnerable principals
    $VulnerablePrincipals = $IssueCombinations | Group-Object PrincipalName | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object {
        $PrincipalCombinations = $_.Group
        [PSCustomObject]@{
            PrincipalName = $_.Name
            IssueCombinationCount = $_.Count
            IsExpandedFromGroup = ($PrincipalCombinations | Select-Object -First 1).IsExpandedFromGroup
            ExpandedFromGroup = ($PrincipalCombinations | Select-Object -First 1).ExpandedFromGroup
        }
    }
    
    $Summary | Add-Member -NotePropertyName "MostVulnerablePrincipals" -NotePropertyValue $VulnerablePrincipals
    
    if ($IncludeStatistics) {
        $Stats = [PSCustomObject]@{
            ExpandedFromGroupCount = ($IssueCombinations | Where-Object IsExpandedFromGroup).Count
            DirectPrincipalCount = ($IssueCombinations | Where-Object { -not $_.IsExpandedFromGroup }).Count
            UniqueTemplatesAffected = ($IssueCombinations | ForEach-Object { $_.AffectedTemplates } | Select-Object -Unique).Count
            UniqueCAsAffected = ($IssueCombinations | ForEach-Object { $_.AffectedCAs } | Select-Object -Unique).Count
        }
        
        $Summary | Add-Member -NotePropertyName "Statistics" -NotePropertyValue $Stats
    }
    
    return $Summary
}

function Get-DetailedReport {
    param ($IssueCombinations, [switch]$GroupByPrincipal)
    
    if ($GroupByPrincipal) {
        $GroupedCombinations = $IssueCombinations | Group-Object PrincipalName | ForEach-Object {
            $PrincipalCombinations = $_.Group
            [PSCustomObject]@{
                PrincipalName = $_.Name
                PrincipalSID = ($PrincipalCombinations | Select-Object -First 1).PrincipalSID
                TotalIssueCombinations = $_.Count
                IssueCombinations = $PrincipalCombinations | Select-Object IssueCombinationName, IssueCombinationDescription
                ESC4Capabilities = ($PrincipalCombinations | Select-Object -First 1).ESC4Capabilities
                ESC5Capabilities = ($PrincipalCombinations | Select-Object -First 1).ESC5Capabilities
                AffectedTemplates = ($PrincipalCombinations | ForEach-Object { $_.AffectedTemplates } | Select-Object -Unique)
                AffectedCAs = ($PrincipalCombinations | ForEach-Object { $_.AffectedCAs } | Select-Object -Unique)
                IsExpandedFromGroup = ($PrincipalCombinations | Select-Object -First 1).IsExpandedFromGroup
                ExpandedFromGroup = ($PrincipalCombinations | Select-Object -First 1).ExpandedFromGroup
            }
        } | Sort-Object TotalIssueCombinations -Descending
        
        return $GroupedCombinations
    } else {
        return $IssueCombinations | Sort-Object IssueCombinationName
    }
}

function Get-PrincipalFocusReport {
    param ($IssueCombinations)
    
    $PrincipalAnalysis = $IssueCombinations | Group-Object PrincipalName | ForEach-Object {
        $PrincipalCombinations = $_.Group
        $FirstCombination = $PrincipalCombinations | Select-Object -First 1
        
        # Analyze capability overlap
        $ESC4Count = $FirstCombination.ESC4Capabilities.Count
        $ESC5Count = $FirstCombination.ESC5Capabilities.Count
        
        $CapabilityProfile = if ($ESC4Count -gt 0 -and $ESC5Count -gt 0) { "Full Stack" }
                           elseif ($ESC4Count -gt 0) { "Template Modifier" }
                           elseif ($ESC5Count -gt 0) { "Infrastructure Controller" }
                           else { "Unknown" }
        
        [PSCustomObject]@{
            PrincipalName = $_.Name
            PrincipalSID = $FirstCombination.PrincipalSID
            CapabilityProfile = $CapabilityProfile
            ESC4CapabilityCount = $ESC4Count
            ESC5CapabilityCount = $ESC5Count
            TotalIssueCombinations = $_.Count
            IsExpandedFromGroup = $FirstCombination.IsExpandedFromGroup
            ExpandedFromGroup = $FirstCombination.ExpandedFromGroup
            UniqueTemplatesAffected = ($PrincipalCombinations | ForEach-Object { $_.AffectedTemplates } | Select-Object -Unique).Count
            UniqueCAsAffected = ($PrincipalCombinations | ForEach-Object { $_.AffectedCAs } | Select-Object -Unique).Count
        }
    } | Sort-Object TotalIssueCombinations -Descending
    
    return $PrincipalAnalysis
}

function Get-StepsReport {
    param ($IssueCombinations)
    
    $StepsAnalysis = $IssueCombinations | Group-Object IssueCombinationId | ForEach-Object {
        $CombinationGroup = $_.Group
        $FirstCombination = $CombinationGroup | Select-Object -First 1
        
        [PSCustomObject]@{
            IssueCombinationId = $_.Name
            IssueCombinationName = $FirstCombination.IssueCombinationName
            Description = $FirstCombination.IssueCombinationDescription
            AffectedPrincipalCount = $_.Count
            Steps = $FirstCombination.Steps
            RequiredCapabilities = $FirstCombination.RequiredCapabilities
            ExamplePrincipals = ($CombinationGroup | Select-Object -First 5).PrincipalName
        }
    } | Sort-Object AffectedPrincipalCount -Descending
    
    return $StepsAnalysis
}

function Export-Report {
    param ($Report, $Path)
    
    $Extension = [System.IO.Path]::GetExtension($Path).ToLower()
    
    switch ($Extension) {
        '.json' {
            $Report | ConvertTo-Json -Depth 10 | Set-Content $Path -Encoding UTF8
            Write-Verbose "Report exported to JSON: $Path"
        }
        '.csv' {
            if ($Report -is [Array] -and $Report[0] -is [PSCustomObject]) {
                $Report | Export-Csv $Path -NoTypeInformation -Encoding UTF8
                Write-Verbose "Report exported to CSV: $Path"
            } else {
                Write-Warning "CSV export requires array of PSCustomObjects. Use JSON format for complex reports."
            }
        }
        '.html' {
            $Html = $Report | ConvertTo-Html -Title "ESC Issue Combo Report" -PreContent "<h1>ESC Issue Combo Analysis Report</h1><p>Generated: $(Get-Date)</p>"
            $Html | Set-Content $Path -Encoding UTF8
            Write-Verbose "Report exported to HTML: $Path"
        }
        default {
            Write-Warning "Unsupported export format: $Extension. Supported formats: .json, .csv, .html"
        }
    }
}