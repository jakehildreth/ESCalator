function Get-IssueComboReport {
    <#
        .SYNOPSIS
        Generates comprehensive reports from ESC issue combination analysis results.

        .DESCRIPTION
        This function takes ESC issue combination analysis results and generates various report formats
        including summary statistics, detailed principal analysis, and capability breakdowns.

        .PARAMETER IssueCombos
        Array of issue combination objects from Find-IssueCombos.

        .PARAMETER ReportType
        Type of report to generate. Valid values: Summary, Detailed, PrincipalFocus, Steps.

        .PARAMETER GroupByPrincipal
        Group results by principal rather than by issue combination.

        .PARAMETER IncludeStatistics
        Include statistical analysis in the report.

        .PARAMETER ExportPath
        Optional path to export the report as JSON, CSV, or HTML.

        .EXAMPLE
        $IssueCombos = Find-IssueCombos -Issues $AllIssues
        Get-IssueComboReport -IssueCombos $IssueCombos -ReportType Summary

        .EXAMPLE
        Get-IssueComboReport -IssueCombos $IssueCombos -ReportType Detailed -GroupByPrincipal -IncludeStatistics

        .EXAMPLE
        Get-IssueComboReport -IssueCombos $IssueCombos -ReportType Summary -ExportPath "C:\Reports\ESC-Analysis.json"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [object[]]$IssueCombos,
        
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
        $AllCombinations += $IssueCombos
    }

    end {
        Write-Verbose "Generating $ReportType report for $($AllCombinations.Count) issue combinations"
        
        $Report = switch ($ReportType) {
            'Summary' { 
                Get-SummaryReport -IssueCombos $AllCombinations -IncludeStatistics:$IncludeStatistics
            }
            'Detailed' { 
                Get-DetailedReport -IssueCombos $AllCombinations -GroupByPrincipal:$GroupByPrincipal
            }
            'PrincipalFocus' { 
                Get-PrincipalFocusReport -IssueCombos $AllCombinations
            }
            'Steps' { 
                Get-StepsReport -IssueCombos $AllCombinations
            }
        }
        
        if ($ExportPath) {
            Export-Report -Report $Report -Path $ExportPath
        }
        
        return $Report
    }
}

function Get-SummaryReport {
    param ($IssueCombos, [switch]$IncludeStatistics)
    
    $Summary = [PSCustomObject]@{
        ReportType = 'ESC Issue Combination Summary'
        GeneratedDate = Get-Date
        TotalIssueCombos = $IssueCombos.Count
        UniquePrincipals = ($IssueCombos | Select-Object PrincipalName -Unique).Count
        UniqueIssueComboTypes = ($IssueCombos | Select-Object IssueComboId -Unique).Count
    }
    
    # Top issue combinations by frequency
    $TopIssueCombos = $IssueCombos | Group-Object IssueComboName | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object {
        [PSCustomObject]@{
            IssueComboName = $_.Name
            Count = $_.Count
            UniquePrincipals = ($_.Group | Select-Object PrincipalName -Unique).Count
        }
    }
    
    $Summary | Add-Member -NotePropertyName "TopIssueCombos" -NotePropertyValue $TopIssueCombos
    
    # Most vulnerable principals
    $VulnerablePrincipals = $IssueCombos | Group-Object PrincipalName | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object {
        $PrincipalCombinations = $_.Group
        [PSCustomObject]@{
            PrincipalName = $_.Name
            IssueComboCount = $_.Count
            IsExpandedFromGroup = ($PrincipalCombinations | Select-Object -First 1).IsExpandedFromGroup
            ExpandedFromGroup = ($PrincipalCombinations | Select-Object -First 1).ExpandedFromGroup
        }
    }
    
    $Summary | Add-Member -NotePropertyName "MostVulnerablePrincipals" -NotePropertyValue $VulnerablePrincipals
    
    if ($IncludeStatistics) {
        $Stats = [PSCustomObject]@{
            ExpandedFromGroupCount = ($IssueCombos | Where-Object IsExpandedFromGroup).Count
            DirectPrincipalCount = ($IssueCombos | Where-Object { -not $_.IsExpandedFromGroup }).Count
            UniqueTemplatesAffected = ($IssueCombos | ForEach-Object { $_.AffectedTemplates } | Select-Object -Unique).Count
            UniqueCAsAffected = ($IssueCombos | ForEach-Object { $_.AffectedCAs } | Select-Object -Unique).Count
        }
        
        $Summary | Add-Member -NotePropertyName "Statistics" -NotePropertyValue $Stats
    }
    
    return $Summary
}

function Get-DetailedReport {
    param ($IssueCombos, [switch]$GroupByPrincipal)
    
    if ($GroupByPrincipal) {
        $GroupedCombinations = $IssueCombos | Group-Object PrincipalName | ForEach-Object {
            $PrincipalCombinations = $_.Group
            [PSCustomObject]@{
                PrincipalName = $_.Name
                PrincipalSID = ($PrincipalCombinations | Select-Object -First 1).PrincipalSID
                TotalIssueCombos = $_.Count
                IssueCombos = $PrincipalCombinations | Select-Object IssueComboName, IssueComboDescription
                ESC4Capabilities = ($PrincipalCombinations | Select-Object -First 1).ESC4Capabilities
                ESC5Capabilities = ($PrincipalCombinations | Select-Object -First 1).ESC5Capabilities
                AffectedTemplates = ($PrincipalCombinations | ForEach-Object { $_.AffectedTemplates } | Select-Object -Unique)
                AffectedCAs = ($PrincipalCombinations | ForEach-Object { $_.AffectedCAs } | Select-Object -Unique)
                IsExpandedFromGroup = ($PrincipalCombinations | Select-Object -First 1).IsExpandedFromGroup
                ExpandedFromGroup = ($PrincipalCombinations | Select-Object -First 1).ExpandedFromGroup
            }
        } | Sort-Object TotalIssueCombos -Descending
        
        return $GroupedCombinations
    } else {
        return $IssueCombos | Sort-Object IssueComboName
    }
}

function Get-PrincipalFocusReport {
    param ($IssueCombos)
    
    $PrincipalAnalysis = $IssueCombos | Group-Object PrincipalName | ForEach-Object {
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
            TotalIssueCombos = $_.Count
            IsExpandedFromGroup = $FirstCombination.IsExpandedFromGroup
            ExpandedFromGroup = $FirstCombination.ExpandedFromGroup
            UniqueTemplatesAffected = ($PrincipalCombinations | ForEach-Object { $_.AffectedTemplates } | Select-Object -Unique).Count
            UniqueCAsAffected = ($PrincipalCombinations | ForEach-Object { $_.AffectedCAs } | Select-Object -Unique).Count
        }
    } | Sort-Object TotalIssueCombos -Descending
    
    return $PrincipalAnalysis
}

function Get-StepsReport {
    param ($IssueCombos)
    
    $StepsAnalysis = $IssueCombos | Group-Object IssueComboId | ForEach-Object {
        $CombinationGroup = $_.Group
        $FirstCombination = $CombinationGroup | Select-Object -First 1
        
        [PSCustomObject]@{
            IssueComboId = $_.Name
            IssueComboName = $FirstCombination.IssueComboName
            Description = $FirstCombination.IssueComboDescription
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