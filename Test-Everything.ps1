# Import all functions
Set-Location -Path C:\Users\Administrator.horse\Documents\ESCalator
Get-ChildItem ".\Private\*.ps1" | ForEach-Object { . $_ }
Get-ChildItem ".\Public\*.ps1" | ForEach-Object { . $_ }

# Get AD CS objects
$AdcsObjects = Get-AdcsObjects

# Get all issues with AD CS objects
$OriginalIssues = @(Find-ESC4 -AdcsObjects $AdcsObjects; Find-ESC5 -AdcsObjects $AdcsObjects)

# Expand group ESCalatorIssue objects into individual principal ESCalatorIssue objects.
$ExpandedIssues = $OriginalIssues | Expand-Issue

# Attach Issue objects to AD CS objects (using both original and expanded issues)
$AdcsObjects | Add-IssueToObject -Issues $OriginalIssues, $ExpandedIssues

# Get all individual principals identified in Issues
$AllPrincipals = Get-IndividualPrincipals -Issues $OriginalIssues, $ExpandedIssues

# Attach Issue objects to Principal Objects
$AllPrincipals | Add-IssueToPrincipal -Issues $OriginalIssues, $ExpandedIssues

# NEW: Find ESC1 Issue Combinations
Write-Host "`n🎯 Analyzing ESC1 Issue Combinations..." -ForegroundColor Cyan
$ESC1IssueCombinations = Find-ESC1IssueCombinations -Issues $OriginalIssues, $ExpandedIssues -Verbose

# Display summary
if ($ESC1IssueCombinations) {
    Write-Host "`n✅ Found $($ESC1IssueCombinations.Count) ESC1 issue combination capabilities!" -ForegroundColor Green
    
    # Show issue combinations summary
    Write-Host "`n� AD CS ISSUE COMBINATIONS FOUND:" -ForegroundColor Yellow
    $ESC1IssueCombinations | Format-Table PrincipalName, IssueCombinationName, ESC4Capabilities, ESC5Capabilities -AutoSize
    
    # Generate comprehensive report
    Write-Host "`n📊 Generating Issue Combination Report..." -ForegroundColor Cyan
    $IssueCombinationReport = Get-ESC1IssueCombinationReport -IssueCombinations $ESC1IssueCombinations -ReportType Summary -IncludeStatistics
    $IssueCombinationReport | Format-List
    
} else {
    Write-Host "`n✅ No ESC1 issue combination capabilities found." -ForegroundColor Green
}