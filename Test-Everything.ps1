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

# NEW: Find ESC Issue Combinations
Write-Host "`n🎯 Analyzing ESC Issue Combinations..." -ForegroundColor Cyan
$IssueCombos = Find-IssueCombos -Issues $OriginalIssues, $ExpandedIssues -Verbose

# Display summary
if ($IssueCombos) {
    Write-Host "`n✅ Found $($IssueCombos.Count) ESC issue combination capabilities!" -ForegroundColor Green
    
    # Show issue combinations summary
    Write-Host "`n� AD CS ISSUE COMBINATIONS FOUND:" -ForegroundColor Yellow
    $IssueCombos | Format-Table PrincipalName, IssueComboName, ESC4Capabilities, ESC5Capabilities -AutoSize
    
    # Generate comprehensive report
    Write-Host "`n📊 Generating Issue Combination Report..." -ForegroundColor Cyan
    $IssueComboReport = Get-IssueComboReport -IssueCombos $IssueCombos -ReportType Summary -IncludeStatistics
    $IssueComboReport | Format-List
    
} else {
    Write-Host "`n✅ No ESC issue combination capabilities found." -ForegroundColor Green
}