# Import all functions
Set-Location -Path C:\Users\Administrator.horse\Documents\ESCalator
Get-ChildItem ".\Private\*.ps1" | ForEach-Object { . $_ }
Get-ChildItem ".\Public\*.ps1" | ForEach-Object { . $_ }

# Get AD CS objects
$AdcsObjects = Get-AdcsObjects
$EnabledTemplates = $AdcsObjects | Get-EnabledTemplate
$AdcsObjects | Set-EnabledTemplateStatus -EnabledTemplates $EnabledTemplates | Out-Null

# Get Safe User SIDs
$SafeUsers = Expand-SafeUsers

# Get all issues with AD CS objects
$OriginalIssues = @(Find-ESC4Issue -AdcsObjects $AdcsObjects; Find-ESC5Issue -AdcsObjects $AdcsObjects)

# Expand group ESCalatorIssue objects into individual principal ESCalatorIssue objects.
$ExpandedIssues = $OriginalIssues | Expand-Issue

# Attach Issue objects to AD CS objects (using both original and expanded issues)
$AdcsObjects | Add-IssueToObject -Issues $OriginalIssues, $ExpandedIssues | Out-Null

# Get all individual principals identified in Issues
$AllPrincipals = Get-IndividualPrincipals -Issues $OriginalIssues, $ExpandedIssues

# Attach Issue objects to Principal Objects
$AllPrincipals | Add-IssueToPrincipal -Issues $OriginalIssues, $ExpandedIssues | Out-Null

# Mini report
$AllIssues = $OriginalIssues + $ExpandedIssues
@"
Original Issues: $($OriginalIssues.Count)
Expanded Issues: $($ExpandedIssues.Count)
All Issues:      $($AllIssues.Count)
ESC4s:           $($AllIssues.Where({$_.Technique -eq 'ESC4'}).Count)
ESC5s:           $($AllIssues.Where({$_.Technique -eq 'ESC5'}).Count)
"@