# Import all functions
Get-ChildItem "$PSScriptRoot\Private" | ForEach-Object { . $_ }

# Get AD CS objects
$AdcsObjects = Get-AdcsObjects

# Get all issues with AD CS objects
$OriginalIssues = @(Find-ESC4 -AdcsObjects $ADCSObjects; Find-ESC5 -AdcsObjects $ADCSObjects)

# Expand group ESCalatorIssue objects into individual principal ESCalatorIssue objects.
$ExpandedIssues = $OriginalIssues | Expand-Issue

# Attach Issue objects to AD CS objects (using both original and expanded issues)
$AdcsObjects | Add-IssueToObject -Issues $OriginalIssues, $ExpandedIssues

# Get all individual principals identified in Issues
$AllPrincipals = Get-IndividualPrincipals -Issues $OriginalIssues, $ExpandedIssues

# Attach Issue objects to Principal Objects
$AllPrincipals | Add-IssueToPrincipal -Issues $OriginalIssues, $ExpandedIssues