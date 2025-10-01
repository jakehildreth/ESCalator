# Import all functions
Get-ChildItem .\ESCalator\Private | ForEach-Object { . $_ }

# Get AD CS objects
$AdcsObjects = Get-AdcsObjects

# Get all issues with AD CS objects
$AllIssues = @(Find-ESC4 -AdcsObjects $ADCSObjects; Find-ESC5 -AdcsObjects $ADCSObjects)

# Attach Issue objects to AD CS objects
$AdcsObjects | Add-IssueToObject -Issues $AllIssues

# Get all individual principals identified in Issues
$AllPrincipals = Get-IndividualPrincipals -Issues $AdcsObjects.SecurityIssues

# Attach Issue objects to Principal Objects
$AllPrincipals | Add-IssueToPrincipal -Issues $AdcsObjects.SecurityIssues