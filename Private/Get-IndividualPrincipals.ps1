function Get-IndividualPrincipals {
    <#
        .SYNOPSIS
        Extracts DirectoryEntry objects for all individual principals identified in ESC4/ESC5 issues.

        .DESCRIPTION
        This function takes ESCalatorIssue objects from Find-ESC4 and Find-ESC5 and returns DirectoryEntry 
        objects for each unique individual principal (users, computers) that has been identified 
        with permissions on AD CS objects. For well-known security principals that don't exist in Active Directory
        (like SYSTEM), it creates mock DirectoryEntry objects with appropriate properties. Supports automatic array flattening for multiple input arrays.

        .PARAMETER Issues
        Array of ESCalatorIssue objects from Find-ESC4, Find-ESC5, or other vulnerability scanning functions.
        Supports multiple arrays that will be automatically flattened.

        .PARAMETER IncludeGroups
        Switch to include group principals in the output. By default, only individual users and computers are included.

        .INPUTS
        ESCalatorIssue[]
        ESCalatorIssue objects with IdentityReference and IdentityReferenceSID properties.
        Supports multiple arrays that will be automatically flattened.

        .OUTPUTS
        System.DirectoryServices.DirectoryEntry[]
        DirectoryEntry objects for each unique individual principal. For well-known security principals
        that don't exist in Active Directory, returns mock DirectoryEntry objects with TypeName 'MockDirectoryEntry'.

        .EXAMPLE
        $AdcsObjects = Get-AdcsObjects
        $AllIssues = @(Find-ESC4 -AdcsObjects $AdcsObjects; Find-ESC5 -AdcsObjects $AdcsObjects)
        $ObjectsWithIssues = Add-Issue -AdcsObjects $AdcsObjects -Issues $AllIssues
        $AllIndividualMemberIssues = $ObjectsWithIssues | ForEach-Object { $_.IndividualMemberIssues }
        $IndividualPrincipals = Get-IndividualPrincipals -Issues $AllIndividualMemberIssues
        $IndividualPrincipals | Select-Object Name, samAccountName, objectClass

        .EXAMPLE
        # Include groups in the output
        $AllPrincipals = Get-IndividualPrincipals -Issues $AllIndividualMemberIssues -IncludeGroups

        .LINK
        https://posts.specterops.io/certified-pre-owned-d95910965cd2
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [object[]]$Issues,
        
        [Parameter()]
        [switch]$IncludeGroups
    )

    #requires -Version 5

    begin {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Starting $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
        
        # Load ESCalatorIssue class if not already loaded
        if (-not ([System.Management.Automation.PSTypeName]'ESCalatorIssue').Type) {
            $escalatorIssuePath = Join-Path $PSScriptRoot "ESCalatorIssue.ps1"
            if (Test-Path $escalatorIssuePath) {
                . $escalatorIssuePath
            } else {
                throw "ESCalatorIssue class not found. Please ensure ESCalatorIssue.ps1 is available."
            }
        }
        
        $principalSIDs = @{}
        $AllIssues = @()
        $NonESCalatorIssues = @()
    }

    process {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Processing $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
        
        # Flatten any nested arrays and validate all items are ESCalatorIssue objects
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
            Write-Warning "Found $($NonESCalatorIssues.Count) non-ESCalatorIssue objects that will be ignored. Expected ESCalatorIssue objects."
        }
        
        foreach ($issue in $AllIssues) {
            Write-Verbose "Processing issue for principal: $($issue.IdentityReference)"
            
            try {
                # Skip groups if not requested
                if (-not $IncludeGroups -and $issue.MemberType -eq 'GroupPrincipal') {
                    Write-Verbose "Skipping group principal: $($issue.IdentityReference)"
                    continue
                }
                
                # Collect unique SIDs
                if ($issue.IdentityReferenceSID -and -not $principalSIDs.ContainsKey($issue.IdentityReferenceSID)) {
                    $principalSIDs[$issue.IdentityReferenceSID] = $issue.IdentityReference
                }
                
            } catch {
                Write-Warning "Failed to process issue for principal $($issue.IdentityReference): $_"
            }
        }
    }

    end {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Processing final results for $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
        Write-Verbose "Found $($principalSIDs.Count) unique principals"
        
        $directoryEntries = @()
        
        foreach ($sid in $principalSIDs.Keys) {
            try {
                Write-Verbose "Creating DirectoryEntry for SID: $sid ($($principalSIDs[$sid]))"
                
                # Create DirectoryEntry using the SID
                $searcher = New-Object System.DirectoryServices.DirectorySearcher
                $searcher.Filter = "(objectSid=$sid)"
                $searcher.PropertiesToLoad.AddRange(@('distinguishedName', 'samAccountName', 'name', 'objectClass', 'objectSid'))
                
                $result = $searcher.FindOne()
                if ($result) {
                    $directoryEntry = $result.GetDirectoryEntry()
                    $directoryEntries += $directoryEntry
                    Write-Verbose "Successfully created DirectoryEntry for: $($directoryEntry.Name)"
                } else {
                    Write-Verbose "Could not find AD object for SID: $sid ($($principalSIDs[$sid])). Trying well-known security principal paths."
                    
                    # Dynamically enumerate well-known security principals from AD
                    try {
                        # Get the root DSE to find the configuration naming context
                        $rootDSE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
                        $configNC = $rootDSE.Properties['configurationNamingContext'][0]
                        
                        # Search the WellKnown Security Principals container
                        $wellKnownPath = "LDAP://CN=WellKnown Security Principals,$configNC"
                        Write-Verbose "Searching well-known security principals in: $wellKnownPath"
                        
                        $wellKnownSearcher = New-Object System.DirectoryServices.DirectorySearcher
                        $wellKnownSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($wellKnownPath)
                        $wellKnownSearcher.Filter = "(objectClass=foreignSecurityPrincipal)"
                        $wellKnownSearcher.PropertiesToLoad.AddRange(@('distinguishedName', 'objectSid', 'name'))
                        
                        $wellKnownResults = $wellKnownSearcher.FindAll()
                        
                        $foundWellKnownPrincipal = $false
                        foreach ($wellKnownResult in $wellKnownResults) {
                            try {
                                $wellKnownSidBytes = $wellKnownResult.Properties['objectsid'][0]
                                $wellKnownSid = New-Object System.Security.Principal.SecurityIdentifier($wellKnownSidBytes, 0)
                                
                                if ($wellKnownSid.Value -eq $sid) {
                                    $wellKnownDN = $wellKnownResult.Properties['distinguishedname'][0]
                                    Write-Verbose "Found matching well-known principal: $wellKnownDN"
                                    
                                    $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$wellKnownDN")
                                    
                                    # Verify this is the correct object by checking if we can access its properties
                                    $null = $directoryEntry.Properties.Count
                                    
                                    $directoryEntries += $directoryEntry
                                    Write-Verbose "Successfully created DirectoryEntry for well-known principal: $($principalSIDs[$sid])"
                                    $foundWellKnownPrincipal = $true
                                    break
                                }
                            } catch {
                                Write-Verbose "Error processing well-known principal result: $_"
                                continue
                            }
                        }
                        
                        if (-not $foundWellKnownPrincipal) {
                            throw "No matching well-known principal found for SID $sid"
                        }
                        
                    } catch {
                        Write-Verbose "Failed to find well-known principal for $sid ($($principalSIDs[$sid])): $_"
                        Write-Verbose "Creating mock DirectoryEntry instead."
                        
                        # Fallback to creating a mock object
                        $mockEntry = New-Object PSObject
                        
                        # Add properties that mimic a real DirectoryEntry
                        $mockEntry | Add-Member -MemberType NoteProperty -Name "Name" -Value $principalSIDs[$sid]
                        $mockEntry | Add-Member -MemberType NoteProperty -Name "samAccountName" -Value $principalSIDs[$sid]
                        $mockEntry | Add-Member -MemberType NoteProperty -Name "distinguishedName" -Value "CN=$($principalSIDs[$sid]),CN=WellKnownSecurityPrincipals,CN=Configuration"
                        $mockEntry | Add-Member -MemberType NoteProperty -Name "objectClass" -Value @('top', 'foreignSecurityPrincipal')
                        $mockEntry | Add-Member -MemberType NoteProperty -Name "objectSid" -Value $sid
                        $mockEntry | Add-Member -MemberType NoteProperty -Name "Path" -Value "LDAP://CN=$($principalSIDs[$sid]),CN=WellKnownSecurityPrincipals,CN=Configuration"
                        $mockEntry | Add-Member -MemberType NoteProperty -Name "IsMock" -Value $true -Force
                        
                        # Create Properties collection that mimics real DirectoryEntry.Properties
                        $propertiesCollection = @{
                            'name' = @($principalSIDs[$sid])
                            'samaccountname' = @($principalSIDs[$sid])
                            'distinguishedname' = @("CN=$($principalSIDs[$sid]),CN=WellKnownSecurityPrincipals,CN=Configuration")
                            'objectclass' = @('top', 'foreignSecurityPrincipal')
                            'objectsid' = @($sid)
                        }
                        $mockEntry | Add-Member -MemberType NoteProperty -Name "Properties" -Value $propertiesCollection
                        
                        # Set the type name to make it appear as close to a DirectoryEntry as possible
                        $mockEntry.PSObject.TypeNames.Clear()
                        $mockEntry.PSObject.TypeNames.Add('System.DirectoryServices.DirectoryEntry')
                        $mockEntry.PSObject.TypeNames.Add('MockDirectoryEntry')
                        
                        $directoryEntries += $mockEntry
                        Write-Verbose "Successfully created mock DirectoryEntry for: $($principalSIDs[$sid])"
                    }
                }
                
            } catch {
                Write-Warning "Failed to create DirectoryEntry for SID $sid ($($principalSIDs[$sid])): $_"
            }
        }
        
        Write-Verbose "Returning $($directoryEntries.Count) DirectoryEntry objects"
        Write-Output $directoryEntries
        
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Finishing $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
    }
}