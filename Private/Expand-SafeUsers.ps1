function Expand-SafeUsers {
    <#
        .SYNOPSIS
        Expands the SafeUsers pattern by recursively enumerating members of well-known privileged security groups.

        .DESCRIPTION
        This function takes a base SafeUsers pattern and expands it by recursively enumerating the members of 
        well-known privileged security groups across all domains in the forest. It builds a comprehensive
        SafeUsers regex pattern that includes both the base well-known SIDs and all individual members
        of privileged groups.

        .PARAMETER BaseSafeUsers
        The base SafeUsers regex pattern containing well-known SIDs for privileged groups.
        If not provided, uses the standard Locksmith pattern.

        .PARAMETER AdcsObjects
        Array of DirectoryEntry objects from Get-AdcsObjects. Used to determine forest and domain context.
        If not provided, the function will attempt to discover the forest automatically.

        .INPUTS
        System.DirectoryServices.DirectoryEntry[]

        .OUTPUTS
        System.String
        Returns an expanded SafeUsers regex pattern that includes both base SIDs and recursively enumerated group members.

        .EXAMPLE
        $AdcsObjects = Get-AdcsObjects
        $ExpandedSafeUsers = Expand-SafeUsers -AdcsObjects $AdcsObjects
        
        Expands SafeUsers to include all members of privileged groups across the forest.

        .EXAMPLE
        $BaseSafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-521$|-498$|-9$|-526$|-527$|S-1-5-10'
        $ExpandedSafeUsers = Expand-SafeUsers -BaseSafeUsers $BaseSafeUsers -AdcsObjects $AdcsObjects
        
        Uses a custom base SafeUsers pattern and expands it with group memberships.

        .EXAMPLE
        # Use the expanded SafeUsers with other ESCalator functions
        $ExpandedSafeUsers = Expand-SafeUsers -AdcsObjects $AdcsObjects
        $ESC4Issues = Find-ESC4Issue -AdcsObjects $AdcsObjects -SafeOwners $ExpandedSafeUsers

        .NOTES
        This function performs Active Directory queries using DirectoryEntry objects and may take some time to complete in large environments.
        Does not require the ActiveDirectory PowerShell module - uses pure DirectoryEntry approach for maximum compatibility.

        .LINK
        https://posts.specterops.io/certified-pre-owned-d95910965cd2
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$BaseSafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-521$|-498$|-9$|-526$|-527$|S-1-5-10',
        
        [Parameter(ValueFromPipeline)]
        [System.DirectoryServices.DirectoryEntry[]]$AdcsObjects
    )

    #requires -Version 5

    begin {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Starting $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
        
        # Initialize the SafeUsers with the base pattern
        $SafeUsers = $BaseSafeUsers
        Write-Verbose "Base SafeUsers pattern: $BaseSafeUsers"
        
        # Initialize collections for tracking
        $ProcessedSIDs = @{}
        $ErrorSIDs = @{}
        
        # Get forest context
        $Forest = $null
        $ForestDomains = @()
        
        try {
            if ($AdcsObjects -and $AdcsObjects.Count -gt 0) {
                # Extract forest information from AdcsObjects
                $sampleObject = $AdcsObjects[0]
                $sampleDN = if ($sampleObject.distinguishedName.Value) { 
                    $sampleObject.distinguishedName.Value 
                } elseif ($sampleObject.distinguishedName) { 
                    $sampleObject.distinguishedName 
                } else { 
                    $null 
                }
                
                if ($sampleDN) {
                    # Extract domain components from DN
                    $dcComponents = ($sampleDN -split ',DC=' | Where-Object { $_ -match '^DC=' -or $_ -notmatch '=' })
                    if ($dcComponents.Count -gt 1) {
                        $forestRoot = ($dcComponents[1..($dcComponents.Count - 1)] -join '.').Replace('DC=', '')
                        Write-Verbose "Detected forest root from AdcsObjects: $forestRoot"
                    }
                }
            }
            
            # Get forest information using DirectoryEntry
            try {
                $rootDSE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
                $forestRootNC = $rootDSE.rootDomainNamingContext.Value
                $configNC = $rootDSE.configurationNamingContext.Value
                
                if ($forestRootNC) {
                    $forestName = ($forestRootNC -replace 'DC=', '' -replace ',', '.')
                    Write-Verbose "Found forest using DirectoryEntry: $forestName"
                    
                    # Create a mock forest object for compatibility
                    $Forest = [PSCustomObject]@{
                        Name = $forestName
                        RootDomain = $forestName
                        RootDomainNC = $forestRootNC
                    }
                    
                    # Enumerate domains from partitions container
                    if ($configNC) {
                        $partitionsContainer = New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Partitions,$configNC")
                        $searcher = New-Object System.DirectoryServices.DirectorySearcher($partitionsContainer)
                        $searcher.Filter = "(&(objectClass=crossRef)(systemFlags=3))"
                        $searcher.PropertiesToLoad.AddRange(@("dnsRoot"))
                        
                        $domains = $searcher.FindAll()
                        foreach ($domain in $domains) {
                            if ($domain.Properties["dnsRoot"]) {
                                $ForestDomains += $domain.Properties["dnsRoot"][0]
                            }
                        }
                        $domains.Dispose()
                        $searcher.Dispose()
                        $partitionsContainer.Dispose()
                    }
                }
                $rootDSE.Dispose()
            } catch {
                Write-Warning "Failed to get forest information via DirectoryEntry: $($_.Exception.Message)"
            }
            
            if (-not $ForestDomains -or $ForestDomains.Count -eq 0) {
                Write-Warning "Could not determine forest domains. SafeUsers expansion will be limited to base pattern."
                return $SafeUsers
            }
            
        } catch {
            Write-Warning "Failed to determine forest context: $($_.Exception.Message)"
            return $SafeUsers
        }
    }

    process {
        Write-Verbose "Expanding SafeUsers across $($ForestDomains.Count) domains..."
        
        # Helper function to get group members recursively using DirectoryEntry
        function Get-GroupMembersRecursive {
            param(
                [string]$GroupSID,
                [string]$DomainName,
                [hashtable]$ProcessedGroups = @{},
                [int]$MaxDepth = 10,
                [int]$CurrentDepth = 0
            )
            
            if ($CurrentDepth -ge $MaxDepth) {
                Write-Verbose "Maximum recursion depth reached for group $GroupSID"
                return @()
            }
            
            if ($ProcessedGroups.ContainsKey($GroupSID)) {
                Write-Verbose "Group $GroupSID already processed, skipping to avoid circular reference"
                return @()
            }
            
            $ProcessedGroups[$GroupSID] = $true
            $members = @()
            
            try {
                Write-Verbose "Getting members for group SID: $GroupSID (depth: $CurrentDepth)"
                
                # Try to bind to the group using SID
                $groupEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://<SID=$GroupSID>")
                
                if ($groupEntry.Properties["member"]) {
                    foreach ($memberDN in $groupEntry.Properties["member"]) {
                        try {
                            $memberEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$memberDN")
                            
                            if ($memberEntry.Properties["objectSid"]) {
                                $memberSidBytes = $memberEntry.Properties["objectSid"][0]
                                $memberSidObj = New-Object System.Security.Principal.SecurityIdentifier($memberSidBytes, 0)
                                $memberSID = $memberSidObj.Value
                                
                                # Check if this is a group that needs recursive expansion
                                $objectClass = $memberEntry.Properties["objectClass"]
                                if ($objectClass -contains "group") {
                                    Write-Verbose "Found nested group: $memberSID, expanding recursively"
                                    $nestedMembers = Get-GroupMembersRecursive -GroupSID $memberSID -DomainName $DomainName -ProcessedGroups $ProcessedGroups -MaxDepth $MaxDepth -CurrentDepth ($CurrentDepth + 1)
                                    $members += $nestedMembers
                                } else {
                                    # This is a user or computer, add it directly
                                    $members += $memberSID
                                    Write-Verbose "Added member: $memberSID"
                                }
                            }
                            $memberEntry.Dispose()
                        } catch {
                            Write-Verbose "Failed to process member $memberDN : $($_.Exception.Message)"
                        }
                    }
                }
                $groupEntry.Dispose()
            } catch {
                Write-Verbose "Failed to process group $GroupSID : $($_.Exception.Message)"
            }
            
            return $members
        }
        
        # Get Enterprise Admins SID and expand members
        if ($Forest -and $Forest.RootDomainNC) {
            try {
                # Get the domain SID of the root domain
                $rootDomainEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($Forest.RootDomainNC)")
                if ($rootDomainEntry.Properties["objectSid"]) {
                    $rootDomainSidBytes = $rootDomainEntry.Properties["objectSid"][0]
                    $rootDomainSidObj = New-Object System.Security.Principal.SecurityIdentifier($rootDomainSidBytes, 0)
                    $rootDomainSID = $rootDomainSidObj.Value
                    
                    $EnterpriseAdminsSID = $rootDomainSID + '-519'
                    Write-Verbose "Enterprise Admins SID: $EnterpriseAdminsSID"
                    
                    # Get Enterprise Admins members recursively
                    $eaMembers = Get-GroupMembersRecursive -GroupSID $EnterpriseAdminsSID -DomainName $Forest.RootDomain
                    foreach ($memberSID in $eaMembers) {
                        if (-not $ProcessedSIDs.ContainsKey($memberSID)) {
                            $SafeUsers += '|' + $memberSID
                            $ProcessedSIDs[$memberSID] = $true
                            Write-Verbose "Added Enterprise Admin member: $memberSID"
                        }
                    }
                }
                $rootDomainEntry.Dispose()
            } catch {
                Write-Verbose "Failed to process Enterprise Admins: $($_.Exception.Message)"
            }
        }

        # Process each domain
        foreach ($DomainName in $ForestDomains) {
            Write-Verbose "Processing domain: $DomainName"
            
            try {
                # Get domain SID using DirectoryEntry
                $domainDN = "DC=" + ($DomainName -replace '\.', ',DC=')
                $domainEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domainDN")
                
                $DomainSID = $null
                if ($domainEntry.Properties["objectSid"]) {
                    $domainSidBytes = $domainEntry.Properties["objectSid"][0]
                    $domainSidObj = New-Object System.Security.Principal.SecurityIdentifier($domainSidBytes, 0)
                    $DomainSID = $domainSidObj.Value
                    Write-Verbose "Domain SID for $DomainName : $DomainSID"
                }
                $domainEntry.Dispose()
                
                if (-not $DomainSID) {
                    Write-Warning "Could not determine domain SID for $DomainName, skipping domain"
                    continue
                }

                # Define safe group RIDs and SIDs to process
                $SafeGroupRIDs = @('-517', '-512')  # Cert Publishers, Domain Admins
                $SafeGroupSIDs = @('S-1-5-32-544')  # Local Administrators
                
                # Add domain-specific groups
                foreach ($rid in $SafeGroupRIDs) {
                    $SafeGroupSIDs += $DomainSID + $rid
                }
                
                # Process each safe group
                foreach ($groupSID in $SafeGroupSIDs) {
                    Write-Verbose "Processing group SID: $groupSID"
                    
                    try {
                        # Get group members recursively using DirectoryEntry
                        $groupMembers = Get-GroupMembersRecursive -GroupSID $groupSID -DomainName $DomainName
                        
                        # Add all members to SafeUsers
                        foreach ($memberSID in $groupMembers) {
                            if (-not $ProcessedSIDs.ContainsKey($memberSID)) {
                                $SafeUsers += '|' + $memberSID
                                $ProcessedSIDs[$memberSID] = $true
                                Write-Verbose "Added group member: $memberSID"
                            }
                        }
                        
                    } catch {
                        Write-Verbose "Failed to process group $groupSID in domain $DomainName : $($_.Exception.Message)"
                        $ErrorSIDs[$groupSID] = $_.Exception.Message
                    }
                }
                
            } catch {
                Write-Warning "Failed to process domain $DomainName : $($_.Exception.Message)"
            }
        }
    }

    end {
        # Clean up the SafeUsers pattern
        $SafeUsers = $SafeUsers.Replace('||', '|')
        
        # Remove any leading/trailing pipe characters
        $SafeUsers = $SafeUsers.Trim('|')
        
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Completed $($MyInvocation.MyCommand)"
        Write-Verbose "Final SafeUsers pattern length: $($SafeUsers.Length) characters"
        Write-Verbose "Processed $($ProcessedSIDs.Count) individual SIDs"
        
        if ($ErrorSIDs.Count -gt 0) {
            Write-Verbose "Encountered errors processing $($ErrorSIDs.Count) groups"
        }
        
        return $SafeUsers
    }
}