function Resolve-Principal {
    <#
        .SYNOPSIS
        Resolves a DirectoryEntry object for a security principal using UPN, NetBIOS name, or SID.

        .DESCRIPTION
        This function accepts a User Principal Name (UPN), NetBIOS name (DOMAIN\username), or Security Identifier (SID)
        and returns the corresponding DirectoryEntry object from Active Directory. The function automatically determines
        the input type and performs the appropriate lookup to resolve the principal.

        The function supports both user accounts and computer accounts, automatically searching both object types
        when performing the lookup.

        When provided with any one of these identifiers, the function can derive the other values and return a
        complete DirectoryEntry object representing the security principal.

        .PARAMETER Identity
        The identity of the principal to retrieve. Can be specified as:
        - UPN: user@domain.com
        - NetBIOS: DOMAIN\username or username
        - SID: S-1-5-21-domain-rid or SecurityIdentifier object

        .PARAMETER Server
        The domain controller to query. If not specified, uses the default domain controller.

        .INPUTS
        System.String or System.Security.Principal.SecurityIdentifier
        Identity of the principal to retrieve.

        .OUTPUTS
        System.DirectoryServices.DirectoryEntry
        DirectoryEntry object representing the resolved security principal.

        .EXAMPLE
        # Resolve using UPN
        $Principal = Resolve-Principal -Identity "administrator@domain.com"

        .EXAMPLE
        # Resolve using NetBIOS name
        $Principal = Resolve-Principal -Identity "DOMAIN\administrator"
        $Principal = Resolve-Principal -Identity "administrator"  # Current domain assumed

        .EXAMPLE
        # Resolve using SID
        $Principal = Resolve-Principal -Identity "S-1-5-21-1234567890-1234567890-1234567890-500"

        .EXAMPLE
        # Use with pipeline
        "administrator@domain.com", "DOMAIN\user1", "S-1-5-21-1234567890-1234567890-1234567890-1001" | Resolve-Principal

        .NOTES
        The function supports the following input formats:
        - UPN: Contains '@' character (user@domain.com)
        - NetBIOS: Contains '\' character (DOMAIN\user) or plain username
        - SID: Starts with 'S-1-' or is a SecurityIdentifier object

        For NetBIOS names without a domain prefix, the current domain is assumed.

        .LINK
        https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers
    #>
    [CmdletBinding()]
    [OutputType([System.DirectoryServices.DirectoryEntry])]
    param (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [object]$Identity,
        
        [Parameter()]
        [string]$Server
    )

    #requires -Version 7.4

    begin {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Starting $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
        
        # Get domain information for context
        try {
            if ($Server) {
                $rootDSE = [ADSI]"LDAP://$Server/RootDSE"
            } else {
                $rootDSE = [ADSI]"LDAP://RootDSE"
            }
            $defaultNC = $rootDSE.defaultNamingContext
            
            # Extract domain name from DN
            $domainDN = $defaultNC
            $domainName = ($domainDN -replace 'DC=', '' -replace ',', '.').Trim()
            $netbiosDomain = $domainName.Split('.')[0].ToUpper()
            
            Write-Verbose "Domain: $domainName, NetBIOS: $netbiosDomain, DN: $domainDN"
        } catch {
            throw "Failed to connect to domain: $($_.Exception.Message)"
        }
    }

    process {
        try {
            $identityString = $Identity.ToString()
            Write-Verbose "Processing identity: $identityString"
            
            $directoryEntry = $null
            $searchFilter = $null
            
            # Determine identity type and create appropriate search filter
            if ($identityString -match '@') {
                # UPN format (user@domain.com)
                Write-Verbose "Detected UPN format: $identityString"
                $searchFilter = "(&(|(objectCategory=person)(objectCategory=computer))(userPrincipalName=$identityString))"
                
            } elseif ($identityString -match '^S-1-') {
                # SID format
                Write-Verbose "Detected SID format: $identityString"
                try {
                    $sid = New-Object System.Security.Principal.SecurityIdentifier($identityString)
                    $sidBytes = New-Object byte[] $sid.BinaryLength
                    $sid.GetBinaryForm($sidBytes, 0)
                    
                    # Convert to hex string for LDAP filter
                    $sidHex = ($sidBytes | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $searchFilter = "(&(|(objectCategory=person)(objectCategory=computer))(objectSid=$sidHex))"
                } catch {
                    throw "Invalid SID format: $identityString"
                }
                
            } elseif ($Identity -is [System.Security.Principal.SecurityIdentifier]) {
                # SecurityIdentifier object
                Write-Verbose "Detected SecurityIdentifier object: $($Identity.Value)"
                $sidBytes = New-Object byte[] $Identity.BinaryLength
                $Identity.GetBinaryForm($sidBytes, 0)
                
                # Convert to hex string for LDAP filter
                $sidHex = ($sidBytes | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                $searchFilter = "(&(|(objectCategory=person)(objectCategory=computer))(objectSid=$sidHex))"
                
            } elseif ($identityString -match '\\') {
                # NetBIOS format (DOMAIN\username)
                Write-Verbose "Detected NetBIOS format with domain: $identityString"
                $parts = $identityString.Split('\', 2)
                $username = $parts[1]
                
                # Use sAMAccountName for search (works for both users and computers)
                $searchFilter = "(&(|(objectCategory=person)(objectCategory=computer))(sAMAccountName=$username))"
                
            } else {
                # Plain username (assume current domain)
                Write-Verbose "Detected plain username, assuming current domain: $identityString"
                $searchFilter = "(&(|(objectCategory=person)(objectCategory=computer))(sAMAccountName=$identityString))"
            }
            
            # Perform LDAP search
            Write-Verbose "Search filter: $searchFilter"
            
            if ($Server) {
                $searcher = [ADSISearcher]"LDAP://$Server/$defaultNC"
            } else {
                $searcher = [ADSISearcher]"LDAP://$defaultNC"
            }
            
            $searcher.Filter = $searchFilter
            $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
            $searcher.PropertiesToLoad.AddRange(@(
                'distinguishedName', 'sAMAccountName', 'userPrincipalName', 
                'objectSid', 'objectClass', 'name', 'displayName'
            ))
            
            $searchResult = $searcher.FindOne()
            
            if ($searchResult) {
                $directoryEntry = $searchResult.GetDirectoryEntry()
                Write-Verbose "Successfully resolved principal: $($directoryEntry.Properties['distinguishedName'].Value)"
                
                # Add derived properties for easy access
                $directoryEntry | Add-Member -MemberType NoteProperty -Name 'ResolvedUPN' -Value $directoryEntry.Properties['userPrincipalName'].Value -Force
                $directoryEntry | Add-Member -MemberType NoteProperty -Name 'ResolvedNetBIOS' -Value "$netbiosDomain\$($directoryEntry.Properties['sAMAccountName'].Value)" -Force
                
                if ($directoryEntry.Properties['objectSid'].Value) {
                    $sidObj = New-Object System.Security.Principal.SecurityIdentifier($directoryEntry.Properties['objectSid'].Value, 0)
                    $directoryEntry | Add-Member -MemberType NoteProperty -Name 'ResolvedSID' -Value $sidObj.Value -Force
                }
                
                return $directoryEntry
            } else {
                throw "Principal not found: $identityString"
            }
            
        } catch {
            Write-Error "Failed to resolve principal '$identityString': $($_.Exception.Message)"
            return $null
        } finally {
            if ($searcher) {
                $searcher.Dispose()
            }
        }
    }

    end {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] Completed $($MyInvocation.MyCommand)"
    }
}