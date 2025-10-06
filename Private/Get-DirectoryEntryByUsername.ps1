function Get-DirectoryEntryByUsername {
    <#
        .SYNOPSIS
        Retrieves a DirectoryEntry object for a specified username.

        .DESCRIPTION
        This function searches Active Directory for a user account based on the provided username
        and returns the corresponding DirectoryEntry object. The function can handle various
        username formats including sAMAccountName, userPrincipalName, and distinguished name.

        .PARAMETER Username
        The username to search for. Can be in various formats:
        - sAMAccountName (e.g., "testuser")
        - Domain\Username (e.g., "DOMAIN\testuser")
        - userPrincipalName (e.g., "testuser@domain.com")
        - Distinguished Name (e.g., "CN=Test User,OU=Users,DC=domain,DC=com")

        .INPUTS
        System.String
        Username string in various supported formats.

        .OUTPUTS
        System.DirectoryServices.DirectoryEntry
        Returns a DirectoryEntry object representing the user account, or $null if not found.

        .EXAMPLE
        # Get DirectoryEntry by sAMAccountName
        $user = Get-DirectoryEntryByUsername -Username "testuser"

        .EXAMPLE
        # Get DirectoryEntry by domain\username format
        $user = Get-DirectoryEntryByUsername -Username "DOMAIN\testuser"

        .EXAMPLE
        # Get DirectoryEntry by UPN
        $user = Get-DirectoryEntryByUsername -Username "testuser@domain.com"

        .EXAMPLE
        # Pipeline usage
        "testuser" | Get-DirectoryEntryByUsername

        .NOTES
        This function requires Active Directory access and appropriate permissions to query
        user objects. The function will attempt to resolve the username using multiple
        search methods to handle different input formats.
        
        The returned DirectoryEntry object can be used with other ESCalator functions
        that require DirectoryEntry parameters, such as Find-ESC4e1.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [string]$Username
    )

    #requires -Version 7.4

    begin {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Starting $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
    }

    process {
        try {
            Write-Verbose "Searching for user: $Username"
            
            # Initialize variables
            $directoryEntry = $null
            $searchFilter = $null
            
            # Clean up the username and determine search strategy
            $cleanUsername = $Username.Trim()
            
            # Check if it's a Distinguished Name (starts with CN=)
            if ($cleanUsername -match '^CN=.*,.*DC=') {
                Write-Verbose "Username appears to be a Distinguished Name"
                try {
                    $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$cleanUsername")
                    # Verify the object exists by accessing a property
                    $null = $directoryEntry.Properties['objectClass'].Value
                    Write-Verbose "Found user by DN: $($directoryEntry.Properties['distinguishedName'].Value)"
                    return $directoryEntry
                } catch {
                    Write-Verbose "Failed to find user by DN: $($_.Exception.Message)"
                    return $null
                }
            }
            
            # Check if it's a UPN (contains @)
            if ($cleanUsername -contains '@') {
                Write-Verbose "Username appears to be a UPN"
                $searchFilter = "(&(objectClass=user)(userPrincipalName=$cleanUsername))"
            }
            # Check if it's domain\username format
            elseif ($cleanUsername -contains '\') {
                Write-Verbose "Username appears to be in DOMAIN\Username format"
                $parts = $cleanUsername -split '\\'
                if ($parts.Length -eq 2) {
                    $samAccountName = $parts[1]
                    $searchFilter = "(&(objectClass=user)(sAMAccountName=$samAccountName))"
                } else {
                    Write-Warning "Invalid DOMAIN\Username format: $cleanUsername"
                    return $null
                }
            }
            # Assume it's a sAMAccountName
            else {
                Write-Verbose "Treating username as sAMAccountName"
                $searchFilter = "(&(objectClass=user)(sAMAccountName=$cleanUsername))"
            }
            
            # Perform LDAP search
            Write-Verbose "Using search filter: $searchFilter"
            
            # Get domain root
            $rootDSE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
            $defaultNC = $rootDSE.Properties["defaultNamingContext"].Value
            $domainRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$defaultNC")
            
            # Create DirectorySearcher
            $searcher = New-Object System.DirectoryServices.DirectorySearcher($domainRoot)
            $searcher.Filter = $searchFilter
            $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
            
            # Perform search
            $searchResult = $searcher.FindOne()
            
            if ($searchResult) {
                $directoryEntry = $searchResult.GetDirectoryEntry()
                $foundUsername = $directoryEntry.Properties['sAMAccountName'].Value
                $foundDN = $directoryEntry.Properties['distinguishedName'].Value
                Write-Verbose "Found user: $foundUsername ($foundDN)"
                return $directoryEntry
            } else {
                Write-Warning "User not found: $Username"
                return $null
            }
            
        } catch {
            Write-Error "Failed to retrieve DirectoryEntry for user '$Username': $($_.Exception.Message)"
            Write-Verbose "Exception details: $($_.Exception.ToString())"
            return $null
        } finally {
            # Clean up searcher if it was created
            if ($searcher) {
                $searcher.Dispose()
            }
        }
    }

    end {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Finishing $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
    }
}