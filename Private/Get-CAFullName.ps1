function Get-CAFullName {
    <#
        .SYNOPSIS
        Extracts Certificate Authority full names from DirectoryEntry objects.

        .DESCRIPTION
        This function processes one or more DirectoryEntry objects representing Certificate Authorities
        and extracts their full names. Returns a single string if one CA is provided, or a generic
        list of strings if multiple CAs are provided.

        .PARAMETER CAObjects
        One or more DirectoryEntry objects representing Certificate Authorities (pKIEnrollmentService
        schema class). These are typically obtained from Get-AdcsObjects or similar functions.

        .INPUTS
        System.DirectoryServices.DirectoryEntry[]
        Certificate Authority DirectoryEntry objects.

        .OUTPUTS
        System.String or System.Collections.Generic.List[System.String]
        Returns a single string if one CA is provided, or a generic list of strings if multiple CAs are provided.

        .EXAMPLE
        # Get CA full names from ADCS objects
        $AdcsObjects = Get-AdcsObjects
        $CAs = $AdcsObjects | Where-Object { $_.SchemaClassName -eq 'pKIEnrollmentService' }
        $CANames = Get-CAFullName -CAObjects $CAs

        .EXAMPLE
        # Get single CA full name
        $SingleCA = $AdcsObjects | Where-Object { $_.SchemaClassName -eq 'pKIEnrollmentService' } | Select-Object -First 1
        $CAName = Get-CAFullName -CAObjects $SingleCA
        # Returns: "CA.domain.com\CA-Name"

        .EXAMPLE
        # Pipeline usage
        $AdcsObjects | Where-Object { $_.SchemaClassName -eq 'pKIEnrollmentService' } | Get-CAFullName

        .NOTES
        Certificate Authority objects should have the pKIEnrollmentService schema class.
        The function constructs the full name from the CA's DNS hostname and display name.

        .LINK
        https://docs.microsoft.com/en-us/windows/security/identity-protection/smart-cards/smart-card-certificate-requirements-and-enumeration
    #>
    [CmdletBinding()]
    [OutputType([string], [System.Collections.Generic.List[string]])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNull()]
        [System.DirectoryServices.DirectoryEntry[]]$CAObjects
    )

    #requires -Version 7.4

    begin {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Starting $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
        
        # Initialize collection for multiple results
        $caFullNames = New-Object System.Collections.Generic.List[string]
        
        # Initialize collection to gather all input objects
        $allInputObjects = New-Object System.Collections.Generic.List[System.DirectoryServices.DirectoryEntry]
    }

    process {
        # Collect all input objects
        foreach ($caObject in $CAObjects) {
            $allInputObjects.Add($caObject)
        }
    }

    end {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Processing collected objects..."
        
        # Filter to only Certificate Authority objects
        $validCAObjects = $allInputObjects | Where-Object { $_.SchemaClassName -eq 'pKIEnrollmentService' }
        
        # Get reliable count using @() array subexpression operator
        $caCount = @($validCAObjects).Count
        
        if ($caCount -eq 0) {
            Write-Warning "No Certificate Authority objects found in input. Expected objects with SchemaClassName 'pKIEnrollmentService'."
            return $null
        }
        
        Write-Verbose "Found $caCount valid CA objects to process"
        
        foreach ($caObject in $validCAObjects) {
            try {
                # Extract CA information
                $caDisplayName = $caObject.Properties['displayName'].Value
                $caDnsHostName = $caObject.Properties['dNSHostName'].Value
                
                # Validate required properties exist
                if (-not $caDisplayName) {
                    Write-Warning "CA object missing displayName property. DN: $($caObject.Properties['distinguishedName'].Value)"
                    continue
                }
                
                if (-not $caDnsHostName) {
                    Write-Warning "CA object missing dNSHostName property. DN: $($caObject.Properties['distinguishedName'].Value)"
                    continue
                }
                
                # Construct full CA name in the format "hostname\ca-name"
                $fullName = "$caDnsHostName\$caDisplayName"
                
                Write-Verbose "Found CA: $fullName"
                $caFullNames.Add($fullName)
                
            } catch {
                Write-Error "Failed to process CA object: $($_.Exception.Message). DN: $($caObject.Properties['distinguishedName'].Value)"
                continue
            }
        }
        
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Finishing $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
        Write-Verbose "Found $($caFullNames.Count) Certificate Authority full names"
        
        # Return appropriate type based on count
        if ($caFullNames.Count -eq 0) {
            Write-Warning "No valid Certificate Authority full names found"
            return $null
        } elseif ($caFullNames.Count -eq 1) {
            # Return single string
            return $caFullNames[0]
        } else {
            # Return generic list of strings
            return $caFullNames
        }
    }
}
