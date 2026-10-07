function Test-IsLocalAdmin {
    <#
        .SYNOPSIS
        Tests if the current user is a local administrator on the current computer.

        .DESCRIPTION
        This function checks if the current PowerShell session is running with local administrator privileges 
        by testing membership in the built-in Administrators group. This is useful for determining if 
        operations requiring elevated privileges can be performed.

        .INPUTS
        None

        .OUTPUTS
        System.Boolean
        Returns $true if the current user is a local administrator, $false otherwise.

        .EXAMPLE
        Test-IsLocalAdmin
        Returns $true if running as local admin, $false otherwise.

        .EXAMPLE
        if (Test-IsLocalAdmin) {
            Write-Host "Running with administrator privileges"
        } else {
            Write-Warning "Administrator privileges required"
        }

        .LINK
        https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts
    #>
    [CmdletBinding()]
    param (
    )


    begin {
        Write-Verbose "Testing if current user is a local administrator"
    }

    process {
        try {
            # Get the current user's Windows identity
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            
            # Create a Windows principal object from the current user
            $principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)
            
            # Check if the user is in the built-in Administrators role
            $isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
            
            Write-Verbose "Current user: $($currentUser.Name)"
            Write-Verbose "Is local administrator: $isAdmin"
            
            return $isAdmin
        }
        catch {
            Write-Warning "Failed to determine administrator status: $($_.Exception.Message)"
            return $false
        }
    }

    end {
        Write-Verbose "Administrator check completed"
    }
}
