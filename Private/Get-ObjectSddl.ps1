function Get-ObjectSddl {
    <#
        .SYNOPSIS

        .DESCRIPTION

        .PARAMETER Parameter

        .INPUTS

        .OUTPUTS

        .EXAMPLE

        .LINK
    #>
    [CmdletBinding()]
    param(
        [System.DirectoryServices.DirectoryEntry]$DirectoryEntry
    )

    #requires -Version 5 -Modules Microsoft.PowerShell.Security
    
    try {
        # Method 1: Try ObjectSecurity property first
        if ($DirectoryEntry.ObjectSecurity) {
            return $DirectoryEntry.ObjectSecurity.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::All)
        }
        
        # Method 2: Fall back to nTSecurityDescriptor attribute
        if ($DirectoryEntry.Properties['nTSecurityDescriptor'] -and $DirectoryEntry.Properties['nTSecurityDescriptor'].Count -gt 0) {
            $securityDescriptorBytes = $DirectoryEntry.Properties['nTSecurityDescriptor'][0]
            $securityDescriptor = New-Object System.DirectoryServices.ActiveDirectorySecurity
            $securityDescriptor.SetSecurityDescriptorBinaryForm($securityDescriptorBytes)
            return $securityDescriptor.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::All)
        }
        
        return $null
    }
    catch {
        Write-Warning "Failed to get SDDL for $($DirectoryEntry.Name): $_"
        return $null
    }
}
