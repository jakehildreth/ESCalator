function New-Template {
    <#
        .SYNOPSIS
        Creates a new certificate template by cloning an existing template and configuring its properties.

        .DESCRIPTION
        This function creates a new certificate template by cloning an existing base template and 
        optionally configuring specific properties like subject name handling and private key settings.
        The function uses the Windows Certificate Authority API (certca.dll) to perform the template
        creation and configuration without requiring additional PowerShell modules.

        .PARAMETER BaseTemplateName
        The name of the existing certificate template to use as a base for cloning.
        This template must exist in the Active Directory certificate templates container.

        .PARAMETER NewTemplateName
        The internal name for the new certificate template. This must be unique and will be
        used as the template identifier in Active Directory.

        .PARAMETER NewTemplateFriendlyName
        The display name for the new certificate template. This is the name that will be
        visible in the Certificate Authority management console and to end users.

        .PARAMETER EnrolleeSuppliesSubject
        If specified, configures the template to allow the certificate requestor to supply
        the subject name in the certificate request (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT).
        This creates an ESC1 vulnerability.

        .PARAMETER AllowExportableKey
        If specified, configures the template to allow private keys to be marked as exportable
        (CT_FLAG_EXPORTABLE_KEY).

        .PARAMETER EnableTemplate
        If specified, automatically enables the new template on all Certificate Authorities
        in the forest after creation.

        .INPUTS
        None
        This function does not accept pipeline input.

        .OUTPUTS
        PSCustomObject
        Returns a result object indicating success/failure and template details.

        .EXAMPLE
        New-Template -BaseTemplateName "User" -NewTemplateName "VulnUser" -NewTemplateFriendlyName "Vulnerable User Template" -EnrolleeSuppliesSubject

        .EXAMPLE
        New-Template -BaseTemplateName "Computer" -NewTemplateName "TestComputer" -NewTemplateFriendlyName "Test Computer Template" -AllowExportableKey -EnableTemplate

        .EXAMPLE
        $result = New-Template -BaseTemplateName "SmartcardLogon" -NewTemplateName "MySmartcard" -NewTemplateFriendlyName "My Smartcard Template" -EnrolleeSuppliesSubject -AllowExportableKey -EnableTemplate
        if ($result.Success) { Write-Host "Template created successfully" }

        .LINK
        https://docs.microsoft.com/en-us/windows/win32/api/certca/

        .NOTES
        Requires administrative privileges on the Certificate Authority.
        Uses Windows Certificate Authority API (certca.dll) for template operations.
        
        WARNING: Using -EnrolleeSuppliesSubject creates ESC1 vulnerabilities. Only use in test environments.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$BaseTemplateName,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$NewTemplateName,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$NewTemplateFriendlyName,
        
        [Parameter()]
        [switch]$EnrolleeSuppliesSubject,
        
        [Parameter()]
        [switch]$AllowExportableKey,
        
        [Parameter()]
        [switch]$EnableTemplate
    )

    #requires -Version 5

    begin {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Starting $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
        
        # Define the Certificate Authority API wrapper
        $certcaDefinition = @"
using System;
using System.Runtime.InteropServices;

public class CertCA
{
    // Enumeration flags
    public const uint CA_FLAG_ENUM_ALL_TYPES = 0x00000004;
    public const uint CT_FIND_LOCAL_SYSTEM = 0x00000002;
    public const uint CT_ENUM_MACHINE_TYPES = 0x00000040;
    public const uint CT_ENUM_USER_TYPES = 0x00000080;
    public const uint CT_FIND_BY_OID = 0x00000200;
    public const uint CT_FLAG_NO_CACHE_LOOKUP = 0x00000400;
    public const uint CT_FLAG_SCOPE_IS_LDAP_HANDLE = 0x00000800;
    public const uint CT_ENUM_ADMINISTRATOR_FORCE_MACHINE = 0x00001000;
    public const uint CT_ENUM_NO_CACHE_TO_REGISTRY = 0x00002000;
    public const uint CT_FLAG_ENUM_INCLUDE_INVALID_TYPES = 0x00004000;

    // Certificate Type Flag Types
    public const uint CERTTYPE_ENROLLMENT_FLAG = 0x01;
    public const uint CERTTYPE_SUBJECT_NAME_FLAG = 0x02;
    public const uint CERTTYPE_PRIVATE_KEY_FLAG = 0x03;
    public const uint CERTTYPE_GENERAL_FLAG = 0x04;

    // Subject Name Flags
    public const uint CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001;
    public const uint CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000;
    public const uint CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH = 0x80000000;
    public const uint CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME = 0x40000000;
    public const uint CT_FLAG_SUBJECT_REQUIRE_EMAIL = 0x20000000;
    public const uint CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN = 0x10000000;
    public const uint CT_FLAG_SUBJECT_ALT_REQUIRE_DNS = 0x08000000;
    public const uint CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL = 0x04000000;
    public const uint CT_FLAG_SUBJECT_ALT_REQUIRE_UPN = 0x02000000;
    public const uint CT_FLAG_SUBJECT_ALT_REQUIRE_DIRECTORY_GUID = 0x01000000;
    public const uint CT_FLAG_SUBJECT_ALT_REQUIRE_SPN = 0x00800000;
    public const uint CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS = 0x00400000;
    public const uint CT_FLAG_OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME = 0x00000008;

    // Private Key Flags
    public const uint CT_FLAG_ALLOW_PRIVATE_KEY_ARCHIVAL = 0x00000001;
    public const uint CT_FLAG_REQUIRE_PRIVATE_KEY_ARCHIVAL = 0x00000001;
    public const uint CT_FLAG_EXPORTABLE_KEY = 0x00000010;
    public const uint CT_FLAG_STRONG_KEY_PROTECTION_REQUIRED = 0x00000020;

    // Common HRESULT values
    public const int S_OK = 0x00000000;
    public const int CRYPT_E_NOT_FOUND = unchecked((int)0x80092004);
    public const int CRYPT_E_EXISTS = unchecked((int)0x80092005);

    [DllImport("certca.dll", CharSet = CharSet.Unicode)]
    public static extern int CAFindCertTypeByName(
        string wszCertType,
        IntPtr hCAInfo,
        uint dwFlags,
        out IntPtr phCertType
    );

    [DllImport("certca.dll", CharSet = CharSet.Unicode)]
    public static extern int CACloneCertType(
        IntPtr hCertType,
        string wszCertType,
        string wszFriendlyName,
        IntPtr pvldap,
        uint dwFlags,
        out IntPtr phCertType
    );

    [DllImport("certca.dll", CharSet = CharSet.Unicode)]
    public static extern int CASetCertTypeFlagsEx(
        IntPtr hCertType,
        uint dwOption,
        uint dwFlags
    );

    [DllImport("certca.dll", CharSet = CharSet.Unicode)]
    public static extern int CAUpdateCertType(
        IntPtr hCertType
    );

    [DllImport("certca.dll", CharSet = CharSet.Unicode)]
    public static extern int CACloseCertType(
        IntPtr hCertType
    );
}
"@

        try {
            if (-not ([System.Management.Automation.PSTypeName]'CertCA').Type) {
                Add-Type -TypeDefinition $certcaDefinition
                Write-Verbose "Certificate Authority API wrapper loaded successfully"
            }
        } catch {
            Write-Error "Failed to load Certificate Authority API wrapper: $($_.Exception.Message)"
            return
        }
    }

    process {
        Write-Verbose "Creating new template '$NewTemplateName' based on '$BaseTemplateName'"
        
        # Initialize variables
        $hCAInfo = [IntPtr]::Zero
        $hBaseCertType = [IntPtr]::Zero
        $hNewCertType = [IntPtr]::Zero
        $dwFlags = [CertCA]::CT_FLAG_NO_CACHE_LOOKUP -bor [CertCA]::CT_ENUM_MACHINE_TYPES -bor [CertCA]::CT_ENUM_USER_TYPES
        $changes = @()
        
        try {
            # Step 1: Find the base certificate template
            Write-Verbose "Searching for base template: $BaseTemplateName"
            $hr = [CertCA]::CAFindCertTypeByName($BaseTemplateName, $hCAInfo, $dwFlags, [ref]$hBaseCertType)
            
            if ($hr -ne [CertCA]::S_OK -or $hBaseCertType -eq [IntPtr]::Zero) {
                if ($hr -eq [CertCA]::CRYPT_E_NOT_FOUND) {
                    $errorMsg = "Base certificate template '$BaseTemplateName' was not found"
                } else {
                    $errorMsg = "Failed to find base template '$BaseTemplateName': HRESULT 0x$($hr.ToString('X8'))"
                }
                
                return [PSCustomObject]@{
                    Success = $false
                    BaseTemplate = $BaseTemplateName
                    NewTemplate = $NewTemplateName
                    NewTemplateFriendlyName = $NewTemplateFriendlyName
                    Changes = @()
                    Error = $errorMsg
                }
            }
            
            Write-Verbose "Base template found successfully"
            
            # Step 2: Clone the base template
            Write-Verbose "Cloning template to create '$NewTemplateName'"
            $hr = [CertCA]::CACloneCertType($hBaseCertType, $NewTemplateName, $NewTemplateFriendlyName, [IntPtr]::Zero, 0, [ref]$hNewCertType)
            
            # Close the base template handle immediately after cloning
            if ($hBaseCertType -ne [IntPtr]::Zero) {
                [CertCA]::CACloseCertType($hBaseCertType) | Out-Null
                $hBaseCertType = [IntPtr]::Zero
            }
            
            if ($hr -ne [CertCA]::S_OK -or $hNewCertType -eq [IntPtr]::Zero) {
                if ($hr -eq [CertCA]::CRYPT_E_EXISTS) {
                    $errorMsg = "Certificate template '$NewTemplateName' already exists"
                } else {
                    $errorMsg = "Failed to clone template '$BaseTemplateName' to '$NewTemplateName': HRESULT 0x$($hr.ToString('X8'))"
                }
                
                return [PSCustomObject]@{
                    Success = $false
                    BaseTemplate = $BaseTemplateName
                    NewTemplate = $NewTemplateName
                    NewTemplateFriendlyName = $NewTemplateFriendlyName
                    Changes = @()
                    Error = $errorMsg
                }
            }
            
            Write-Verbose "Template cloned successfully"
            
            # Step 3: Configure subject name flags
            if ($EnrolleeSuppliesSubject) {
                Write-Verbose "Enabling enrollee supplies subject flag"
                $subjectNameFlag = [CertCA]::CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
                $hr = [CertCA]::CASetCertTypeFlagsEx($hNewCertType, [CertCA]::CERTTYPE_SUBJECT_NAME_FLAG, $subjectNameFlag)
                
                if ($hr -eq [CertCA]::S_OK) {
                    $changes += "Enabled CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT (ESC1 vulnerability)"
                    Write-Verbose "Subject name flag configured successfully"
                } else {
                    Write-Warning "Failed to set subject name flag: HRESULT 0x$($hr.ToString('X8'))"
                }
            }
            
            # Step 4: Configure private key flags
            if ($AllowExportableKey) {
                Write-Verbose "Enabling exportable key flag"
                $privateKeyFlag = [CertCA]::CT_FLAG_EXPORTABLE_KEY
                $hr = [CertCA]::CASetCertTypeFlagsEx($hNewCertType, [CertCA]::CERTTYPE_PRIVATE_KEY_FLAG, $privateKeyFlag)
                
                if ($hr -eq [CertCA]::S_OK) {
                    $changes += "Enabled CT_FLAG_EXPORTABLE_KEY"
                    Write-Verbose "Private key flag configured successfully"
                } else {
                    Write-Warning "Failed to set private key flag: HRESULT 0x$($hr.ToString('X8'))"
                }
            }
            
            # Step 5: Save the template
            Write-Verbose "Saving template changes to Active Directory"
            $hr = [CertCA]::CAUpdateCertType($hNewCertType)
            
            if ($hr -ne [CertCA]::S_OK) {
                $errorMsg = "Failed to save template '$NewTemplateName': HRESULT 0x$($hr.ToString('X8'))"
                
                return [PSCustomObject]@{
                    Success = $false
                    BaseTemplate = $BaseTemplateName
                    NewTemplate = $NewTemplateName
                    NewTemplateFriendlyName = $NewTemplateFriendlyName
                    Changes = $changes
                    Error = $errorMsg
                }
            }
            
            Write-Verbose "Template saved successfully"
            
            # Step 6: Enable template on CAs if requested
            $enableResult = $null
            if ($EnableTemplate) {
                Write-Verbose "Enabling template on Certificate Authorities"
                try {
                    # Find the newly created template
                    $AdcsObjects = Get-AdcsObjects
                    $NewTemplateObj = $AdcsObjects | Where-Object { 
                        $_.ObjectClass -eq 'pKICertificateTemplate' -and 
                        $_.Properties['name'].Value -eq $NewTemplateName 
                    }
                    
                    if ($NewTemplateObj) {
                        $enableResult = Enable-Template -Template $NewTemplateObj -PassThru
                        if ($enableResult.Success) {
                            $changes += "Enabled template on Certificate Authority: $($enableResult.CertificateAuthority)"
                            Write-Verbose "Template enabled on CA successfully"
                        } else {
                            Write-Warning "Failed to enable template on CA: $($enableResult.Error)"
                        }
                    } else {
                        Write-Warning "Could not find newly created template to enable on CAs"
                    }
                } catch {
                    Write-Warning "Failed to enable template on CAs: $($_.Exception.Message)"
                }
            }
            
            # Return success result
            return [PSCustomObject]@{
                Success = $true
                BaseTemplate = $BaseTemplateName
                NewTemplate = $NewTemplateName
                NewTemplateFriendlyName = $NewTemplateFriendlyName
                Changes = $changes
                EnableResult = $enableResult
                Error = $null
            }
            
        } catch {
            $errorMsg = "Unexpected error during template creation: $($_.Exception.Message)"
            Write-Warning $errorMsg
            
            return [PSCustomObject]@{
                Success = $false
                BaseTemplate = $BaseTemplateName
                NewTemplate = $NewTemplateName
                NewTemplateFriendlyName = $NewTemplateFriendlyName
                Changes = $changes
                Error = $errorMsg
            }
            
        } finally {
            # Clean up handles
            if ($hNewCertType -ne [IntPtr]::Zero) {
                [CertCA]::CACloseCertType($hNewCertType) | Out-Null
                Write-Verbose "New template handle closed"
            }
            if ($hBaseCertType -ne [IntPtr]::Zero) {
                [CertCA]::CACloseCertType($hBaseCertType) | Out-Null
                Write-Verbose "Base template handle closed"
            }
        }
    }

    end {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Finishing $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
    }
}