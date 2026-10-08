function Find-ESC1Issue {
    <#
        .SYNOPSIS
        Identifies AD CS certificate templates vulnerable to ESC1 (SAN spoofing) attacks.

        .DESCRIPTION
        This function analyzes certificate templates for the conditions that enable ESC1:
        1. CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT (0x1) set in msPKI-Certificate-Name-Flag
        2. Client Authentication EKU (1.3.6.1.5.5.7.3.2) in pKIExtendedKeyUsage
        3. A non-administrative principal holds the Enroll extended right
        4. Template is enabled on at least one CA
        5. Manager approval is not required (msPKI-Enrollment-Flag bit 0x2 not set)
        6. No authorized signatures required (msPKI-RA-Signature = 0)

        .PARAMETER AdcsObjects
        Array of AD CS objects from Get-AdcsObjects. The function filters for certificate templates.

        .PARAMETER SafeOwners
        Regex pattern of SIDs for principals that are safe to own certificate templates.

        .PARAMETER SafeUsers
        Regex pattern of SIDs for principals considered safe (excluded from findings).

        .PARAMETER EnrollGUID
        GUID of the Enroll extended right. Defaults to the well-known value.

        .INPUTS
        System.DirectoryServices.DirectoryEntry[]

        .OUTPUTS
        ESCalatorIssue[] with Technique='ESC1', Subtype='Template-EnrolleeSuppliesSubject'

        .EXAMPLE
        $AdcsObjects = Get-AdcsObjects
        $ESC1Issues = Find-ESC1Issue -AdcsObjects $AdcsObjects

        .LINK
        https://posts.specterops.io/certified-pre-owned-d95910965cd2
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [System.DirectoryServices.DirectoryEntry[]]$AdcsObjects,

        [Parameter()]
        [string]$SafeOwners = '-519$',

        [Parameter()]
        [string]$SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-521$|-498$|-9$|-526$|-527$|S-1-5-10',

        [Parameter()]
        [string]$EnrollGUID = '0e10c968-78fb-11d2-90d4-00c04f79dc55',

        [Parameter()]
        [string]$ClientAuthOID = '1.3.6.1.5.5.7.3.2'
    )

    begin {
        . "$PSScriptRoot\ESCalatorIssue.ps1"
        Write-Verbose "Starting ESC1 template vulnerability scan"
    }

    process {
        $Templates = $AdcsObjects | Where-Object { $_.objectClass -contains 'pKICertificateTemplate' }
        Write-Verbose "Processing $($Templates.Count) certificate templates"

        foreach ($Template in $Templates) {
            $templateName = $Template.Properties['name'].Value
            $templateDN = $Template.Properties['distinguishedName'].Value

            # Check 1: SAN allowed (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
            $nameFlag = 0
            try { $nameFlag = [int]$Template.Properties['msPKI-Certificate-Name-Flag'].Value } catch { }
            $sanAllowed = ($nameFlag -band 0x1) -eq 0x1
            if (-not $sanAllowed) { continue }

            # Check 2: Client Authentication EKU
            $ekus = @($Template.Properties['pKIExtendedKeyUsage'].Value)
            $clientAuthEnabled = $ekus -contains $ClientAuthOID
            if (-not $clientAuthEnabled) { continue }

            # Check 3: Enabled on at least one CA
            $templateEnabled = $false
            if ($Template.PSObject.Properties['Enabled']) {
                $templateEnabled = $Template.Enabled
            }
            if (-not $templateEnabled) { continue }

            # Check 4: No manager approval required
            $enrollFlag = 0
            try { $enrollFlag = [int]$Template.Properties['msPKI-Enrollment-Flag'].Value } catch { }
            $managerApprovalRequired = ($enrollFlag -band 0x2) -eq 0x2
            if ($managerApprovalRequired) { continue }

            # Check 5: No authorized signatures required
            $raSignature = 0
            try { $raSignature = [int]$Template.Properties['msPKI-RA-Signature'].Value } catch { }
            if ($raSignature -gt 0) { continue }

            # All property conditions met. Now check enroll rights.
            $forestName = if ($templateDN) {
                $parts = $templateDN -split ',DC='
                if ($parts.Count -gt 1) { $parts[1..($parts.Count - 1)] -join '.' } else { 'Unknown' }
            } else { 'Unknown' }

            try {
                $security = $Template.ObjectSecurity
                if (-not $security.Access) { continue }

                foreach ($ace in $security.Access) {
                    try {
                        if ($ace.AccessControlType -ne 'Allow') { continue }

                        # Only care about the Enroll extended right
                        if ($ace.ObjectType -and $ace.ObjectType.Guid -ne $EnrollGUID) { continue }

                        # Resolve identity to SID
                        $aceSID = $null
                        if ($ace.IdentityReference -match '^S-1-') {
                            $aceSID = $ace.IdentityReference.Value
                        } else {
                            try {
                                $acePrincipal = New-Object System.Security.Principal.NTAccount($ace.IdentityReference)
                                $aceSID = $acePrincipal.Translate([System.Security.Principal.SecurityIdentifier]).Value
                            } catch { continue }
                        }

                        # Skip safe principals
                        if ($aceSID -match $SafeOwners -or $aceSID -match $SafeUsers) { continue }

                        Write-Verbose "Found ESC1 issue: $templateName - $($ace.IdentityReference) can enroll with SAN spoofing"

                        [ESCalatorIssue]::CreateOriginalIssue(
                            $forestName,
                            $templateName,
                            $templateDN,
                            $ace.IdentityReference.Value,
                            $aceSID,
                            $ace.ActiveDirectoryRights.ToString(),
                            'ESC1',
                            'Template-EnrolleeSuppliesSubject',
                            "$($ace.IdentityReference) can enroll in this template which allows SAN specification and has Client Authentication EKU, enabling certificate requests with arbitrary Subject Alternative Names.",
                            'Critical',
                            $EnrollGUID,
                            $Template
                        )
                    } catch {
                        Write-Warning "Failed to process ACE for identity $($ace.IdentityReference) on template $templateName : $_"
                    }
                }
            } catch {
                Write-Warning "Failed to analyze security for template $templateName : $_"
            }
        }
    }

    end {
        Write-Verbose "ESC1 template vulnerability scan completed"
    }
}
