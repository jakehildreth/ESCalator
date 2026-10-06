function Find-ESC2Issue {
    <#
        .SYNOPSIS
        Identifies AD CS certificate templates vulnerable to ESC2 (Any Purpose EKU / no EKU) attacks.

        .DESCRIPTION
        ESC2 occurs when a certificate template has the Any Purpose EKU (2.5.29.37.0) or no EKU
        extension at all, AND a low-privileged principal can enroll in it. A certificate issued
        from such a template is valid for any application - including acting as a Certificate
        Request Agent - which enables Enroll On Behalf Of (EOBO) to obtain a client-auth
        certificate for another user.

        This function flags templates that:
        1. Have Any Purpose EKU (2.5.29.37.0) or an empty pKIExtendedKeyUsage, AND
        2. Grant Enroll (or GenericAll/FullControl) to a non-safe principal, AND
        3. Do not require manager approval (CT_FLAG_PEND_ALL_REQUESTS not set).

        .PARAMETER AdcsObjects
        Array of AD CS objects from Get-AdcsObjects. Filtered to certificate templates.

        .PARAMETER SafeUsers
        Regex pattern of SIDs considered safe (default: built-in admin/system principals).

        .INPUTS
        System.DirectoryServices.DirectoryEntry[]

        .OUTPUTS
        ESCalatorIssue[] with Technique 'ESC2'. Subtypes:
        - Template-AnyPurposeEKU: template has the Any Purpose EKU and is enrollable
        - Template-NoEKU: template has no EKU extension and is enrollable

        .EXAMPLE
        $AdcsObjects = Get-AdcsObjects
        $ESC2Issues = Find-ESC2Issue -AdcsObjects $AdcsObjects

        .NOTES
        The exploit path is Invoke-EOBOAttack (EOBO via the Any-Purpose cert as enrollment agent).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.DirectoryServices.DirectoryEntry[]]$AdcsObjects,

        [Parameter()]
        [string]$SafeUsers
    )

    #requires -Version 5.1

    if (-not $SafeUsers) {
        $SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-521$|-498$|-9$|-526$|-527$|S-1-5-10$'
    }

    $anyPurposeOid = '2.5.29.37.0'
    $enrollGuid = [System.Guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
    $autoEnrollGuid = [System.Guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'

    $forestName = ''
    try {
        $first = $AdcsObjects | Select-Object -First 1
        if ($first -and $first.Properties['rootDomainNamingContext']) { $forestName = $first.Properties['rootDomainNamingContext'].Value }
    } catch { $forestName = '' }

    $issues = @()

    $templates = $AdcsObjects | Where-Object { $_.SchemaClassName -eq 'pKICertificateTemplate' }
    foreach ($template in $templates) {
        $name = $template.Properties['name'].Value
        $dn = $template.Properties['distinguishedName'].Value

        # ESC2 EKU condition
        $ekuProp = $template.Properties['pKIExtendedKeyUsage']
        $ekus = @()
        if ($ekuProp -and $ekuProp.Count -gt 0) { foreach ($e in $ekuProp) { $ekus += "$e" } }
        $hasAnyPurpose = $ekus -contains $anyPurposeOid
        $hasNoEku = ($ekus.Count -eq 0)
        if (-not ($hasAnyPurpose -or $hasNoEku)) { continue }
        $subtype = if ($hasAnyPurpose) { 'Template-AnyPurposeEKU' } else { 'Template-NoEKU' }

        # Not pending-approval gated
        $enrollFlag = 0
        if ($template.Properties['msPKI-Enrollment-Flag'].Value) { $enrollFlag = [int]$template.Properties['msPKI-Enrollment-Flag'].Value }
        $pendingApproval = ($enrollFlag -band 0x2) -ne 0
        if ($pendingApproval) { continue }

        # Find a non-safe principal with Enroll (or full control) rights
        $security = $template.ObjectSecurity
        foreach ($ace in $security.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            $sid = $ace.IdentityReference.Value
            # Resolve group/user name to SID if it's not already one
            if ($sid -notmatch '^S-1-') {
                try { $sid = (New-Object System.Security.Principal.NTAccount($sid)).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { continue }
            }
            if ($sid -match $SafeUsers) { continue }

            $grantsEnroll = ($ace.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner') -or
                            (($ace.ActiveDirectoryRights -match 'ExtendedRight') -and ($ace.ObjectType -eq $enrollGuid -or $ace.ObjectType -eq [System.Guid]::Empty -or $ace.ObjectType -eq $autoEnrollGuid))
            if (-not $grantsEnroll) { continue }

            $issueText = if ($hasAnyPurpose) {
                "$($ace.IdentityReference) can enroll in this template, which has the Any Purpose EKU (2.5.29.37.0). An issued certificate can act as a Certificate Request Agent to Enroll On Behalf Of other users (ESC2)."
            } else {
                "$($ace.IdentityReference) can enroll in this template, which has no EKU restriction. An issued certificate is valid for any application - including acting as a Certificate Request Agent for Enroll On Behalf Of (ESC2)."
            }

            $issues += [ESCalatorIssue]::new(
                $forestName, $name, $dn, $ace.IdentityReference.Value, $sid,
                $ace.ActiveDirectoryRights.ToString(), 'ESC2', $subtype, $issueText, 'High',
                $null, $template
            )
        }
    }

    return $issues
}
