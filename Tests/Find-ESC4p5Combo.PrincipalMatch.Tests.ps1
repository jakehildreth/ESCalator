BeforeAll {
    $moduleRoot = Split-Path -Path $PSScriptRoot -Parent
    . (Join-Path -Path $moduleRoot -ChildPath 'Private/ESCalatorIssue.ps1')
    . (Join-Path -Path $moduleRoot -ChildPath 'Private/Find-ESC4p5Combo.ps1')
    . (Join-Path -Path $moduleRoot -ChildPath 'Private/Get-AdcsObjects.ps1')
    . (Join-Path -Path $moduleRoot -ChildPath 'Private/Get-EnabledTemplate.ps1')
    . (Join-Path -Path $moduleRoot -ChildPath 'Private/Set-TemplateEnabledStatus.ps1')

    $script:AdcsObjects = Get-AdcsObjects
    $script:EnabledMap = Get-EnabledTemplate -AdcsObjects $script:AdcsObjects
    Set-EnabledTemplateStatus -AdcsObjects $script:AdcsObjects -EnabledTemplates $script:EnabledMap

    $script:DisabledTemplate = $script:AdcsObjects | Where-Object {
        $_.Properties['name'].Value -eq 'Copy of Workstation'
    }
}

Describe 'Find-ESC4p5Combo principal matching' -Tag 'Integration' {
    Context 'When ESC4 is on Domain Users (expanded) and ESC5 is on Authenticated Users' {
        It 'Should find the combo for a domain user who is in both groups' {
            # ESC4 issue: expanded from Domain Users to Administrator
            $esc4Issue = [ESCalatorIssue]::CreateExpandedIssue(
                'adcs.goat',
                'Copy of Workstation',
                $script:DisabledTemplate.Properties['distinguishedName'].Value,
                'adcs\Administrator',
                'S-1-5-21-2191158864-3153074209-2010794967-500',
                'GenericAll',
                'ESC4',
                'Template-GenericAll',
                'adcs\Administrator has GenericAll rights on this certificate template.',
                'Critical',
                $null,
                $script:DisabledTemplate,
                'adcs\Domain Users',
                'S-1-5-21-2191158864-3153074209-2010794967-513',
                'UserPrincipal'
            )

            # ESC5 issue: Authenticated Users (S-1-5-11), NOT expanded (pseudo-SID)
            $esc5Issue = [ESCalatorIssue]::CreateOriginalIssue(
                'adcs.goat',
                'LabRootCA1',
                'CN=LabRootCA1,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=adcs,DC=goat',
                'NT AUTHORITY\Authenticated Users',
                'S-1-5-11',
                'GenericAll',
                'ESC5',
                'EnrollmentService-GenericAll',
                'Authenticated Users has GenericAll on the enrollment service.',
                'Critical',
                $null,
                $null
            )

            # Run as Administrator (the expanded principal)
            $adminPrincipal = $script:AdcsObjects | Where-Object {
                $_.Properties['name'].Value -eq 'Test SSL'
            }
            # We need a real DirectoryEntry for the Principal parameter.
            # Use the Administrator's actual AD object.
            $adminEntry = [System.DirectoryServices.DirectoryEntry]::new("LDAP://CN=Administrator,CN=Users,DC=adcs,DC=goat")
            $adminEntry.RefreshCache()

            $results = Find-ESC4p5Combo -Issues @($esc4Issue, $esc5Issue) -Principal $adminEntry
            $results | Should -Not -BeNullOrEmpty -Because 'Administrator is in Domain Users (ESC4) and implicitly in Authenticated Users (ESC5)'
        }

        It 'Should find the combo for Everyone (S-1-1-0) as well' {
            $esc4Issue = [ESCalatorIssue]::CreateExpandedIssue(
                'adcs.goat',
                'Copy of Workstation',
                $script:DisabledTemplate.Properties['distinguishedName'].Value,
                'adcs\Administrator',
                'S-1-5-21-2191158864-3153074209-2010794967-500',
                'GenericAll',
                'ESC4',
                'Template-GenericAll',
                'adcs\Administrator has GenericAll rights on this certificate template.',
                'Critical',
                $null,
                $script:DisabledTemplate,
                'adcs\Domain Users',
                'S-1-5-21-2191158864-3153074209-2010794967-513',
                'UserPrincipal'
            )

            # ESC5 issue on Everyone (S-1-1-0)
            $esc5Issue = [ESCalatorIssue]::CreateOriginalIssue(
                'adcs.goat',
                'LabRootCA1',
                'CN=LabRootCA1,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=adcs,DC=goat',
                'Everyone',
                'S-1-1-0',
                'GenericAll',
                'ESC5',
                'EnrollmentService-GenericAll',
                'Everyone has GenericAll on the enrollment service.',
                'Critical',
                $null,
                $null
            )

            $adminEntry = [System.DirectoryServices.DirectoryEntry]::new("LDAP://CN=Administrator,CN=Users,DC=adcs,DC=goat")
            $adminEntry.RefreshCache()

            $results = Find-ESC4p5Combo -Issues @($esc4Issue, $esc5Issue) -Principal $adminEntry
            $results | Should -Not -BeNullOrEmpty -Because 'Administrator is implicitly in Everyone (ESC5)'
        }
    }
}
