BeforeAll {
    $moduleRoot = Split-Path -Path $PSScriptRoot -Parent
    . (Join-Path -Path $moduleRoot -ChildPath 'Private/ESCalatorIssue.ps1')
    . (Join-Path -Path $moduleRoot -ChildPath 'Private/Find-ESC4p5Combo.ps1')
    . (Join-Path -Path $moduleRoot -ChildPath 'Private/Get-AdcsObjects.ps1')
    . (Join-Path -Path $moduleRoot -ChildPath 'Private/Get-EnabledTemplate.ps1')
    . (Join-Path -Path $moduleRoot -ChildPath 'Private/Set-TemplateEnabledStatus.ps1')

    # Collect real objects from the lab
    $script:AdcsObjects = Get-AdcsObjects
    $script:EnabledMap = Get-EnabledTemplate -AdcsObjects $script:AdcsObjects
    Set-EnabledTemplateStatus -AdcsObjects $script:AdcsObjects -EnabledTemplates $script:EnabledMap

    # Find the 'Test SSL' template (enabled in the lab)
    $script:EnabledTemplate = $script:AdcsObjects | Where-Object {
        $_.Properties['name'].Value -eq 'Test SSL'
    }

    # Find the 'Copy of Workstation' template (disabled in the lab)
    $script:DisabledTemplate = $script:AdcsObjects | Where-Object {
        $_.Properties['name'].Value -eq 'Copy of Workstation'
    }
}

Describe 'Find-ESC4p5Combo enabled status' -Tag 'Integration' {
    Context 'When a template has Enabled stamped via Add-Member' {
        It 'Should exclude the enabled template from the disabled set' {
            # Verify the stamping landed
            $script:EnabledTemplate.Enabled | Should -Be $true

            # Create a Critical ESC4 issue for the enabled template
            $esc4Issue = [ESCalatorIssue]::CreateOriginalIssue(
                'adcs.goat',
                'Test SSL',
                $script:EnabledTemplate.Properties['distinguishedName'].Value,
                'adcs\Administrator',
                'S-1-5-21-2191158864-3153074209-2010794967-500',
                'GenericAll',
                'ESC4',
                'Template-GenericAll',
                'Administrator has GenericAll rights on this certificate template.',
                'Critical',
                $null,
                $script:EnabledTemplate
            )

            # Create a matching Critical ESC5 issue
            $esc5Issue = [ESCalatorIssue]::CreateOriginalIssue(
                'adcs.goat',
                'LabRootCA1',
                'CN=LabRootCA1,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=adcs,DC=goat',
                'adcs\Administrator',
                'S-1-5-21-2191158864-3153074209-2010794967-500',
                'GenericAll',
                'ESC5',
                'EnrollmentService-GenericAll',
                'Administrator has GenericAll on the enrollment service.',
                'Critical',
                $null,
                $null
            )

            $results = Find-ESC4p5Combo -Issues @($esc4Issue, $esc5Issue)
            $results | Should -BeNullOrEmpty -Because 'Test SSL is enabled and should not be in the ESC4p5 disabled set'
        }

        It 'Should include a disabled template in the disabled set' {
            # Verify the stamping landed
            $script:DisabledTemplate.Enabled | Should -Be $false

            $esc4Issue = [ESCalatorIssue]::CreateOriginalIssue(
                'adcs.goat',
                'Copy of Workstation',
                $script:DisabledTemplate.Properties['distinguishedName'].Value,
                'adcs\Administrator',
                'S-1-5-21-2191158864-3153074209-2010794967-500',
                'GenericAll',
                'ESC4',
                'Template-GenericAll',
                'Administrator has GenericAll rights on this certificate template.',
                'Critical',
                $null,
                $script:DisabledTemplate
            )

            $esc5Issue = [ESCalatorIssue]::CreateOriginalIssue(
                'adcs.goat',
                'LabRootCA1',
                'CN=LabRootCA1,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=adcs,DC=goat',
                'adcs\Administrator',
                'S-1-5-21-2191158864-3153074209-2010794967-500',
                'GenericAll',
                'ESC5',
                'EnrollmentService-GenericAll',
                'Administrator has GenericAll on the enrollment service.',
                'Critical',
                $null,
                $null
            )

            $results = Find-ESC4p5Combo -Issues @($esc4Issue, $esc5Issue)
            $results | Should -Not -BeNullOrEmpty -Because 'Copy of Workstation is disabled and should produce a combo'
        }
    }
}
