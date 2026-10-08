BeforeAll {
    $moduleRoot = Split-Path -Path $PSScriptRoot -Parent
    . (Join-Path -Path $moduleRoot -ChildPath 'Private/ESCalatorIssue.ps1')
    . (Join-Path -Path $moduleRoot -ChildPath 'Private/Find-ESC1Issue.ps1')
    . (Join-Path -Path $moduleRoot -ChildPath 'Private/Get-AdcsObjects.ps1')
    . (Join-Path -Path $moduleRoot -ChildPath 'Private/Get-EnabledTemplate.ps1')
    . (Join-Path -Path $moduleRoot -ChildPath 'Private/Set-TemplateEnabledStatus.ps1')

    $script:AdcsObjects = Get-AdcsObjects
    $script:EnabledMap = Get-EnabledTemplate -AdcsObjects $script:AdcsObjects
    Set-EnabledTemplateStatus -AdcsObjects $script:AdcsObjects -EnabledTemplates $script:EnabledMap
}

Describe 'Find-ESC1Issue' -Tag 'Integration' {
    Context 'When scanning the ADCSGoat lab' {
        It 'Should detect Copy of Web Server as ESC1' {
            $issues = Find-ESC1Issue -AdcsObjects $script:AdcsObjects
            $copyOfWebServer = $issues | Where-Object { $_.Name -eq 'Copy of Web Server' }
            $copyOfWebServer | Should -Not -BeNullOrEmpty -Because 'Copy of Web Server has SAN allowed, Client Auth EKU, and Domain Users enroll'
        }

        It 'Should not detect templates without SAN as ESC1' {
            $issues = Find-ESC1Issue -AdcsObjects $script:AdcsObjects
            $userTemplate = $issues | Where-Object { $_.Name -eq 'User' }
            $userTemplate | Should -BeNullOrEmpty -Because 'User template does not allow SAN specification'
        }

        It 'Should not detect templates without Client Auth EKU as ESC1' {
            $issues = Find-ESC1Issue -AdcsObjects $script:AdcsObjects
            $webServer = $issues | Where-Object { $_.Name -eq 'WebServer' }
            $webServer | Should -BeNullOrEmpty -Because 'WebServer has SAN but no Client Authentication EKU'
        }

        It 'Should not detect disabled templates as ESC1' {
            $issues = Find-ESC1Issue -AdcsObjects $script:AdcsObjects
            foreach ($issue in $issues) {
                $issue.DirectoryEntry.Enabled | Should -Be $true -Because "ESC1 issue '$($issue.Name)' should only be reported for enabled templates"
            }
        }

        It 'Should set Technique to ESC1' {
            $issues = Find-ESC1Issue -AdcsObjects $script:AdcsObjects
            foreach ($issue in $issues) {
                $issue.Technique | Should -Be 'ESC1'
            }
        }
    }
}
