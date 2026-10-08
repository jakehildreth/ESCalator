BeforeAll {
    $moduleRoot = Split-Path -Path $PSScriptRoot -Parent
    . (Join-Path -Path $moduleRoot -ChildPath 'Private/ESCalatorIssue.ps1')
    . (Join-Path -Path $moduleRoot -ChildPath 'Private/Find-ESC2.ps1')

    $script:CurrentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

    function New-ESC2Issue {
        param(
            [string]$Sid,
            [string]$Identity,
            [string]$Technique = 'ESC2',
            [string]$Name = 'VMware 6.x'
        )
        [ESCalatorIssue]::CreateOriginalIssue(
            'adcs.goat', $Name,
            "CN=$Name,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=adcs,DC=goat",
            $Identity, $Sid, 'ExtendedRight', $Technique, 'Template-AnyPurposeEKU',
            "$Identity can enroll in this template, which has the Any Purpose EKU.",
            'High', $null, $null
        )
    }
}

Describe 'Find-ESC2 principal filtering' {
    Context 'For the current user' {
        It 'Matches an issue whose SID is the current user' {
            $issue = New-ESC2Issue -Sid $script:CurrentSid -Identity "$env:USERDOMAIN\$env:USERNAME"
            $results = @(Find-ESC2 -Issues @($issue))
            $results.Count | Should -Be 1
            $results[0].Technique | Should -Be 'ESC2'
            $results[0].ESC2Count | Should -Be 1
        }

        It 'Matches an issue on an implicit-membership SID (Authenticated Users)' {
            $issue = New-ESC2Issue -Sid 'S-1-5-11' -Identity 'NT AUTHORITY\Authenticated Users'
            $results = @(Find-ESC2 -Issues @($issue))
            $results.Count | Should -Be 1 -Because 'the current user is implicitly in Authenticated Users'
        }

        It 'Matches an issue on Everyone (S-1-1-0)' {
            $issue = New-ESC2Issue -Sid 'S-1-1-0' -Identity 'Everyone'
            $results = @(Find-ESC2 -Issues @($issue))
            $results.Count | Should -Be 1
        }

        It 'Groups matched issues under the principal and exposes the technique' {
            $issue = New-ESC2Issue -Sid $script:CurrentSid -Identity "$env:USERDOMAIN\$env:USERNAME"
            $results = @(Find-ESC2 -Issues @($issue))
            $results[0].PrincipalSID | Should -Be $script:CurrentSid
            $results[0].Attack | Should -Be 'Enroll On Behalf Of (ESC2)'
        }
    }

    Context 'Filtering out non-applicable issues' {
        It 'Ignores issues for other techniques' {
            $issue = New-ESC2Issue -Sid $script:CurrentSid -Identity "$env:USERDOMAIN\$env:USERNAME" -Technique 'ESC1'
            $results = @(Find-ESC2 -Issues @($issue))
            $results.Count | Should -Be 0
        }

        It 'Ignores issues for an unrelated principal' {
            $issue = New-ESC2Issue -Sid 'S-1-5-21-0-0-0-999999' -Identity 'OTHERDOMAIN\nobody'
            $results = @(Find-ESC2 -Issues @($issue))
            $results.Count | Should -Be 0
        }
    }
}
