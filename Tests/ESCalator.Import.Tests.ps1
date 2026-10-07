BeforeAll {
    $manifestPath = Join-Path -Path $PSScriptRoot -ChildPath '../ESCalator.psd1'
    $powerShellPath = (Get-Process -Id $PID).Path
}

Describe 'ESCalator import' {
    It 'Exports the Start-ESCalator command' {
        $scriptPath = Join-Path -Path $TestDrive -ChildPath 'Import-Module.ps1'
        @'
param($ManifestPath)
$ErrorActionPreference = 'Stop'
$env:PSModulePath = Join-Path -Path $PSHOME -ChildPath 'Modules'
Import-Module -Name $ManifestPath
$command = Get-Command -Name Start-ESCalator -Module ESCalator
if ($command.CommandType -ne 'Function') { throw 'Start-ESCalator is unavailable.' }
Write-Output 'Start-ESCalator command available.'
'@ | Set-Content -Path $scriptPath -Encoding UTF8

        $output = & $powerShellPath -NoProfile -File $scriptPath -ManifestPath $manifestPath 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($output -join [Environment]::NewLine)
        $output | Should -Contain 'Start-ESCalator command available.'
    }
}
