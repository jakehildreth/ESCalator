param (
    # A CalVer string if you need to manually override the default yyyy.M.dHHmm version string.
    [string]$CalVer,
    # A prerelease tag to append to the module version (e.g., 'alpha', 'beta', 'rc1').
    [string]$Prerelease,
    [switch]$PublishToPSGallery,
    [string]$PSGalleryAPIPath,
    [string]$PSGalleryAPIKey,
    # When present, creates a GitHub release and attaches the artefact as a zip asset.
    [switch]$PublishToGitHub,
    # GitHub personal access token for creating releases. Used in CI via a secret environment variable.
    [string]$GitHubAPIKey,
    # Path to a file containing the GitHub personal access token. Used for local developer workflows.
    [string]$GitHubAPIPath,
    # GitHub owner (user or organization) for release publishing. Defaults to 'jakehildreth'.
    [string]$GitHubOwner = 'jakehildreth',
    # GitHub repository name for release publishing. Defaults to 'ESCalator'.
    [string]$GitHubRepository = 'ESCalator'
)

# The VS Code PowerShell Extension pre-loads PSScriptAnalyzer into the host
# process. PSPublishModule imports PSScriptAnalyzer internally, and loading a
# second copy of its assembly into the same appdomain throws an assembly-already-
# loaded error. Re-invoke in a clean pwsh -NoProfile child process to avoid it.
if ($Host.Name -eq 'Visual Studio Code Host' -or
    $null -ne [System.AppDomain]::CurrentDomain.GetAssemblies().Where({
            $_.GetName().Name -eq 'Microsoft.Windows.PowerShell.ScriptAnalyzer'
        }, 'First')[0]) {
    Write-Host 'Re-invoking in a clean pwsh process to avoid PSScriptAnalyzer assembly conflict...'
    $passThrough = @('-NoProfile', '-File', $PSCommandPath)
    if ($CalVer) { $passThrough += '-CalVer'; $passThrough += $CalVer }
    if ($Prerelease) { $passThrough += '-Prerelease'; $passThrough += $Prerelease }
    if ($PublishToPSGallery) { $passThrough += '-PublishToPSGallery' }
    if ($PSGalleryAPIPath) { $passThrough += '-PSGalleryAPIPath'; $passThrough += $PSGalleryAPIPath }
    if ($PSGalleryAPIKey) { $passThrough += '-PSGalleryAPIKey'; $passThrough += $PSGalleryAPIKey }
    if ($PublishToGitHub) { $passThrough += '-PublishToGitHub' }
    if ($GitHubAPIKey) { $passThrough += '-GitHubAPIKey'; $passThrough += $GitHubAPIKey }
    if ($GitHubAPIPath) { $passThrough += '-GitHubAPIPath'; $passThrough += $GitHubAPIPath }
    if ($PSBoundParameters.ContainsKey('GitHubOwner')) { $passThrough += '-GitHubOwner'; $passThrough += $GitHubOwner }
    if ($PSBoundParameters.ContainsKey('GitHubRepository')) { $passThrough += '-GitHubRepository'; $passThrough += $GitHubRepository }
    & pwsh @passThrough
    exit $LASTEXITCODE
}

if (Get-Module -Name 'PSPublishModule' -ListAvailable) {
    Write-Verbose 'PSPublishModule is installed.'
} else {
    Write-Verbose 'PSPublishModule is not installed. Attempting installation.'
    try {
        Install-Module -Name Pester -AllowClobber -Scope CurrentUser -SkipPublisherCheck -Force
        Install-Module -Name PSScriptAnalyzer -AllowClobber -Scope CurrentUser -Force
        Install-Module -Name PSPublishModule -MaximumVersion 2.0.27 -AllowClobber -Scope CurrentUser -Force
    } catch {
        Write-Error "PSPublishModule installation failed. $_"
    }
}

Import-Module -Name PSPublishModule -Force

$CopyrightYear = if ($Calver) { $CalVer.Split('.')[0] } else { (Get-Date -Format yyyy) }

Build-Module -ModuleName 'ESCalator' {
    # Always use 3-part CalVer: yyyy.M.dHHmm (e.g., 2026.7.220745)
    # Prerelease builds append the supplied tag to the version string.
    $moduleVersion = if ($CalVer) { $CalVer } else { (Get-Date -Format 'yyyy.M.dHHmm') }
    $Manifest = [ordered] @{
        ModuleVersion        = $moduleVersion
        CompatiblePSEditions = @('Desktop', 'Core')
        GUID                 = '3f75ccf6-a762-44b4-84b4-cad211662403'
        Author               = 'Jake Hildreth'
        CompanyName          = 'Gilmour Technologies Ltd'
        Copyright            = "(c) 2025 - $CopyrightYear Jake Hildreth, Gilmour Technologies Ltd. All rights reserved."
        Description          = 'A tiny tool for identifying and abusing AD CS issue combinations that may not be readily obvious'
        ProjectUri           = 'https://github.com/jakehildreth/ESCalator'
        PowerShellVersion    = '5.1'
        Tags                 = @('ADCS', 'ESCalator', 'CertificateServices', 'PKI', 'ActiveDirectory', 'Windows', 'Security')
    }
    if ($Prerelease) {
        $Manifest['Prerelease'] = $Prerelease
    }
    New-ConfigurationManifest @Manifest
    New-ConfigurationModule -Type ExternalModule -Name @(
        'Microsoft.PowerShell.Utility',
        'Microsoft.PowerShell.Management',
        'Microsoft.PowerShell.Security'
    )

    $ConfigurationFormat = [ordered] @{
        RemoveComments                              = $false

        PlaceOpenBraceEnable                        = $true
        PlaceOpenBraceOnSameLine                    = $true
        PlaceOpenBraceNewLineAfter                  = $true
        PlaceOpenBraceIgnoreOneLineBlock            = $false

        PlaceCloseBraceEnable                       = $true
        PlaceCloseBraceNewLineAfter                 = $true
        PlaceCloseBraceIgnoreOneLineBlock           = $false
        PlaceCloseBraceNoEmptyLineBefore            = $true

        UseConsistentIndentationEnable              = $true
        UseConsistentIndentationKind                = 'space'
        UseConsistentIndentationPipelineIndentation = 'IncreaseIndentationAfterEveryPipeline'
        UseConsistentIndentationIndentationSize     = 4

        UseConsistentWhitespaceEnable               = $true
        UseConsistentWhitespaceCheckInnerBrace      = $true
        UseConsistentWhitespaceCheckOpenBrace       = $true
        UseConsistentWhitespaceCheckOpenParen       = $true
        UseConsistentWhitespaceCheckOperator        = $true
        UseConsistentWhitespaceCheckPipe            = $true
        UseConsistentWhitespaceCheckSeparator       = $true

        AlignAssignmentStatementEnable              = $true
        AlignAssignmentStatementCheckHashtable      = $true

        UseCorrectCasingEnable                      = $true
    }
    # Format PSM1 files within the module.
    New-ConfigurationFormat -ApplyTo 'DefaultPSM1' -EnableFormatting -Sort None
    # Use a minimal PSD1 style when creating the merged manifest.
    # DefaultPSD1 is intentionally excluded: PSPublishModule rewrites the source
    # PSD1 during the build and produces mixed CRLF/LF endings, which causes
    # PSScriptAnalyzer to throw.
    New-ConfigurationFormat -ApplyTo 'OnMergePSD1' -PSD1Style 'Minimal'

    # Disable PSPublishModule documentation generation so existing hand-written
    # help files under docs\ and en-US\ are preserved.
    New-ConfigurationDocumentation -Enable:$false -StartClean -UpdateWhenNew -PathReadme 'docs\Readme.md' -Path 'docs'

    New-ConfigurationImportModule -ImportSelf -ImportRequiredModules

    New-ConfigurationBuild -Enable:$true -SignModule:$false -DeleteTargetModuleBeforeBuild -MergeModuleOnBuild:$false -DoNotAttemptToFixRelativePaths -UseWildcardForFunctions

    New-ConfigurationArtefact -Type Unpacked -Enable -Path "$PSScriptRoot\..\Artefacts\Unpacked"
    New-ConfigurationArtefact -Type Packed -Enable -Path "$PSScriptRoot\..\Artefacts\Packed" -IncludeTagName
}

# PSPublishModule's Publish-Module call uses -Name (resolves from PSModulePath),
# which publishes the pre-vendoring copy of the module. Publish via -Path from
# the artefact directory instead.

# Post-build: optionally publish from the artefact path to PSGallery and GitHub.
. "$PSScriptRoot\Invoke-ESCPostBuildPublish.ps1"

$postBuildParams = @{
    ArtefactRoot       = Join-Path $PSScriptRoot '..' 'Artefacts' 'Unpacked' 'ESCalator'
    PublishToPSGallery = $PublishToPSGallery
    PublishToGitHub    = $PublishToGitHub
}
if ($PSGalleryAPIKey) { $postBuildParams['PSGalleryAPIKey'] = $PSGalleryAPIKey }
if ($PSGalleryAPIPath) { $postBuildParams['PSGalleryAPIPath'] = $PSGalleryAPIPath }
if ($GitHubAPIKey) { $postBuildParams['GitHubAPIKey'] = $GitHubAPIKey }
if ($GitHubAPIPath) { $postBuildParams['GitHubAPIPath'] = $GitHubAPIPath }
if ($PSBoundParameters.ContainsKey('GitHubOwner')) { $postBuildParams['GitHubOwner'] = $GitHubOwner }
if ($PSBoundParameters.ContainsKey('GitHubRepository')) { $postBuildParams['GitHubRepository'] = $GitHubRepository }
if ($Prerelease) { $postBuildParams['Prerelease'] = $Prerelease }

Invoke-ESCPostBuildPublish @postBuildParams
