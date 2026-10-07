function Invoke-ESCPostBuildPublish {
    <#
    .SYNOPSIS
    Copies about help into the artefact and optionally publishes to PSGallery and GitHub.

    .DESCRIPTION
    Copies the about_* help files into the module-root culture folder of the unpacked
    artefact, then - if requested - publishes directly from the artefact path so that
    what ships matches exactly what is in the artefact directory rather than the
    source tree resolved from PSModulePath.

    When a GitHub token is supplied and publishing is enabled, the unpacked artefact is
    compressed into a zip and attached to a GitHub release.

    .PARAMETER ArtefactRoot
    Full path to the unpacked module artefact directory (contains ESCalator.psd1).

    .PARAMETER PublishToPSGallery
    When present, publishes the module to PSGallery.

    .PARAMETER PSGalleryAPIKey
    NuGet API key in clear text. Used when running in CI via a secret environment variable.

    .PARAMETER PSGalleryAPIPath
    Path to a file containing the NuGet API key. Used for local developer workflows.

    .PARAMETER PublishToGitHub
    When present, creates a GitHub release and attaches the artefact as a zip asset.

    .PARAMETER GitHubAPIKey
    GitHub personal access token in clear text. Used when running in CI via a secret environment variable.

    .PARAMETER GitHubAPIPath
    Path to a file containing the GitHub personal access token. Used for local developer workflows.

    .PARAMETER GitHubOwner
    GitHub owner (user or organization) for release publishing. Defaults to 'jakehildreth'.

    .PARAMETER GitHubRepository
    GitHub repository name for release publishing. Defaults to 'ESCalator'.

    .PARAMETER Prerelease
    Prerelease tag appended to the module version. When present, the GitHub release is marked as a prerelease.

    .PARAMETER GitHubSha
    Commit SHA to use as the GitHub release target_commitish. Defaults to $env:GITHUB_SHA.
    GitHub releases are only allowed when this value is provided.

    .EXAMPLE
    Invoke-ESCPostBuildPublish -ArtefactRoot 'C:\ESCalator\Artefacts\Unpacked\ESCalator' -PublishToPSGallery -PSGalleryAPIKey $env:PSGALLERY_API_KEY

    .EXAMPLE
    Invoke-ESCPostBuildPublish -ArtefactRoot 'C:\ESCalator\Artefacts\Unpacked\ESCalator' -PublishToGitHub -GitHubAPIKey $env:GITHUB_TOKEN -Prerelease 'pre'

    .OUTPUTS
    None. Writes host/verbose messages only.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$ArtefactRoot,

        [Parameter()]
        [switch]$PublishToPSGallery,

        [Parameter()]
        [string]$PSGalleryAPIKey,

        [Parameter()]
        [string]$PSGalleryAPIPath,

        [Parameter()]
        [switch]$PublishToGitHub,

        [Parameter()]
        [string]$GitHubAPIKey,

        [Parameter()]
        [string]$GitHubAPIPath,

        [Parameter()]
        [string]$GitHubOwner = 'jakehildreth',

        [Parameter()]
        [string]$GitHubRepository = 'ESCalator',

        [Parameter()]
        [string]$Prerelease,

        [Parameter()]
        [string]$GitHubSha = $env:GITHUB_SHA
    )

    if (-not (Test-Path -Path $ArtefactRoot)) {
        Write-Error "Artefact root '$ArtefactRoot' does not exist. Build-Module may have failed to produce the Unpacked artefact."
        return
    }

    $moduleName = 'ESCalator'
    $sourceRoot = Resolve-Path -Path (Join-Path $PSScriptRoot '..')
    $psd1 = Join-Path $ArtefactRoot "$moduleName.psd1"

    # ── Copy about_* help files into the module-root culture folder ────────────
    # PowerShell's about-topic lookup expects these at <module-root>\en-US\ rather
    # than under docs\en-US\, so copy them from the source docs\en-US\ location.
    Write-Host ''
    Write-Host '[i] Copying about help files into artefact' -ForegroundColor Cyan

    $sourceEnUS = Join-Path $sourceRoot 'docs' 'en-US'
    $targetEnUS = Join-Path $ArtefactRoot 'en-US'
    if (Test-Path -Path $sourceEnUS) {
        New-Item -ItemType Directory -Path $targetEnUS -Force | Out-Null
        $aboutFiles = Get-ChildItem -Path $sourceEnUS -Filter 'about_*.help.txt'
        foreach ($file in $aboutFiles) {
            Copy-Item -Path $file.FullName -Destination $targetEnUS -Force
            Write-Host "   [+] Copied $($file.Name)" -ForegroundColor Green
        }
    } else {
        Write-Warning "Source about-help directory not found: $sourceEnUS"
    }

    # ── Publish from artefact path (not from PSModulePath) ────────────────────
    if (-not $PublishToPSGallery) {
        return
    }

    Write-Host ''
    Write-Host '[i] Publishing to PSGallery' -ForegroundColor Cyan

    if ($PSGalleryAPIKey) {
        $apiKey = $PSGalleryAPIKey
    } elseif ($PSGalleryAPIPath) {
        $apiKey = Get-Content -Path $PSGalleryAPIPath -ErrorAction Stop -Encoding UTF8 |
            Select-Object -First 1
    } else {
        Write-Host '[x] -PublishToPSGallery specified but neither -PSGalleryAPIKey nor -PSGalleryAPIPath was provided.' -ForegroundColor Red
        Write-Error '-PublishToPSGallery was specified but neither -PSGalleryAPIKey nor -PSGalleryAPIPath was provided.'
        return
    }

    if ($PSCmdlet.ShouldProcess($ArtefactRoot, 'Publish-Module to PSGallery')) {
        Write-Host "   [>] Calling Publish-Module -Path $ArtefactRoot" -ForegroundColor Yellow
        $publishParams = @{
            Path        = $ArtefactRoot
            NuGetApiKey = $apiKey
            Repository  = 'PSGallery'
            Force       = $true
            ErrorAction = 'Stop'
        }
        Publish-Module @publishParams
        Write-Host "[+] Published $moduleName to PSGallery successfully" -ForegroundColor Green
    }

    # region GitHub Release
    if (-not $PublishToGitHub) {
        return
    }

    if (-not ($GitHubAPIKey -or $GitHubAPIPath)) {
        Write-Host '[x] -PublishToGitHub specified but neither -GitHubAPIKey nor -GitHubAPIPath was provided.' -ForegroundColor Red
        Write-Error '-PublishToGitHub was specified but neither -GitHubAPIKey nor -GitHubAPIPath was provided.'
        return
    }

    if ([string]::IsNullOrEmpty($GitHubSha)) {
        Write-Host '[x] -PublishToGitHub was specified but -GitHubSha was not provided and $env:GITHUB_SHA is not set. GitHub releases must be created from GitHub Actions.' -ForegroundColor Red
        Write-Error '-PublishToGitHub was specified but -GitHubSha was not provided and $env:GITHUB_SHA is not set. GitHub releases must be created from GitHub Actions.'
        return
    }

    Write-Host ''
    Write-Host '[i] Creating GitHub release' -ForegroundColor Cyan

    if ($GitHubAPIKey) {
        $gitHubToken = $GitHubAPIKey
    } else {
        $gitHubToken = Get-Content -Path $GitHubAPIPath -ErrorAction Stop -Encoding UTF8 |
            Select-Object -First 1
    }

    if (-not (Test-Path -Path $psd1)) {
        Write-Error "Cannot determine module version for GitHub release; manifest not found at $psd1."
        return
    }

    $moduleVersion = (Import-PowerShellDataFile -Path $psd1).ModuleVersion
    $releaseTag = if ($Prerelease) { "$moduleVersion-$Prerelease" } else { $moduleVersion }
    $releaseName = "$moduleName $releaseTag"
    $zipName = "$moduleName-$releaseTag.zip"
    $zipPath = Join-Path (Split-Path $ArtefactRoot -Parent) $zipName
    $releaseUri = "https://api.github.com/repos/$GitHubOwner/$GitHubRepository/releases"

    if (-not $PSCmdlet.ShouldProcess($releaseUri, 'Create GitHub release')) {
        return
    }

    if (Test-Path -Path $zipPath) {
        Remove-Item -Path $zipPath -Force
    }

    $stagingRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
    $stagingPath = Join-Path $stagingRoot $moduleName
    New-Item -ItemType Directory -Path $stagingPath -Force | Out-Null
    Get-ChildItem -Path $ArtefactRoot | Copy-Item -Destination $stagingPath -Recurse -Force

    Write-Host "   [>] Compressing artefact to $zipName" -ForegroundColor Yellow
    Compress-Archive -Path $stagingPath -DestinationPath $zipPath -Force
    Write-Host "   [+] Release zip created at $zipPath" -ForegroundColor Green

    Remove-Item -Path $stagingRoot -Recurse -Force -ErrorAction SilentlyContinue

    $releaseBody = "$moduleName release $releaseTag"
    $releaseData = @{
        tag_name               = $releaseTag
        target_commitish       = $GitHubSha
        name                   = $releaseName
        body                   = $releaseBody
        draft                  = $false
        prerelease             = [bool]$Prerelease
        generate_release_notes = $true
    } | ConvertTo-Json

    $headers = @{
        Authorization          = "Bearer $gitHubToken"
        Accept                 = 'application/vnd.github+json'
        'X-GitHub-Api-Version' = '2022-11-28'
    }

    Write-Host "   [>] Creating GitHub release $releaseTag" -ForegroundColor Yellow
    try {
        $release = Invoke-RestMethod -Uri $releaseUri -Method Post -Headers $headers -Body $releaseData -ContentType 'application/json'
        Write-Host "   [+] GitHub release created" -ForegroundColor Green

        $uploadUri = $release.upload_url -replace '{\?name,[^}]*}', "?name=$zipName"
        Write-Host "   [>] Uploading $zipName to GitHub release" -ForegroundColor Yellow
        Invoke-RestMethod -Uri $uploadUri -Method Post -Headers $headers -InFile $zipPath -ContentType 'application/zip' | Out-Null
        Write-Host "   [+] Uploaded $zipName to GitHub release" -ForegroundColor Green
    } catch {
        Write-Host "   [x] GitHub release creation failed: $_" -ForegroundColor Red
        Write-Error $_
    }
}
# endregion
