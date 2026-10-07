## [Unreleased]

### Added

- Module scaffolding: ESCalator.psm1 dot-source loader, ESCalator.psd1 manifest, and PSPublishModule-based Build/Build-Module.ps1 with CalVer versioning
- Post-build publish script (Build/Invoke-ESCPostBuildPublish.ps1): copies about help into the artefact and publishes to PSGallery and GitHub releases from the artefact path
- GitHub Actions publish workflow (.github/workflows/publish.yaml): runs Pester tests, builds, and publishes releases from main and prereleases from other branches
- Import test (Tests/ESCalator.Import.Tests.ps1) verifying Start-ESCalator is exported in a clean session
- about_ESCalator help topic, cliff.toml changelog configuration, and CHANGELOG.md stub
