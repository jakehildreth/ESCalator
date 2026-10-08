## [Unreleased]

### Added

- Module scaffolding: ESCalator.psm1 dot-source loader, ESCalator.psd1 manifest, and PSPublishModule-based Build/Build-Module.ps1 with CalVer versioning

- ESC2 detection and abuse wiring (#25): Find-ESC2Issue results now feed the Start-ESCalator scan, a new Find-ESC2 principal filter, and the interactive analysis menu (Show-ESC2AttackDetails) with Invoke-EOBOAttack as the Enroll-On-Behalf-Of abuse path

- Invoke-EOBOAttack fixes (#25): default target template changed from 'UserEOBO' to the built-in 'User' (schema v1 templates accept an EOBO request without requiring an agent signature); null-safe agent-cert EKU read and corrected no-EKU template detection so the attack runs against a no-EKU template such as 'VMware 6.x'
- Post-build publish script (Build/Invoke-ESCPostBuildPublish.ps1): copies about help into the artefact and publishes to PSGallery and GitHub releases from the artefact path
- GitHub Actions publish workflow (.github/workflows/publish.yaml): runs Pester tests, builds, and publishes releases from main and prereleases from other branches
- Import test (Tests/ESCalator.Import.Tests.ps1) verifying Start-ESCalator is exported in a clean session
- about_ESCalator help topic, cliff.toml changelog configuration, and CHANGELOG.md stub
