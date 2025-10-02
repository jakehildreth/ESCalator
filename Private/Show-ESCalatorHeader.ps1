function Show-ESCalatorHeader {
    <#
        .SYNOPSIS
        Displays the ESCalator logo and information header with gradient colors.

        .DESCRIPTION
        Shows the gradient ESCalator logo and information box using the provided color scheme.

        .PARAMETER Color1
        First gradient color (ANSI code)

        .PARAMETER Color2
        Second gradient color (ANSI code)

        .PARAMETER Color3
        Third gradient color (ANSI code)

        .PARAMETER Color4
        Fourth gradient color (ANSI code)

        .PARAMETER Color5
        Fifth gradient color (ANSI code)
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [int]$Color1,
        
        [Parameter(Mandatory)]
        [int]$Color2,
        
        [Parameter(Mandatory)]
        [int]$Color3,
        
        [Parameter(Mandatory)]
        [int]$Color4,
        
        [Parameter(Mandatory)]
        [int]$Color5
    )

    Write-Host ""
    Write-Host "`e[38;5;${Color1}m█        ███      ████      ████      ███  █████████      ███        ███      ███       ██`e[0m"
    Write-Host "`e[38;5;${Color2}m█  ████████  ████████  ████  ██  ████  ██  ████████  ████  █████  █████  ████  ██  ████  █`e[0m"
    Write-Host "`e[38;5;${Color3}m█      █████      ███  ████████  ████  ██  ████████  ████  █████  █████  ████  ██       ██`e[0m"
    Write-Host "`e[38;5;${Color4}m█  ██████████████  ██  ████  ██        ██  ████████        █████  █████  ████  ██  ███  ██`e[0m"
    Write-Host "`e[38;5;${Color5}m█        ███      ████      ███  ████  ██        ██  ████  █████  ██████      ███  ████  █`e[0m"
    Write-Host "`e[38;5;${Color5}m                   ╔═════════════════════════════════════════════════╗`e[0m"
    Write-Host "`e[38;5;${Color4}m                   ║`e[0m AD CS Attack Path Identification and Abuse Tool `e[38;5;${Color4}m║`e[0m"
    Write-Host "`e[38;5;${Color3}m                   ║`e[0m             (c) 2025 Jake Hildreth              `e[38;5;${Color3}m║`e[0m"
    Write-Host "`e[38;5;${Color2}m                   ║`e[0m          `e[1mFOR EDUCATIONAL PURPOSES ONLY`e[0m          `e[38;5;${Color2}m║`e[0m"
    Write-Host "`e[38;5;${Color1}m                   ╚═════════════════════════════════════════════════╝`e[0m"
    Write-Host ""
}