function Show-ESCalatorHeader-Legacy {
    <#
        .SYNOPSIS
        Displays the ESCalator logo and information header with legacy 256-color gradients.

        .DESCRIPTION
        Shows the gradient ESCalator logo and information box using the provided ANSI color scheme.
        This is the legacy version that uses ANSI 256-color codes for backward compatibility.
        Colors should be ANSI 256-color codes (0-255). Use Get-GradientColors with -Legacy256Color
        to generate compatible color arrays.

        .PARAMETER Color1
        First gradient color (ANSI 256-color code, 0-255)

        .PARAMETER Color2
        Second gradient color (ANSI 256-color code, 0-255)

        .PARAMETER Color3
        Third gradient color (ANSI 256-color code, 0-255)

        .PARAMETER Color4
        Fourth gradient color (ANSI 256-color code, 0-255)

        .PARAMETER Color5
        Fifth gradient color (ANSI 256-color code, 0-255)

        .EXAMPLE
        $colors = Get-GradientColors -Theme "Ocean" -Steps 5 -Legacy256Color
        Show-ESCalatorHeader-Legacy -Color1 $colors[0] -Color2 $colors[1] -Color3 $colors[2] -Color4 $colors[3] -Color5 $colors[4]
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
    Write-Host "`e[38;5;${Color5}m                 ╔══════════════════════════════════════════════════╗`e[0m"
    Write-Host "`e[38;5;${Color4}m                 ║`e[0m AD CS Issue Combo Identification and Attack Tool `e[38;5;${Color4}m║`e[0m"
    Write-Host "`e[38;5;${Color3}m                 ║`e[0m               (c) 2025 Jake Hildreth             `e[38;5;${Color3}m║`e[0m"
    Write-Host "`e[38;5;${Color2}m                 ║`e[0m           `e[1mFOR EDUCATIONAL PURPOSES ONLY`e[0m          `e[38;5;${Color2}m║`e[0m"
    Write-Host "`e[38;5;${Color1}m                 ╚══════════════════════════════════════════════════╝`e[0m"
    Write-Host ""
}