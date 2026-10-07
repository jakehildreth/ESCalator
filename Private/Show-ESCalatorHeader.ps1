function Show-ESCalatorHeader {
    <#
        .SYNOPSIS
        Displays the ESCalator logo and information header with 24-bit true color gradients.

        .DESCRIPTION
        Shows the gradient ESCalator logo and information box using the provided RGB color scheme.
        Colors should be RGB objects with R, G, B properties. Use Get-GradientColors (default mode)
        to generate compatible color arrays.

        .PARAMETER Color1
        First gradient color (RGB object with R, G, B properties)

        .PARAMETER Color2
        Second gradient color (RGB object with R, G, B properties)

        .PARAMETER Color3
        Third gradient color (RGB object with R, G, B properties)

        .PARAMETER Color4
        Fourth gradient color (RGB object with R, G, B properties)

        .PARAMETER Color5
        Fifth gradient color (RGB object with R, G, B properties)

        .EXAMPLE
        $colors = Get-GradientColors -Theme "Ocean" -Steps 5
        Show-ESCalatorHeader -Color1 $colors[0] -Color2 $colors[1] -Color3 $colors[2] -Color4 $colors[3] -Color5 $colors[4]

        .EXAMPLE
        # Using specific RGB colors
        $rgb1 = @{R=255; G=69; B=0}
        $rgb2 = @{R=255; G=105; B=180}
        Show-ESCalatorHeader -Color1 $rgb1 -Color2 $rgb2 -Color3 $rgb1 -Color4 $rgb2 -Color5 $rgb1
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [hashtable]$Color1,
        
        [Parameter(Mandatory)]
        [hashtable]$Color2,
        
        [Parameter(Mandatory)]
        [hashtable]$Color3,
        
        [Parameter(Mandatory)]
        [hashtable]$Color4,
        
        [Parameter(Mandatory)]
        [hashtable]$Color5
    )

    # PowerShell 5.1 has no `e escape; use the ESC character directly for ANSI sequences.
    $esc = [char]0x1b


    Write-Host ""
    Write-Host "${esc}[38;2;$($Color1.R);$($Color1.G);$($Color1.B)m█        ███      ████      ████      ███  █████████      ███        ███      ███       ██${esc}[0m"
    Write-Host "${esc}[38;2;$($Color2.R);$($Color2.G);$($Color2.B)m█  ████████  ████████  ████  ██  ████  ██  ████████  ████  █████  █████  ████  ██  ████  █${esc}[0m"
    Write-Host "${esc}[38;2;$($Color3.R);$($Color3.G);$($Color3.B)m█      █████      ███  ████████  ████  ██  ████████  ████  █████  █████  ████  ██       ██${esc}[0m"
    Write-Host "${esc}[38;2;$($Color4.R);$($Color4.G);$($Color4.B)m█  ██████████████  ██  ████  ██        ██  ████████        █████  █████  ████  ██  ███  ██${esc}[0m"
    Write-Host "${esc}[38;2;$($Color5.R);$($Color5.G);$($Color5.B)m█        ███      ████      ███  ████  ██        ██  ████  █████  ██████      ███  ████  █${esc}[0m"
    Write-Host "${esc}[38;2;$($Color5.R);$($Color5.G);$($Color5.B)m                 ╔══════════════════════════════════════════════════╗${esc}[0m"
    Write-Host "${esc}[38;2;$($Color4.R);$($Color4.G);$($Color4.B)m                 ║${esc}[0m AD CS Issue Combo Identification and Attack Tool ${esc}[38;2;$($Color4.R);$($Color4.G);$($Color4.B)m║${esc}[0m"
    Write-Host "${esc}[38;2;$($Color3.R);$($Color3.G);$($Color3.B)m                 ║${esc}[0m               (c) 2025 Jake Hildreth             ${esc}[38;2;$($Color3.R);$($Color3.G);$($Color3.B)m║${esc}[0m"
    Write-Host "${esc}[38;2;$($Color2.R);$($Color2.G);$($Color2.B)m                 ║${esc}[0m           ${esc}[1mFOR EDUCATIONAL PURPOSES ONLY${esc}[0m          ${esc}[38;2;$($Color2.R);$($Color2.G);$($Color2.B)m║${esc}[0m"
    Write-Host "${esc}[38;2;$($Color1.R);$($Color1.G);$($Color1.B)m                 ╚══════════════════════════════════════════════════╝${esc}[0m"
    Write-Host ""
}