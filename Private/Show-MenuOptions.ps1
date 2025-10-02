function Show-MenuOptions {
    <#
        .SYNOPSIS
        Displays a formatted menu with gradient-colored options and box drawing.

        .DESCRIPTION
        Creates a professional menu display with numbered options, gradient colors,
        and double-line box drawing characters. Supports custom titles and option lists.

        .PARAMETER Title
        The title to display at the top of the menu

        .PARAMETER Options
        Array of menu option strings to display

        .PARAMETER Color1
        First gradient color (ANSI code) - used for top elements

        .PARAMETER Color2
        Second gradient color (ANSI code)

        .PARAMETER Color3
        Third gradient color (ANSI code)

        .PARAMETER Color4
        Fourth gradient color (ANSI code)

        .PARAMETER Color5
        Fifth gradient color (ANSI code) - used for bottom elements

        .EXAMPLE
        $colors = Get-RandomGradientColors
        $menuOptions = @(
            "Current user/computer context",
            "Specific user/computer",
            "Forest-wide analysis"
        )
        Show-MenuOptions -Title "Select Analysis Scope" -Options $menuOptions @colors
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Title,
        
        [Parameter(Mandatory)]
        [array]$Options,
        
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

    # Calculate the maximum width needed for the menu
    $maxOptionLength = ($Options | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum
    $titleLength = $Title.Length
    $minWidth = [Math]::Max($maxOptionLength + 8, $titleLength + 4)  # +8 for "1. " and padding, +4 for title padding
    $boxWidth = [Math]::Max($minWidth, 50)  # Minimum width of 50 characters
    
    # Create the menu box
    Write-Host ""
    
    # Top border with title
    $innerWidth = $boxWidth - 2  # Account for the border characters ║ on each side
    $availableSpace = $innerWidth - $titleLength
    $titlePaddingLeft = [Math]::Floor($availableSpace / 2.0) + 1
    $titlePaddingRight = $availableSpace - [Math]::Floor($availableSpace / 2.0) + 1
    Write-Host "`e[38;5;${Color1}m╔$('═' * $boxWidth)╗`e[0m"
    Write-Host "`e[38;5;${Color1}m║$(' ' * $titlePaddingLeft)`e[1m$Title`e[0m`e[38;5;${Color1}m$(' ' * $titlePaddingRight)║`e[0m"
    Write-Host "`e[38;5;${Color2}m╠$('═' * $boxWidth)╣`e[0m"
    
    # Menu options
    $colorArray = @($Color2, $Color3, $Color4, $Color5)
    for ($i = 0; $i -lt $Options.Count; $i++) {
        $optionNumber = $i + 1
        $optionText = "$optionNumber. $($Options[$i])"
        $padding = $boxWidth - $optionText.Length - 1
        $colorIndex = $i % $colorArray.Count
        $currentColor = $colorArray[$colorIndex]
        
        Write-Host "`e[38;5;${currentColor}m║`e[0m $optionText$(' ' * $padding)`e[38;5;${currentColor}m║`e[0m"
    }
    
    # Add separator for exit option
    Write-Host "`e[38;5;${Color4}m╠$('═' * $boxWidth)╣`e[0m"
    
    # Exit option
    $exitText = "0. Exit"
    $exitPadding = $boxWidth - $exitText.Length - 1
    Write-Host "`e[38;5;${Color5}m║`e[0m $exitText$(' ' * $exitPadding)`e[38;5;${Color5}m║`e[0m"
    
    # Bottom border
    Write-Host "`e[38;5;${Color5}m╚$('═' * $boxWidth)╝`e[0m"
    Write-Host ""
}