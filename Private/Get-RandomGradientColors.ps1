function Get-RandomGradientColors {
    <#
        .SYNOPSIS
        Returns a random gradient color scheme for ESCalator interface elements.

        .DESCRIPTION
        Selects one of two gradient color schemes (dark magenta to coral or coral to dark magenta)
        and returns the five ANSI color codes for use in interface display.

        .OUTPUTS
        System.Collections.Hashtable
        Returns a hashtable with Color1 through Color5 properties containing ANSI color codes.

        .EXAMPLE
        $colors = Get-RandomGradientColors
        Show-ESCalatorHeader -Color1 $colors.Color1 -Color2 $colors.Color2 -Color3 $colors.Color3 -Color4 $colors.Color4 -Color5 $colors.Color5
    #>
    [CmdletBinding()]
    param ()

    # Randomly choose gradient direction
    $useReverseGradient = Get-Random -Maximum 2
    
    if ($useReverseGradient) {
        # Light to dark gradient (coral to dark magenta)
        return @{
            Color1 = 203  # coral
            Color2 = 198  # pink-red  
            Color3 = 162  # bright magenta-pink
            Color4 = 126  # medium magenta
            Color5 = 90   # dark magenta
        }
    } else {
        # Dark to light gradient (dark magenta to coral)
        return @{
            Color1 = 90   # dark magenta
            Color2 = 126  # medium magenta
            Color3 = 162  # bright magenta-pink
            Color4 = 198  # pink-red
            Color5 = 203  # coral
        }
    }
}