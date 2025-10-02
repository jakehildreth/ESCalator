function Start-ESCalator {
    <#
        .SYNOPSIS
        Interactive menu for ESCalator attack path analysis.

        .DESCRIPTION
        Displays a menu with options to analyze Active Directory Certificate Services attack paths.

        .INPUTS
        None

        .OUTPUTS
        None - Interactive menu

        .EXAMPLE
        Start-ESCalator

        .LINK
    #>
    [CmdletBinding()]
    [Alias('ESCalator')]
    param (
    )

    #requires -Version 5

    do {
        # Randomly choose gradient direction
        $useReverseGradient = Get-Random -Maximum 2
        
        if ($useReverseGradient) {
            # Light to dark gradient (coral to dark magenta)
            $color1 = 203  # coral
            $color2 = 198  # pink-red  
            $color3 = 162  # bright magenta-pink
            $color4 = 126  # medium magenta
            $color5 = 90   # dark magenta
        } else {
            # Dark to light gradient (dark magenta to coral)
            $color1 = 90   # dark magenta
            $color2 = 126  # medium magenta
            $color3 = 162  # bright magenta-pink
            $color4 = 198  # pink-red
            $color5 = 203  # coral
        }
        
        Show-ESCalatorHeader -Color1 $color1 -Color2 $color2 -Color3 $color3 -Color4 $color4 -Color5 $color5
        
        Write-Host "Which attack paths would you like to display?"
        Write-Host "1. Current user/computer context"
        Write-Host "2. Specific user/computer"
        Write-Host "3. Forest-wide"
        Write-Host ""
        Write-Host "q. Quit"
        Write-Host ""
        
        $choice = Read-Host "Select an option"
        
        switch ($choice.ToUpper()) {
            '1' {
                Write-Host ""
                Write-Host "You selected: 1 - Current user/computer context" -ForegroundColor Yellow
                Write-Host ""
                Read-Host "Press Enter to continue"
            }
            '2' {
                Write-Host ""
                Write-Host "You selected: 2 - Specific user/computer" -ForegroundColor Yellow
                Write-Host ""
                Read-Host "Press Enter to continue"
            }
            '3' {
                Write-Host ""
                Write-Host "You selected: 3 - Forest-wide" -ForegroundColor Yellow
                Write-Host ""
                Read-Host "Press Enter to continue"
            }
            'Q' {
                Write-Host ""
                Write-Host "Goodbye!" -ForegroundColor Green
                break
            }
            default {
                Write-Host ""
                Write-Host "Invalid selection. Please choose 1, 2, 3, or Q." -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    } while ($choice.ToUpper() -ne 'Q')
}
