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
        # Get random gradient colors
        $colors = Get-RandomGradientColors
        
        Show-ESCalatorHeader -Color1 $colors.Color1 -Color2 $colors.Color2 -Color3 $colors.Color3 -Color4 $colors.Color4 -Color5 $colors.Color5
        
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
