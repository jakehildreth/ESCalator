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

    # Select random theme colors once at the start of the session
    $sessionColors = Get-GradientColors -Theme "Random" -Steps 5
    Write-Verbose "Session theme colors selected: $($sessionColors -join ', ')"

    do {
        # Show the ESCalator header with consistent session colors
        Show-ESCalatorHeader -Color1 $sessionColors[0] -Color2 $sessionColors[1] -Color3 $sessionColors[2] -Color4 $sessionColors[3] -Color5 $sessionColors[4]
        
        # Create menu options array
        $menuOptions = @(
            "Current user/computer context",
            "Specific user/computer", 
            "Forest-wide analysis"
        )
        
        # Display the simple menu
        Show-MenuOptions -Title "ESCalator Attack Path Analysis" -Options $menuOptions
        
        # Get user choice with validation
        $choice = Get-MenuChoice -MaxOption 3 -Prompt "Select an option"
        
        switch ($choice) {
            1 {
                Write-Host ""
                Write-Host "You selected: Current user/computer context" -ForegroundColor Yellow
                Write-Host ""
                Read-Host "Press Enter to continue"
            }
            2 {
                Write-Host ""
                Write-Host "You selected: Specific user/computer" -ForegroundColor Yellow
                Write-Host ""
                Read-Host "Press Enter to continue"
            }
            3 {
                Write-Host ""
                Write-Host "You selected: Forest-wide analysis" -ForegroundColor Yellow
                Write-Host ""
                Read-Host "Press Enter to continue"
            }
            'q' {
                Write-Host ""
                Write-Host "Goodbye! 👋" -ForegroundColor Green
                return  # Exit the function completely
            }
        }
    } while ($choice -ne 'q')
}
