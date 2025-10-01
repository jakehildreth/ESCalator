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
    param (
    )

    #requires -Version 5

    do {
        Write-Host ""
        Write-Host "`e[38;5;90m░        ░░░      ░░░░      ░░░░      ░░░  ░░░░░░░░░      ░░░        ░░░      ░░░       ░░`e[0m"
        Write-Host "`e[38;5;126m▒  ▒▒▒▒▒▒▒▒  ▒▒▒▒▒▒▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒▒▒▒▒  ▒▒▒▒  ▒▒▒▒▒  ▒▒▒▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒`e[0m"
        Write-Host "`e[38;5;162m▓      ▓▓▓▓▓      ▓▓▓  ▓▓▓▓▓▓▓▓  ▓▓▓▓  ▓▓  ▓▓▓▓▓▓▓▓  ▓▓▓▓  ▓▓▓▓▓  ▓▓▓▓▓  ▓▓▓▓  ▓▓       ▓▓`e[0m"
        Write-Host "`e[38;5;198m█  ██████████████  ██  ████  ██        ██  ████████        █████  █████  ████  ██  ███  ██`e[0m"
        Write-Host "`e[38;5;203m█        ███      ████      ███  ████  ██        ██  ████  █████  ██████      ███  ████  █`e[0m"
        Write-Host ""
        Write-Host "::AD CS Attack Path Analysis" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "1. Display all attack paths available in the current context"
        Write-Host "2. Display all attack paths available for a specific user/computer"
        Write-Host "Q. Quit"
        Write-Host ""
        
        $choice = Read-Host "Select an option"
        
        switch ($choice.ToUpper()) {
            '1' {
                Write-Host ""
                Write-Host "You selected: 1" -ForegroundColor Yellow
                Write-Host ""
                Read-Host "Press Enter to continue"
            }
            '2' {
                Write-Host ""
                Write-Host "You selected: 2" -ForegroundColor Yellow
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
                Write-Host "Invalid selection. Please choose 1, 2, or Q." -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    } while ($choice.ToUpper() -ne 'Q')
}
