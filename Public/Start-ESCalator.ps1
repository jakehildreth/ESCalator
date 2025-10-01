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
        Write-Host ""
        Write-Host "╔══════════════════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor White
        Write-Host "║`e[38;5;90m░        ░░░      ░░░░      ░░░░      ░░░  ░░░░░░░░░      ░░░        ░░░      ░░░       ░░`e[0m║" -ForegroundColor White
        Write-Host "║`e[38;5;126m▒  ▒▒▒▒▒▒▒▒  ▒▒▒▒▒▒▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒▒▒▒▒  ▒▒▒▒  ▒▒▒▒▒  ▒▒▒▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒`e[0m║" -ForegroundColor White
        Write-Host "║`e[38;5;162m▓      ▓▓▓▓▓      ▓▓▓  ▓▓▓▓▓▓▓▓  ▓▓▓▓  ▓▓  ▓▓▓▓▓▓▓▓  ▓▓▓▓  ▓▓▓▓▓  ▓▓▓▓▓  ▓▓▓▓  ▓▓       ▓▓`e[0m║" -ForegroundColor White
        Write-Host "║`e[38;5;198m█  ██████████████  ██  ████  ██        ██  ████████        █████  █████  ████  ██  ███  ██`e[0m║" -ForegroundColor White
        Write-Host "║`e[38;5;203m█        ███      ████      ███  ████  ██        ██  ████  █████  ██████      ███  ████  █`e[0m║" -ForegroundColor White
        Write-Host "╚══════════════════╦═════════════════════════════════════════════════╦═════════════════════╝" -ForegroundColor White
        Write-Host "                   ║ AD CS Attack Path Identification and Abuse Tool ║" -ForegroundColor White
        Write-Host "                   ║             (c) 2025 Jake Hildreth              ║" -ForegroundColor White
        Write-Host "                   ║          `e[1mFOR EDUCATIONAL PURPOSES ONLY`e[0m          ║" -ForegroundColor White
        Write-Host "                   ╚═════════════════════════════════════════════════╝" -ForegroundColor White
        Write-Host ""
        Write-Host "Which attack paths would you like to display?"
        Write-Host "1. Forest-wide"
        Write-Host "2. Current context"
        Write-Host "3. Specific user/computer"
        Write-Host ""
        Write-Host "q. Quit"
        Write-Host ""
        
        $choice = Read-Host "Select an option"
        
        switch ($choice.ToUpper()) {
            '1' {
                Write-Host ""
                Write-Host "You selected: 1 - Forest-wide" -ForegroundColor Yellow
                Write-Host ""
                Read-Host "Press Enter to continue"
            }
            '2' {
                Write-Host ""
                Write-Host "You selected: 2 - Current context" -ForegroundColor Yellow
                Write-Host ""
                Read-Host "Press Enter to continue"
            }
            '3' {
                Write-Host ""
                Write-Host "You selected: 3 - Specific user/computer" -ForegroundColor Yellow
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
