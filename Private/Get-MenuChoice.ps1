function Get-MenuChoice {
    <#
        .SYNOPSIS
        Gets validated user input for menu selection.

        .DESCRIPTION
        Prompts the user for menu selection and validates the input against
        the available options. Continues prompting until valid input is received.
        Supports 'q' for quit and 'b' for back navigation.

        .PARAMETER MaxOption
        The maximum valid option number (based on number of menu items)

        .PARAMETER Prompt
        Custom prompt text to display (defaults to "Please enter your choice")

        .PARAMETER AllowBack
        Whether to allow 'b' as a valid input (for back navigation)

        .EXAMPLE
        $choice = Get-MenuChoice -MaxOption 3 -AllowBack
        # Accepts input 1, 2, 3, 'q' (quit), or 'b' (back)

        .EXAMPLE
        $choice = Get-MenuChoice -MaxOption 5 -Prompt "Select an analysis type"
        # Accepts input 1, 2, 3, 4, 5, or 'q' (quit)
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [int]$MaxOption,
        
        [string]$Prompt = "Please enter your choice",
        
        [switch]$AllowBack
    )

    #requires -Version 7.4

    $validInput = $false
    $choice = $null  # Can now be integer, 'q', or 'b'

    do {
        Write-Host "`e[1m$Prompt`e[0m" -NoNewline
        $optionText = " (1-$MaxOption"
        if ($AllowBack) {
            $optionText += ", b=back"
        }
        $optionText += ", q=quit): "
        Write-Host $optionText -NoNewline
        
        $userInput = Read-Host
        $userInput = $userInput.Trim().ToLower()
        
        # Check for quit
        if ($userInput -eq 'q') {
            $choice = 'q'
            $validInput = $true
        }
        # Check for back (if allowed)
        elseif ($AllowBack -and $userInput -eq 'b') {
            $choice = 'b'
            $validInput = $true
        }
        # Try to parse as integer
        else {
            $numericChoice = 0
            if ([int]::TryParse($userInput, [ref]$numericChoice)) {
                # Check if the choice is within valid range
                if ($numericChoice -ge 1 -and $numericChoice -le $MaxOption) {
                    $choice = $numericChoice
                    $validInput = $true
                } else {
                    $validInput = $false
                    Write-Host "`e[38;5;196m[x] Invalid choice. Please enter a number between 1 and $MaxOption" -NoNewline
                    if ($AllowBack) {
                        Write-Host ", 'b' for back, or 'q' to quit.`e[0m"
                    } else {
                        Write-Host " or 'q' to quit.`e[0m"
                    }
                    Write-Host ""
                }
            } else {
                $validInput = $false
                $validOptions = "a number (1-$MaxOption)"
                if ($AllowBack) {
                    $validOptions += ", 'b' for back"
                }
                $validOptions += ", or 'q' to quit"
                Write-Host "`e[38;5;196m[x] Invalid input. Please enter $validOptions.`e[0m"
                Write-Host ""
            }
        }
    } while (-not $validInput)

    return $choice
}