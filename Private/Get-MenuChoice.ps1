function Get-MenuChoice {
    <#
        .SYNOPSIS
        Gets validated user input for menu selection.

        .DESCRIPTION
        Prompts the user for menu selection and validates the input against
        the available options. Continues prompting until valid input is received.

        .PARAMETER MaxOption
        The maximum valid option number (based on number of menu items)

        .PARAMETER Prompt
        Custom prompt text to display (defaults to "Please enter your choice")

        .PARAMETER AllowZero
        Whether to allow 0 as a valid input (typically for exit option)

        .EXAMPLE
        $choice = Get-MenuChoice -MaxOption 3 -AllowZero
        # Accepts input 0, 1, 2, or 3

        .EXAMPLE
        $choice = Get-MenuChoice -MaxOption 5 -Prompt "Select an analysis type"
        # Accepts input 1, 2, 3, 4, or 5 with custom prompt
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [int]$MaxOption,
        
        [string]$Prompt = "Please enter your choice",
        
        [switch]$AllowZero
    )

    do {
        Write-Host "`e[1m$Prompt`e[0m" -NoNewline
        if ($AllowZero) {
            Write-Host " (0-$MaxOption): " -NoNewline
        } else {
            Write-Host " (1-$MaxOption): " -NoNewline
        }
        
        $userInput = Read-Host
        
        # Try to parse the input as an integer
        if ([int]::TryParse($userInput, [ref]$choice)) {
            # Check if the choice is within valid range
            if ($AllowZero -and ($choice -ge 0 -and $choice -le $MaxOption)) {
                $validInput = $true
            } elseif (-not $AllowZero -and ($choice -ge 1 -and $choice -le $MaxOption)) {
                $validInput = $true
            } else {
                $validInput = $false
                Write-Host "`e[38;5;196m❌ Invalid choice. " -NoNewline
                if ($AllowZero) {
                    Write-Host "Please enter a number between 0 and $MaxOption.`e[0m"
                } else {
                    Write-Host "Please enter a number between 1 and $MaxOption.`e[0m"
                }
                Write-Host ""
            }
        } else {
            $validInput = $false
            Write-Host "`e[38;5;196m❌ Invalid input. Please enter a number.`e[0m"
            Write-Host ""
        }
    } while (-not $validInput)

    return $choice
}