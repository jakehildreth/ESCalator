function Show-MenuOptions {
    <#
        .SYNOPSIS
        Displays a simple menu with numbered options.

        .DESCRIPTION
        Creates a clean menu display with numbered options and a title.

        .PARAMETER Title
        The title to display at the top of the menu

        .PARAMETER Options
        Array of menu option strings to display

        .PARAMETER AllowBack
        Whether to show the back option

        .EXAMPLE
        $menuOptions = @(
            "Current user/computer context",
            "Specific user/computer",
            "Forest-wide analysis"
        )
        Show-MenuOptions -Title "Select Analysis Scope" -Options $menuOptions -AllowBack
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Title,
        
        [Parameter(Mandatory)]
        [array]$Options,
        
        [switch]$AllowBack
    )

    # Display the menu
    Write-Host ""
    Write-Host $Title -ForegroundColor White
    Write-Host ""
    
    # Menu options
    for ($i = 0; $i -lt $Options.Count; $i++) {
        $optionNumber = $i + 1
        Write-Host "$optionNumber. $($Options[$i])"
    }
    
    Write-Host ""
    if ($AllowBack) {
        Write-Host "b. Back" -ForegroundColor Yellow
    }
    Write-Host "q. Quit" -ForegroundColor Red
    Write-Host ""
}