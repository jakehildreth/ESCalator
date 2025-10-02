function Start-ESCalator {
    <#
        .SYNOPSIS
        Interactive menu for ESCalator AD CS issue combination analysis.

        .DESCRIPTION
        Displays a menu with options to analyze Active Directory Certificate Services issue combinations.

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
        Show-MenuOptions -Title "Select Issue Combos to Display:" -Options $menuOptions
        
        # Get user choice with validation
        $choice = Get-MenuChoice -MaxOption 3 -Prompt "Select an option"
        
        switch ($choice) {
            1 {
                Write-Host ""
                Write-Host "You selected: Current user/computer context" -ForegroundColor Yellow
                Write-Host ""
                
                # Check if user is local administrator
                Write-Host "Checking local administrator privileges..." -ForegroundColor Cyan
                if (Test-IsLocalAdmin) {
                    Write-Host "✅ Local administrator privileges confirmed" -ForegroundColor Green
                    Write-Host ""
                    
                    # Get AD CS objects and analyze issue combinations
                    Write-Host "Gathering AD CS objects and analyzing issue combinations..." -ForegroundColor Cyan
                    try {
                        $AdcsObjects = Get-AdcsObjects
                        $AllIssues = @()
                        $AllIssues += Find-ESC4 -AdcsObjects $AdcsObjects
                        $AllIssues += Find-ESC5 -AdcsObjects $AdcsObjects
                        
                        # Find issue combinations for current context
                        $IssueCombinations = Find-IssueCombinations -Issues $AllIssues
                        
                        if ($IssueCombinations) {
                            Write-Host "✅ Found $($IssueCombinations.Count) issue combination capabilities!" -ForegroundColor Green
                            Write-Host ""
                            
                            # Create submenu for issue combinations
                            do {
                                Show-ESCalatorHeader -Color1 $sessionColors[0] -Color2 $sessionColors[1] -Color3 $sessionColors[2] -Color4 $sessionColors[3] -Color5 $sessionColors[4]
                                
                                Write-Host "📊 IDENTIFIED ISSUE COMBINATIONS" -ForegroundColor Yellow
                                Write-Host "Current User/Computer Context" -ForegroundColor Gray
                                Write-Host ""
                                
                                # Group combinations by type for menu
                                $groupedCombos = $IssueCombinations | Group-Object IssueCombinationName | Sort-Object Name
                                
                                $subMenuOptions = @()
                                foreach ($group in $groupedCombos) {
                                    $subMenuOptions += "$($group.Name) ($($group.Count) instances)"
                                }
                                $subMenuOptions += "Generate comprehensive report"
                                $subMenuOptions += "Return to main menu"
                                
                                Show-MenuOptions -Title "Select Issue Combination to View:" -Options $subMenuOptions
                                
                                $subChoice = Get-MenuChoice -MaxOption $subMenuOptions.Count -Prompt "Select an option" -AllowBack
                                
                                if ($subChoice -eq 'q') {
                                    # Quit entirely
                                    Write-Host ""
                                    Write-Host "Goodbye! 👋" -ForegroundColor Green
                                    return
                                } elseif ($subChoice -eq 'b' -or $subChoice -eq $subMenuOptions.Count) {
                                    # Return to main menu (back or explicit return option)
                                    break
                                } elseif ($subChoice -eq ($subMenuOptions.Count - 1)) {
                                    # Generate comprehensive report
                                    Write-Host ""
                                    Write-Host "📊 Generating Comprehensive Issue Combination Report..." -ForegroundColor Cyan
                                    $report = Get-IssueCombinationReport -IssueCombinations $IssueCombinations -ReportType Summary -IncludeStatistics
                                    $report | Format-List
                                    Write-Host ""
                                    Read-Host "Press Enter to continue"
                                } elseif ($subChoice -ge 1 -and $subChoice -le $groupedCombos.Count) {
                                    # Show specific combination details
                                    $selectedGroup = $groupedCombos[$subChoice - 1]
                                    Write-Host ""
                                    Write-Host "📋 Details for: $($selectedGroup.Name)" -ForegroundColor Yellow
                                    Write-Host ""
                                    $selectedGroup.Group | Format-Table PrincipalName, ESC4Capabilities, ESC5Capabilities -AutoSize
                                    Write-Host ""
                                    Read-Host "Press Enter to continue"
                                }
                            } while ($subChoice -ne $subMenuOptions.Count -and $subChoice -ne 'b' -and $subChoice -ne 'q')
                        } else {
                            Write-Host "ℹ️ No issue combination capabilities found for current context." -ForegroundColor Blue
                            Write-Host ""
                            Read-Host "Press Enter to continue"
                        }
                    } catch {
                        Write-Warning "Failed to analyze issue combinations: $($_.Exception.Message)"
                        Write-Host ""
                        Read-Host "Press Enter to continue"
                    }
                } else {
                    Write-Warning "❌ Local administrator privileges required for current user/computer analysis"
                    Write-Host "This option requires elevated privileges to access AD CS objects and analyze security permissions." -ForegroundColor Gray
                    Write-Host ""
                    Read-Host "Press Enter to continue"
                }
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
