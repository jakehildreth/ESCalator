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

    # Show the ESCalator header with consistent session colors
    Show-ESCalatorHeader -Color1 $sessionColors[0] -Color2 $sessionColors[1] -Color3 $sessionColors[2] -Color4 $sessionColors[3] -Color5 $sessionColors[4]
    
    # Initialize variables for the comprehensive analysis (run once)
    Write-Host "🚀 Initializing ESCalator Analysis Engine..." -ForegroundColor Cyan
    Write-Host ""
    
    # Get AD CS objects
    Write-Host "📋 Gathering Active Directory Certificate Services objects..." -ForegroundColor Yellow
    try {
        $AdcsObjects = Get-AdcsObjects
        Write-Host "   ✅ Successfully retrieved $($AdcsObjects.Count) AD CS objects" -ForegroundColor Green
    } catch {
        Write-Host "   ❌ Failed to retrieve AD CS objects: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
        Read-Host "Press Enter to exit"
        return
    }
    
    # Get all issues with AD CS objects
    Write-Host "🔍 Scanning for ESC4 and ESC5 vulnerabilities..." -ForegroundColor Yellow
    try {
        $OriginalIssues = @()
        
        Write-Host "   • Analyzing ESC4 (Vulnerable Certificate Template Access Control)..." -ForegroundColor Gray
        $ESC4Issues = Find-ESC4 -AdcsObjects $AdcsObjects
        $OriginalIssues += $ESC4Issues
        Write-Host "     ✅ Found $($ESC4Issues.Count) ESC4 issues" -ForegroundColor Green
        
        Write-Host "   • Analyzing ESC5 (Vulnerable PKI Object Access Control)..." -ForegroundColor Gray
        $ESC5Issues = Find-ESC5 -AdcsObjects $AdcsObjects
        $OriginalIssues += $ESC5Issues
        Write-Host "     ✅ Found $($ESC5Issues.Count) ESC5 issues" -ForegroundColor Green
        
        Write-Host "   ✅ Total issues found: $($OriginalIssues.Count)" -ForegroundColor Green
    } catch {
        Write-Host "   ❌ Failed to scan for vulnerabilities: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
        Read-Host "Press Enter to exit"
        return
    }
    
    # Expand group ESCalatorIssue objects into individual principal ESCalatorIssue objects
    Write-Host "🔄 Expanding group issues to individual principal issues..." -ForegroundColor Yellow
    try {
        $ExpandedIssues = $OriginalIssues | Expand-Issue
        Write-Host "   ✅ Expanded $($OriginalIssues.Count) group issues to $($ExpandedIssues.Count) individual principal issues" -ForegroundColor Green
    } catch {
        Write-Host "   ❌ Failed to expand issues: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
        Read-Host "Press Enter to exit"
        return
    }
    
    # Attach Issue objects to AD CS objects
    Write-Host "🔗 Attaching issues to collected AD CS objects..." -ForegroundColor Yellow
    try {
        $AdcsObjects | Add-IssueToObject -Issues $OriginalIssues, $ExpandedIssues | Out-Null
        Write-Host "   ✅ Successfully attached issues to AD CS objects" -ForegroundColor Green
    } catch {
        Write-Host "   ❌ Failed to attach issues to objects: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # Get all individual principals identified in Issues
    Write-Host "👥 Identifying individual principals..." -ForegroundColor Yellow
    try {
        $AllPrincipals = Get-IndividualPrincipals -Issues $OriginalIssues, $ExpandedIssues
        Write-Host "   ✅ Identified $($AllPrincipals.Count) individual principals" -ForegroundColor Green
    } catch {
        Write-Host "   ❌ Failed to identify principals: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # Attach Issue objects to Principal Objects
    Write-Host "🔗 Attaching issues to principal objects..." -ForegroundColor Yellow
    try {
        $AllPrincipals | Add-IssueToPrincipal -Issues $OriginalIssues, $ExpandedIssues | Out-Null
        Write-Host "   ✅ Successfully attached issues to principals" -ForegroundColor Green
    } catch {
        Write-Host "   ❌ Failed to attach issues to principals: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    # Find ESC Issue Combinations
    Write-Host "🎯 Analyzing ESC Issue Combinations..." -ForegroundColor Yellow
    try {
        $IssueCombinations = Find-IssueCombinations -Issues $OriginalIssues, $ExpandedIssues
        if ($IssueCombinations) {
            Write-Host "   ✅ Found $($IssueCombinations.Count) ESC issue combination attacks!" -ForegroundColor Green
        } else {
            Write-Host "   ℹ️ No ESC issue combination attacks found" -ForegroundColor Blue
        }
    } catch {
        Write-Host "   ❌ Failed to analyze issue combinations: $($_.Exception.Message)" -ForegroundColor Red
        $IssueCombinations = @()
    }
    
    Write-Host ""
    Write-Host "🏁 Analysis complete! Ready for interactive exploration..." -ForegroundColor Green
    Write-Host ""

    # Flag to track first menu display
    $firstDisplay = $true

    do {
        # Show the ESCalator header with consistent session colors (only after first time)
        if (-not $firstDisplay) {
            Show-ESCalatorHeader -Color1 $sessionColors[0] -Color2 $sessionColors[1] -Color3 $sessionColors[2] -Color4 $sessionColors[3] -Color5 $sessionColors[4]
        }
        $firstDisplay = $false
        
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
