function GradientPlayground {
    <#
         $gradient = GradientPlayground -Theme "Sunset" -Steps 10      .SYNOPSIS
        Generates a gradient of true color ANSI escape sequences between two colors or from a predefined theme.

        .DESCRIPTION
        Creates a smooth color gradient between two colors by calculating
        intermediate RGB values and outputting them as 24-bit true color ANSI escape sequences.
        Supports both custom color specification and predefined color themes.

        .PARAMETER StartColor
        Starting color as hex code (e.g., "#FF0000"), HTML name (e.g., "red"), or "Random"

        .PARAMETER EndColor
        Ending color as hex code (e.g., "#0000FF"), HTML name (e.g., "blue"), or "Random"

        .PARAMETER Steps
        Number of gradient steps to generate (minimum 2)

        .PARAMETER Theme
        Predefined color theme to use instead of custom colors. Use "Random" to randomly select a theme.

        .PARAMETER Preview
        Display a vertical preview of the gradient colors with ANSI codes and color names

        .PARAMETER PassThru
        When used with -Preview, returns the gradient colors to the pipeline in addition to displaying the preview

        .PARAMETER Legacy256Color
        Use legacy 256-color mode instead of 24-bit true color (for compatibility with older terminals)

        .EXAMPLE
        $gradient = GradientPlayground -StartColor "#FF0000" -EndColor "#0000FF" -Steps 5
        # Returns 5 ANSI color codes creating a red-to-blue gradient

        .EXAMPLE
        $gradient = Get-GradientColors -StartColor "red" -EndColor "blue" -Steps 5
        # Same as above using HTML color names

        .EXAMPLE
        $gradient = Get-GradientColors -Theme "Sunset" -Steps 5
        # Creates a sunset-themed gradient

        .EXAMPLE
        $gradient = Get-GradientColors -Theme "Random" -Steps 5
        # Creates a gradient using a randomly selected theme

        .EXAMPLE
        Get-GradientColors -Theme "Ocean" -Steps 8 -Preview
        # Creates an ocean-themed gradient with 8 steps and displays a preview (no return value)

        .EXAMPLE
        $colors = Get-GradientColors -Theme "Ocean" -Steps 8 -Preview -PassThru
        # Displays preview AND returns the gradient colors to the pipeline
    #>
    [CmdletBinding(DefaultParameterSetName = 'CustomColors')]
    param (
        [Parameter(Mandatory, ParameterSetName = 'CustomColors')]
        [ValidateScript({
                $color = $_.ToLower().Trim()
                # Allow 'random'
                if ($color -eq 'random') { return $true }
                # Allow hex colors
                if ($color -match '^#[0-9a-f]{6}$') { return $true }
                # Allow HTML color names - use the same list as defined in the function body
                $htmlColorNames = @(
                    'aliceblue', 'antiquewhite', 'aqua', 'aquamarine', 'azure', 'beige', 'bisque', 'black',
                    'blanchedalmond', 'blue', 'blueviolet', 'brown', 'burlywood', 'cadetblue', 'chartreuse', 'chocolate',
                    'coral', 'cornflowerblue', 'cornsilk', 'crimson', 'cyan', 'darkblue', 'darkcyan', 'darkgoldenrod',
                    'darkgray', 'darkgrey', 'darkgreen', 'darkkhaki', 'darkmagenta', 'darkolivegreen', 'darkorange', 'darkorchid',
                    'darkred', 'darksalmon', 'darkseagreen', 'darkslateblue', 'darkslategray', 'darkslategrey', 'darkturquoise', 'darkviolet',
                    'deeppink', 'deepskyblue', 'dimgray', 'dimgrey', 'dodgerblue', 'firebrick', 'floralwhite', 'forestgreen',
                    'fuchsia', 'gainsboro', 'ghostwhite', 'gold', 'goldenrod', 'gray', 'grey', 'green',
                    'greenyellow', 'honeydew', 'hotpink', 'indianred', 'indigo', 'ivory', 'khaki', 'lavender',
                    'lavenderblush', 'lawngreen', 'lemonchiffon', 'lightblue', 'lightcoral', 'lightcyan', 'lightgoldenrodyellow', 'lightgray',
                    'lightgrey', 'lightgreen', 'lightpink', 'lightsalmon', 'lightseagreen', 'lightskyblue', 'lightslategray', 'lightslategrey',
                    'lightsteelblue', 'lightyellow', 'lime', 'limegreen', 'linen', 'magenta', 'maroon', 'mediumaquamarine',
                    'mediumblue', 'mediumorchid', 'mediumpurple', 'mediumseagreen', 'mediumslateblue', 'mediumspringgreen', 'mediumturquoise', 'mediumvioletred',
                    'midnightblue', 'mintcream', 'mistyrose', 'moccasin', 'navajowhite', 'navy', 'oldlace', 'olive',
                    'olivedrab', 'orange', 'orangered', 'orchid', 'palegoldenrod', 'palegreen', 'paleturquoise', 'palevioletred',
                    'papayawhip', 'peachpuff', 'peru', 'pink', 'plum', 'powderblue', 'purple', 'red',
                    'rosybrown', 'royalblue', 'saddlebrown', 'salmon', 'sandybrown', 'seagreen', 'seashell', 'sienna',
                    'silver', 'skyblue', 'slateblue', 'slategray', 'slategrey', 'snow', 'springgreen', 'steelblue',
                    'tan', 'teal', 'thistle', 'tomato', 'turquoise', 'violet', 'wheat', 'white', 'whitesmoke', 'yellow', 'yellowgreen'
                )
                if ($htmlColorNames -contains $color) { return $true }
                throw "Invalid color: '$_'. Must be a valid hex color (#RRGGBB), HTML color name, or 'Random'."
            })]
        [string]$StartColor,
        
        [Parameter(Mandatory, ParameterSetName = 'CustomColors')]
        [ValidateScript({
                $color = $_.ToLower().Trim()
                # Allow 'random'
                if ($color -eq 'random') { return $true }
                # Allow hex colors
                if ($color -match '^#[0-9a-f]{6}$') { return $true }
                # Allow HTML color names - use the same list as defined in the function body
                $htmlColorNames = @(
                    'aliceblue', 'antiquewhite', 'aqua', 'aquamarine', 'azure', 'beige', 'bisque', 'black',
                    'blanchedalmond', 'blue', 'blueviolet', 'brown', 'burlywood', 'cadetblue', 'chartreuse', 'chocolate',
                    'coral', 'cornflowerblue', 'cornsilk', 'crimson', 'cyan', 'darkblue', 'darkcyan', 'darkgoldenrod',
                    'darkgray', 'darkgrey', 'darkgreen', 'darkkhaki', 'darkmagenta', 'darkolivegreen', 'darkorange', 'darkorchid',
                    'darkred', 'darksalmon', 'darkseagreen', 'darkslateblue', 'darkslategray', 'darkslategrey', 'darkturquoise', 'darkviolet',
                    'deeppink', 'deepskyblue', 'dimgray', 'dimgrey', 'dodgerblue', 'firebrick', 'floralwhite', 'forestgreen',
                    'fuchsia', 'gainsboro', 'ghostwhite', 'gold', 'goldenrod', 'gray', 'grey', 'green',
                    'greenyellow', 'honeydew', 'hotpink', 'indianred', 'indigo', 'ivory', 'khaki', 'lavender',
                    'lavenderblush', 'lawngreen', 'lemonchiffon', 'lightblue', 'lightcoral', 'lightcyan', 'lightgoldenrodyellow', 'lightgray',
                    'lightgrey', 'lightgreen', 'lightpink', 'lightsalmon', 'lightseagreen', 'lightskyblue', 'lightslategray', 'lightslategrey',
                    'lightsteelblue', 'lightyellow', 'lime', 'limegreen', 'linen', 'magenta', 'maroon', 'mediumaquamarine',
                    'mediumblue', 'mediumorchid', 'mediumpurple', 'mediumseagreen', 'mediumslateblue', 'mediumspringgreen', 'mediumturquoise', 'mediumvioletred',
                    'midnightblue', 'mintcream', 'mistyrose', 'moccasin', 'navajowhite', 'navy', 'oldlace', 'olive',
                    'olivedrab', 'orange', 'orangered', 'orchid', 'palegoldenrod', 'palegreen', 'paleturquoise', 'palevioletred',
                    'papayawhip', 'peachpuff', 'peru', 'pink', 'plum', 'powderblue', 'purple', 'red',
                    'rosybrown', 'royalblue', 'saddlebrown', 'salmon', 'sandybrown', 'seagreen', 'seashell', 'sienna',
                    'silver', 'skyblue', 'slateblue', 'slategray', 'slategrey', 'snow', 'springgreen', 'steelblue',
                    'tan', 'teal', 'thistle', 'tomato', 'turquoise', 'violet', 'wheat', 'white', 'whitesmoke', 'yellow', 'yellowgreen'
                )
                if ($htmlColorNames -contains $color) { return $true }
                throw "Invalid color: '$_'. Must be a valid hex color (#RRGGBB), HTML color name, or 'Random'."
            })]
        [string]$EndColor,
        
        [Parameter(Mandatory, ParameterSetName = 'CustomColors')]
        [Parameter(Mandatory, ParameterSetName = 'Theme')]
        [ValidateRange(2, 50)]
        [int]$Steps,
        
        [Parameter(Mandatory, ParameterSetName = 'Theme')]
        [ValidateSet('Best', 'Sunset', 'Ocean', 'Forest', 'Fire', 'Purple', 'Grayscale', 'Rainbow', 'Neon', 'Cyberpunk', 'Pastel', 'Autumn', 'Winter', 'Spring', 'Summer', 'Random')]
        [string]$Theme,
        
        [Parameter(ParameterSetName = 'CustomColors')]
        [Parameter(ParameterSetName = 'Theme')]
        [switch]$Preview,
        
        [Parameter(ParameterSetName = 'CustomColors')]
        [Parameter(ParameterSetName = 'Theme')]
        [switch]$PassThru,
        
        [Parameter(ParameterSetName = 'CustomColors')]
        [Parameter(ParameterSetName = 'Theme')]
        [switch]$Legacy256Color
    )

    # Predefined color themes
    $colorThemes = @{
        'Autumn'    = @{ Start = '#8B4513'; End = '#FF8C00' } # Saddle Brown to Dark Orange
        'Best'      = @{ Start = '#FF875F'; End = '#870087' } # Coral to Dark Magenta
        'Cyberpunk' = @{ Start = '#00FFFF'; End = '#FF1493' } # Cyan to Deep Pink
        'Fire'      = @{ Start = '#8B0000'; End = '#FFD700' } # Dark Red to Gold
        'Forest'    = @{ Start = '#006400'; End = '#90EE90' } # Dark Green to Light Green
        'Grayscale' = @{ Start = '#000000'; End = '#FFFFFF' } # Black to White
        'Neon'      = @{ Start = '#00FF00'; End = '#FF00FF' } # Lime to Magenta
        'Ocean'     = @{ Start = '#000080'; End = '#00CED1' } # Navy to Dark Turquoise
        'Pastel'    = @{ Start = '#FFB6C1'; End = '#E0E6FF' } # Light Pink to Lavender
        'Purple'    = @{ Start = '#4B0082'; End = '#DDA0DD' } # Indigo to Plum
        'Rainbow'   = @{ Start = '#FF0000'; End = '#9400D3' } # Red to Dark Violet
        'Spring'    = @{ Start = '#32CD32'; End = '#FFB6C1' } # Lime Green to Light Pink
        'Summer'    = @{ Start = '#FFD700'; End = '#00BFFF' } # Gold to Deep Sky Blue
        'Sunset'    = @{ Start = '#FF4500'; End = '#FF69B4' } # Orange to Pink
        'Winter'    = @{ Start = '#4682B4'; End = '#B0E0E6' } # Steel Blue to Powder Blue
    }

    # If using a theme, get the colors from the theme
    if ($PSCmdlet.ParameterSetName -eq 'Theme') {
        # Handle random theme selection
        if ($Theme -eq 'Random') {
            $availableThemes = @('Sunset', 'Ocean', 'Forest', 'Fire', 'Purple', 'Grayscale', 'Rainbow', 'Neon', 'Cyberpunk', 'Pastel', 'Autumn', 'Winter', 'Spring', 'Summer')
            $Theme = $availableThemes | Get-Random
            Write-Verbose "Random theme selected: $Theme"
        }
        
        $themeColors = $colorThemes[$Theme]
        $StartColor = $themeColors.Start
        $EndColor = $themeColors.End
        Write-Verbose "Using theme '$Theme': $StartColor to $EndColor"
    }

    # HTML color name to hex mapping
    $htmlColors = @{
        "aliceblue" = "#F0F8FF"; "antiquewhite" = "#FAEBD7"; "aqua" = "#00FFFF"; "aquamarine" = "#7FFFD4"
        "azure" = "#F0FFFF"; "beige" = "#F5F5DC"; "bisque" = "#FFE4C4"; "black" = "#000000"
        "blanchedalmond" = "#FFEBCD"; "blue" = "#0000FF"; "blueviolet" = "#8A2BE2"; "brown" = "#A52A2A"
        "burlywood" = "#DEB887"; "cadetblue" = "#5F9EA0"; "chartreuse" = "#7FFF00"; "chocolate" = "#D2691E"
        "coral" = "#FF7F50"; "cornflowerblue" = "#6495ED"; "cornsilk" = "#FFF8DC"; "crimson" = "#DC143C"
        "cyan" = "#00FFFF"; "darkblue" = "#00008B"; "darkcyan" = "#008B8B"; "darkgoldenrod" = "#B8860B"
        "darkgray" = "#A9A9A9"; "darkgrey" = "#A9A9A9"; "darkgreen" = "#006400"; "darkkhaki" = "#BDB76B"
        "darkmagenta" = "#8B008B"; "darkolivegreen" = "#556B2F"; "darkorange" = "#FF8C00"; "darkorchid" = "#9932CC"
        "darkred" = "#8B0000"; "darksalmon" = "#E9967A"; "darkseagreen" = "#8FBC8F"; "darkslateblue" = "#483D8B"
        "darkslategray" = "#2F4F4F"; "darkslategrey" = "#2F4F4F"; "darkturquoise" = "#00CED1"; "darkviolet" = "#9400D3"
        "deeppink" = "#FF1493"; "deepskyblue" = "#00BFFF"; "dimgray" = "#696969"; "dimgrey" = "#696969"
        "dodgerblue" = "#1E90FF"; "firebrick" = "#B22222"; "floralwhite" = "#FFFAF0"; "forestgreen" = "#228B22"
        "fuchsia" = "#FF00FF"; "gainsboro" = "#DCDCDC"; "ghostwhite" = "#F8F8FF"; "gold" = "#FFD700"
        "goldenrod" = "#DAA520"; "gray" = "#808080"; "grey" = "#808080"; "green" = "#008000"
        "greenyellow" = "#ADFF2F"; "honeydew" = "#F0FFF0"; "hotpink" = "#FF69B4"; "indianred" = "#CD5C5C"
        "indigo" = "#4B0082"; "ivory" = "#FFFFF0"; "khaki" = "#F0E68C"; "lavender" = "#E6E6FA"
        "lavenderblush" = "#FFF0F5"; "lawngreen" = "#7CFC00"; "lemonchiffon" = "#FFFACD"; "lightblue" = "#ADD8E6"
        "lightcoral" = "#F08080"; "lightcyan" = "#E0FFFF"; "lightgoldenrodyellow" = "#FAFAD2"; "lightgray" = "#D3D3D3"
        "lightgrey" = "#D3D3D3"; "lightgreen" = "#90EE90"; "lightpink" = "#FFB6C1"; "lightsalmon" = "#FFA07A"
        "lightseagreen" = "#20B2AA"; "lightskyblue" = "#87CEFA"; "lightslategray" = "#778899"; "lightslategrey" = "#778899"
        "lightsteelblue" = "#B0C4DE"; "lightyellow" = "#FFFFE0"; "lime" = "#00FF00"; "limegreen" = "#32CD32"
        "linen" = "#FAF0E6"; "magenta" = "#FF00FF"; "maroon" = "#800000"; "mediumaquamarine" = "#66CDAA"
        "mediumblue" = "#0000CD"; "mediumorchid" = "#BA55D3"; "mediumpurple" = "#9370DB"; "mediumseagreen" = "#3CB371"
        "mediumslateblue" = "#7B68EE"; "mediumspringgreen" = "#00FA9A"; "mediumturquoise" = "#48D1CC"; "mediumvioletred" = "#C71585"
        "midnightblue" = "#191970"; "mintcream" = "#F5FFFA"; "mistyrose" = "#FFE4E1"; "moccasin" = "#FFE4B5"
        "navajowhite" = "#FFDEAD"; "navy" = "#000080"; "oldlace" = "#FDF5E6"; "olive" = "#808000"
        "olivedrab" = "#6B8E23"; "orange" = "#FFA500"; "orangered" = "#FF4500"; "orchid" = "#DA70D6"
        "palegoldenrod" = "#EEE8AA"; "palegreen" = "#98FB98"; "paleturquoise" = "#AFEEEE"; "palevioletred" = "#DB7093"
        "papayawhip" = "#FFEFD5"; "peachpuff" = "#FFDAB9"; "peru" = "#CD853F"; "pink" = "#FFC0CB"
        "plum" = "#DDA0DD"; "powderblue" = "#B0E0E6"; "purple" = "#800080"; "red" = "#FF0000"
        "rosybrown" = "#BC8F8F"; "royalblue" = "#4169E1"; "saddlebrown" = "#8B4513"; "salmon" = "#FA8072"
        "sandybrown" = "#F4A460"; "seagreen" = "#2E8B57"; "seashell" = "#FFF5EE"; "sienna" = "#A0522D"
        "silver" = "#C0C0C0"; "skyblue" = "#87CEEB"; "slateblue" = "#6A5ACD"; "slategray" = "#708090"
        "slategrey" = "#708090"; "snow" = "#FFFAFA"; "springgreen" = "#00FF7F"; "steelblue" = "#4682B4"
        "tan" = "#D2B48C"; "teal" = "#008080"; "thistle" = "#D8BFD8"; "tomato" = "#FF6347"
        "turquoise" = "#40E0D0"; "violet" = "#EE82EE"; "wheat" = "#F5DEB3"; "white" = "#FFFFFF"
        "whitesmoke" = "#F5F5F5"; "yellow" = "#FFFF00"; "yellowgreen" = "#9ACD32"
    }

    # Convert color name or hex to hex format
    function ConvertTo-Hex {
        param([string]$Color)
        
        $color = $Color.ToLower().Trim()
        
        # Handle random color selection
        if ($color -eq "random") {
            $randomColorName = $htmlColors.Keys | Get-Random
            Write-Verbose "Random color selected: $randomColorName"
            return $htmlColors[$randomColorName]
        }
        
        # If it's already a hex color, validate and return
        if ($color -match "^#[0-9a-f]{6}$") {
            return $color.ToUpper()
        }
        
        # If it's an HTML color name, convert to hex
        if ($htmlColors.ContainsKey($color)) {
            return $htmlColors[$color]
        }
        
        # If not found, throw an error
        throw "Invalid color: '$Color'. Must be a valid hex color (#RRGGBB), HTML color name, or 'Random'."
    }

    # Convert hex to RGB
    function ConvertFrom-Hex {
        param([string]$HexColor)
        $hex = $HexColor.TrimStart('#')
        return @{
            R = [Convert]::ToInt32($hex.Substring(0, 2), 16)
            G = [Convert]::ToInt32($hex.Substring(2, 2), 16)
            B = [Convert]::ToInt32($hex.Substring(4, 2), 16)
        }
    }

    # Convert RGB to nearest ANSI 256 color code
    function ConvertTo-ANSI256 {
        param([int]$R, [int]$G, [int]$B)
        
        # ANSI 256-color palette mapping
        # Colors 16-231 are a 6x6x6 RGB cube
        # Each component can be 0, 1, 2, 3, 4, or 5
        
        # Map RGB (0-255) to cube values (0-5)
        $rCube = [Math]::Round($R / 255.0 * 5)
        $gCube = [Math]::Round($G / 255.0 * 5)
        $bCube = [Math]::Round($B / 255.0 * 5)
        
        # Calculate ANSI color code: 16 + 36*r + 6*g + b
        $ansiCode = 16 + (36 * $rCube) + (6 * $gCube) + $bCube
        
        return [Math]::Min(231, [Math]::Max(16, $ansiCode))
    }

    # Find closest HTML color name for RGB values
    function Find-ClosestColorName {
        param([int]$R, [int]$G, [int]$B)
        
        $closestColor = $null
        $minDistance = [double]::MaxValue
        
        foreach ($colorName in $htmlColors.Keys) {
            $colorHex = $htmlColors[$colorName]
            $colorRGB = ConvertFrom-Hex -HexColor $colorHex
            
            # Calculate Euclidean distance in RGB space
            $distance = [Math]::Sqrt(
                [Math]::Pow($R - $colorRGB.R, 2) + 
                [Math]::Pow($G - $colorRGB.G, 2) + 
                [Math]::Pow($B - $colorRGB.B, 2)
            )
            
            if ($distance -lt $minDistance) {
                $minDistance = $distance
                $closestColor = $colorName
            }
        }
        
        return $closestColor
    }

    # Parse start and end colors (convert to hex if needed)
    $startHex = ConvertTo-Hex -Color $StartColor
    $endHex = ConvertTo-Hex -Color $EndColor
    
    $startRGB = ConvertFrom-Hex -HexColor $startHex
    $endRGB = ConvertFrom-Hex -HexColor $endHex

    # Generate gradient
    $gradientColors = @()
    $gradientInfo = @()  # Store RGB and color name info for preview
    
    for ($i = 0; $i -lt $Steps; $i++) {
        # Calculate interpolation factor (0.0 to 1.0)
        $factor = if ($Steps -eq 1) { 0 } else { $i / ($Steps - 1) }
        
        # Interpolate RGB values
        $currentR = [Math]::Round($startRGB.R + ($endRGB.R - $startRGB.R) * $factor)
        $currentG = [Math]::Round($startRGB.G + ($endRGB.G - $startRGB.G) * $factor)
        $currentB = [Math]::Round($startRGB.B + ($endRGB.B - $startRGB.B) * $factor)
        
        if ($Legacy256Color) {
            # Convert to ANSI 256-color code for legacy mode
            $ansiColor = ConvertTo-ANSI256 -R $currentR -G $currentG -B $currentB
            $gradientColors += $ansiColor
        } else {
            # Use 24-bit true color RGB values
            $rgbColor = @{ R = $currentR; G = $currentG; B = $currentB }
            $gradientColors += $rgbColor
        }
        
        # Store info for preview
        $closestColorName = Find-ClosestColorName -R $currentR -G $currentG -B $currentB
        if ($Legacy256Color) {
            $gradientInfo += @{
                ANSI      = $ansiColor
                ColorName = $closestColorName
                RGB       = @{ R = $currentR; G = $currentG; B = $currentB }
            }
        } else {
            $gradientInfo += @{
                RGB       = @{ R = $currentR; G = $currentG; B = $currentB }
                ColorName = $closestColorName
                TrueColor = "38;2;$currentR;$currentG;$currentB"
            }
        }
    }

    # Display preview if requested
    if ($Preview) {
        Write-Host ""
        Write-Host "`e[1mGradient Preview`e[0m" -ForegroundColor White
        
        # Find the longest color name for consistent padding
        $maxColorNameLength = ($gradientInfo | ForEach-Object { $_.ColorName.Length } | Measure-Object -Maximum).Maximum
        
        for ($i = 0; $i -lt $gradientColors.Count; $i++) {
            $info = $gradientInfo[$i]
            $colorName = $info.ColorName.PadRight($maxColorNameLength)
            
            # Create the preview block
            $block = "████████████"  # 12 block characters
            
            if ($Legacy256Color) {
                $color = $info.ANSI
                $invertedText = "`e[48;5;${color};30m $colorName `e[0m"  # Black text on color background
                $ansiCode = "`e[38;5;${color}m$block`e[0m"  # Colored block
                Write-Host "$ansiCode $invertedText ANSI: $color"
            } else {
                $rgb = $info.RGB
                $trueColorCode = $info.TrueColor
                $invertedText = "`e[48;2;$($rgb.R);$($rgb.G);$($rgb.B);30m $colorName `e[0m"  # Black text on RGB background
                $rgbCode = "`e[${trueColorCode}m$block`e[0m"  # True color block
                $hexColor = "#{0:X2}{1:X2}{2:X2}" -f [int]$rgb.R, [int]$rgb.G, [int]$rgb.B
                Write-Host "$rgbCode $invertedText RGB: $($rgb.R),$($rgb.G),$($rgb.B) ($hexColor)"
            }
        }
        
        Write-Host ""
        # When Preview is enabled, only return objects if PassThru is also specified
        if (-not $PassThru) {
            return
        }
    }

    # Return gradient colors when not in preview mode or when PassThru is specified
    return $gradientColors
}