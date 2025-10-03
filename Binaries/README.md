# Binaries Folder

This folder contains external tools required by ESCalator functions.

## Required Tools

### Certify.exe
- **Source repo**: https://github.com/GhostPack/Certify
- **Used by**: `Invoke-ESC1Attack` function
- **Purpose**: Performs certificate enrollment attacks against AD CS
- **Filename**: `Certify.exe`
- **Installation**:
  1. Clone the source repo
  2. Compile Certify using whatever method you need (or ask Spencer)
  2. Place the executable in this Binaries folder
  3. Ensure the file is named exactly `Certify.exe`

> **Security Note:**
These are offensive security tools. Use only in authorized environments for testing and research purposes.