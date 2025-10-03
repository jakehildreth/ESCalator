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
  2. Compile using whatever method you need (or ask Spencer)
  3. Place the executable in this Binaries folder
  4. Ensure the file is named exactly `Certify.exe`

### Rubeus.exe
- **Source repo**: https://github.com/GhostPack/Rubeus
- **Used by**: `Invoke-ESC1Attack` function
- **Purpose**: Kerberos abuse tool for authentication with certificates obtained from ESC attacks
- **Filename**: `Rubeus.exe`
- **Installation**:
  1. Clone the source repo
  2. Compile using whatever method you need (or ask Spencer)
  2. Place the executable in this Binaries folder
  3. Ensure the file is named exactly `Rubeus.exe`
- **Common usage**: Use the `asktgt` command with certificates from Certify to obtain Kerberos tickets
  ```
  Rubeus.exe asktgt /user:Administrator /certificate:<base64-cert> /ptt
  ```

> **Security Note:**
These are offensive security tools. Use only in authorized environments for testing and research purposes.