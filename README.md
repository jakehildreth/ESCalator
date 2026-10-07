# ESCalator

A tiny tool for identifying and abusing AD CS issue combinations that may not be readily obvious.

## Installation

```powershell
Install-Module -Name ESCalator -Scope CurrentUser
```

Or clone the repository and import the module from the repo root:

```powershell
Import-Module ./ESCalator.psd1
```

## Quick start

Run the interactive analysis menu:

```powershell
Start-ESCalator
```

Run the analysis once and print results without entering the interactive menu:

```powershell
Start-ESCalator -ReportOnly
```

## Examples

- `Start-ESCalator` - gather AD CS objects, scan for ESC4/ESC5 issues, and open the interactive menu.
- `Start-ESCalator -ReportOnly` - run the same analysis and exit after reporting.

## License

MIT License w/Commons Clause - see [LICENSE](..\LICENSE) file for details.

---

Made with 💜 by [Jake Hildreth](https://jakehildreth.com)
