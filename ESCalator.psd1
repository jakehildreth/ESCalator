@{
    AliasesToExport=@('*')
    Author='Jake Hildreth'
    CmdletsToExport=@()
    CompanyName='Gilmour Technologies Ltd'
    CompatiblePSEditions=@('Desktop',        'Core')
    Copyright='(c) 2025 - 2026 Jake Hildreth, Gilmour Technologies Ltd. All rights reserved.'
    Description='A tiny tool for identifying and abusing AD CS issue combinations that may not be readily obvious'
    FunctionsToExport=@('*')
    ModuleVersion='2026.1.10000'
    PowerShellVersion='5.1'
    PrivateData=@{
        PSData=@{
            ExternalModuleDependencies=@('Microsoft.PowerShell.Utility',                'Microsoft.PowerShell.Management',                'Microsoft.PowerShell.Security')
            ProjectUri='https://github.com/jakehildreth/ESCalator'
            RequireLicenseAcceptance=$false
            Tags=@('ADCS',                'ESCalator',                'CertificateServices',                'PKI',                'ActiveDirectory',                'Windows',                'Security')
        }
    }
    RequiredModules=@('Microsoft.PowerShell.Utility',        'Microsoft.PowerShell.Management',        'Microsoft.PowerShell.Security')
    RootModule='ESCalator.psm1'
    VariablesToExport='*'
}
