@{
    RootModule        = 'Am.Keyward.SecretManagement.psm1'
    ModuleVersion     = '{{VERSION}}'
    GUID              = '5d0f4a52-6f0e-4b8c-9a3e-6e2d3c1b7a41'
    Author            = 'Ardimedia'
    CompanyName       = 'Ardimedia'
    Copyright         = '(c) Ardimedia. MIT License.'
    Description       = 'AM KEYWARD as a PowerShell SecretManagement vault (read-only): Get-Secret reads application secrets through the software-client API with the app token of a keyward profile. Requires the keyward command line (dotnet tool install --global Am.Keyward.Cli --prerelease).'
    PowerShellVersion = '5.1'
    NestedModules     = @('.\Am.Keyward.SecretManagement.Extension')
    FunctionsToExport = @('Get-KeywardSecret')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{ PSData = @{ Tags = @('SecretManagement', 'Keyward', 'Secrets') } }
}
