@{
    ModuleVersion     = '{{VERSION}}'
    RootModule        = 'Am.Keyward.SecretManagement.Extension.psm1'
    FunctionsToExport = @('Set-Secret', 'Get-Secret', 'Remove-Secret', 'Get-SecretInfo', 'Test-SecretVault')
}
