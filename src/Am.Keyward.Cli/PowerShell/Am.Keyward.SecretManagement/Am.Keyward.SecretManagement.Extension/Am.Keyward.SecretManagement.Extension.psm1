# AM KEYWARD SecretManagement extension vault (decision T21 A) — read-only.
# Register-SecretVault -Name Keyward -ModuleName Am.Keyward.SecretManagement -VaultParameters @{ Profile = 'ops' }
# Each vault is one keyward profile, i.e. one app token: the keys of one application in one environment.

. (Join-Path $PSScriptRoot 'Invoke-Keyward.ps1')

function Get-VaultProfile([hashtable] $AdditionalParameters) {
    $profile = $AdditionalParameters['Profile']
    if ([string]::IsNullOrWhiteSpace($profile)) {
        throw "The vault has no keyward profile: register it with -VaultParameters @{ Profile = '<profile>' }."
    }
    return $profile
}

function Get-Secret {
    [CmdletBinding()]
    param([string] $Name, [string] $VaultName, [hashtable] $AdditionalParameters)

    # Returned as a string; SecretManagement hands it out as SecureString unless -AsPlainText is given.
    return Invoke-KeywardGet -Profile (Get-VaultProfile $AdditionalParameters) -Key $Name
}

function Get-SecretInfo {
    [CmdletBinding()]
    param([string] $Filter, [string] $VaultName, [hashtable] $AdditionalParameters)

    $pattern = if ([string]::IsNullOrEmpty($Filter)) { '*' } else { $Filter }
    $keys = Invoke-Keyward -Arguments @('keys', (Get-VaultProfile $AdditionalParameters), '--json') | ConvertFrom-Json
    foreach ($key in $keys) {
        if ($key -like $pattern) {
            [Microsoft.PowerShell.SecretManagement.SecretInformation]::new(
                $key, [Microsoft.PowerShell.SecretManagement.SecretType]::String, $VaultName)
        }
    }
}

function Set-Secret {
    [CmdletBinding()]
    param([string] $Name, [object] $Secret, [string] $VaultName, [hashtable] $AdditionalParameters)
    throw 'The Keyward vault is read-only: values are maintained in Keyward (Applications → keys).'
}

function Remove-Secret {
    [CmdletBinding()]
    param([string] $Name, [string] $VaultName, [hashtable] $AdditionalParameters)
    throw 'The Keyward vault is read-only: values are maintained in Keyward (Applications → keys).'
}

function Test-SecretVault {
    [CmdletBinding()]
    param([string] $VaultName, [hashtable] $AdditionalParameters)
    try {
        $null = Invoke-Keyward -Arguments @('keys', (Get-VaultProfile $AdditionalParameters), '--json')
        return $true
    } catch {
        Write-Error $_.Exception.Message
        return $false
    }
}
