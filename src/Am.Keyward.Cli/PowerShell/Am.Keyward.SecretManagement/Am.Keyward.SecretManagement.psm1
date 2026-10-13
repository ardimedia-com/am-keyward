# AM KEYWARD — convenience command next to the SecretManagement vault (decision T21 A).
# A credential is stored as typed keys (Prtg:Username, Prtg:Password, Prtg:Token) — never parsed out of text.

. (Join-Path (Join-Path $PSScriptRoot 'Am.Keyward.SecretManagement.Extension') 'Invoke-Keyward.ps1')

function Get-KeywardSecret {
    <#
    .SYNOPSIS
    Reads a secret from AM KEYWARD through the keyward command line.

    .EXAMPLE
    $token = Get-KeywardSecret -Profile ops -Name Prtg -Field token -AsPlainText   # key Prtg:Token

    .EXAMPLE
    $cred = Get-KeywardSecret -Profile ops -Name Prtg -AsCredential                # keys Prtg:Username + Prtg:Password
    #>
    [CmdletBinding(DefaultParameterSetName = 'Value')]
    param(
        # The keyward profile (an app token stored with 'keyward login'). Default: $env:KEYWARD_PROFILE.
        [string] $Profile = $env:KEYWARD_PROFILE,

        # The key, or the section of a credential (Prtg for Prtg:Username / Prtg:Password).
        [Parameter(Mandatory, Position = 0)]
        [string] $Name,

        # A part of the credential: username, password, token — or any other key suffix.
        [Parameter(ParameterSetName = 'Value')]
        [string] $Field,

        [Parameter(ParameterSetName = 'Value')]
        [switch] $AsPlainText,

        [Parameter(Mandatory, ParameterSetName = 'Credential')]
        [switch] $AsCredential
    )

    if ([string]::IsNullOrWhiteSpace($Profile)) {
        throw 'Which keyward profile? Pass -Profile or set $env:KEYWARD_PROFILE.'
    }

    if ($AsCredential) {
        $user = Invoke-KeywardGet -Profile $Profile -Key "$($Name):Username"
        $password = Invoke-KeywardGet -Profile $Profile -Key "$($Name):Password"
        return [pscredential]::new($user, (ConvertTo-SecureString $password -AsPlainText -Force))
    }

    $key = $Name
    if ($Field) {
        $suffix = switch ($Field.ToLowerInvariant()) {
            'username' { 'Username' }
            'password' { 'Password' }
            'token'    { 'Token' }
            default    { $Field }
        }
        $key = "$($Name):$suffix"
    }

    $value = Invoke-KeywardGet -Profile $Profile -Key $key
    if ($AsPlainText) { return $value }
    return ConvertTo-SecureString $value -AsPlainText -Force
}
