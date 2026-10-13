# Runs the keyward command line and returns its JSON output; a failure becomes an error with keyward's own reason.
# Values travel on stdout as JSON (ASCII-escaped), never on a command line.

function Invoke-Keyward {
    param(
        [Parameter(Mandatory)] [string[]] $Arguments,
        [string] $Executable = $(if ($env:KEYWARD_EXE) { $env:KEYWARD_EXE } else { 'keyward' })
    )

    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName = (Get-Command $Executable -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $start.StandardErrorEncoding = [System.Text.Encoding]::UTF8
    if ($start.PSObject.Properties.Name -contains 'ArgumentList' -and $null -ne $start.ArgumentList) {
        foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    } else {
        # Windows PowerShell 5.1 (.NET Framework): one quoted argument string.
        $start.Arguments = ($Arguments | ForEach-Object { '"' + ($_ -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"' }) -join ' '
    }

    $process = [System.Diagnostics.Process]::Start($start)
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) {
        throw ($stderr.Result.Trim() -replace '^keyward: ', '')
    }

    return $stdout.Result
}

function Invoke-KeywardGet {
    param([Parameter(Mandatory)] [string] $Profile, [Parameter(Mandatory)] [string] $Key)
    return (Invoke-Keyward -Arguments @('get', "$($Profile):$Key", '--json') | ConvertFrom-Json).value
}
