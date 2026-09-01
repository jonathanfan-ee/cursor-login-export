$ErrorActionPreference = 'Stop'

$scriptDir = $PSScriptRoot
$launcher = Join-Path -Path $scriptDir -ChildPath 'cursor-export-credential.ps1'
if (-not (Test-Path -LiteralPath $launcher -PathType Leaf)) {
    [Console]::Error.WriteLine("Cannot find cursor-export-credential.ps1 next to this launcher.")
    exit 1
}

try {
    & $launcher '--show-token' @args
    $ok = $?
    $exitCode = $LASTEXITCODE
    if (-not $ok -and ($null -eq $exitCode -or $exitCode -eq 0)) {
        $exitCode = 1
    }
    exit $exitCode
} catch {
    [Console]::Error.WriteLine("Unable to start the launcher: $($_.Exception.Message)")
    exit 1
}
