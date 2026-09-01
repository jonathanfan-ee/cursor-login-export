$ErrorActionPreference = 'Stop'
$scriptDir = $PSScriptRoot
$scriptPath = Join-Path -Path $scriptDir -ChildPath 'cursor-export-credential.py'

if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
    [Console]::Error.WriteLine("Cannot find cursor-export-credential.py next to this launcher.")
    exit 1
}

# Deliberately leave the script without a param block. PowerShell then keeps
# arbitrary Python-style flags such as --db and --show-meta in $args instead of
# trying to bind them as PowerShell parameters.
$argumentList = @($args)

function Test-PythonCandidate {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Command,
        [string[]] $Prefix = @()
    )

    & $Command @Prefix -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 8) else 1)' *> $null
    return ($LASTEXITCODE -eq 0)
}

$pythonCommand = $null
$pythonPrefix = @()
if ($env:CURSOR_PYTHON_EXE) {
    $explicit = Get-Command $env:CURSOR_PYTHON_EXE -CommandType Application -ErrorAction SilentlyContinue
    if ($null -ne $explicit) {
        $pythonCommand = $explicit.Path
    } else {
        $pythonCommand = $env:CURSOR_PYTHON_EXE
    }
    if (-not (Test-PythonCandidate -Command $pythonCommand -Prefix $pythonPrefix)) {
        [Console]::Error.WriteLine('CURSOR_PYTHON_EXE is missing or is not Python 3.8+.')
        exit 1
    }
} else {
    $py = Get-Command py -CommandType Application -ErrorAction SilentlyContinue
    if ($null -ne $py -and (Test-PythonCandidate -Command $py.Path -Prefix @('-3'))) {
        $pythonCommand = $py.Path
        $pythonPrefix = @('-3')
    }
    if ($null -eq $pythonCommand) {
        foreach ($name in @('python', 'python3')) {
            $candidate = Get-Command $name -CommandType Application -ErrorAction SilentlyContinue
            if ($null -ne $candidate -and (Test-PythonCandidate -Command $candidate.Path)) {
                $pythonCommand = $candidate.Path
                break
            }
        }
    }
}

if ($null -eq $pythonCommand) {
    [Console]::Error.WriteLine('Python 3.8 or newer was not found. Install Python and try again.')
    exit 1
}

try {
    & $pythonCommand @pythonPrefix $scriptPath @argumentList
    $ok = $?
    $exitCode = $LASTEXITCODE
    if (-not $ok -and ($null -eq $exitCode -or $exitCode -eq 0)) {
        $exitCode = 1
    }
    exit $exitCode
} catch {
    [Console]::Error.WriteLine("Unable to start Python: $($_.Exception.Message)")
    exit 1
}
