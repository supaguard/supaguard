$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$cliPath = Join-Path $scriptDir "supaguard"

if (Get-Command python -ErrorAction SilentlyContinue) {
    & python $cliPath @args
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    & py -3 $cliPath @args
} else {
    Write-Error "[SupaGuard Error] Python 3 not found in PATH."
    exit 1
}
