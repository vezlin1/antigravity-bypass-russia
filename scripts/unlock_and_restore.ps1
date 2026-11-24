# Windows PowerShell 5.1 and PowerShell 7: both launch the same Rust engine.
# This script does not edit settings.json, executables, or network settings itself.
$ErrorActionPreference = 'Stop'
$engineArgs = @($args)
$repoRoot = Split-Path -Parent $PSScriptRoot
$candidates = @(
    (Join-Path $PSScriptRoot 'antigravity-bypass-windows.exe'),
    (Join-Path $PSScriptRoot 'antigravity-bypass-russia.exe'),
    (Join-Path $repoRoot 'target\release\antigravity-bypass-russia.exe'),
    (Join-Path $repoRoot 'antigravity-bypass-russia.exe')
)
if (-not (Test-Path -LiteralPath $candidates[0] -PathType Leaf) -and -not (Test-Path -LiteralPath $candidates[1] -PathType Leaf) -and (Test-Path -LiteralPath (Join-Path $repoRoot 'Cargo.toml')) -and (Get-Command cargo -ErrorAction SilentlyContinue)) {
    & cargo build --release --locked --manifest-path (Join-Path $repoRoot 'Cargo.toml')
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
$engine = $candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
if (-not $engine) {
    throw 'Rust engine not found. Place the release EXE next to this script, or install Rust and run this script from the repository.'
}
# Use CRT escaping explicitly: Windows PowerShell 5.1 loses empty arguments
# and embedded quotes when invoking a native executable through the & operator.
$quotedArgs = foreach ($argument in $engineArgs) {
    $escaped = [regex]::Replace([string]$argument, '(\\*)"', '$1$1\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    '"' + $escaped + '"'
}
$startInfo = New-Object System.Diagnostics.ProcessStartInfo
$startInfo.FileName = $engine
$startInfo.UseShellExecute = $false
$startInfo.Arguments = $quotedArgs -join ' '
$process = [System.Diagnostics.Process]::Start($startInfo)
$process.WaitForExit()
$exitCode = $process.ExitCode
$process.Dispose()
exit $exitCode
