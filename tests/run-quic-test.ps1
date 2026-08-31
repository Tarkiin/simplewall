[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PythonPath,
    [string]$DependencyPath,
    [string]$CollectorPath = 'temp/network-integration.exe'
)
$ErrorActionPreference = 'Stop'
$projectPath = Split-Path $PSScriptRoot -Parent
$report = Join-Path $projectPath ('temp/quic-' + [Guid]::NewGuid().ToString('N') + '.txt')
$collector = (Resolve-Path -LiteralPath (Join-Path $projectPath $CollectorPath)).Path
$script = Join-Path $PSScriptRoot 'quic_loopback.py'
$previousPythonPath = $env:PYTHONPATH
try {
    if ($DependencyPath) { $env:PYTHONPATH = (Resolve-Path -LiteralPath $DependencyPath).Path }
    $python = Start-Process -FilePath $PythonPath -ArgumentList ('-u "' + $script + '" "' + $report + '"') -WindowStyle Hidden -PassThru -RedirectStandardOutput "$report.python.log" -RedirectStandardError "$report.python.err"
} finally { $env:PYTHONPATH = $previousPythonPath }
Write-Host "Local QUIC test report: $report"
$watcher = Start-Process -FilePath $collector -ArgumentList ('--watch "' + $report + '" ' + $python.Id) -Verb RunAs -WindowStyle Hidden -PassThru
$deadline = [DateTime]::UtcNow.AddSeconds(60)
while ((!$python.HasExited -or !$watcher.HasExited) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 250 }
if (!$python.HasExited -or !$watcher.HasExited) { throw "Test timed out; inspect processes $($python.Id) and $($watcher.Id)." }
$python.WaitForExit(); $watcher.WaitForExit()
Get-Content -LiteralPath $report
Get-Content -LiteralPath "$report.python.log"
Get-Content -LiteralPath "$report.python.err"
if ($python.ExitCode -ne 0 -or $watcher.ExitCode -ne 0) { throw 'QUIC test failed' }
if (!(Select-String -LiteralPath "$report.python.log" -SimpleMatch 'QUIC_ACCOUNTING: PASS' -Quiet)) { throw 'Missing independent QUIC accounting verification' }
