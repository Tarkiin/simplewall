[CmdletBinding()]
param([switch]$UdpDisabled, [string]$LanguagePath)
$ErrorActionPreference='Stop'
$projectPath=Split-Path $PSScriptRoot -Parent
$probeRoot=Join-Path $projectPath 'temp/startup-probe'
$runPath=Join-Path $probeRoot ('run-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $runPath | Out-Null
Copy-Item -LiteralPath (Join-Path $probeRoot 'simplewall.exe'),(Join-Path $probeRoot 'simplewall.pdb') -Destination $runPath
if($LanguagePath) { Copy-Item -LiteralPath $LanguagePath -Destination (Join-Path $runPath 'simplewall.lng') }
$enabled=if($UdpDisabled){'false'}else{'true'}
$settings="[simplewall]`r`nLanguage=Spanish`r`nIsNetworkMonitorEnabled=true`r`nIsUdpTrafficEnabled=$enabled`r`nCheckUpdatesPeriod=0`r`nIsStartMinimized=false`r`nCurrentTab=112`r`n"
[IO.File]::WriteAllText((Join-Path $runPath 'simplewall.ini'),$settings)
Write-Host "Isolated startup report: $runPath"
$probe=Start-Process -FilePath (Join-Path $runPath 'simplewall.exe') -WorkingDirectory $runPath -Verb RunAs -WindowStyle Hidden -PassThru
if(!$probe.WaitForExit(60000)) { throw "Startup probe timed out (PID $($probe.Id))" }
$probe.Refresh()
$report=Join-Path $runPath 'startup-report.txt'
Get-Content -LiteralPath $report
if($probe.ExitCode -ne 0 -or !(Select-String -LiteralPath $report -SimpleMatch 'STARTUP_RESULT: 0 failures' -Quiet)) { throw 'Startup probe failed' }
