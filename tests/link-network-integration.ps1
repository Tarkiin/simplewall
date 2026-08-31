$ErrorActionPreference = 'Stop'
$objects = Get-ChildItem -LiteralPath temp/public-sdk-obj -Filter *.obj | Where-Object Name -notin @('network.obj','udpstats.obj','rapp.obj')
$arguments = @('/NOLOGO','/SUBSYSTEM:CONSOLE','/ENTRY:mainCRTStartup','/OUT:temp/network-integration.exe','/INCREMENTAL:NO','/OPT:REF','/LTCG','temp/network-integration.obj')
$arguments += $objects.FullName | ForEach-Object { '"' + $_ + '"' }
$arguments += 'temp/network-integration-rapp.obj'
$arguments += @('/MANIFEST:EMBED','/MANIFESTINPUT:tests/network-integration.manifest')
$arguments += @('kernel32.lib','user32.lib','gdi32.lib','comdlg32.lib','advapi32.lib','shell32.lib','ole32.lib','oleaut32.lib','uuid.lib','windowsapp.lib')
[IO.File]::WriteAllLines((Join-Path $PWD 'temp/network-integration.rsp'), $arguments)
& link.exe '@temp/network-integration.rsp'
if ($LASTEXITCODE) { throw 'Integration test link failed' }
