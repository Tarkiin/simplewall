$ErrorActionPreference='Stop'
$source=[IO.File]::ReadAllText((Join-Path $PWD 'src/wfp.c'))
$engine='(?ms)^HANDLE _wfp_getenginehandle \(\)\r?\n\{.*?^\}'
$firewall='(?ms)^VOID _wfp_firewallenable \(.*?^\}'
if ([regex]::Matches($source,$engine).Count -ne 1 -or [regex]::Matches($source,$firewall).Count -ne 1) { throw 'WFP test substitutions do not match source' }
$source=[regex]::Replace($source,$engine,"HANDLE _wfp_getenginehandle ()`r`n{ return NULL; }")
$source=[regex]::Replace($source,$firewall,"VOID _wfp_firewallenable (BOOLEAN enabled)`r`n{ UNREFERENCED_PARAMETER(enabled); }")
if ($source.Contains('FwpmEngineOpen0 (') -or $source.Contains('INetFwPolicy2_put_FirewallEnabled')) { throw 'WFP write boundary still reachable in test object' }
New-Item -ItemType Directory -Path temp/startup-probe -Force | Out-Null
[IO.File]::WriteAllText((Join-Path $PWD 'temp/startup-probe/wfp-probe.c'),$source)
$objects=Get-ChildItem temp/public-sdk-obj -Filter *.obj | Where-Object Name -ne 'wfp.obj'
$arguments=@('/NOLOGO','/SUBSYSTEM:CONSOLE','/ENTRY:mainCRTStartup','/OUT:temp/startup-probe/simplewall.exe','/DEBUG','/PDB:temp/startup-probe/simplewall.pdb','/INCREMENTAL:NO','/OPT:REF','/LTCG','temp/startup-probe/startup_probe.obj','temp/startup-probe/wfp-probe.obj','temp/public-sdk-obj/resource.res','/MANIFEST:NO')
$arguments+=$objects.FullName | ForEach-Object { '"'+$_+'"' }
$arguments+=@('kernel32.lib','user32.lib','gdi32.lib','comdlg32.lib','advapi32.lib','shell32.lib','ole32.lib','oleaut32.lib','uuid.lib','windowsapp.lib')
[IO.File]::WriteAllLines((Join-Path $PWD 'temp/startup-probe/link.rsp'),$arguments)
