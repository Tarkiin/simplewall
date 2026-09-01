@echo off
setlocal
call "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 exit /b 1
cd /d "%~dp0.."
pwsh -NoProfile -File tests\prepare-startup-probe.ps1
if errorlevel 1 exit /b 1
cl /nologo /W3 /WX /Zi /O2 /Gy /MT /std:clatest /Zc:preprocessor /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /DSECURITY_WIN32 /DAPP_NO_GUEST /DAPP_HAVE_AUTORUN /DAPP_HAVE_SKIPUAC /DAPP_HAVE_TRAY /DAPP_HAVE_SETTINGS /DAPP_HAVE_UPDATES /FI"%CD%\tools\public-sdk\routine-compat.h" /Itemp\public-sdk-source\src /Isrc /c tests\startup_probe.c temp\startup-probe\wfp-probe.c /Fotemp\startup-probe\ /Fdtemp\startup-probe\probe-objects.pdb
if errorlevel 1 exit /b 1
link @temp\startup-probe\link.rsp
