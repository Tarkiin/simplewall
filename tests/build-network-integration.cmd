@echo off
setlocal
call "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 exit /b 1
cd /d "%~dp0.."
if not exist temp\public-sdk-obj\messages.obj exit /b 1
cl /nologo /W3 /WX /O2 /Gy /MT /std:clatest /Zc:preprocessor /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /DSECURITY_WIN32 /DAPP_NO_GUEST /DAPP_HAVE_AUTORUN /DAPP_HAVE_SKIPUAC /DAPP_HAVE_TRAY /DAPP_HAVE_SETTINGS /DAPP_HAVE_UPDATES /FI"%CD%\tools\public-sdk\routine-compat.h" /Itemp\public-sdk-source\src /Isrc /c tests\network_integration_test.c /Fotemp\network-integration.obj
if errorlevel 1 exit /b 1
rem Isolated portable configuration for the menu callback test, never user settings.
cl /nologo /W3 /WX /O2 /Gy /MT /std:clatest /Zc:preprocessor /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /DAPP_NO_APPDATA /DAPP_NO_GUEST /DAPP_HAVE_AUTORUN /DAPP_HAVE_SKIPUAC /DAPP_HAVE_TRAY /DAPP_HAVE_SETTINGS /DAPP_HAVE_UPDATES /Itests\public-sdk /Itemp\public-sdk-source\src /Isrc /c temp\public-sdk-source\src\rapp.c /Fotemp\network-integration-rapp.obj
if errorlevel 1 exit /b 1
pwsh -NoProfile -File tests\link-network-integration.ps1
