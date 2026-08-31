@echo off
setlocal
call "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 exit /b 1
cd /d "%~dp0.."
if not exist temp\public-sdk-tests mkdir temp\public-sdk-tests
pwsh -NoProfile -File tools\public-sdk\prepare.ps1
if errorlevel 1 exit /b 1
set "compatTestOptions=/O2"
if /I "%~1"=="--asan" set "compatTestOptions=/Od /Zi /fsanitize=address /Fdtemp\public-sdk-tests\compat-test.pdb"
rem Match the application's compiler mode and warning level for the old SDK.
cl /nologo /W3 /WX %compatTestOptions% /Gy /MT /std:clatest /Zc:preprocessor /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /DAPP_NO_APPDATA /DAPP_HAVE_UPDATES /Itests\public-sdk /Itemp\public-sdk-source\src /Isrc tests\public_sdk_test.c temp\public-sdk-source\src\routine.c temp\public-sdk-source\src\rapp.c /Fetemp\public-sdk-tests\compat_test.exe /Fotemp\public-sdk-tests\ /link /INCREMENTAL:NO /OPT:REF user32.lib gdi32.lib shell32.lib advapi32.lib ole32.lib oleaut32.lib comdlg32.lib uuid.lib ntdll.lib
if errorlevel 1 exit /b 1
temp\public-sdk-tests\compat_test.exe
