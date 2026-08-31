@echo off
setlocal
call "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 exit /b 1
cd /d "%~dp0.."
if not exist temp mkdir temp
cl /nologo /W4 /WX /analyze /c /std:c17 /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN src\udpstats.c /Fotemp\udpstats-analyze.obj
if errorlevel 1 exit /b 1
cl /nologo /W4 /WX /O2 /MT /std:c17 /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN tests\udpstats_test.c /Fetemp\udpstats_test.exe /Fotemp\udpstats_test.obj /link /INCREMENTAL:NO
