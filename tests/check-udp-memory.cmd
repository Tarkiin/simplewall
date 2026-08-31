@echo off
setlocal
call "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 exit /b 1
cd /d "%~dp0.."
if not exist temp mkdir temp
cl /nologo /W4 /WX /Od /Zi /MT /fsanitize=address /std:c17 /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN tests\udpstats_test.c /Fetemp\udpstats_asan.exe /Fotemp\udpstats_asan.obj /Fdtemp\udpstats_asan.pdb /link /INCREMENTAL:NO
if errorlevel 1 exit /b 1
temp\udpstats_asan.exe
