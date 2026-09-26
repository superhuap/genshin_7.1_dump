@echo off
setlocal
cd /d %~dp0
set CFLAGS=/nologo /std:c++17 /O2 /EHsc /W3 /utf-8 /D_CRT_SECURE_NO_WARNINGS
if not exist build mkdir build

echo building dump.dll (x64) ...
cl %CFLAGS% /LD dumper\dllmain.cpp dumper\locate.cpp dumper\string.cpp dumper\meta.cpp dumper\output.cpp /Fe:build\dump.dll /link /MACHINE:X64 /out:build\dump.dll
if errorlevel 1 goto :err

echo.
echo done: build\dump.dll (x64)
echo mode : pure memory (reads no global-metadata.dat / startup-metadata.dat)
echo note : run from "x64 Native Tools Command Prompt for VS 20xx"
echo usage: inject with Xenos at game startup; console shows readiness + feature flags
goto :eof

:err
echo BUILD FAILED
exit /b 1
