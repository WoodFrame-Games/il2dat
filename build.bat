@echo off
rem ---------------------------------------------------------------------------
rem  HypperDump - one-shot MinGW/ucrt64 build (static exe + unicorn.dll)
rem ---------------------------------------------------------------------------
setlocal
cd /d "%~dp0"

where g++ >nul 2>nul
if errorlevel 1 (
  echo [build] g++ not found in PATH. Install MSYS2 ucrt64 toolchain.
  exit /b 1
)

if not exist dist mkdir dist

echo [build] compiling...
g++ -O2 -std=c++17 -static -static-libgcc -static-libstdc++ ^
    -Isrc -Ithird_party\unicorn\include ^
    src\main.cpp src\elf.cpp src\emulator.cpp src\metadata.cpp src\codereg.cpp src\zip.cpp ^
    third_party\unicorn\unicorn.dll -lz -o dist\hypperdump.exe
if errorlevel 1 (
  echo [build] FAILED
  exit /b 1
)

copy /y third_party\unicorn\unicorn.dll dist\ >nul
echo [build] OK -^> dist\hypperdump.exe
endlocal