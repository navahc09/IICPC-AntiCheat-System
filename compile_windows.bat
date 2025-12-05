@echo off
if not exist "bin\windows" mkdir "bin\windows"
echo Compiling for Windows...
g++ -o bin\windows\main.exe src\common\*.cpp src\windows\*.cpp -I include -lws2_32 -liphlpapi -lwtsapi32 -luser32 -lgdi32 -static
if %errorlevel% neq 0 (
    echo Compilation Failed!
    exit /b %errorlevel%
)
echo Compilation Successful! Output: bin\windows\main.exe
