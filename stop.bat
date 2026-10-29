@echo off
setlocal EnableExtensions
title Stop Cyber Range

echo ================================================================
echo      STOPPING CYBER RANGE PLATFORM
echo ================================================================
echo.
echo This script stops listeners on ports 8000 and 3000.
echo IMPORTANT: if another unrelated app uses either port, it will also
echo be stopped. Close the two Cyber Range server windows first if unsure.
echo.
choice /M "Continue"
if errorlevel 2 exit /b 0

cd /d "%~dp0"

echo.
echo [1/3] Stopping Docker Compose services (if Docker is available)...
docker info >nul 2>&1
if not errorlevel 1 (
    docker compose down
    if errorlevel 1 echo [WARNING] docker compose down reported an error.
) else (
    echo [INFO] Docker is not running; skipping Docker Compose shutdown.
)

echo.
echo [2/3] Checking port 8000...
call :stop_port 8000

echo.
echo [3/3] Checking port 3000...
call :stop_port 3000

echo.
echo Shutdown attempt complete.
echo If a server terminal remains open, inspect its output and close it manually.
echo.
pause
exit /b 0

:stop_port
set "PORT=%~1"
for /f "tokens=5" %%P in ('netstat -aon ^| findstr /R /C:":%PORT% .*LISTENING"') do (
    if not "%%P"=="0" (
        echo Stopping PID %%P listening on port %PORT%...
        taskkill /PID %%P /T /F
    )
)
exit /b 0
