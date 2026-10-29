```bat
@echo off
setlocal EnableExtensions
title Cyber Range Launcher

set "ROOT=%~dp0"
cd /d "%ROOT%" || goto :fatal

if not exist "logs" mkdir "logs" >nul 2>&1
set "LOG=%ROOT%logs\launcher.log"

> "%LOG%" echo Launcher started: %DATE% %TIME%
>>"%LOG%" echo Project: %ROOT%

echo.
echo ==========================================
echo   CYBER RANGE - STARTUP
echo ==========================================
echo Project: %ROOT%
echo.

REM Check required files
echo [1/5] Checking project files...
if not exist "%ROOT%app_server.py" (
    echo ERROR: app_server.py not found.
    goto :fatal
)
if not exist "%ROOT%web\package.json" (
    echo ERROR: web\package.json not found.
    goto :fatal
)
>>"%LOG%" echo STEP 1 OK: Project files found

REM Check Python
echo.
echo [2/5] Checking Python...
python --version
if errorlevel 1 goto :fatal
>>"%LOG%" echo STEP 2 OK: Python available

REM Check Node and npm
echo.
echo [3/5] Checking Node.js and npm...
node --version
if errorlevel 1 goto :fatal

call npm --version
if errorlevel 1 goto :fatal
>>"%LOG%" echo STEP 3 OK: Node and npm available

REM Check frontend dependencies without installing
echo.
echo [4/5] Checking frontend dependencies...
if not exist "%ROOT%web\node_modules\vite\bin\vite.js" (
    echo ERROR: Frontend dependencies are missing.
    echo Open another terminal and run:
    echo cd /d "%ROOT%web"
    echo npm install
    >>"%LOG%" echo ERROR: Vite dependency missing
    goto :fatal
)
>>"%LOG%" echo STEP 4 OK: Frontend dependencies found

REM Launch backend
echo.
echo [5/5] Starting backend...
start "Cyber Range Backend" /D "%ROOT%" cmd.exe /k python -u app_server.py
if errorlevel 1 (
    echo ERROR: Could not launch backend terminal.
    >>"%LOG%" echo ERROR: Backend terminal launch failed
    goto :fatal
)
>>"%LOG%" echo Backend launch command issued

REM Launch frontend
echo Starting frontend...
start "Cyber Range Frontend" /D "%ROOT%web" cmd.exe /k npm run dev -- --host 127.0.0.1
if errorlevel 1 (
    echo ERROR: Could not launch frontend terminal.
    >>"%LOG%" echo ERROR: Frontend terminal launch failed
    goto :fatal
)
>>"%LOG%" echo Frontend launch command issued

echo.
echo ==========================================
echo Startup commands issued.
echo ==========================================
echo.
echo Dashboard: http://127.0.0.1:3000
echo Backend:   http://127.0.0.1:8000
echo API docs:  http://127.0.0.1:8000/docs
echo.
echo If the dashboard does not load, inspect both
echo service windows and logs\launcher.log.
>>"%LOG%" echo Launcher completed: %DATE% %TIME%
pause
exit /b 0

:fatal
echo.
echo ==========================================
echo STARTUP FAILED
echo ==========================================
echo Check the error above.
echo Log: "%LOG%"
>>"%LOG%" echo STARTUP FAILED: %DATE% %TIME%
echo.
pause
exit /b 1
```