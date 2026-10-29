```bat
@echo off
setlocal
cd /d "%~dp0"
title Cyber Range Diagnostic

echo ====================================
echo CYBER RANGE STARTUP DIAGNOSTIC
echo ====================================
echo.

echo [TEST 1] Python executable
where python
echo Exit code: %errorlevel%
echo.

echo [TEST 2] Python version
python --version
echo Exit code: %errorlevel%
echo.

echo [TEST 3] Python pip
python -m pip --version
echo Exit code: %errorlevel%
echo.

echo [TEST 4] Project files
if exist "app_server.py" (echo app_server.py FOUND) else (echo app_server.py MISSING)
if exist "requirements.txt" (echo requirements.txt FOUND) else (echo requirements.txt MISSING)
if exist "web\package.json" (echo web\package.json FOUND) else (echo web\package.json MISSING)
echo.

echo [TEST 5] Node.js
where node
node --version
echo Exit code: %errorlevel%
echo.

echo [TEST 6] npm
where npm
call npm --version
echo Exit code: %errorlevel%
echo.

echo ====================================
echo DIAGNOSTIC FINISHED
echo ====================================
pause
```