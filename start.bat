@echo off
setlocal
cd /d "%~dp0"
if not exist "%~dp0run.bat" (
    echo [ERROR] run.bat was not found beside start.bat.
    echo Put start.bat and run.bat in the project root, beside app_server.py.
    pause
    exit /b 1
)
call "%~dp0run.bat"
