# Reliable PowerShell entry point. Keep this file beside run.bat.
$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RunScript = Join-Path $ScriptDir 'run.bat'

if (-not (Test-Path $RunScript)) {
    Write-Host "[ERROR] run.bat was not found beside start.ps1." -ForegroundColor Red
    Write-Host "Put the launcher files in the project root, beside app_server.py."
    Read-Host "Press Enter to exit"
    exit 1
}

Set-Location $ScriptDir
# Run in this PowerShell console so setup errors remain visible.
& $RunScript
if ($LASTEXITCODE -ne 0) {
    Write-Host "Launcher exited with code $LASTEXITCODE" -ForegroundColor Red
}
