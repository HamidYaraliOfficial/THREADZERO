@echo off
REM Double-click wrapper for install.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
pause
