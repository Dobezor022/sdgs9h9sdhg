@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Prepare-Go-Dependencies.ps1" -ProjectRoot "C:\Users\STUDIO-PC\Pictures\androidconsole"
exit /b %ERRORLEVEL%
