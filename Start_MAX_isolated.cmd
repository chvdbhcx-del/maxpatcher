@echo off
rem Starts max.exe from this folder in a Windows AppContainer (no access to user files).
rem Diagnostic log: launch.log in this folder.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Launch-MAX-Isolated.ps1" -FromCmd %*
echo.
echo Log: %~dp0launch.log
pause
