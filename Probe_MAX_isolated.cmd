@echo off
rem Runs test commands inside the MAX AppContainer (Max itself is NOT started). Result: launch.log in this folder.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Launch-MAX-Isolated.ps1" -Probe -FromCmd
echo.
echo Log: %~dp0launch.log
pause
