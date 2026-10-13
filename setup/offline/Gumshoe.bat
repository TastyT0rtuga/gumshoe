@echo off
rem Gumshoe - double-click to start. First run installs everything from this folder (offline);
rem every run after that just starts the local model server and opens the UI in your browser.
setlocal
set "B=%~dp0"
set "B=%B:~0,-1%"
title Gumshoe
powershell -NoProfile -ExecutionPolicy Bypass -File "%B%\gumshoe\setup\offline\gumshoe.ps1" -Bundle "%B%"
echo.
pause
