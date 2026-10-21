@echo off
rem Move Gumshoe's data (the DFIR distro, the Ollama models, the hopper) to another drive when C: is full.
rem Close the Gumshoe UI window first.
setlocal
set "B=%~dp0"
set "B=%B:~0,-1%"
title Gumshoe - move to another drive
powershell -NoProfile -ExecutionPolicy Bypass -File "%B%\gumshoe\setup\offline\move_to_drive.ps1"
echo.
pause
