@echo off
rem Gumshoe - rescue. Use it when Gumshoe.bat stops at "=== WSL distro DFIR" with a WSL error (User not found,
rem getpwnam failed, WSL_E_USER_NOT_FOUND) or the distro will not start. It finds the cause (usually a full
rem drive), repairs the distro's disk from a throwaway rescue distro, and copies your cases out if the disk
rem cannot be brought back. Nothing is deleted or reinstalled. Windows asks for administrator rights once.
setlocal
set "B=%~dp0"
set "B=%B:~0,-1%"
title Gumshoe - rescue
powershell -NoProfile -ExecutionPolicy Bypass -File "%B%\gumshoe\setup\offline\rescue.ps1" -Bundle "%B%"
echo.
echo The log is C:\DFIR\rescue.log
pause
