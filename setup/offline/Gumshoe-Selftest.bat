@echo off
rem Re-runs the installation checks: tools, Python env, Ollama + models, no-network check, Gumshoe self-test.
setlocal
set "B=%~dp0"
set "B=%B:~0,-1%"
title Gumshoe self-test
powershell -NoProfile -ExecutionPolicy Bypass -File "%B%\gumshoe\setup\offline\gumshoe.ps1" -Bundle "%B%" -Selftest
echo.
pause
