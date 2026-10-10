<#
.SYNOPSIS
  Install the bundle on the AIR-GAPPED Windows 11 sandbox. No network is used.

.DESCRIPTION
  1. verifies the bundle hashes
  2. installs Ollama silently and copies the model store; sets OLLAMA_HOST so WSL can reach it
  3. installs Arsenal Image Mounter if its installer is present
  4. installs WSL from the MSI (if needed), writes .wslconfig (memory cap, P-cores, mirrored networking)
     and imports the pre-provisioned distro
  5. copies the Gumshoe project to <Dest>\gumshoe and writes a P-core-pinned Ollama launcher
  Then: open the distro (`wsl -d DFIR`) and run  bash /mnt/c/DFIR/gumshoe/setup/wsl/02_install_offline.sh

  Run as Administrator:  powershell -ExecutionPolicy Bypass -File D:\gumshoe-transfer\gumshoe\setup\windows\02_install_offline.ps1 -Bundle D:\gumshoe-transfer
#>
param(
  [Parameter(Mandatory = $true)][string]$Bundle,
  [string]$Dest = "C:\DFIR",
  [string]$WslName = "DFIR",
  [int]$WslMemoryGB = 5,
  [int]$WslProcessors = 8,
  [switch]$SkipHashCheck
)
$ErrorActionPreference = "Stop"
function Step($name, [scriptblock]$body) {
  Write-Host "`n=== $name ===" -ForegroundColor Cyan
  try { & $body; Write-Host "ok: $name" -ForegroundColor Green }
  catch { Write-Host "FAILED: $name -> $($_.Exception.Message)" -ForegroundColor Red }
}

if (-not $SkipHashCheck) {
  Step "Verify bundle hashes" { & (Join-Path $Bundle "gumshoe\setup\windows\hash_bundle.ps1") -Path $Bundle -Verify }
}

Step "Copy Gumshoe project to $Dest\gumshoe" {
  New-Item -ItemType Directory -Force -Path $Dest | Out-Null
  robocopy (Join-Path $Bundle "gumshoe") (Join-Path $Dest "gumshoe") /E | Out-Null
}

Step "Install Ollama and copy the model store" {
  $setup = Join-Path $Bundle "ollama\OllamaSetup.exe"
  if (Test-Path $setup) { Start-Process -Wait -FilePath $setup -ArgumentList "/VERYSILENT", "/NORESTART" }
  Get-Process ollama* -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  $store = Join-Path $env:USERPROFILE ".ollama\models"
  New-Item -ItemType Directory -Force -Path $store | Out-Null
  robocopy (Join-Path $Bundle "models") $store /E | Out-Null
  # reachable from WSL even without mirrored networking; keep models loaded between questions
  [Environment]::SetEnvironmentVariable("OLLAMA_HOST", "0.0.0.0:11434", "User")
  [Environment]::SetEnvironmentVariable("OLLAMA_KEEP_ALIVE", "30m", "User")
  [Environment]::SetEnvironmentVariable("OLLAMA_MAX_LOADED_MODELS", "1", "User")
  # P-core pinned launcher (i7-12700: logical processors 0-15 are the 8 P-cores with HT)
  $launcher = Join-Path $Dest "ollama-pcores.cmd"
  @"
@echo off
set OLLAMA_HOST=0.0.0.0:11434
set OLLAMA_KEEP_ALIVE=30m
set OLLAMA_MAX_LOADED_MODELS=1
start "ollama" /affinity FFFF "%LOCALAPPDATA%\Programs\Ollama\ollama.exe" serve
"@ | Set-Content -Path $launcher -Encoding ASCII
  Write-Host "  start Ollama with $launcher (pins to P-cores)."
}

Step "Arsenal Image Mounter" {
  $inst = Get-ChildItem (Join-Path $Bundle "tools\arsenal") -Filter *.exe -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($inst) { Start-Process -Wait -FilePath $inst.FullName } else { Write-Host "  no installer in tools\arsenal; install it by hand" -ForegroundColor Yellow }
}

Step "WSL: install MSI if needed, write .wslconfig, import distro" {
  if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    Start-Process -Wait msiexec.exe -ArgumentList "/i", (Join-Path $Bundle "wsl\wsl.msi"), "/quiet", "/norestart"
  }
  $cfg = Join-Path $env:USERPROFILE ".wslconfig"
  @"
[wsl2]
memory=${WslMemoryGB}GB
processors=$WslProcessors
swap=4GB
networkingMode=mirrored
"@ | Set-Content -Path $cfg -Encoding ASCII
  $tar = Join-Path $Bundle "wsl\dfir-ubuntu.tar"
  $have = (wsl -l -q 2>$null) -join "`n"
  if ($have -notmatch "^$WslName$") {
    New-Item -ItemType Directory -Force -Path (Join-Path $Dest "wsl\$WslName") | Out-Null
    wsl --import $WslName (Join-Path $Dest "wsl\$WslName") $tar --version 2
  }
  wsl --set-default $WslName
  Write-Host "  distro '$WslName' ready. Next: wsl -d $WslName   then   bash /mnt/c/DFIR/gumshoe/setup/wsl/02_install_offline.sh -b /mnt/<drive>/gumshoe-transfer"
}

Write-Host "`nWindows side done. Reboot if WSL was just installed." -ForegroundColor Green
