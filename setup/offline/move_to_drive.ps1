<#
  Move Gumshoe's data off a full C: drive, in one go:
    - the DFIR distro (WSL virtual disk: cases, tools, extracted images)  ->  <Drive>:\DFIR\wsl
    - the Ollama model store (about 8 GB)                                  ->  <Drive>:\DFIR\ollama\models
    - new hopper / work / exports folders                                   ->  <Drive>:\DFIR\{hopper,work,exports}
  Close Gumshoe first (the UI window). Run from Gumshoe-MoveToDrive.bat. Needs WSL 2.1 or newer (the
  bundle installs 3.x). Nothing is deleted on failure: WSL moves the disk with its own command, robocopy
  moves the models only after a complete copy.
#>
param([string]$Drive = "", [string]$WslName = "DFIR")
. (Join-Path $PSScriptRoot "common.ps1")
if (-not $Drive) { $Drive = Read-Host "Drive letter to move Gumshoe's data to (for example D)" }
$Drive = $Drive.Trim().TrimEnd(':', '\').ToUpper()
if ($Drive -notmatch '^[A-Z]$' -or -not (Test-Path "${Drive}:\")) { Write-Host "no such drive: $Drive" -ForegroundColor Red; Pause-IfConsole; exit 1 }
$Dest = "${Drive}:\DFIR"
$free = [math]::Round((Get-PSDrive -Name $Drive).Free / 1GB)
Write-Host "Destination $Dest ($free GB free on ${Drive}:)"
New-Item -ItemType Directory -Force -Path "$Dest\wsl", "$Dest\hopper", "$Dest\work", "$Dest\exports", "$Dest\ollama" | Out-Null

Write-Step "WSL distro $WslName -> $Dest\wsl"
if (-not (Test-WslDistro $WslName)) { Write-Host "distro $WslName not found; nothing to move" -ForegroundColor Red; Pause-IfConsole; exit 1 }
& wsl.exe --shutdown
$loc = ""
try { $loc = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss\*" -ErrorAction SilentlyContinue | Where-Object { $_.DistributionName -eq $WslName } | Select-Object -First 1).BasePath } catch { }
if ($loc -and ($loc.TrimEnd('\') -ieq "$Dest\wsl")) { Write-Ok "already at $Dest\wsl" }
else {
  Write-Host "  (current location: $loc) moving - this copies the whole virtual disk, allow a few minutes"
  & wsl.exe --manage $WslName --move "$Dest\wsl"
  if ($LASTEXITCODE -ne 0) {
    Write-Host "wsl --manage --move failed (exit $LASTEXITCODE). Check 'wsl --version' is 2.1 or newer and that nothing holds the distro open." -ForegroundColor Red
    Pause-IfConsole; exit 1
  }
  Write-Ok "distro now at $Dest\wsl"
}

Write-Step "Ollama models -> $Dest\ollama\models"
$src = Get-OllamaModelsDir
$dst = "$Dest\ollama\models"
if ((Test-Path $src) -and ((Resolve-Path $src).Path.TrimEnd('\') -ine $dst)) {
  Get-Process -Name "ollama*" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep 2
  & robocopy.exe $src $dst /E /MOVE /R:1 /W:1 /NFL /NDL /NJH /NJS /NP | Out-Null
  if ($LASTEXITCODE -ge 8) { Write-Host "robocopy reported errors (exit $LASTEXITCODE); the models may be split between $src and $dst" -ForegroundColor Red; Pause-IfConsole; exit 1 }
  [Environment]::SetEnvironmentVariable("OLLAMA_MODELS", $dst, "User")
  $env:OLLAMA_MODELS = $dst
  Write-Ok "models at $dst; OLLAMA_MODELS set for your account (Gumshoe.bat starts Ollama with it)"
} else { Write-Ok "models already at $dst" }

Write-Step "folders"
& wsl.exe -d $WslName -u root -- python3 /opt/dfir/gumshoe/gumshoe.py --cases-root /opt/dfir/cases settings --hopper "$Dest\hopper" --work "" --exports "$Dest\exports" | Out-Null
if ($LASTEXITCODE -eq 0) { Write-Ok "hopper $Dest\hopper, exports $Dest\exports; extracted images stay inside the distro (now on ${Drive}:)" }
else { Write-Warn2 "could not write the settings inside the distro; set the folders in the UI (Hopper -> Folders)" }
Write-Host ""
Write-Host "Done. Double-click Gumshoe.bat. Drop evidence into $Dest\hopper from now on." -ForegroundColor Green
Pause-IfConsole
