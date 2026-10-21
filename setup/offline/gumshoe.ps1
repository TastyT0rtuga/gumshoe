<#
  Gumshoe launcher (what Gumshoe.bat runs). Not elevated.
  First time: hands off to first_run.ps1 with administrator rights. After that: starts Ollama, starts the
  Gumshoe UI inside the DFIR distro and opens the browser. No network is used.
#>
param([Parameter(Mandatory = $true)][string]$Bundle, [string]$Dest = "C:\DFIR", [string]$WslName = "DFIR", [int]$Port = 8501, [switch]$Selftest)
. (Join-Path $PSScriptRoot "common.ps1")
$Bundle = [IO.Path]::GetFullPath($Bundle).TrimEnd('\')
$installed = Join-Path $Dest ".installed"

if (-not (Test-Path $installed)) {
  Write-Host "First run: Gumshoe is not installed on this machine yet." -ForegroundColor White
  Write-Host "Installing Ollama + models, WSL and the forensic distro from the bundle (offline). Windows will ask for administrator rights."
  if (Test-Path (Join-Path $Dest ".reboot-needed")) { Write-Host "(continuing after the reboot)" }
  $fr = Join-Path $PSScriptRoot "first_run.ps1"
  try {
    $p = Start-Process -ErrorAction Stop -FilePath "powershell.exe" -Verb RunAs -PassThru -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$fr`"", "-Bundle", "`"$Bundle`"", "-Dest", "`"$Dest`"", "-WslName", $WslName)
    # not -Wait: it would also wait for the `ollama serve` process the installer leaves running
    $p.WaitForExit()
  } catch { Write-Host "Administrator approval was declined; nothing was installed." -ForegroundColor Red; exit 1 }
  if (-not (Test-Path $installed)) {
    if (Test-Path (Join-Path $Dest ".reboot-needed")) { Write-Host "`nReboot now, then double-click Gumshoe.bat again." -ForegroundColor Yellow }
    else { Write-Host "`nSetup did not finish; see $Dest\first-run.log" -ForegroundColor Red }
    exit 1
  }
}

Write-Step "Ollama"
$OllamaPort = Start-OllamaForGumshoe $Bundle
if ($OllamaPort -eq 0) { Write-Host "Cannot continue without an Ollama that has the bundled models. See $Dest\first-run.log" -ForegroundColor Red; exit 1 }
Write-Host ("  models on port ${OllamaPort}: " + ((Get-OllamaModels $OllamaPort) -join ", "))

Write-Step "WSL distro $WslName"
if (-not (Test-WslDistro $WslName)) { Write-Host "distro $WslName is missing; delete $installed and double-click Gumshoe.bat to reinstall" -ForegroundColor Red; exit 1 }
& wsl.exe -d $WslName -u root -- test -f /opt/dfir/.provisioned
if ($LASTEXITCODE -ne 0) { Write-Host "distro is not provisioned; delete $installed and double-click Gumshoe.bat to reinstall" -ForegroundColor Red; exit 1 }
# keep the distro's copy of Gumshoe current with the bundle (so updating = replacing the folder); the
# distro keeps its own cases, unpacked tools and config.yaml
$bwsl = ConvertTo-WslPath $WslName $Bundle
$changed = @(& wsl.exe -d $WslName -u root -- rsync -a --delete --itemize-changes --exclude cases --exclude tools --exclude config.yaml --exclude __pycache__ --exclude .git "$bwsl/gumshoe/" /opt/dfir/gumshoe/ 2>$null | Where-Object { $_ -match '^[<>ch*]' })
if ($LASTEXITCODE -ne 0) { Write-Warn2 "could not sync the project from the bundle (rsync $LASTEXITCODE)" }
elseif ($changed.Count -gt 0) { Write-Ok "project in the distro updated from the bundle ($($changed.Count) files); the UI will be restarted" }
else { Write-Ok "project in the distro matches the bundle" }
# a script copied through Windows may have picked up CRLF line endings; bash cannot run those
& wsl.exe -d $WslName -u root -- sh -c "sed -i 's/\r\$//' /opt/dfir/gumshoe/setup/wsl/*.sh /opt/dfir/gumshoe/setup/offline/*.sh /opt/dfir/gumshoe/gumshoe.py 2>/dev/null; chmod +x /opt/dfir/gumshoe/setup/wsl/*.sh /opt/dfir/gumshoe/setup/offline/*.sh"
# packages an updated bundle adds (debs folder) and the hopper folders
& wsl.exe -d $WslName -u root -- bash /opt/dfir/gumshoe/setup/offline/wsl_update.sh "$bwsl"
if (-not (Test-Path "C:\DFIR\hopper")) { New-Item -ItemType Directory -Force -Path "C:\DFIR\hopper" | Out-Null }
# can the distro reach Ollama? mirrored networking -> 127.0.0.1; NAT -> the Windows host address
[void](Ensure-OllamaFromWsl $WslName $OllamaPort)

if ($Selftest) {
  Write-Step "self-test"
  & wsl.exe -d $WslName -u root -- bash /opt/dfir/gumshoe/setup/wsl/03_verify_offline.sh
  exit $LASTEXITCODE
}

Write-Step "Gumshoe UI"
if ((Test-Port $Port) -and $changed.Count -gt 0) {
  & wsl.exe -d $WslName -u root -- pkill -f "streamlit run" 2>$null; Start-Sleep 2
}
if (Test-Port $Port) { Write-Ok "UI already running on $Port" }
else {
  # a UI left over from an earlier start that Windows cannot reach (wrong bind address) is restarted
  & wsl.exe -d $WslName -u root -- curl -s -m 2 -o /dev/null "http://127.0.0.1:$Port/"
  if ($LASTEXITCODE -eq 0) {
    Write-Warn2 "a UI is listening inside the distro but Windows cannot reach it; restarting it"
    & wsl.exe -d $WslName -u root -- pkill -f "streamlit run" 2>$null; Start-Sleep 2
  }
  Start-Process -FilePath "wsl.exe" -ArgumentList @("-d", $WslName, "-u", "root", "--", "gumshoe", "ui", "--cases-root", "/opt/dfir/cases", "--port", "$Port") -WindowStyle Minimized
  if (-not (Wait-Port $Port 120 "the UI")) {
    Write-Host "the UI did not come up on port $Port. The minimized wsl window shows why; Gumshoe-Selftest.bat checks the rest." -ForegroundColor Red
    Write-Host "(If that window says it is listening, Windows cannot reach the distro's port: run  wsl --shutdown  and double-click Gumshoe.bat again.)"
    exit 1
  }
  Write-Ok "UI listening on $Port"
}
Start-Process "http://localhost:$Port"
Write-Host ""
Write-Host "Gumshoe is running at http://localhost:$Port  (keep the minimized wsl window open)." -ForegroundColor Green
Write-Host "Drop evidence (E01, raw/img, vhdx, zip/7z of an image, or a folder) into C:\DFIR\hopper and press Intake in the Run tab."
