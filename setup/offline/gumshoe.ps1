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
if (-not (Start-Ollama)) { Write-Host "Cannot continue without Ollama. See $Dest\first-run.log" -ForegroundColor Red; exit 1 }
$models = Get-OllamaModels; Write-Host ("  models: " + ($models -join ", "))

Write-Step "WSL distro $WslName"
if (-not (Test-WslDistro $WslName)) { Write-Host "distro $WslName is missing; delete $installed and double-click Gumshoe.bat to reinstall" -ForegroundColor Red; exit 1 }
& wsl.exe -d $WslName -u root -- test -f /opt/dfir/.provisioned
if ($LASTEXITCODE -ne 0) { Write-Host "distro is not provisioned; delete $installed and double-click Gumshoe.bat to reinstall" -ForegroundColor Red; exit 1 }
# can the distro reach Ollama? mirrored networking -> 127.0.0.1; NAT -> the Windows host address
[void](Ensure-OllamaFromWsl $WslName)

if ($Selftest) {
  Write-Step "self-test"
  & wsl.exe -d $WslName -u root -- bash /opt/dfir/gumshoe/setup/wsl/03_verify_offline.sh
  exit $LASTEXITCODE
}

Write-Step "Gumshoe UI"
if (Test-Port $Port) { Write-Ok "UI already running on $Port" }
else {
  Start-Process -FilePath "wsl.exe" -ArgumentList @("-d", $WslName, "-u", "root", "--", "gumshoe", "ui", "--cases-root", "/opt/dfir/cases", "--port", "$Port") -WindowStyle Minimized
  if (-not (Wait-Port $Port 90 "the UI")) { Write-Host "the UI did not come up on port $Port; run Gumshoe-Selftest.bat" -ForegroundColor Red; exit 1 }
  Write-Ok "UI listening on $Port"
}
Start-Process "http://localhost:$Port"
Write-Host ""
Write-Host "Gumshoe is running at http://localhost:$Port  (keep the minimized wsl window open)." -ForegroundColor Green
Write-Host "Evidence images go under C:\DFIR\evidence (or any folder); mount with  wsl -d $WslName -u root -- mount_image <image>   (see docs\RUNBOOK.md)."
