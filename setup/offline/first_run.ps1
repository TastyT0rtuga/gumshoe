<#
.SYNOPSIS
  Gumshoe offline first-run installer for the AIR-GAPPED Windows 11 sandbox. Started by Gumshoe.bat
  with administrator rights the first time it is double-clicked. Nothing here touches the network.

.DESCRIPTION
  1. verifies the bundle (SHA-256 manifest, model blobs against their digests, installer signatures)
  2. installs Ollama silently and copies the bundled model store into the user's Ollama store
  3. installs WSL from the bundled MSI and enables Virtual Machine Platform if needed (then asks for ONE
     reboot; double-click Gumshoe.bat again afterwards and it carries on from here)
  4. writes .wslconfig, imports the bundled Ubuntu root filesystem as the "DFIR" distro
  5. provisions the distro offline (packages, Python env, UAC, Loki, Chainsaw, Sigma, Gumshoe)
  6. runs the verification script and writes C:\DFIR\.installed

  Safe to re-run: every step checks what is already done.
#>
param(
  [Parameter(Mandatory = $true)][string]$Bundle,
  [string]$Dest = "C:\DFIR",
  [string]$WslName = "DFIR",
  [int]$WslMemoryGB = 5,
  [int]$WslProcessors = 8,
  [switch]$SkipVerify
)
. (Join-Path $PSScriptRoot "common.ps1")
$Bundle = [IO.Path]::GetFullPath($Bundle).TrimEnd('\')
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
Start-Transcript -Path (Join-Path $Dest "first-run.log") -Append | Out-Null
$ok = $true
function Fail($msg) { Write-Host "FAILED: $msg" -ForegroundColor Red; $script:ok = $false }
function Leave([int]$code) {
  Stop-Transcript | Out-Null
  try { Copy-Item (Join-Path $Dest "first-run.log") (Join-Path $Bundle "first-run.log") -Force -ErrorAction SilentlyContinue } catch {}
  if ($code -ne 0) { Pause-IfConsole }
  exit $code
}

Write-Host "Gumshoe offline first run" -ForegroundColor White
Write-Host "  bundle : $Bundle"
Write-Host "  install: $Dest   distro: $WslName"
if ($Bundle -match '\s') { Fail "the bundle path contains a space. Move the Gumshoe-offline folder to a path without spaces (e.g. E:\Gumshoe-offline) and run again."; Leave 2 }
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Fail "administrator rights are required (Gumshoe.bat asks for them)"; Leave 2 }
foreach ($need in "ollama\OllamaSetup.exe", "wsl\wsl.msi", "wsl\rootfs.tar.gz", "models\blobs", "debs", "wheels\linux", "gumshoe\setup\offline\wsl_provision.sh") {
  if (-not (Test-Path (Join-Path $Bundle $need))) { Fail "bundle is incomplete: missing $need" }
}
if (-not $ok) { Leave 2 }

# ---- 1. verify ------------------------------------------------------------------------------------
if (-not $SkipVerify) {
  Write-Step "1/6 verifying the bundle (a few minutes; reads every file once)"
  $man = Join-Path $Bundle "SHA256SUMS.txt"; $n = 0; $bad = 0
  if (Test-Path $man) {
    foreach ($line in Get-Content $man) {
      if (-not $line.Trim() -or $line.StartsWith("#")) { continue }
      $h, $rel = $line -split "\s+", 2; $rel = $rel.Trim().TrimStart("*")
      $f = Join-Path $Bundle ($rel -replace '/', '\'); $n++
      if (-not (Test-Path $f)) { Write-Warn2 "missing  $rel"; $bad++; continue }
      if ((Get-FileHash -Algorithm SHA256 $f).Hash.ToLower() -ne $h.ToLower()) { Write-Warn2 "CHANGED  $rel"; $bad++ }
    }
    if ($bad -eq 0) { Write-Ok "$n manifest entries match" } else { Fail "$bad of $n manifest entries do not match" }
  } else { Write-Warn2 "no SHA256SUMS.txt in the bundle; skipping manifest check" }
  # model blobs are named after their own SHA-256
  $bn = 0; $bbad = 0
  foreach ($b in Get-ChildItem (Join-Path $Bundle "models\blobs") -File) {
    if ($b.Name -notmatch '^sha256-([0-9a-f]{64})$') { continue }
    $bn++; if ((Get-FileHash -Algorithm SHA256 $b.FullName).Hash.ToLower() -ne $Matches[1]) { Write-Warn2 "model blob corrupt: $($b.Name)"; $bbad++ }
  }
  if ($bbad -eq 0) { Write-Ok "$bn model blobs match their digests" } else { Fail "$bbad model blobs are corrupt; copy the bundle again" }
  # the two installers are Authenticode-signed; the chain is embedded so this works offline
  foreach ($inst in @(@{f = "ollama\OllamaSetup.exe"; who = "Ollama"}, @{f = "wsl\wsl.msi"; who = "Microsoft"})) {
    $sig = Get-AuthenticodeSignature (Join-Path $Bundle $inst.f)
    $subj = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "(unsigned)" }
    if ($sig.Status -eq "Valid" -and $subj -match $inst.who) { Write-Ok "$($inst.f) signed by $subj" }
    else { Write-Warn2 "$($inst.f): signature status $($sig.Status), signer $subj" }
  }
  if (-not $ok) { Write-Host "Verification failed; not installing. Re-copy the bundle from the hash-checked original." -ForegroundColor Red; Leave 3 }
}

# ---- 2. Ollama + models ---------------------------------------------------------------------------
Write-Step "2/6 Ollama and the model store"
$justInstalled = $false
if (-not (Get-OllamaExe)) {
  Write-Host "  installing Ollama silently..."
  # not -Wait: Windows PowerShell's -Wait also waits for every descendant, and the installer leaves the
  # Ollama tray app running, so -Wait would never return. WaitForExit() waits for the installer alone.
  $ip = Start-Process -PassThru -FilePath (Join-Path $Bundle "ollama\OllamaSetup.exe") -ArgumentList "/VERYSILENT", "/NORESTART", "/SUPPRESSMSGBOXES"
  $ip.WaitForExit()
  Start-Sleep 3
  if (-not (Get-OllamaExe)) { Fail "Ollama did not install (see ollama\OllamaSetup.exe /LOG)" } else { $justInstalled = $true }
}
else { Write-Ok "Ollama already installed" }
if ($justInstalled) {
  # the tray app the installer just started is ours to restart with the right settings; an Ollama that was
  # already on this machine before us is left alone (Start-OllamaForGumshoe works around it instead)
  Get-Process "ollama*" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  [Environment]::SetEnvironmentVariable("OLLAMA_HOST", "0.0.0.0:11434", "User")       # reachable from WSL in NAT mode too
  [Environment]::SetEnvironmentVariable("OLLAMA_KEEP_ALIVE", "30m", "User")
  [Environment]::SetEnvironmentVariable("OLLAMA_MAX_LOADED_MODELS", "1", "User")
}
$store = Get-OllamaModelsDir
Write-Host "  copying models to $store (about 8 GB; this is the slow part)..."
if (Copy-ModelStore $Bundle $store) { Write-Ok "model store copied" } else { Fail "robocopy of the model store failed ($LASTEXITCODE)" }
# air-gapped box: an inbound allow rule for WSL -> Ollama costs nothing and saves a NAT-mode headache
if (Get-NetFirewallRule -DisplayName "Gumshoe Ollama (WSL)" -ErrorAction SilentlyContinue) {
  Get-NetFirewallRule -DisplayName "Gumshoe Ollama (WSL)" | Set-NetFirewallRule -LocalPort 11434, 11435 -ErrorAction SilentlyContinue
} else {
  New-NetFirewallRule -DisplayName "Gumshoe Ollama (WSL)" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 11434, 11435 -Profile Any | Out-Null
}
$OllamaPort = Start-OllamaForGumshoe $Bundle
if ($OllamaPort -eq 0) { Fail "no Ollama with the bundled models could be started" }
else { Write-Ok ("models visible on port ${OllamaPort}: " + ((Get-OllamaModels $OllamaPort) -join ", ")) }

# ---- 3. WSL ----------------------------------------------------------------------------------------
Write-Step "3/6 WSL"
$needReboot = $false
$wslVer = 0
try { $v = (& wsl.exe --version 2>$null) -join "`n"; if ($LASTEXITCODE -eq 0 -and $v -match "WSL[^\d]*(\d+)\.(\d+)") { $wslVer = [int]$Matches[1] } } catch {}
if ($wslVer -ge 2) { Write-Ok "WSL $(($v -split "`n")[0].Trim()) present" }
else {
  Write-Host "  installing WSL from the bundled MSI..."
  $p = Start-Process -PassThru msiexec.exe -ArgumentList "/i", (Join-Path $Bundle "wsl\wsl.msi"), "/quiet", "/norestart"
  $p.WaitForExit()
  if ($p.ExitCode -notin 0, 3010, 1641) { Fail "wsl.msi returned $($p.ExitCode)" } else { Write-Ok "WSL installed (msiexec $($p.ExitCode))"; $needReboot = $true }
}
$vmp = Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -ErrorAction SilentlyContinue
if ($vmp -and $vmp.State -ne "Enabled") {
  Write-Host "  enabling the Virtual Machine Platform feature (offline; needs a reboot)..."
  $r = Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -All -NoRestart
  if ($r.RestartNeeded) { $needReboot = $true }
  Write-Ok "Virtual Machine Platform enabled"
} elseif ($vmp) { Write-Ok "Virtual Machine Platform already enabled" }
$cfg = Join-Path $env:USERPROFILE ".wslconfig"
if ((Test-Path $cfg) -and -not (Select-String -Path $cfg -Pattern "gumshoe" -Quiet)) {
  Copy-Item $cfg "$cfg.before-gumshoe" -Force
  Write-Warn2 "an existing .wslconfig was backed up to .wslconfig.before-gumshoe"
}
@"
# written by gumshoe first_run.ps1
[wsl2]
memory=${WslMemoryGB}GB
processors=$WslProcessors
swap=4GB
networkingMode=mirrored
"@ | Set-Content -Path $cfg -Encoding ASCII
Write-Ok ".wslconfig written (memory ${WslMemoryGB}GB, $WslProcessors processors, mirrored networking)"
if ($needReboot) {
  Set-Content -Path (Join-Path $Dest ".reboot-needed") -Value (Get-Date -Format s)
  Write-Host ""
  Write-Host "REBOOT NEEDED: WSL was just installed. Reboot, then double-click Gumshoe.bat again to continue." -ForegroundColor Yellow
  Leave 3
}
Remove-Item (Join-Path $Dest ".reboot-needed") -ErrorAction SilentlyContinue

# ---- 4. import -------------------------------------------------------------------------------------
Write-Step "4/6 importing the $WslName distro"
if (Test-WslDistro $WslName) { Write-Ok "distro $WslName already imported" }
else {
  $vhdDir = Join-Path $Dest "wsl\$WslName"; New-Item -ItemType Directory -Force -Path $vhdDir | Out-Null
  & wsl.exe --import $WslName $vhdDir (Join-Path $Bundle "wsl\rootfs.tar.gz") --version 2
  if ($LASTEXITCODE -ne 0 -or -not (Test-WslDistro $WslName)) { Fail "wsl --import failed ($LASTEXITCODE)" } else { Write-Ok "imported into $vhdDir" }
}
if (-not $ok) { Leave 3 }

# ---- 5. provision ----------------------------------------------------------------------------------
Write-Step "5/6 provisioning the distro offline (packages, Python, UAC, Loki, Chainsaw, Sigma, Gumshoe)"
$bwsl = ConvertTo-WslPath $WslName $Bundle
& wsl.exe -d $WslName -u root -- bash "$bwsl/gumshoe/setup/offline/wsl_provision.sh" $bwsl
if ($LASTEXITCODE -ne 0) { Fail "provisioning failed (log inside the distro: /var/log/gumshoe-provision.log)"; Leave 3 }
& wsl.exe --terminate $WslName 2>$null | Out-Null    # so /etc/wsl.conf takes effect on next start
Write-Ok "provisioned"

# ---- 6. verify -------------------------------------------------------------------------------------
Write-Step "6/6 verification inside the distro"
[void](Ensure-OllamaFromWsl $WslName $OllamaPort)
& wsl.exe -d $WslName -u root -- bash /opt/dfir/gumshoe/setup/wsl/03_verify_offline.sh
if ($LASTEXITCODE -ne 0) { Write-Warn2 "some checks failed (see above). Gumshoe-Selftest.bat re-runs them any time." }
else { Write-Ok "all checks passed" }
Set-Content -Path (Join-Path $Dest ".installed") -Value ("installed " + (Get-Date -Format s) + " from " + $Bundle)
Write-Host ""
Write-Host "Done. Double-click Gumshoe.bat to start." -ForegroundColor Green
Leave 0
