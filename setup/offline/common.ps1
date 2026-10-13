# Shared helpers for the Gumshoe offline launcher scripts (dot-sourced). No network is used anywhere.
# Continue, not Stop: Windows PowerShell 5.1 turns a native command's stderr into a terminating error when it is
# redirected (2>$null) under Stop. Every call below is checked through $LASTEXITCODE or its result instead.
$ErrorActionPreference = "Continue"
$env:WSL_UTF8 = "1"            # wsl.exe prints UTF-16 otherwise, which PowerShell mangles when captured

function Write-Step($msg) { Write-Host ""; Write-Host "=== $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "  ok: $msg" -ForegroundColor Green }
function Write-Warn2($msg){ Write-Host "  !! $msg" -ForegroundColor Yellow }

function Test-Port([int]$Port, [string]$Address = "127.0.0.1") {
  try { $c = New-Object Net.Sockets.TcpClient; $c.Connect($Address, $Port); $c.Close(); return $true } catch { return $false }
}
function Wait-Port([int]$Port, [int]$Seconds = 60, [string]$What = "port $Port") {
  for ($i = 0; $i -lt $Seconds; $i++) { if (Test-Port $Port) { return $true }; Start-Sleep 1 }
  return $false
}

function Get-OllamaExe {
  foreach ($p in @("$env:LOCALAPPDATA\Programs\Ollama\ollama.exe", "$env:ProgramFiles\Ollama\ollama.exe")) { if (Test-Path $p) { return $p } }
  $c = Get-Command ollama.exe -ErrorAction SilentlyContinue; if ($c) { return $c.Source }
  return $null
}

# Start Ollama serving on 0.0.0.0:11434 (reachable from WSL in either networking mode), pinned to the
# i7-12700's P-cores (logical processors 0-15) so the model never lands on E-cores. Idempotent.
function Start-Ollama {
  if (Test-Port 11434) { Write-Ok "Ollama already serving on 11434"; return $true }
  $exe = Get-OllamaExe
  if (-not $exe) { Write-Warn2 "ollama.exe not found (first run not completed?)"; return $false }
  $env:OLLAMA_HOST = "0.0.0.0:11434"; $env:OLLAMA_KEEP_ALIVE = "30m"; $env:OLLAMA_MAX_LOADED_MODELS = "1"
  $p = Start-Process -FilePath $exe -ArgumentList "serve" -WindowStyle Minimized -PassThru
  try { $cores = [Environment]::ProcessorCount; if ($cores -ge 16) { $p.ProcessorAffinity = [IntPtr]0xFFFF } } catch {}
  if (Wait-Port 11434 45) { Write-Ok "Ollama started (pid $($p.Id))"; return $true }
  Write-Warn2 "Ollama did not open port 11434 within 45 s"; return $false
}

function Get-OllamaModels {
  try { $j = Invoke-RestMethod "http://127.0.0.1:11434/api/tags" -TimeoutSec 5; return @($j.models | ForEach-Object { $_.name }) } catch { return @() }
}

function Test-WslDistro([string]$Name) {
  try { $list = (& wsl.exe -l -q 2>$null) -join "`n"; return ($list -match "(?m)^\s*$([regex]::Escape($Name))\s*$") } catch { return $false }
}

# Windows path -> what the distro sees (C:\x -> /mnt/c/x). Needs a running wsl.exe.
function ConvertTo-WslPath([string]$Name, [string]$WinPath) {
  $p = ($WinPath -replace '\\', '/').TrimEnd('/')
  $out = & wsl.exe -d $Name -u root -- wslpath -u $p 2>$null
  if ($LASTEXITCODE -ne 0 -or -not $out) { throw "wslpath failed for $WinPath" }
  return ($out | Select-Object -First 1).Trim()
}

# Make sure the distro can talk to Ollama on Windows: 127.0.0.1 with mirrored networking, otherwise the
# Windows host address (NAT mode), written into config.yaml. Returns $true when some route works.
function Ensure-OllamaFromWsl([string]$Name) {
  & wsl.exe -d $Name -u root -- curl -s -m 3 -o /dev/null http://127.0.0.1:11434/api/tags
  if ($LASTEXITCODE -eq 0) {
    & wsl.exe -d $Name -u root -- sed -i 's#base_url: http://[^ ]*#base_url: http://127.0.0.1:11434#' /opt/dfir/gumshoe/config.yaml 2>$null
    Write-Ok "Ollama reachable from WSL at 127.0.0.1"; return $true
  }
  $route = (& wsl.exe -d $Name -u root -- ip route show default 2>$null) -join ' '
  $hostip = ($route -split '\s+' | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -First 1)
  if ($hostip) {
    & wsl.exe -d $Name -u root -- curl -s -m 3 -o /dev/null "http://${hostip}:11434/api/tags"
    if ($LASTEXITCODE -eq 0) {
      & wsl.exe -d $Name -u root -- sed -i "s#base_url: http://[^ ]*#base_url: http://${hostip}:11434#" /opt/dfir/gumshoe/config.yaml
      Write-Ok "Ollama reachable from WSL at $hostip (config.yaml updated)"; return $true
    }
  }
  Write-Warn2 "WSL cannot reach Ollama (tried 127.0.0.1 and '$hostip'). Check the 'Gumshoe Ollama (WSL)' firewall rule and that Ollama is serving on 0.0.0.0:11434."
  return $false
}

function Pause-IfConsole($msg = "Press Enter to close this window") {
  if ($Host.Name -eq "ConsoleHost") { Write-Host ""; Write-Host $msg; [void](Read-Host) }
}
