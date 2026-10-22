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

# The models the bundle ships; names as /api/tags reports them.
$RequiredModels = @("qwen2.5:3b-instruct", "qwen2.5:7b-instruct-q4_K_M", "nomic-embed-text:latest", "bge-m3:latest")

function Get-OllamaModels([int]$Port = 11434) {
  try { $j = Invoke-RestMethod "http://127.0.0.1:$Port/api/tags" -TimeoutSec 5; return @($j.models | ForEach-Object { $_.name }) } catch { return @() }
}
function Get-MissingModels([int]$Port = 11434, [int]$RetrySeconds = 0) {
  # a freshly started Ollama answers /api/tags before it has finished scanning its store: retry briefly
  $deadline = (Get-Date).AddSeconds($RetrySeconds)
  do {
    $have = Get-OllamaModels $Port
    $missing = @($RequiredModels | Where-Object { $have -notcontains $_ })
    if ($missing.Count -eq 0 -or (Get-Date) -ge $deadline) { return $missing }
    Start-Sleep 1
  } while ($true)
}
# Where this machine's Ollama keeps models: OLLAMA_MODELS if set anywhere, else the default store.
function Get-OllamaModelsDir {
  foreach ($scope in "Process", "User", "Machine") {
    $v = [Environment]::GetEnvironmentVariable("OLLAMA_MODELS", $scope); if ($v) { return $v }
  }
  return (Join-Path $env:USERPROFILE ".ollama\models")
}
# Merge the bundled model store into $Store (robocopy skips files already there). $true on success.
function Copy-ModelStore([string]$Bundle, [string]$Store) {
  New-Item -ItemType Directory -Force -Path $Store | Out-Null
  & robocopy.exe (Join-Path $Bundle "models") $Store /E /NFL /NDL /NJH /NJS /NP | Out-Null
  return ($LASTEXITCODE -lt 8)
}
function Start-OllamaServe([int]$Port) {
  $exe = Get-OllamaExe
  if (-not $exe) { Write-Warn2 "ollama.exe not found (first run not completed?)"; return $false }
  # 0.0.0.0 so the distro can reach it in NAT mode too; pinned to the i7-12700's P-cores (logical 0-15)
  $env:OLLAMA_HOST = "0.0.0.0:$Port"; $env:OLLAMA_KEEP_ALIVE = "30m"; $env:OLLAMA_MAX_LOADED_MODELS = "1"
  $env:OLLAMA_MODELS = Get-OllamaModelsDir
  $p = Start-Process -FilePath $exe -ArgumentList "serve" -WindowStyle Minimized -PassThru
  try { if ([Environment]::ProcessorCount -ge 16) { $p.ProcessorAffinity = [IntPtr]0xFFFF } } catch {}
  if (Wait-Port $Port 45) { Write-Ok "Ollama started on $Port (pid $($p.Id), models in $env:OLLAMA_MODELS)"; return $true }
  Write-Warn2 "Ollama did not open port $Port within 45 s"; return $false
}
# Find or start an Ollama that can see the bundled models. Adopts an Ollama already on 11434 when it has
# them (or after being handed the files where it looks); otherwise runs Gumshoe's own on 11435 so another
# Ollama on the machine (Docker, WSL, a different user) is left alone. Returns the port, or 0.
function Start-OllamaForGumshoe([string]$Bundle) {
  if (Test-Port 11434) {
    $missing = Get-MissingModels 11434
    if ($missing.Count -eq 0) { Write-Ok "Ollama on 11434 has all bundled models"; return 11434 }
    $store = Get-OllamaModelsDir
    Write-Host "  the Ollama on 11434 lacks $($missing -join ', '); copying the bundled models into $store ..."
    if ($Bundle -and (Test-Path (Join-Path $Bundle "models")) -and (Copy-ModelStore $Bundle $store)) { $missing = Get-MissingModels 11434 5 }
    if ($missing.Count -eq 0) { Write-Ok "Ollama on 11434 now has all bundled models"; return 11434 }
    Write-Warn2 "the Ollama on 11434 still cannot see them (it may run elsewhere, e.g. in Docker). Using Gumshoe's own Ollama on 11435."
    $port = 11435
    if (Test-Port 11435) {
      if ((Get-MissingModels 11435).Count -eq 0) { Write-Ok "Gumshoe's Ollama already serving on 11435"; return 11435 }
      Write-Warn2 "port 11435 is taken by something without the models"; return 0
    }
  } else { $port = 11434 }
  if (-not (Start-OllamaServe $port)) { return 0 }
  $missing = Get-MissingModels $port 20
  if ($missing.Count -gt 0) { Write-Warn2 "started on $port but these models are missing: $($missing -join ', ')" }
  return $port
}

function Test-WslDistro([string]$Name) {
  try { $list = (& wsl.exe -l -q 2>$null) -join "`n"; return ($list -match "(?m)^\s*$([regex]::Escape($Name))\s*$") } catch { return $false }
}

# Windows path -> what the distro sees (C:\x -> /mnt/c/x). Needs a running wsl.exe. A drive WSL has not mounted
# (a USB drive plugged in after WSL started, a drive added later, a mapped network drive) is mounted into the
# distro with drvfs first - the bundle may well live on such a drive when C: is full.
function ConvertTo-WslPath([string]$Name, [string]$WinPath) {
  $p = ($WinPath -replace '\\', '/').TrimEnd('/')
  $out = & wsl.exe -d $Name -u root -- wslpath -u $p 2>$null
  if ($LASTEXITCODE -eq 0 -and $out) { return ($out | Select-Object -First 1).Trim() }
  if ($p -match '^([A-Za-z]):(/.*)?$') {
    $d = $Matches[1].ToLower(); $rest = $Matches[2]
    $drive = $Matches[1].ToUpper() + ":"
    & wsl.exe -d $Name -u root -- sh -c "mountpoint -q /mnt/$d || (mkdir -p /mnt/$d && mount -t drvfs $drive /mnt/$d)" 2>$null | Out-Null
    $out = & wsl.exe -d $Name -u root -- wslpath -u $p 2>$null
    if ($LASTEXITCODE -eq 0 -and $out) { return ($out | Select-Object -First 1).Trim() }
    & wsl.exe -d $Name -u root -- test -d "/mnt/$d$rest" 2>$null
    if ($LASTEXITCODE -eq 0) { return "/mnt/$d$rest" }
    throw "the distro cannot see $WinPath (drive $drive is not mounted inside WSL and could not be mounted with drvfs). Run  wsl --shutdown  and double-click again; if the drive is a network drive, map it in Windows first."
  }
  throw "wslpath failed for $WinPath"
}

# Make sure the distro can talk to Ollama on Windows: 127.0.0.1 with mirrored networking, otherwise the
# Windows host address (NAT mode), written into config.yaml. Returns $true when some route works.
function Ensure-OllamaFromWsl([string]$Name, [int]$Port = 11434) {
  & wsl.exe -d $Name -u root -- curl -s -m 3 -o /dev/null "http://127.0.0.1:${Port}/api/tags"
  if ($LASTEXITCODE -eq 0) {
    & wsl.exe -d $Name -u root -- sed -i "s#base_url: http://[^ ]*#base_url: http://127.0.0.1:${Port}#" /opt/dfir/gumshoe/config.yaml 2>$null
    Write-Ok "Ollama reachable from WSL at 127.0.0.1:$Port"; return $true
  }
  $route = (& wsl.exe -d $Name -u root -- ip route show default 2>$null) -join ' '
  $hostip = ($route -split '\s+' | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -First 1)
  if ($hostip) {
    & wsl.exe -d $Name -u root -- curl -s -m 3 -o /dev/null "http://${hostip}:${Port}/api/tags"
    if ($LASTEXITCODE -eq 0) {
      & wsl.exe -d $Name -u root -- sed -i "s#base_url: http://[^ ]*#base_url: http://${hostip}:${Port}#" /opt/dfir/gumshoe/config.yaml
      Write-Ok "Ollama reachable from WSL at ${hostip}:$Port (config.yaml updated)"; return $true
    }
  }
  Write-Warn2 "WSL cannot reach Ollama on port $Port (tried 127.0.0.1 and '$hostip'). Check the 'Gumshoe Ollama (WSL)' firewall rule and that Ollama is serving on 0.0.0.0."
  return $false
}

function Pause-IfConsole($msg = "Press Enter to close this window") {
  if ($Host.Name -eq "ConsoleHost") { Write-Host ""; Write-Host $msg; [void](Read-Host) }
}
