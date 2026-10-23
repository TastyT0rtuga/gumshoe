<#
.SYNOPSIS
  Build the offline transfer bundle on an INTERNET-CONNECTED Windows 11 machine.

.DESCRIPTION
  Produces  <Out>\  (default .\gumshoe-transfer) containing everything the air-gapped
  sandbox needs: the Gumshoe project, Python wheels for Windows and WSL, the Ollama
  installer and model store, UAC, Loki + signature-base, Chainsaw + Sigma rules, the
  WSL installer and an exported, pre-provisioned Ubuntu distro.

  Run from the project root:   powershell -ExecutionPolicy Bypass -File setup\windows\01_prepare_online.ps1
  Each step is independent; re-run to fill in anything that failed. Use -SkipWsl if
  WSL cannot be installed on this machine (then build the distro tar elsewhere).

.NOTES
  Wheels must match the sandbox's Python (default 3.12, x86-64). Change -PyVersion if the
  sandbox runs another version. The Arsenal Image Mounter installer must be downloaded by
  hand from https://arsenalrecon.com/downloads (registration) into <Out>\tools\arsenal\.
#>
param(
  [string]$Out = ".\gumshoe-transfer",
  [string]$PyVersion = "3.12",
  [string[]]$Models = @("qwen2.5:3b-instruct", "qwen2.5:7b-instruct-q4_K_M", "nomic-embed-text"),
  [string]$UbuntuDistro = "Ubuntu-24.04",
  [switch]$SkipWsl,
  [switch]$SkipModels,
  [switch]$Lite          # a bundle without Ollama and without models (about 6 GB smaller): the AI assistant stays off
)
if ($Lite) { $SkipModels = $true }
$ErrorActionPreference = "Stop"
$ProjectRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$Out = [System.IO.Path]::GetFullPath($Out)
$PyAbi = "cp" + ($PyVersion -replace "\.", "")

function Step($name, [scriptblock]$body) {
  Write-Host "`n=== $name ===" -ForegroundColor Cyan
  try { & $body; Write-Host "ok: $name" -ForegroundColor Green }
  catch { Write-Host "FAILED: $name -> $($_.Exception.Message)" -ForegroundColor Red }
}
function Get-LatestAsset($repo, $pattern) {
  $rel = Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest" -Headers @{ "User-Agent" = "gumshoe-prep" }
  $asset = $rel.assets | Where-Object { $_.name -match $pattern } | Select-Object -First 1
  if (-not $asset) { throw "no asset matching $pattern in $repo $($rel.tag_name)" }
  return $asset
}
function Download($url, $dest) {
  New-Item -ItemType Directory -Force -Path (Split-Path $dest) | Out-Null
  Write-Host "  downloading $url"
  Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing
}

foreach ($d in (@("gumshoe", "wheels\win", "wheels\linux", "wsl", "tools\uac", "tools\loki", "tools\chainsaw", "tools\sigma", "tools\arsenal") + $(if ($Lite) { @() } else { @("ollama", "models") }))) {
  New-Item -ItemType Directory -Force -Path (Join-Path $Out $d) | Out-Null
}

Step "Copy the Gumshoe project" {
  robocopy $ProjectRoot (Join-Path $Out "gumshoe") /E /XD cases .git __pycache__ /XF *.pyc | Out-Null
  New-Item -ItemType Directory -Force -Path (Join-Path $Out "gumshoe\cases") | Out-Null
}

Step "Python wheels for Windows ($PyVersion win_amd64) and WSL (manylinux)" {
  $req = Join-Path $ProjectRoot "requirements.txt"
  python -m pip download -r $req -d (Join-Path $Out "wheels\win") --platform win_amd64 --python-version $PyVersion --only-binary=:all:
  python -m pip download -r $req -d (Join-Path $Out "wheels\linux") --platform manylinux2014_x86_64 --platform manylinux_2_17_x86_64 --platform manylinux_2_28_x86_64 --python-version $PyVersion --abi $PyAbi --abi abi3 --abi none --only-binary=:all:
  # Loki's own requirements (installed into the WSL venv by 02_install_offline.sh)
  $lokiReq = Join-Path $Out "tools\loki\Loki\requirements.txt"
  if (Test-Path $lokiReq) {
    python -m pip download -r $lokiReq -d (Join-Path $Out "wheels\linux") --platform manylinux2014_x86_64 --platform manylinux_2_17_x86_64 --platform manylinux_2_28_x86_64 --python-version $PyVersion --abi $PyAbi --abi abi3 --abi none --only-binary=:all:
    python -m pip download -r $lokiReq -d (Join-Path $Out "wheels\win") --platform win_amd64 --python-version $PyVersion --only-binary=:all:
  } else { Write-Host "  (Loki not fetched yet; re-run after the Loki step to get its wheels)" }
}

if (-not $Lite) {
  Step "Ollama installer" {
    Download "https://ollama.com/download/OllamaSetup.exe" (Join-Path $Out "ollama\OllamaSetup.exe")
  }
} else { Write-Host "== lite bundle: no Ollama installer, no models (the AI assistant switch in Gumshoe stays off)" }

if (-not $SkipModels) {
  Step "Pull models and copy the model store" {
    if (-not (Get-Command ollama -ErrorAction SilentlyContinue)) {
      Write-Host "  installing Ollama locally to pull models"
      Start-Process -Wait -FilePath (Join-Path $Out "ollama\OllamaSetup.exe") -ArgumentList "/VERYSILENT", "/NORESTART"
      $env:PATH += ";$env:LOCALAPPDATA\Programs\Ollama"
    }
    foreach ($m in $Models) { Write-Host "  ollama pull $m"; ollama pull $m }
    $store = Join-Path $env:USERPROFILE ".ollama\models"
    robocopy $store (Join-Path $Out "models") /E | Out-Null
  }
}

Step "UAC (Unix-like Artifact Collector)" {
  $a = Get-LatestAsset "tclahr/uac" "^uac-.*\.tar\.gz$"
  Download $a.browser_download_url (Join-Path $Out "tools\uac\$($a.name)")
}

Step "Loki + signature-base (git clone; Loki runs from source inside WSL)" {
  $dest = Join-Path $Out "tools\loki"
  if (-not (Test-Path (Join-Path $dest "Loki\.git"))) { git clone --depth 1 https://github.com/Neo23x0/Loki.git (Join-Path $dest "Loki") }
  if (-not (Test-Path (Join-Path $dest "Loki\signature-base\.git"))) { git clone --depth 1 https://github.com/Neo23x0/signature-base.git (Join-Path $dest "Loki\signature-base") }
  Write-Host "  NOTE: re-run this script once more so the wheels step picks up Loki\requirements.txt"
}

Step "Chainsaw (all platforms + rules)" {
  $a = Get-LatestAsset "WithSecureLabs/chainsaw" "chainsaw_all_platforms\+rules.*\.zip$"
  Download $a.browser_download_url (Join-Path $Out "tools\chainsaw\$($a.name)")
}

Step "Sigma rules (git clone)" {
  $dest = Join-Path $Out "tools\sigma"
  if (-not (Test-Path (Join-Path $dest "sigma\.git"))) { git clone --depth 1 https://github.com/SigmaHQ/sigma.git (Join-Path $dest "sigma") }
}

Step "WSL installer (MSI)" {
  $a = Get-LatestAsset "microsoft/WSL" "^wsl\..*x64\.msi$"
  Download $a.browser_download_url (Join-Path $Out "wsl\wsl.msi")
}

Step "Arsenal Image Mounter" {
  if (-not (Get-ChildItem (Join-Path $Out "tools\arsenal") -ErrorAction SilentlyContinue)) {
    Write-Host "  Download Arsenal Image Mounter from https://arsenalrecon.com/downloads and place the installer in $Out\tools\arsenal\" -ForegroundColor Yellow
  }
}

if (-not $SkipWsl) {
  Step "Provision and export the WSL analysis distro ($UbuntuDistro)" {
    $have = (wsl -l -q 2>$null) -join "`n"
    if ($have -notmatch [regex]::Escape($UbuntuDistro)) {
      wsl --install -d $UbuntuDistro --no-launch
      Write-Host "  If this was the first WSL install, reboot and re-run the script." -ForegroundColor Yellow
    }
    $script = (Join-Path $ProjectRoot "setup\wsl\prepare_distro.sh") -replace "\\", "/" -replace "^([A-Za-z]):", { "/mnt/" + $_.Groups[1].Value.ToLower() }
    wsl -d $UbuntuDistro -u root bash -lc "bash '$script'"
    wsl --terminate $UbuntuDistro
    wsl --export $UbuntuDistro (Join-Path $Out "wsl\dfir-ubuntu.tar")
  }
}

Step "Hash the bundle" {
  & (Join-Path $PSScriptRoot "hash_bundle.ps1") -Path $Out
}

Write-Host "`nBundle ready at $Out. Copy the whole folder to the external drive." -ForegroundColor Green
