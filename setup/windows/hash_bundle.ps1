<#
.SYNOPSIS  Write (or verify) SHA-256 hashes of every file in the transfer bundle.
.EXAMPLE   .\hash_bundle.ps1 -Path D:\gumshoe-transfer            # writes bundle.sha256
.EXAMPLE   .\hash_bundle.ps1 -Path D:\gumshoe-transfer -Verify    # compares against bundle.sha256
#>
param([Parameter(Mandatory = $true)][string]$Path, [switch]$Verify)
$ErrorActionPreference = "Stop"
$Path = [System.IO.Path]::GetFullPath($Path)
$manifest = Join-Path $Path "bundle.sha256"
if ($Verify) {
  if (-not (Test-Path $manifest)) { throw "no bundle.sha256 in $Path" }
  $bad = 0; $n = 0
  foreach ($line in Get-Content $manifest) {
    if (-not $line.Trim()) { continue }
    $hash, $rel = $line -split "\s+", 2
    $f = Join-Path $Path $rel
    $n++
    if (-not (Test-Path $f)) { Write-Host "MISSING  $rel" -ForegroundColor Red; $bad++; continue }
    $h = (Get-FileHash -Algorithm SHA256 $f).Hash.ToLower()
    if ($h -ne $hash.ToLower()) { Write-Host "CHANGED  $rel" -ForegroundColor Red; $bad++ }
  }
  if ($bad -gt 0) { throw "$bad of $n files failed verification" }
  Write-Host "verified $n files OK" -ForegroundColor Green
} else {
  $lines = Get-ChildItem -Path $Path -Recurse -File | Where-Object { $_.Name -ne "bundle.sha256" } | ForEach-Object {
    $rel = $_.FullName.Substring($Path.Length).TrimStart("\")
    "{0}  {1}" -f (Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLower(), $rel
  }
  $lines | Set-Content -Path $manifest -Encoding ASCII
  Write-Host "wrote $manifest ($($lines.Count) files)" -ForegroundColor Green
}
