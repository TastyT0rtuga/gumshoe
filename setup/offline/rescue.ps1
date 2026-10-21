<#
  Gumshoe-Rescue: when Gumshoe.bat stops at "=== WSL distro DFIR" with a WSL error - "User not found",
  "getpwnam(root) failed", "WSL_E_USER_NOT_FOUND", or the distro simply will not start - this finds out why
  and repairs what it can, WITHOUT deleting or reinstalling anything:

    1. the facts: where the distro's virtual disk is, how big, how much room its drive has (a full drive is
       the usual cause: the disk grows on demand and cannot when C: is full), the WSL version
    2. a clean restart of just this distro (wsl --terminate DFIR) and a start test (wsl -d DFIR -u root -- id)
    3. a filesystem check and repair of the distro's disk (e2fsck) from a small throwaway rescue distro
       imported from the bundle's own root filesystem (about 1 GB on the drive with the most room; removed
       at the end unless -Keep), then the start test again
    4. if the disk still does not start: the cases and settings are copied OUT of it (read-only mount, no
       journal replay) to <drive>:\DFIR-rescue\<date>\, and the exact reinstall steps are printed - they are
       not run. Add -Everything to copy the extracted images/trees (work folders) as well.

  Run from Gumshoe-Rescue.bat (it asks for administrator rights: attaching a virtual disk needs them).
  Everything printed is also written to C:\DFIR\rescue.log.
#>
param([string]$Bundle = "", [string]$WslName = "DFIR", [string]$Disk = "", [string]$RescueDir = "", [switch]$Force, [switch]$Keep, [switch]$Everything)
. (Join-Path $PSScriptRoot "common.ps1")
if (-not $Bundle) { $Bundle = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path }
# attaching a virtual disk (wsl --mount) needs administrator rights: re-launch elevated, same user, same distros
$isAdmin = $true
try { $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { }
if (-not $isAdmin) {
  $al = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"", "-Bundle", "`"$Bundle`"", "-WslName", $WslName)
  if ($Disk) { $al += @("-Disk", "`"$Disk`"") }
  if ($RescueDir) { $al += @("-RescueDir", "`"$RescueDir`"") }
  if ($Force) { $al += "-Force" }; if ($Keep) { $al += "-Keep" }; if ($Everything) { $al += "-Everything" }
  Write-Host "Windows will ask for administrator approval (attaching the distro's disk for the check needs it)."
  try { $p = Start-Process -FilePath "powershell.exe" -Verb RunAs -Wait -PassThru -ArgumentList $al; exit $p.ExitCode }
  catch { Write-Host "administrator approval was declined; the disk check cannot run without it." -ForegroundColor Red; exit 1 }
}
$Dest = "C:\DFIR"
$Rescue = "$WslName-rescue"
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
try { Start-Transcript -Path (Join-Path $Dest "rescue.log") -Append | Out-Null } catch { }

function Invoke-Wsl([string[]]$ArgList) {
  # (exit code, output text) of a wsl.exe call; stderr included in the text
  $out = & wsl.exe @ArgList 2>&1
  $code = $LASTEXITCODE
  return @($code, (($out | ForEach-Object { "$_" }) -join "`n").Trim())
}
function Test-Start([string]$Name) {
  $r = Invoke-Wsl @("-d", $Name, "-u", "root", "--", "id", "-u")
  return @(($r[0] -eq 0 -and $r[1] -match '(?m)^0\s*$'), $r[1])
}
function Get-DistroDisk([string]$Name) {
  # the distro's virtual disk from the registry (BasePath\ext4.vhdx, or VhdFileName when it was imported in place)
  try {
    $k = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss\*" -ErrorAction SilentlyContinue | Where-Object { $_.DistributionName -eq $Name } | Select-Object -First 1
    if ($k) {
      $base = $k.BasePath -replace '^\\\\\?\\', ''
      $file = if ($k.PSObject.Properties.Name -contains "VhdFileName" -and $k.VhdFileName) { $k.VhdFileName } else { "ext4.vhdx" }
      if ([System.IO.Path]::IsPathRooted($file)) { return $file }
      return (Join-Path $base $file)
    }
  } catch { }
  return $null
}
function Get-FreeGB([string]$Path) {
  try { return [math]::Round((Get-PSDrive -Name $Path.Substring(0, 1) -ErrorAction Stop).Free / 1GB, 1) } catch { return -1 }
}
function Finish([int]$code) { try { Stop-Transcript | Out-Null } catch { }; Pause-IfConsole; exit $code }
function Get-SpaceDir([string]$Sub) {
  # a folder on the drive with the most room (2 GB at least), or under -RescueDir when given
  if ($RescueDir) { return (Join-Path $RescueDir $Sub) }
  $drive = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -gt 2GB -and $_.Root -match '^[A-Z]:\\$' } | Sort-Object Free -Descending | Select-Object -First 1
  if (-not $drive) { return $null }
  return (Join-Path $drive.Root "DFIR-rescue\$Sub")
}

Write-Host "Gumshoe rescue for the WSL distro $WslName  (log: $Dest\rescue.log)"
Write-Host "Nothing is deleted or reinstalled by this script."

# ---- 1. facts ----------------------------------------------------------------------------------------
Write-Step "1/4 the facts"
$ver = (Invoke-Wsl @("--version"))[1]
if ($ver) { Write-Host ("  " + (($ver -split "`n") | Select-Object -First 2) -join "; ") }
$list = (Invoke-Wsl @("--list", "--verbose"))[1]
Write-Host "  registered distros:"; ($list -split "`n") | ForEach-Object { Write-Host "    $_" }
if (-not (Test-WslDistro $WslName)) {
  Write-Host "  the distro $WslName is not registered at all (it was unregistered, or WSL lost its registration)." -ForegroundColor Red
  Write-Host "  Look for its disk: dir /s /b C:\DFIR\ext4.vhdx D:\DFIR\ext4.vhdx - if it exists, wsl --import-in-place $WslName <path to ext4.vhdx> brings it back;"
  Write-Host "  otherwise delete $Dest\.installed and double-click Gumshoe.bat to install a fresh distro (the old cases are gone with the disk)."
  Finish 2
}
$vhd = if ($Disk) { $Disk } else { Get-DistroDisk $WslName }
if ($vhd -and (Test-Path $vhd)) {
  $gb = [math]::Round((Get-Item $vhd).Length / 1GB, 1)
  $free = Get-FreeGB $vhd
  Write-Host "  disk: $vhd ($gb GB; $free GB free on its drive)"
  if ($free -ge 0 -and $free -lt 2) {
    Write-Host "  !! the drive holding the distro's disk has only $free GB free. That is the usual cause of this failure: the disk" -ForegroundColor Yellow
    Write-Host "     grows on demand and cannot. Free at least 3-5 GB on that drive (Recycle Bin, hopper, exports, Downloads)" -ForegroundColor Yellow
    Write-Host "     and, once the distro starts again, run Gumshoe-MoveToDrive.bat so it lives on a drive with room." -ForegroundColor Yellow
  }
} else {
  Write-Host "  !! the distro's disk could not be located (registry says '$vhd'). The repair step needs it:" -ForegroundColor Yellow
  Write-Host "     find ext4.vhdx (dir /s /b C:\DFIR\ext4.vhdx, D:\DFIR\ext4.vhdx ...) and run: powershell -File rescue.ps1 -Disk <path>" -ForegroundColor Yellow
}
$up = if ($env:USERPROFILE) { $env:USERPROFILE } else { $HOME }
$cfg = Join-Path $up ".wslconfig"
$swap = Join-Path $(if ($env:TEMP) { $env:TEMP } else { "C:\Temp" }) "swap.vhdx"
if (Test-Path $cfg) { $m = Select-String -Path $cfg -Pattern '^\s*swapFile\s*=\s*(.+)$' | Select-Object -First 1; if ($m) { $swap = $m.Matches[0].Groups[1].Value.Trim() } }
Write-Host ("  swap file: $swap (" + (Get-FreeGB (Split-Path $swap)) + " GB free on its drive)")
$cFree = Get-FreeGB "C:\"
Write-Host "  C: has $cFree GB free"

# ---- 2. restart just this distro, start test ------------------------------------------------------------
Write-Step "2/4 clean restart of $WslName and a start test"
[void](Invoke-Wsl @("--terminate", $WslName)); Start-Sleep 2
$t = Test-Start $WslName
if ($t[0]) {
  Write-Ok "the distro starts (root resolves). Nothing to repair."
  if (-not $Force) {
    Write-Host "Double-click Gumshoe.bat. If this keeps happening, run Gumshoe-MoveToDrive.bat (C: has $cFree GB free)." -ForegroundColor Green
    Finish 0
  }
  Write-Host "  (-Force given: checking the disk anyway)"
} else {
  Write-Host "  start test failed:" -ForegroundColor Red
  ($t[1] -split "`n") | ForEach-Object { Write-Host "    $_" }
  if ($t[1] -match 'USER_NOT_FOUND|getpwnam|failed 5') { Write-Host "  -> WSL cannot read the distro's user database: the disk is dirty, damaged, or its drive is full. Checking the disk." }
}
if (-not ($vhd -and (Test-Path $vhd))) { Write-Host "no disk to check; stopping here." -ForegroundColor Red; Finish 2 }

# ---- 3. fsck from a throwaway rescue distro -----------------------------------------------------------
Write-Step "3/4 filesystem check of $vhd"
$rootfs = Join-Path $Bundle "wsl\rootfs.tar.gz"
if (-not (Test-Path $rootfs)) { Write-Host "the bundle's wsl\rootfs.tar.gz is missing ($rootfs); cannot build the rescue distro." -ForegroundColor Red; Finish 2 }
if (-not (Test-WslDistro $Rescue)) {
  $rdir = Get-SpaceDir "wsl"
  if (-not $rdir) { Write-Host "no drive has 2 GB free for the rescue distro; free some space first (or give -RescueDir <folder>)." -ForegroundColor Red; Finish 2 }
  New-Item -ItemType Directory -Force -Path $rdir | Out-Null
  Write-Host "  importing a rescue distro ($Rescue) into $rdir from the bundle (about a minute)..."
  $r = Invoke-Wsl @("--import", $Rescue, $rdir, $rootfs, "--version", "2")
  if ($r[0] -ne 0 -or -not (Test-WslDistro $Rescue)) { Write-Host "  wsl --import failed: $($r[1])" -ForegroundColor Red; Finish 2 }
  Write-Ok "rescue distro ready"
} else { Write-Ok "rescue distro $Rescue already exists" }
$ts = Test-Start $Rescue
if (-not $ts[0]) { Write-Host "  even the fresh rescue distro does not start: $($ts[1])" -ForegroundColor Red; Write-Host "  WSL itself is unwell on this machine: run  wsl --shutdown  and, if that does not help, reboot; then run this again."; Finish 2 }

# attach the broken disk bare, find it, fsck it
[void](Invoke-Wsl @("--terminate", $WslName)); Start-Sleep 1
$before = (Invoke-Wsl @("-d", $Rescue, "-u", "root", "--", "lsblk", "-dno", "NAME"))[1] -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }
$m = Invoke-Wsl @("--mount", $vhd, "--vhd", "--bare")
if ($m[0] -ne 0) {
  Write-Warn2 "could not attach the disk ($($m[1])); shutting WSL down completely and trying once more"
  [void](Invoke-Wsl @("--shutdown")); Start-Sleep 3
  [void](Test-Start $Rescue)
  $before = (Invoke-Wsl @("-d", $Rescue, "-u", "root", "--", "lsblk", "-dno", "NAME"))[1] -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }
  $m = Invoke-Wsl @("--mount", $vhd, "--vhd", "--bare")
  if ($m[0] -ne 0) { Write-Host "  wsl --mount --vhd failed: $($m[1])" -ForegroundColor Red; Write-Host "  (it needs administrator rights and WSL 0.67 or newer)"; Finish 2 }
}
Start-Sleep 2
$after = (Invoke-Wsl @("-d", $Rescue, "-u", "root", "--", "lsblk", "-dno", "NAME"))[1] -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }
$new = @($after | Where-Object { $before -notcontains $_ })
if ($new.Count -ne 1) {
  Write-Host "  could not tell which block device is the attached disk (before: $($before -join ','); after: $($after -join ','))" -ForegroundColor Red
  [void](Invoke-Wsl @("--unmount", $vhd)); Finish 2
}
$dev = "/dev/" + $new[0]
Write-Host "  attached as $dev inside $Rescue; running e2fsck -f -y (repairs what it finds; minutes on a large disk)..."
$f = Invoke-Wsl @("-d", $Rescue, "-u", "root", "--", "e2fsck", "-f", "-y", $dev)
($f[1] -split "`n") | Select-Object -Last 25 | ForEach-Object { Write-Host "    $_" }
switch ($f[0]) {
  0 { Write-Ok "the filesystem was clean (so the disk is not the problem: see the drive space above, or WSL itself)" }
  1 { Write-Ok "errors were found and repaired" }
  2 { Write-Ok "errors were repaired (e2fsck asked for a reboot of the system that mounts it; terminating the distro does that here)" }
  default { Write-Host "  e2fsck exit $($f[0]): errors remain or the check could not run" -ForegroundColor Red }
}
[void](Invoke-Wsl @("--unmount", $vhd)); Start-Sleep 1
[void](Invoke-Wsl @("--terminate", $WslName)); Start-Sleep 2
$t = Test-Start $WslName
if ($t[0]) {
  Write-Ok "the distro starts now."
  if (-not $Keep) { [void](Invoke-Wsl @("--unregister", $Rescue)); Write-Host "  (rescue distro removed)" }
  Write-Host "Double-click Gumshoe.bat. Then run Gumshoe-MoveToDrive.bat if the drive holding the distro is nearly full ($free GB free)." -ForegroundColor Green
  Finish 0
}
Write-Host "  still failing after the check: $($t[1])" -ForegroundColor Red

# ---- 4. salvage the cases out of the disk --------------------------------------------------------------
Write-Step "4/4 copying the cases out of the disk (read-only, no journal replay)"
$m = Invoke-Wsl @("--mount", $vhd, "--vhd", "--name", "dfirdisk", "--options", "ro,noload")
if ($m[0] -ne 0) { $m = Invoke-Wsl @("--mount", $vhd, "--vhd", "--name", "dfirdisk", "--options", "ro") }
if ($m[0] -ne 0) {
  Write-Host "  the disk cannot be mounted even read-only: $($m[1])" -ForegroundColor Red
  Write-Host "  Last resort: copy $vhd to another drive now (so a specialist can try), then reinstall as printed below." -ForegroundColor Yellow
} else {
  $stamp = Get-Date -Format "yyyyMMdd-HHmm"
  $outWin = Get-SpaceDir $stamp
  if (-not $outWin) { Write-Host "no drive has 2 GB free to copy the cases to; free some space first (or give -RescueDir <folder>)." -ForegroundColor Red; [void](Invoke-Wsl @("--unmount", $vhd)); Finish 2 }
  New-Item -ItemType Directory -Force -Path $outWin | Out-Null
  $outWsl = ""
  try { $outWsl = ConvertTo-WslPath $Rescue $outWin } catch { Write-Host "  cannot map $outWin into the rescue distro ($_)" -ForegroundColor Red; [void](Invoke-Wsl @("--unmount", $vhd)); Finish 2 }
  $sizes = (Invoke-Wsl @("-d", $Rescue, "-u", "root", "--", "sh", "-c", "du -sh /mnt/wsl/dfirdisk/opt/dfir/cases /mnt/wsl/dfirdisk/opt/dfir/images /mnt/wsl/dfirdisk/opt/dfir/trees /mnt/wsl/dfirdisk/opt/dfir/dbwork 2>/dev/null"))[1]
  Write-Host "  inside the disk:"; ($sizes -split "`n") | ForEach-Object { Write-Host "    $_" }
  $what = "cases gumshoe-settings.json"
  if ($Everything) { $what += " images trees" }
  Write-Host "  copying $what -> $outWin ..."
  $c = Invoke-Wsl @("-d", $Rescue, "-u", "root", "--", "sh", "-c", "mkdir -p $outWsl && cd /mnt/wsl/dfirdisk/opt/dfir && for x in $what; do [ -e `$x ] && cp -a `$x $outWsl/; done; ls -la $outWsl")
  ($c[1] -split "`n") | ForEach-Object { Write-Host "    $_" }
  if ($c[0] -eq 0) { Write-Ok "saved to $outWin" } else { Write-Host "  the copy reported errors (exit $($c[0])); check $outWin" -ForegroundColor Yellow }
  [void](Invoke-Wsl @("--unmount", $vhd))
}
if (-not $Keep) { [void](Invoke-Wsl @("--unregister", $Rescue)); Write-Host "  (rescue distro removed)" }
Write-Host ""
Write-Host "The distro's disk could not be brought back. To reinstall (your cases are in the folder above):" -ForegroundColor Yellow
Write-Host "  1. wsl --unregister $WslName                  (deletes the damaged disk)"
Write-Host "  2. delete $Dest\.installed, free space on C: (or run the install on a drive with room), double-click Gumshoe.bat"
Write-Host "  3. after it finishes, copy the cases back: Explorer -> \\wsl.localhost\$WslName\opt\dfir\cases  <- <saved>\cases"
Write-Host "     (or:  wsl -d $WslName -u root -- cp -a /mnt/<drive>/DFIR-rescue/<date>/cases/. /opt/dfir/cases/ )"
Write-Host "  4. Gumshoe-MoveToDrive.bat so the distro lives on a drive with room"
Finish 1
