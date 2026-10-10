<#
.SYNOPSIS
  Create the Gumshoe test VM in Hyper-V: an Ubuntu Server 22.04 guest that 02_provision_aapanel.sh
  turns into a small aaPanel + MariaDB + WordPress host with a written answer key.

.DESCRIPTION
  Run as Administrator on a Windows 10/11 Pro host with Hyper-V enabled:
      powershell -ExecutionPolicy Bypass -File tests\testvm\01_create_vm.ps1
  Downloads the Ubuntu ISO (verifies SHA-256 against Ubuntu's published SHA256SUMS), creates a
  Generation 2 VM with a 40 GB VHDX on the Default Switch, attaches the ISO and starts it.
  The Ubuntu installer still needs ~8 answers from you (printed at the end). After the first
  boot, copy 02_provision_aapanel.sh into the VM and run it as root.

  The VHDX this creates is the evidence you will later attach to WSL:
      wsl --mount --vhd <path>\gumshoe-test.vhdx --bare
#>
param(
  [string]$Name = "gumshoe-test",
  [string]$VmRoot = "C:\VMs",
  [int]$MemoryGB = 4,
  [int]$Cpus = 2,
  [int]$DiskGB = 40,
  [string]$Switch = "Default Switch",
  [string]$UbuntuRelease = "22.04.5"
)
$ErrorActionPreference = "Stop"
$iso = Join-Path $VmRoot "ubuntu-$UbuntuRelease-live-server-amd64.iso"
$vhd = Join-Path $VmRoot "$Name.vhdx"
New-Item -ItemType Directory -Force -Path $VmRoot | Out-Null

if (-not (Test-Path $iso)) {
  $base = "https://releases.ubuntu.com/$UbuntuRelease"
  Write-Host "downloading $base/$(Split-Path $iso -Leaf) (~2 GB) ..."
  Invoke-WebRequest -Uri "$base/$(Split-Path $iso -Leaf)" -OutFile $iso -UseBasicParsing
  $sums = (Invoke-WebRequest -Uri "$base/SHA256SUMS" -UseBasicParsing).Content
  $expected = ($sums -split "`n" | Where-Object { $_ -match [regex]::Escape((Split-Path $iso -Leaf)) }) -split "\s+" | Select-Object -First 1
  $actual = (Get-FileHash -Algorithm SHA256 $iso).Hash.ToLower()
  if ($expected -and $actual -ne $expected.ToLower()) { Remove-Item $iso; throw "ISO hash mismatch: $actual vs $expected" }
  Write-Host "ISO verified: $actual"
}

if (Get-VM -Name $Name -ErrorAction SilentlyContinue) { throw "VM '$Name' already exists" }
New-VM -Name $Name -Generation 2 -MemoryStartupBytes ($MemoryGB * 1GB) -NewVHDPath $vhd -NewVHDSizeBytes ($DiskGB * 1GB) -SwitchName $Switch | Out-Null
Set-VMProcessor -VMName $Name -Count $Cpus
Set-VMMemory -VMName $Name -DynamicMemoryEnabled $false
Set-VMFirmware -VMName $Name -EnableSecureBoot On -SecureBootTemplate "MicrosoftUEFICertificateAuthority"
Add-VMDvdDrive -VMName $Name -Path $iso
$dvd = Get-VMDvdDrive -VMName $Name
Set-VMFirmware -VMName $Name -FirstBootDevice $dvd
Set-VM -Name $Name -CheckpointType Disabled -AutomaticStopAction ShutDown
Start-VM -Name $Name
vmconnect.exe localhost $Name

Write-Host @"

VM '$Name' is booting the Ubuntu installer. Answer it like this:
  language English  |  keyboard default  |  "Ubuntu Server"  |  network: default (DHCP)  |  no proxy
  mirror default    |  storage: "Use an entire disk" (leave LVM ticked)  |  confirm
  profile: name test, server name gumshoe-test, username testadmin, a password you will remember
  "Install OpenSSH server": YES    |  no snaps    |  reboot when prompted (the ISO is ejected automatically on reboot)

Then, from this PowerShell window (get the VM's address with:  Get-VM $Name | Select -Expand NetworkAdapters | Select -Expand IPAddresses):
  scp tests\testvm\02_provision_aapanel.sh testadmin@<ip>:/tmp/
  ssh testadmin@<ip> "sudo bash /tmp/02_provision_aapanel.sh"
The provisioning script takes 15-30 minutes, writes /root/GROUND_TRUTH.md, and powers the VM off.
Evidence disk: $vhd
"@
