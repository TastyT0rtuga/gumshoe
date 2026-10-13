# The offline bundle (`Gumshoe-offline/`)

One folder that installs and runs Gumshoe on an air-gapped Windows 11 machine with **no network at any
point**. Copy it over on a portable drive, double-click `Gumshoe.bat`, done. `setup/offline/` holds every
script it uses; this page says what is in it and how it was built so it can be rebuilt or audited.

## What the user does

1. Copy `Gumshoe-offline` to the sandbox (path without spaces; exFAT/NTFS drive, one model file is 4.7 GB).
2. Double-click **`Gumshoe.bat`**. First run (`setup/offline/first_run.ps1`, elevated once):
   verifies the bundle → installs Ollama + copies the model store → installs WSL from the MSI and enables
   Virtual Machine Platform if missing (one reboot, then double-click again) → writes `.wslconfig` →
   `wsl --import` of the Ubuntu rootfs as **DFIR** → `wsl_provision.sh` inside it → verification → marker.
3. Every later run (`setup/offline/gumshoe.ps1`): start Ollama pinned to the P-cores, make sure the distro
   can reach it (mirrored networking → 127.0.0.1, otherwise the host address is written into
   `config.yaml`), start `gumshoe ui` in the distro, open `http://localhost:8501`.
4. `Gumshoe-Selftest.bat` re-runs `setup/wsl/03_verify_offline.sh` (tools, venv, models, *no network*, self-test).

## Layout

| path | what | how it is verified on the sandbox |
|---|---|---|
| `Gumshoe.bat`, `Gumshoe-Selftest.bat`, `START-HERE.txt` | entry points | `SHA256SUMS.txt` |
| `gumshoe/` | this repository (no `.git`) | `SHA256SUMS.txt` |
| `ollama/OllamaSetup.exe` | Ollama installer | `SHA256SUMS.txt` (hash taken from the release's `sha256sum.txt`) + Authenticode |
| `models/manifests/…`, `models/blobs/sha256-*` | an Ollama model store: `qwen2.5:3b-instruct`, `qwen2.5:7b-instruct-q4_K_M`, `nomic-embed-text`, `bge-m3` | every blob is hashed and compared with its own file name |
| `wsl/wsl.msi` | WSL (kernel included) | `SHA256SUMS.txt` + Authenticode |
| `wsl/rootfs.tar.gz` | pristine `ubuntu-base-24.04.5-base-amd64.tar.gz` | `SHA256SUMS.txt` |
| `debs/*.deb`, `debs/Packages.gz` | the full dependency closure of the forensic packages on that rootfs, as a local apt repository | `SHA256SUMS.txt`; apt installs by exact version |
| `wheels/linux/*.whl`, `wheels/requirements-wsl.txt` | manylinux wheels for Python 3.12: Gumshoe + Loki requirements | `SHA256SUMS.txt`; `pip --no-index` |
| `tools/chainsaw/…zip`, `tools/uac/uac.tar.gz`, `tools/loki/{Loki,signature-base}.tar.gz`, `tools/sigma/sigma.tar.gz` | Chainsaw release (all platforms + rules), UAC, Loki, signature-base, Sigma (GitHub archives) | `SHA256SUMS.txt` |

Installed on the sandbox: `C:\DFIR\` (`first-run.log`, `.installed`, `wsl\DFIR` virtual disk),
`%USERPROFILE%\.ollama\models`, and inside the distro `/opt/dfir/{gumshoe,venv,tools,cases,bin}` with
`uac`, `loki`, `chainsaw`, `gumshoe`, `mount_image` on `PATH`.

## How it was built (and how to rebuild it)

Everything was downloaded on an internet-connected machine and checked before it went into the folder:

- **Ubuntu packages.** `ubuntu-base-24.04.5` was extracted into a chroot, `apt-get update` run, and
  `apt-get install --no-install-recommends --print-uris` used to list the exact `.deb` URLs, sizes and
  checksums for: `ca-certificates python3 python3-venv python3-pip git jq unzip xz-utils bzip2 rsync curl
  file less ewf-tools sleuthkit goaccess mariadb-server mariadb-client lvm2 mdadm ntfs-3g kpartx qemu-utils
  poppler-utils catdoc antiword` (163 packages, 80 MB). The files were downloaded from
  `archive.ubuntu.com`/`security.ubuntu.com`, each checked against apt's checksum, and indexed with
  `dpkg-scanpackages` into `Packages.gz`. No compiler toolchain is needed: every Python dependency with
  C code (yara-python, psutil, numpy, pandas, pyarrow, pillow, …) ships as a manylinux wheel.
- **Wheels.** `pip download -r wheels/requirements-wsl.txt --only-binary=:all: --python-version 3.12
  --platform manylinux_2_17_x86_64 … --platform any` (49 wheels, 114 MB).
- **Models.** Pulled straight from `registry.ollama.ai` (manifest + blobs) and laid out exactly as
  `ollama pull` does, so Ollama sees them as already pulled. Blob names are their SHA-256.
- **Validation.** The provisioning script was run against the *pristine* rootfs in a chroot with the
  bundle bind-mounted and no DNS: apt installed from the local repository, pip from the wheels, the tools
  unpacked, and `03_verify_offline.sh` passed every check (13/13; the Ollama check is Windows-side) and
  Gumshoe's own 53-check self-test. Versions in this build: Ollama 0.40.3, WSL 3.0.3, Ubuntu 24.04.5,
  Python 3.12.3, Streamlit 1.65.0, yara-python 4.5.4, Chainsaw 2.16.5, UAC 3.4.0, GoAccess 1.8.1,
  MariaDB 10.11.14, Sleuth Kit 4.12.1, Loki / signature-base / Sigma at their `master` of the build date.

To refresh the bundle later (new signatures, new Sigma rules, a newer model): replace that one archive
or model store, regenerate `SHA256SUMS.txt` (`sha256sum` over everything except `models/blobs`), and
re-run `first_run.ps1` with `C:\DFIR\.installed` deleted. `setup/windows/01_prepare_online.ps1` remains
as the scripted alternative for building a bundle from a Windows machine with WSL.

## Things to know

- Arsenal Image Mounter is **not** included (registration-gated download). `setup/wsl/mount_image.sh`
  (`mount_image` inside the distro) mounts E01/raw/VHDX/VMDK and LVM volumes read-only without it.
- Plaso and ClamAV (off by default; `gumshoe deep` can enable them) are not in this bundle.
- The elevated first run installs Ollama for the account that approved the UAC prompt; use the account you
  will work from (it must be an administrator), as on any single-examiner sandbox.
- Memory on a 16 GB machine: `.wslconfig` caps the distro at 5 GB; the 7B model needs about 5.5 GB on the
  Windows side. Don't run the deep profile with both 7B and vectors while the UI is open on 3B.
