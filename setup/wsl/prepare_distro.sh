#!/usr/bin/env bash
# Provision the WSL analysis distro on the ONLINE machine (run as root inside Ubuntu),
# then `wsl --export` it. 01_prepare_online.ps1 calls this automatically.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update
# kpartx + qemu-utils (qemu-nbd) are for setup/wsl/mount_image.sh: partitions in raw images, VHDX/VMDK
apt-get install -y --no-install-recommends \
  ewf-tools sleuthkit goaccess mariadb-server mariadb-client \
  python3 python3-venv python3-pip git jq unzip tar gzip bzip2 xz-utils ca-certificates \
  yara libyara-dev build-essential python3-dev \
  lvm2 mdadm ntfs-3g kpartx qemu-utils \
  poppler-utils catdoc antiword        # pdftotext, catdoc/xls2csv, antiword for document text extraction
# the server must never auto-start; Gumshoe starts a private mariadbd on a copy when asked
systemctl disable --now mariadb 2>/dev/null || service mariadb stop 2>/dev/null || true
# a place for everything
mkdir -p /opt/dfir/tools /opt/dfir/cases
cat > /etc/wsl.conf <<'EOF'
[boot]
systemd=false
[automount]
options = "metadata"
EOF
echo "distro provisioned; export it with: wsl --export <name> dfir-ubuntu.tar"
