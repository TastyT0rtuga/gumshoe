#!/usr/bin/env bash
# Gumshoe offline provisioning. Runs INSIDE the freshly imported WSL distro as root.
# Gumshoe.bat calls this on first run; nothing here needs the network.
#
#   usage: bash wsl_provision.sh <bundle path as seen from WSL>  [<install dir, default /opt/dfir>]
#   e.g.   bash /mnt/e/Gumshoe-offline/gumshoe/setup/offline/wsl_provision.sh /mnt/e/Gumshoe-offline
#
# What it does (idempotent; re-run after a failure and it carries on):
#   1. installs the Ubuntu packages shipped in debs/ through a local apt repository (correct ordering,
#      no network): GoAccess, ewf-tools, Sleuth Kit, MariaDB, LVM/mdadm/kpartx/qemu-utils/ntfs-3g,
#      poppler-utils, catdoc, antiword, python3 + venv, git, jq, rsync, curl, unzip
#   2. copies the Gumshoe project to <dest>/gumshoe
#   3. builds the Python venv from wheels/linux (pip --no-index)
#   4. unpacks UAC, Loki + signature-base, Chainsaw (+ its Sigma mappings) and the Sigma rules
#   5. writes /etc/wsl.conf, the `gumshoe` launcher, and a marker file
set -uo pipefail
B="${1:?bundle path (as seen from WSL, e.g. /mnt/e/Gumshoe-offline)}"
DEST="${2:-/opt/dfir}"
export DEBIAN_FRONTEND=noninteractive
LOG=/var/log/gumshoe-provision.log
log(){ echo; echo "== $*" | tee -a "$LOG"; }
die(){ echo "FAILED: $*" | tee -a "$LOG"; echo "   (details: $LOG)"; exit 1; }
[ "$(id -u)" -eq 0 ] || die "run as root (wsl -d DFIR -u root)"
[ -d "$B/debs" ] && [ -d "$B/gumshoe" ] || die "no bundle at $B (expected debs/ and gumshoe/ inside it)"
mkdir -p "$DEST" "$(dirname "$LOG")"; : > "$LOG"

PKGS="ca-certificates python3 python3-venv python3-pip git jq unzip xz-utils bzip2 rsync curl file less
      ewf-tools sleuthkit goaccess mariadb-server mariadb-client lvm2 mdadm ntfs-3g kpartx qemu-utils
      poppler-utils catdoc antiword 7zip afflib-tools"

log "1/5 Ubuntu packages from $B/debs (offline)"
# services must never start during install (no systemd in this distro anyway)
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d; chmod +x /usr/sbin/policy-rc.d
# local copy of the repo: avoids drvfs quirks and spaces in the Windows path
REPO="$DEST/.apt-offline"; mkdir -p "$REPO"
if ! cmp -s "$B/debs/Packages.gz" "$REPO/Packages.gz" 2>/dev/null; then
  cp -f "$B"/debs/*.deb "$B/debs/Packages.gz" "$REPO/" >>"$LOG" 2>&1 || die "copying debs"   # (rsync is not installed yet)
fi
# the online Ubuntu sources would only produce errors on an air-gapped box; park them
for s in /etc/apt/sources.list.d/ubuntu.sources /etc/apt/sources.list; do
  [ -s "$s" ] && mv -f "$s" "$s.disabled-offline" 2>/dev/null || true
done
echo "deb [trusted=yes] file:$REPO ./" > /etc/apt/sources.list.d/gumshoe-offline.list
apt-get update >>"$LOG" 2>&1 || die "apt-get update against the local repository"
# shellcheck disable=SC2086
apt-get install -y --no-install-recommends $PKGS >>"$LOG" 2>&1 || die "apt-get install (see $LOG)"
for b in goaccess ewfmount fls mariadbd kpartx qemu-nbd lvs pdftotext python3 rsync unzip jq; do
  command -v "$b" >/dev/null || die "$b missing after install"
done
echo "   packages ok" | tee -a "$LOG"

log "2/5 project -> $DEST/gumshoe"
mkdir -p "$DEST/tools" "$DEST/cases"
rsync -a --delete --exclude cases --exclude __pycache__ --exclude .git "$B/gumshoe/" "$DEST/gumshoe/" >>"$LOG" 2>&1 || die "copying project"
ln -sfn "$DEST/cases" "$DEST/gumshoe/cases"

log "3/5 python venv from wheels (offline)"
[ -x "$DEST/venv/bin/python" ] || python3 -m venv "$DEST/venv" >>"$LOG" 2>&1 || die "venv"
"$DEST/venv/bin/pip" install --no-index --find-links "$B/wheels/linux" -r "$B/wheels/requirements-wsl.txt" >>"$LOG" 2>&1 || die "pip install from wheels"
"$DEST/venv/bin/python" -c "import yaml, streamlit, pandas, openpyxl, pypdf, yara, psutil" >>"$LOG" 2>&1 || die "python imports"
echo "   venv ok" | tee -a "$LOG"

log "4/5 tools"
# UAC
rm -rf "$DEST/tools/uac"; mkdir -p "$DEST/tools/uac"
tar xzf "$B/tools/uac/uac.tar.gz" -C "$DEST/tools/uac" --strip-components=1 || die "uac"
chmod +x "$DEST/tools/uac/uac"
cat > "$DEST/tools/uac.sh" <<EOF
#!/usr/bin/env bash
# UAC must run from its own directory; Gumshoe passes absolute paths so this is safe
cd "$DEST/tools/uac" && exec ./uac "\$@"
EOF
chmod +x "$DEST/tools/uac.sh"; ln -sfn "$DEST/tools/uac.sh" /usr/local/bin/uac
# Loki + signature-base (Loki looks for ./signature-base next to loki.py)
rm -rf "$DEST/tools/loki"; mkdir -p "$DEST/tools/loki/signature-base"
tar xzf "$B/tools/loki/Loki.tar.gz" -C "$DEST/tools/loki" --strip-components=1 || die "loki"
tar xzf "$B/tools/loki/signature-base.tar.gz" -C "$DEST/tools/loki/signature-base" --strip-components=1 || die "signature-base"
cat > "$DEST/tools/loki.sh" <<EOF
#!/usr/bin/env bash
cd "$DEST/tools/loki" && exec "$DEST/venv/bin/python" loki.py "\$@"
EOF
chmod +x "$DEST/tools/loki.sh"; ln -sfn "$DEST/tools/loki.sh" /usr/local/bin/loki
# Chainsaw (static binary) + its mappings
rm -rf "$DEST/tools/chainsaw"; mkdir -p "$DEST/tools/chainsaw"
unzip -qo "$B"/tools/chainsaw/chainsaw_all_platforms*.zip -d "$DEST/tools/chainsaw" || die "chainsaw unzip"
CS=$(find "$DEST/tools/chainsaw" -type f -name 'chainsaw_x86_64-unknown-linux-gnu' | head -1)
[ -n "$CS" ] || die "chainsaw linux binary not in zip"
chmod +x "$CS"; ln -sfn "$CS" /usr/local/bin/chainsaw
# Sigma rules where config.yaml expects them (tools/sigma/rules under the project)
rm -rf "$DEST/gumshoe/tools/sigma"; mkdir -p "$DEST/gumshoe/tools/sigma"
tar xzf "$B/tools/sigma/sigma.tar.gz" -C "$DEST/gumshoe/tools/sigma" --strip-components=1 || die "sigma"
for b in uac loki chainsaw; do command -v "$b" >/dev/null || die "$b launcher missing"; done
echo "   uac, loki (+signature-base), chainsaw, sigma rules ok" | tee -a "$LOG"

log "5/5 wsl.conf, launcher"
cat > /etc/wsl.conf <<'EOF'
[boot]
systemd=false
[automount]
options = "metadata"
[network]
generateResolvConf = false
EOF
# an air-gapped box has no DNS; a static resolv.conf stops WSL re-writing it every boot
rm -f /etc/resolv.conf; printf 'nameserver 127.0.0.1\n' > /etc/resolv.conf
mkdir -p "$DEST/bin"
cat > "$DEST/bin/gumshoe" <<EOF
#!/usr/bin/env bash
exec "$DEST/venv/bin/python" "$DEST/gumshoe/gumshoe.py" "\$@"
EOF
chmod +x "$DEST/bin/gumshoe"; ln -sfn "$DEST/bin/gumshoe" /usr/local/bin/gumshoe
ln -sfn "$DEST/gumshoe/setup/wsl/mount_image.sh" /usr/local/bin/mount_image 2>/dev/null || true
bash "$DEST/gumshoe/setup/offline/wsl_update.sh" "$B" 2>&1 | tail -3 || true     # extras: 7zip/afflib, the MySQL 8 engine, folders
date -u +"%Y-%m-%dT%H:%M:%SZ" > "$DEST/.provisioned"
echo
echo "provisioned: $DEST  (log: $LOG)"
echo "verify with: bash $DEST/gumshoe/setup/wsl/03_verify_offline.sh"
