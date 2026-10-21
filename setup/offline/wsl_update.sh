#!/usr/bin/env bash
# Run by the launcher (as root in the distro) after it synced the project from the bundle: installs any
# Ubuntu package the bundle's debs/ folder carries that the distro does not have yet (an update to the
# bundle can add tools, e.g. 7zip and afflib-tools, without reinstalling), and prepares the hopper.
#   bash wsl_update.sh <bundle path inside WSL>
set -uo pipefail
B="${1:-}"
[ -d "$B" ] || { echo "update: bundle not found: $B"; exit 0; }
want="7zip afflib-tools"      # packages added after the first release; others ride along with first_run
todo=()
for p in $want; do
  dpkg-query -W -f='${Status}\n' "$p" 2>/dev/null | grep -q "install ok installed" && continue
  f=$(ls "$B"/debs/${p}_*.deb 2>/dev/null | head -1)
  [ -n "$f" ] && todo+=("$f")
done
if [ ${#todo[@]} -gt 0 ]; then
  echo "update: installing ${#todo[@]} package(s) from the bundle: ${todo[*]##*/}"
  DEBIAN_FRONTEND=noninteractive dpkg -i "${todo[@]}" 2>&1 | tail -3 || true
fi
# the MySQL 8.0 engine: unpacked (dpkg -x), never installed, so it cannot collide with MariaDB
if ls "$B"/debs/mysql8/*.deb >/dev/null 2>&1; then
  stamp=$(ls "$B"/debs/mysql8/*.deb | xargs -n1 basename | sort | sha256sum | cut -c1-16)
  if [ "$(cat /opt/dfir/mysql8/.stamp 2>/dev/null)" != "$stamp" ]; then
    echo "update: unpacking the MySQL 8.0 engine into /opt/dfir/mysql8"
    rm -rf /opt/dfir/mysql8 && mkdir -p /opt/dfir/mysql8
    for d in "$B"/debs/mysql8/*.deb; do dpkg -x "$d" /opt/dfir/mysql8; done
    echo "$stamp" > /opt/dfir/mysql8/.stamp
  fi
fi
mkdir -p /mnt/c/DFIR/hopper /mnt/c/DFIR/exports /opt/dfir/images /opt/dfir/trees 2>/dev/null || true
exit 0
