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
mkdir -p /mnt/c/DFIR/hopper /mnt/c/DFIR/exports /opt/dfir/images /opt/dfir/trees 2>/dev/null || true
exit 0
