#!/usr/bin/env bash
# Offline install inside the imported WSL distro (no network).
# Usage: bash /mnt/c/DFIR/gumshoe/setup/wsl/02_install_offline.sh -b /mnt/d/gumshoe-transfer [-d /opt/dfir]
set -euo pipefail
BUNDLE=""; DEST="/opt/dfir"
while getopts "b:d:" o; do case "$o" in b) BUNDLE="$OPTARG";; d) DEST="$OPTARG";; esac; done
[ -n "$BUNDLE" ] || { echo "usage: $0 -b /mnt/<drive>/gumshoe-transfer [-d /opt/dfir]"; exit 1; }
[ -d "$BUNDLE/gumshoe" ] || { echo "bundle not found at $BUNDLE"; exit 1; }
SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"

echo "== project -> $DEST/gumshoe"
$SUDO mkdir -p "$DEST/tools" "$DEST/cases"
$SUDO rsync -a --delete --exclude cases --exclude __pycache__ "$BUNDLE/gumshoe/" "$DEST/gumshoe/" 2>/dev/null || $SUDO cp -r "$BUNDLE/gumshoe/." "$DEST/gumshoe/"
$SUDO chown -R "$(id -u):$(id -g)" "$DEST"
ln -sfn "$DEST/cases" "$DEST/gumshoe/cases"

echo "== python venv from wheels/linux"
python3 -m venv "$DEST/venv"
"$DEST/venv/bin/pip" install --no-index --find-links "$BUNDLE/wheels/linux" -r "$DEST/gumshoe/requirements.txt"

echo "== UAC"
UAC_TGZ=$(ls "$BUNDLE"/tools/uac/uac-*.tar.gz 2>/dev/null | head -1 || true)
if [ -n "$UAC_TGZ" ]; then
  mkdir -p "$DEST/tools/uac" && tar xzf "$UAC_TGZ" -C "$DEST/tools/uac" --strip-components=1
  chmod +x "$DEST/tools/uac/uac"
  $SUDO ln -sfn "$DEST/tools/uac/uac" /usr/local/bin/uac
else echo "   (no UAC tarball in bundle)"; fi

echo "== Loki + signature-base"
if [ -d "$BUNDLE/tools/loki/Loki" ]; then
  mkdir -p "$DEST/tools" && cp -r "$BUNDLE/tools/loki/Loki" "$DEST/tools/loki"
  "$DEST/venv/bin/pip" install --no-index --find-links "$BUNDLE/wheels/linux" -r "$DEST/tools/loki/requirements.txt" || echo "   (some Loki deps missing from wheels; see docs/TOOLS.md)"
  cat > "$DEST/tools/loki.sh" <<EOF
#!/usr/bin/env bash
cd "$DEST/tools/loki" && exec "$DEST/venv/bin/python" loki.py "\$@"
EOF
  chmod +x "$DEST/tools/loki.sh"; $SUDO ln -sfn "$DEST/tools/loki.sh" /usr/local/bin/loki
else echo "   (no Loki in bundle)"; fi

echo "== Chainsaw + Sigma"
CS_ZIP=$(ls "$BUNDLE"/tools/chainsaw/chainsaw_all_platforms*.zip 2>/dev/null | head -1 || true)
if [ -n "$CS_ZIP" ]; then
  mkdir -p "$DEST/tools/chainsaw" && unzip -qo "$CS_ZIP" -d "$DEST/tools/chainsaw"
  BIN=$(find "$DEST/tools/chainsaw" -type f -name chainsaw -path '*x86_64-unknown-linux*' | head -1 || true)
  [ -z "$BIN" ] && BIN=$(find "$DEST/tools/chainsaw" -type f -name chainsaw | head -1 || true)
  if [ -n "$BIN" ]; then chmod +x "$BIN"; $SUDO ln -sfn "$BIN" /usr/local/bin/chainsaw; fi
else echo "   (no Chainsaw zip in bundle)"; fi
if [ -d "$BUNDLE/tools/sigma/sigma" ]; then
  mkdir -p "$DEST/gumshoe/tools" && rm -rf "$DEST/gumshoe/tools/sigma" && cp -r "$BUNDLE/tools/sigma/sigma" "$DEST/gumshoe/tools/sigma"
fi

echo "== Ollama endpoint for config.yaml"
CFG="$DEST/gumshoe/config.yaml"
if curl -s -m 2 http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
  echo "   Ollama reachable at 127.0.0.1 (mirrored networking)"
else
  HOSTIP=$(ip route 2>/dev/null | awk '/default/ {print $3; exit}')
  if [ -n "$HOSTIP" ] && curl -s -m 2 "http://$HOSTIP:11434/api/tags" >/dev/null 2>&1; then
    sed -i "s#base_url: http://127.0.0.1:11434#base_url: http://$HOSTIP:11434#" "$CFG"
    echo "   Ollama reachable at $HOSTIP (config.yaml updated)"
  else
    echo "   Ollama not reachable yet; start it on Windows (ollama-pcores.cmd) and set llm.base_url in config.yaml if needed"
  fi
fi

echo "== launcher"
cat > "$DEST/gumshoe/gumshoe" <<EOF
#!/usr/bin/env bash
exec "$DEST/venv/bin/python" "$DEST/gumshoe/gumshoe.py" "\$@"
EOF
chmod +x "$DEST/gumshoe/gumshoe"; $SUDO ln -sfn "$DEST/gumshoe/gumshoe" /usr/local/bin/gumshoe
echo
echo "installed. Next: bash $DEST/gumshoe/setup/wsl/03_verify_offline.sh"
