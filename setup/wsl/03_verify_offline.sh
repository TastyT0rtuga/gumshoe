#!/usr/bin/env bash
# Verify the offline install, then run the self-test. Nothing here touches evidence.
# Usage: 03_verify_offline.sh [--online]   (--online: dev/test box with internet; skips the no-network check)
set -u
DEST="${DEST:-/opt/dfir}"
ONLINE=0; [ "${1:-}" = "--online" ] && ONLINE=1
PY="$DEST/venv/bin/python"
ok=0; bad=0
chk() { if eval "$2" >/dev/null 2>&1; then echo "  [ OK ] $1"; ok=$((ok+1)); else echo "  [FAIL] $1"; bad=$((bad+1)); fi; }

echo "== binaries"
chk "python venv"        "test -x $PY"
chk "sqlite FTS5"        "$PY -c \"import sqlite3; c=sqlite3.connect(':memory:'); c.execute('create virtual table t using fts5(x)')\""
chk "pyyaml/streamlit"   "$PY -c 'import yaml, streamlit, pandas'"
chk "uac"                "command -v uac && uac --version"
chk "loki"               "command -v loki"
chk "chainsaw"           "command -v chainsaw && chainsaw --version"
chk "goaccess"           "command -v goaccess && goaccess --version"
chk "ewfmount"           "command -v ewfmount"
chk "sleuthkit (fls)"    "command -v fls"
chk "mariadbd"           "command -v mariadbd && command -v mariadb"
chk "sigma rules"        "test -d $DEST/gumshoe/tools/sigma/rules"
chk "signature-base"     "test -d $DEST/tools/loki/signature-base/yara"

echo "== AI assistant (optional: a switch in Gumshoe, off by default; nothing in the evidence depends on it)"
URL=$(grep -E '^\s*base_url:' "$DEST/gumshoe/config.yaml" | awk '{print $2}')
if curl -s -m 3 "$URL/api/tags" >/dev/null 2>&1; then
  echo "  [ OK ] ollama reachable at $URL (the assistant can be turned on in the sidebar)"
  echo "  models:"; curl -s "$URL/api/tags" | "$PY" -c 'import json,sys; [print("   -", m["name"]) for m in json.load(sys.stdin).get("models", [])]'
else
  echo "  [ -- ] no Ollama at $URL: the AI assistant is unavailable (lite bundle, or Ollama not running); everything else works"
fi

if [ "$ONLINE" -eq 1 ]; then
  echo "== network check skipped (--online: this is a development box, never a sandbox)"
else
  echo "== network must be absent"
  chk "no route to the internet" "! curl -s -m 3 https://example.com"
fi

echo "== self-test (plumbing on a benign synthetic tree)"
if "$PY" "$DEST/gumshoe/gumshoe.py" selftest | tail -1 | grep -q OK; then echo "  [ OK ] selftest"; ok=$((ok+1)); else echo "  [FAIL] selftest"; bad=$((bad+1)); fi

echo
echo "$ok ok, $bad failed"
[ "$bad" -eq 0 ]
