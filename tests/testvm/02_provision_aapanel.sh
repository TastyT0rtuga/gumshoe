#!/usr/bin/env bash
# Turn a fresh Ubuntu Server 22.04 VM into a small aaPanel + MariaDB + WordPress host with
# ordinary admin activity and a handful of deliberately planted, BENIGN test conditions that
# Gumshoe's structural checks and the public rule sets should notice. Every action is recorded
# with a timestamp in /root/GROUND_TRUTH.md together with the Gumshoe finding it should produce,
# so the image has an answer key.
#
# Nothing here is malicious: the "signature hit" is the EICAR test file, the "brute force" is
# failed logins against this VM from itself, the new account is a plain sudo user, and so on.
#
# Stages (run as root inside the VM):
#   bash 02_provision_aapanel.sh            # stage 1: aaPanel + stack; prints a 5-minute panel checklist
#   bash 02_provision_aapanel.sh seed       # stage 2 (after the checklist): WordPress, content, activity, answer key, power off
#   bash 02_provision_aapanel.sh seed --dirty   # same, but ends with an abrupt power-off (dirty journal, like a real seizure)
set -uo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }
STAGE="${1:-base}"; DIRTY=0; [ "${2:-}" = "--dirty" ] && DIRTY=1
GT=/root/GROUND_TRUTH.md
SITE="gumshoe-test.local"
WEBROOT="/www/wwwroot/$SITE"
IP=$(hostname -I | awk '{print $1}')

note() {  # note "<what happened>" "<expected gumshoe finding rule or '-'>"
  mkdir -p "$(dirname "$GT")"
  [ -f "$GT" ] || printf "# Ground truth for the Gumshoe test VM\n\n| UTC time | Action | Expected finding |\n| --- | --- | --- |\n" > "$GT"
  printf "| %s | %s | %s |\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" "${2:--}" >> "$GT"
  echo "[gt] $1"
}

if [ "$STAGE" = "base" ]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq && apt-get install -y -qq curl wget sshpass sqlite3 unzip >/dev/null
  note "Base packages installed; VM address $IP; hostname $(hostname)" "-"
  if [ ! -d /www/server/panel ]; then
    echo "== installing aaPanel (official script; answers 'y' to the install prompt)"
    wget -qO /tmp/install_aapanel.sh https://www.aapanel.com/script/install_7.0_en.sh || wget -qO /tmp/install_aapanel.sh https://www.aapanel.com/script/install-ubuntu_6.0_en.sh
    yes y | bash /tmp/install_aapanel.sh aapanel 2>&1 | tee /root/aapanel-install.log | tail -25
    note "aaPanel installed (official installer); install log /root/aapanel-install.log" "aapanel.settings"
  fi
  # known panel credentials for the test VM (test VM only; recorded in the answer key on purpose)
  cd /www/server/panel && python3 tools.py username gumshoe-admin >/dev/null 2>&1 && python3 tools.py panel 'GumshoeTest-2026' >/dev/null 2>&1 && cd /
  PORT=$(cat /www/server/panel/data/port.pl 2>/dev/null || echo "?"); ENTRANCE=$(cat /www/server/panel/data/admin_path.pl 2>/dev/null || echo "/")
  note "Panel credentials set: user gumshoe-admin, password GumshoeTest-2026, port $PORT, entrance $ENTRANCE" "aapanel.user / aapanel.settings"
  # try the panel's own installer for the stack; the UI one-click is the fallback
  if [ -x /www/server/panel/install/install_soft.sh ]; then
    for spec in "nginx 1.24" "php 8.1" "mysql mariadb_10.6" "phpmyadmin 5.2"; do
      set -- $spec
      bash /www/server/panel/install/install_soft.sh 0 install "$1" "$2" >>/root/stack-install.log 2>&1 && note "Installed $1 $2 via the panel installer" "-" || echo "   panel installer did not accept '$spec' (do it in the UI)"
    done
  fi
  cat <<EOF

================  STAGE 1 DONE — now 5 minutes in the panel UI  ================
Open  https://$IP:$PORT$ENTRANCE   (user gumshoe-admin / GumshoeTest-2026; accept the self-signed cert)
  1. If the App Store did not already show nginx, PHP 8.1 and MariaDB 10.6 installed: App Store -> one-click LNMP (nginx, MariaDB 10.6, PHP 8.1).
  2. Website -> Add site: domain  $SITE   with "Create database" (MySQL, utf8mb4) and "Create FTP" ticked; PHP 8.1.
  3. Cron -> Add task: Shell script, name "nightly backup", daily 03:00, script:
        tar czf /www/backup/$SITE.tgz $WEBROOT
  4. Security: note the panel port and SSH port it shows (that is all).
  5. Log out and back in once (the operation log should show two logins from your workstation's address).
Then run:   sudo bash /tmp/02_provision_aapanel.sh seed [--dirty]
EOF
  exit 0
fi

# ---------------------------------------------------------------- stage 2: seed
[ -d "$WEBROOT" ] || { echo "site root $WEBROOT missing — add the site in the panel first"; exit 1; }
DB=$(sqlite3 /www/server/panel/data/default.db "select name,username,password from databases where name like '%gumshoe%' or name like '%test%' limit 1;" 2>/dev/null || true)
DBNAME=${DB%%|*}; REST=${DB#*|}; DBUSER=${REST%%|*}; DBPASS=${REST#*|}
[ -n "$DBNAME" ] || { echo "no database found in the panel DB; create the site with a database first"; exit 1; }
note "Site $SITE exists; panel database $DBNAME user $DBUSER (password in panel DB, test VM only)" "aapanel.cron / webapp.site"

# WordPress via wp-cli
PHP=$(ls -d /www/server/php/8*/bin/php 2>/dev/null | head -1 || which php)
[ -x /usr/local/bin/wp ] || { curl -sSLo /usr/local/bin/wp https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar; chmod +x /usr/local/bin/wp; }
WP="$PHP /usr/local/bin/wp --allow-root --path=$WEBROOT"
rm -f "$WEBROOT/index.html" "$WEBROOT/404.html" 2>/dev/null
$WP core download --quiet 2>/dev/null || true
$WP config create --dbname="$DBNAME" --dbuser="$DBUSER" --dbpass="$DBPASS" --dbhost=127.0.0.1 --skip-check --force --quiet
$WP core install --url="http://$SITE" --title="Gumshoe Test Site" --admin_user=siteowner --admin_password='Owner-Pass-2026' --admin_email=owner@$SITE --skip-email --quiet
for i in 1 2 3 4 5; do $WP post create --post_status=publish --post_title="Company update $i" --post_content="Routine news item $i for the test site." --quiet; done
$WP user create auditor auditor@$SITE --role=administrator --user_pass='Auditor-Pass-2026' --quiet
note "WordPress $($WP core version) installed at $WEBROOT; admins siteowner and auditor (two administrators)" "webapp.site, db.wp_admin x2"
chown -R www:www "$WEBROOT" 2>/dev/null || true

# documents the examiner should be able to find, open and cite
UP="$WEBROOT/wp-content/uploads"; mkdir -p "$UP/2026/10"
printf "invoice,customer,amount,date\nINV-2001,Northwind Traders,1250.50,2026-08-14\nINV-2002,Contoso Ltd,980.00,2026-08-20\n" > "$UP/2026/10/ledger.csv"
printf "# Handover notes\n\n- Backups run nightly at 03:00 via the panel cron task.\n- Contact: owner@%s\n" "$SITE" > "$UP/2026/10/handover.md"
printf "Сайт компании. Резервное копирование выполняется каждую ночь.\n" > "$UP/2026/10/заметки.txt"
printf "Сайт компании. Резервное копирование выполняется каждую ночь.\n" | iconv -f utf-8 -t cp1251 > "$UP/2026/10/notes-cp1251.txt"
note "Documents placed under wp-content/uploads/2026/10: ledger.csv, handover.md, заметки.txt (UTF-8), notes-cp1251.txt (Windows-1251)" "documents.inventory; cyrillic tag; cp1251 detection"

# planted test conditions (all benign)
touch -d "45 days ago" "$UP/2026/10/handover.md"
note "handover.md mtime set 45 days back (ctime is now)" "uac.timestomp (high)"
curl -sSfo "$UP/2026/10/eicar.com.txt" https://secure.eicar.org/eicar.com.txt && note "EICAR test file placed at wp-content/uploads/2026/10/eicar.com.txt (sha256 $(sha256sum "$UP/2026/10/eicar.com.txt" | cut -c1-16)...)" "loki hit (signature-base EICAR rule)" || note "EICAR download failed (no internet?); signature test skipped" "-"
mysqldump -u"$DBUSER" -p"$DBPASS" "$DBNAME" > "$WEBROOT/backup-$(date +%F).sql" 2>/dev/null && note "Database dump written inside the web root: backup-$(date +%F).sql" "weblog.dump_download (after the GET below)"

useradd -m -s /bin/bash deployer && usermod -aG sudo deployer && echo "deployer:Deploy-Pass-2026" | chpasswd
note "OS account 'deployer' created with bash shell and sudo membership" "uac.account_added (high), auth.account_change"
ssh-keygen -q -t ed25519 -N "" -f /root/testkey -C "test-key-not-real" && mkdir -p /root/.ssh && cat /root/testkey.pub >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys
note "SSH public key added to /root/.ssh/authorized_keys (fingerprint $(ssh-keygen -lf /root/testkey.pub | awk '{print $2}'))" "uac.authorized_keys (medium)"
cat > /usr/local/bin/site-backup.sh <<'EOF'
#!/bin/bash
tar czf /www/backup/site-$(date +%F).tgz /www/wwwroot
EOF
chmod +x /usr/local/bin/site-backup.sh; (crontab -l 2>/dev/null; echo "0 4 * * * /usr/local/bin/site-backup.sh") | crontab -
note "Root crontab entry added: 0 4 * * * /usr/local/bin/site-backup.sh (ordinary; should NOT be flagged)" "no uac.cron_suspicious (false-positive check)"
cat > /etc/systemd/system/site-healthcheck.service <<EOF
[Unit]
Description=site health check
[Service]
ExecStart=/usr/bin/curl -s -o /dev/null http://$SITE/
EOF
note "systemd unit site-healthcheck.service created in /etc/systemd/system (ordinary)" "inventory only"

# traffic: ordinary browsing, a few 404s, a login form POST, the dump download, a scanner-style user agent
echo "127.0.0.1 $SITE" >> /etc/hosts
for i in $(seq 1 40); do curl -s -o /dev/null -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/128.0" "http://$SITE/?p=$((i % 5 + 1))"; done
for p in /missing-page /old/brochure.pdf /favicon.ico; do curl -s -o /dev/null "http://$SITE$p"; done
curl -s -o /dev/null -X POST -d "log=siteowner&pwd=wrong" "http://$SITE/wp-login.php"
curl -s -o /dev/null "http://$SITE/backup-$(date +%F).sql"
curl -s -o /dev/null -A "sqlmap/1.8" "http://$SITE/?id=1"
note "HTTP traffic generated from $IP: 40 page views, 3 x 404, 1 failed wp-login POST, 1 GET of the .sql dump, 1 request with a scanner user agent" "goaccess trends; weblog.dump_download; chainsaw/sigma scanner UA (if the rule set has it)"

# SSH noise: 25 failed logins for a non-existent user, from this VM to itself
for i in $(seq 1 25); do sshpass -p wrongpassword ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 -o PreferredAuthentications=password -o PubkeyAuthentication=no nouser@"$IP" true 2>/dev/null; done
note "25 failed SSH logins for user 'nouser' from $IP" "auth.bruteforce (medium; threshold 20)"

# answer-key extras
{
  echo; echo "## Reference values"; echo
  echo "- VM address: $IP"; echo "- Panel: user gumshoe-admin / GumshoeTest-2026, port $(cat /www/server/panel/data/port.pl 2>/dev/null), entrance $(cat /www/server/panel/data/admin_path.pl 2>/dev/null)"
  echo "- Site: $SITE at $WEBROOT; DB $DBNAME / $DBUSER"; echo "- WordPress admins: siteowner, auditor; OS users: testadmin (installer), deployer (seeded)"
  echo "- Planted file hashes:"; for f in "$UP/2026/10/eicar.com.txt" "$UP/2026/10/handover.md" "$UP/2026/10/ledger.csv" "$WEBROOT/backup-$(date +%F).sql"; do [ -f "$f" ] && echo "  - $(sha256sum "$f")"; done
  echo "- Expected NOT to fire: uac.cron_suspicious, uac.uid0, uac.ld_preload, db.udf, aapanel.vhost"
  echo; echo "Shutdown mode: $([ $DIRTY -eq 1 ] && echo 'abrupt (dirty journal; expect noload and MariaDB crash recovery)' || echo 'clean')"
} >> "$GT"
cp "$GT" "$WEBROOT/../GROUND_TRUTH-copy.md" 2>/dev/null || true
echo; echo "== answer key: $GT"; cat "$GT"
sleep 2
if [ $DIRTY -eq 1 ]; then
  echo "abrupt power-off in 5 s (no sync) ..."; sleep 5; echo 1 > /proc/sys/kernel/sysrq; echo o > /proc/sysrq-trigger
else
  sync; poweroff
fi
