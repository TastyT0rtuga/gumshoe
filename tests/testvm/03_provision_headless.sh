#!/usr/bin/env bash
# Headless variant of 02_provision_aapanel.sh: builds the same aaPanel + MariaDB + WordPress test host
# with NO panel-UI step, so it can run unattended (cloud-init in a VM). The site, database, FTP account
# and cron task are created through the panel's own Python API (what its UI calls); if that fails, the
# equivalent records and files are written directly. Then the seed stage of 02_provision_aapanel.sh runs.
#
#   bash 03_provision_headless.sh [--dirty]      # as root, with internet; ends with power-off
set -uo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
DIRTY="${1:-}"
SITE="gumshoe-test.local"; WEBROOT="/www/wwwroot/$SITE"; DBNAME="gumshoe_test"; DBPASS="GumshoeDb-2026"
GT=/root/GROUND_TRUTH.md
note(){ mkdir -p "$(dirname "$GT")"; [ -f "$GT" ] || printf "# Ground truth for the Gumshoe test VM\n\n| UTC time | Action | Expected finding |\n| --- | --- | --- |\n" > "$GT"
       printf "| %s | %s | %s |\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" "${2:--}" >> "$GT"; echo "[gt] $1"; }
step(){ echo; echo "=== $(date -u +%H:%M:%S) $*"; }
export DEBIAN_FRONTEND=noninteractive

step "base packages"
apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq curl wget sshpass sqlite3 unzip php-cli php-mysql >/dev/null 2>&1
sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config; systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
IP=$(hostname -I | awk '{print $1}')
note "Base packages installed; VM address $IP; hostname $(hostname); $(. /etc/os-release; echo "$PRETTY_NAME")" "-"

step "aaPanel install (official script)"
if [ ! -d /www/server/panel ]; then
  wget -qO /tmp/install_aapanel.sh https://www.aapanel.com/script/install_7.0_en.sh || wget -qO /tmp/install_aapanel.sh https://www.aapanel.com/script/install-ubuntu_6.0_en.sh
  timeout 3600 bash -c 'yes y | bash /tmp/install_aapanel.sh aapanel' > /root/aapanel-install.log 2>&1
  tail -15 /root/aapanel-install.log
fi
[ -d /www/server/panel ] || { echo "aaPanel did not install; see /root/aapanel-install.log"; note "aaPanel install FAILED" "-"; }
note "aaPanel installed (official installer); install log /root/aapanel-install.log" "aapanel.settings"
PY=/www/server/panel/pyenv/bin/python3; [ -x "$PY" ] || PY=python3
cd /www/server/panel && $PY tools.py username gumshoe-admin >/dev/null 2>&1; $PY tools.py panel 'GumshoeTest-2026' >/dev/null 2>&1; cd /
PORT=$(cat /www/server/panel/data/port.pl 2>/dev/null || echo "?"); ENTRANCE=$(cat /www/server/panel/data/admin_path.pl 2>/dev/null || echo "/")
note "Panel credentials set: user gumshoe-admin, password GumshoeTest-2026, port $PORT, entrance $ENTRANCE" "aapanel.user / aapanel.settings"

step "stack via the panel installer (precompiled where available)"
if [ -x /www/server/panel/install/install_soft.sh ]; then
  for spec in "mysql mariadb_10.6" "nginx 1.24" "php 8.1"; do
    set -- $spec
    timeout 5400 bash /www/server/panel/install/install_soft.sh 0 install "$1" "$2" >>/root/stack-install.log 2>&1 && note "Installed $1 $2 via the panel installer" "-" || echo "   panel installer failed/timed out for '$spec' (see /root/stack-install.log)"
  done
fi
ls -d /www/server/mysql /www/server/nginx /www/server/php/* 2>/dev/null
# the panel's MariaDB must be up for the site/DB creation; fall back to the distro's if it is not
if ! mysqladmin ping >/dev/null 2>&1 && [ -x /etc/init.d/mysqld ]; then /etc/init.d/mysqld start >/dev/null 2>&1; sleep 5; fi
if ! mysqladmin ping >/dev/null 2>&1; then
  apt-get install -y -qq mariadb-server >/dev/null 2>&1; systemctl start mariadb; note "Panel MariaDB unavailable; distro mariadb-server used instead" "-"
fi

step "site + database + FTP + cron through the panel API"
cat > /tmp/panel_api.py <<PYEOF
import json, os, sys
os.chdir('/www/server/panel'); sys.path.insert(0, '/www/server/panel/class'); sys.path.insert(0, '/www/server/panel')
import public
def obj(**kw):
    g = public.dict_obj()
    for k, v in kw.items(): setattr(g, k, v)
    return g
import panelSite
r = panelSite.panelSite().AddSite(obj(webname=json.dumps({"domain": "$SITE", "domainlist": [], "count": 0}), path="$WEBROOT",
        type_id=0, type="PHP", version=(os.listdir('/www/server/php')[0] if os.path.isdir('/www/server/php') and os.listdir('/www/server/php') else '00'),
        port="80", ps="gumshoe test site", ftp="true", ftp_username="gumshoe_ftp", ftp_password="GumshoeFtp-2026",
        sql="MySQL", codeing="utf8mb4", datauser="$DBNAME", datapassword="$DBPASS", set_ssl=0, force_ssl=0))
print("AddSite:", r)
import crontab
r = crontab.crontab().AddCrontab(obj(name="nightly backup", type="day", where1="", hour="3", minute="0", week="", sType="toShell",
        sName="", backupTo="localhost", save="3", urladdress="", sBody="tar czf /www/backup/$SITE.tgz $WEBROOT", notice="0", notice_channel=""))
print("AddCrontab:", r)
for ip in ("10.0.2.2", "10.0.2.2"):
    public.WriteLog("Login", "Login successful, login IP: %s" % ip)
print("ok")
PYEOF
$PY /tmp/panel_api.py 2>&1 | tail -5
if [ ! -d "$WEBROOT" ]; then
  echo "   panel API did not create the site; writing the equivalent records directly"
  mkdir -p "$WEBROOT" /www/wwwlogs /www/backup; echo "<h1>gumshoe-test</h1>" > "$WEBROOT/index.html"; chown -R www:www "$WEBROOT" 2>/dev/null || true
  mysql -e "CREATE DATABASE IF NOT EXISTS \`$DBNAME\` DEFAULT CHARSET utf8mb4; CREATE USER IF NOT EXISTS '$DBNAME'@'localhost' IDENTIFIED BY '$DBPASS'; GRANT ALL ON \`$DBNAME\`.* TO '$DBNAME'@'localhost'; FLUSH PRIVILEGES;" 2>&1 | tail -1
  DBF=/www/server/panel/data/default.db
  sqlite3 "$DBF" "insert into sites(name,path,status,ps,addtime,type_id) values('$SITE','$WEBROOT','1','gumshoe test site','$(date '+%F %T')',0);" 2>&1
  SID=$(sqlite3 "$DBF" "select id from sites where name='$SITE';")
  sqlite3 "$DBF" "insert into domain(pid,name,port,addtime) values($SID,'$SITE',80,'$(date '+%F %T')');" 2>&1
  sqlite3 "$DBF" "insert into databases(pid,name,username,password,accept,ps,addtime,type) values($SID,'$DBNAME','$DBNAME','$DBPASS','localhost','$SITE','$(date '+%F %T')','MySQL');" 2>&1
  sqlite3 "$DBF" "insert into crontab(name,type,where1,where_hour,where_minute,echo,addtime,status,save,backupTo,sType,sBody,sName,urladdress) values('nightly backup','day','','3','0','gumshoe-nightly','$(date '+%F %T')',1,3,'localhost','toShell','tar czf /www/backup/$SITE.tgz $WEBROOT','','');" 2>&1
  mkdir -p /www/server/cron /www/server/panel/vhost/nginx; printf '#!/bin/bash\nPATH=/bin:/usr/bin:/usr/local/bin\ntar czf /www/backup/%s.tgz %s\n' "$SITE" "$WEBROOT" > /www/server/cron/gumshoe-nightly; chmod 750 /www/server/cron/gumshoe-nightly
  (crontab -l 2>/dev/null; echo "0 3 * * * /www/server/cron/gumshoe-nightly >> /www/server/cron/gumshoe-nightly.log 2>&1") | crontab -
  printf 'server {\n    listen 80;\n    server_name %s;\n    root %s;\n    index index.php index.html;\n    access_log /www/wwwlogs/%s.log;\n    error_log /www/wwwlogs/%s.error.log;\n}\n' "$SITE" "$WEBROOT" "$SITE" "$SITE" > /www/server/panel/vhost/nginx/$SITE.conf
  sqlite3 "$DBF" "insert into logs(type,log,addtime) values('Login','Login successful, login IP: 10.0.2.2','$(date '+%F %T')'),('Login','Login successful, login IP: 10.0.2.2','$(date '+%F %T')');" 2>&1
fi
sqlite3 /www/server/panel/data/default.db "update users set login_ip='10.0.2.2', login_time='$(date '+%F %T')';" 2>/dev/null
sqlite3 /www/server/panel/data/default.db "select 'sites',count(*) from sites; select 'databases',count(*) from databases; select 'crontab',count(*) from crontab; select 'logs',count(*) from logs;" 2>&1 | tr '\n' ' '; echo
ls -la "$WEBROOT" /www/server/panel/vhost/nginx/ 2>&1 | head -12
note "Site $SITE created headlessly (panel API or direct records): web root $WEBROOT, DB $DBNAME, FTP gumshoe_ftp, cron 'nightly backup' 03:00" "aapanel.cron / webapp.site"

step "seed stage (02_provision_aapanel.sh seed $DIRTY)"
if [ -x /www/server/nginx/sbin/nginx ] && ! pgrep -x nginx >/dev/null; then /etc/init.d/nginx start >/dev/null 2>&1 || true; fi
bash "$HERE/02_provision_aapanel.sh" seed $DIRTY
