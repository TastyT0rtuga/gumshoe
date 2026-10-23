# Gumshoe runbook — do this, in this order

Every step says what to type, what you should see, and what to do if you don't.
Two machines are involved: **PREP** (any Windows 11 box with internet) and **SANDBOX**
(the air-gapped OptiPlex). Nothing in Phase D–G touches the internet.

Rules that never bend:

1. Real evidence goes only on the SANDBOX. Test on anything else with a test image, never a case image.
2. Never skip `gumshoe verify`. If it says FAIL, stop and fix the mount.
3. One model loaded at a time; never run ClamAV while a model is loaded.
4. Write nothing to `/mnt/evidence`. If a command asks to write there, it is the wrong command.

---

## Phase A — PREP machine (internet): build the bundle  (~1–2 hours, mostly downloads)

1. Install Python 3.12 (python.org, tick "Add to PATH"), Git, and WSL (`wsl --install`, reboot once).
2. Unzip `gumshoe.zip` to `C:\build\gumshoe`.
3. Download Arsenal Image Mounter from arsenalrecon.com/downloads (free registration) and save the
   installer into `C:\build\gumshoe-transfer\tools\arsenal\` (create the folders).
4. Open PowerShell **as Administrator** in `C:\build\gumshoe` and run:
   `powershell -ExecutionPolicy Bypass -File setup\windows\01_prepare_online.ps1 -Out C:\build\gumshoe-transfer`
   You should see `ok:` after each step. `FAILED:` lines are fine to re-run.
   Add `-Lite` for a bundle **without Ollama and without the models** (about 6 GB smaller): the AI assistant
   is a switch inside Gumshoe that is off by default and nothing in the evidence depends on it; a lite
   bundle installs and runs everything else, and the `ollama\` and `models\` folders can be added later.
   A stronger model for a stronger machine: `-Models qwen2.5:14b-instruct-q4_K_M,nomic-embed-text` (then
   name it under `llm.models` in `config.yaml` and raise `num_ctx_*`).
5. Run the same command a **second time** (it picks up Loki's Python requirements after Loki is cloned).
6. Check the result: `C:\build\gumshoe-transfer` should contain `gumshoe\`, `wheels\win`, `wheels\linux`,
   `ollama\OllamaSetup.exe`, `models\` (7–8 GB), `wsl\wsl.msi`, `wsl\dfir-ubuntu.tar` (~2 GB),
   `tools\uac`, `tools\loki\Loki`, `tools\chainsaw`, `tools\sigma\sigma`, `tools\arsenal`, `bundle.sha256`.
   If `wsl\dfir-ubuntu.tar` is missing: reboot (first WSL install), re-run step 4.

## Phase B — move it

7. Copy the whole `gumshoe-transfer` folder to the external drive.
8. On the drive, verify: `powershell -ExecutionPolicy Bypass -File D:\gumshoe-transfer\gumshoe\setup\windows\hash_bundle.ps1 -Path D:\gumshoe-transfer -Verify`
   You should see `verified N files OK`.

## Phase C — SANDBOX: install (no network)  (~20 minutes)

9. Plug in the drive. Open PowerShell **as Administrator**:
   `powershell -ExecutionPolicy Bypass -File D:\gumshoe-transfer\gumshoe\setup\windows\02_install_offline.ps1 -Bundle D:\gumshoe-transfer`
   You should see `ok:` for: hashes, project copy, Ollama, Arsenal, WSL. Reboot if it says so.
10. Start Ollama pinned to the fast cores: double-click `C:\DFIR\ollama-pcores.cmd` (leave its window open).
11. Open the Linux side: `wsl -d DFIR`. Then:
    `bash /mnt/c/DFIR/gumshoe/setup/wsl/02_install_offline.sh -b /mnt/d/gumshoe-transfer`
    (use the drive letter the sandbox gave the external drive: `/mnt/d`, `/mnt/e` ...)
12. Verify everything: `bash /opt/dfir/gumshoe/setup/wsl/03_verify_offline.sh`
    You should see `[ OK ]` on every line, `no route to the internet` OK, and `selftest OK`.
    - `ollama reachable` FAIL → on Windows, confirm the Ollama window is open; in WSL run
      `curl http://127.0.0.1:11434/api/tags`. If that fails, find the Windows address with
      `ip route | awk '/default/ {print $3}'` and put `http://<that address>:11434` into
      `llm.base_url` in `/opt/dfir/gumshoe/config.yaml`.
    - `loki` FAIL → `ls /opt/dfir/tools/loki` must show `loki.py`; if the venv lacks yara-python,
      Phase A step 5 was skipped — re-run it on PREP and copy `wheels\linux` over.
    - `chainsaw` FAIL → `ls /opt/dfir/tools/chainsaw` and symlink the Linux binary to `/usr/local/bin/chainsaw`.

Do not go past this line until step 12 is all OK.

## Phase D0 — the hopper: drop it, press Intake  (the normal route)

Phases D and E by hand are still documented below, but the everyday route is the hopper:

1. Copy the evidence into `C:\DFIR\hopper` (Explorer; the launcher creates the folder). Anything goes:
   an E01, a raw/dd/img under any name (no extension needed), a VHDX/VMDK/qcow2, a zip/7z/gz/xz holding
   an image, a tar/zip of a file tree, a folder that is an extracted file system, or **the folder that
   holds all the disks of one server** (`drive-scsi0`, `drive-scsi1.raw`, their hash files, the AXIOM zip
   - the zip is ignored, the hash files are compared).
2. Double-click `Gumshoe.bat`. Run tab → **Hopper**: each item is listed with what it is. Type the
   examiner name once, press **Intake**.
3. Watch the bar: detect → extract (archives go into the analysis distro, never onto the share) →
   mount read-only (partitions, LVM, udev-less) → second volumes (`/www`, `/home`, `/var/lib/mysql` on
   another disk or LV are found through the root's `/etc/fstab` by UUID/label/device order and mounted
   on top) → case created → read-only check → every image hashed (and compared with a hash file next to
   it) → Collect (tools, MariaDB review, normalize). Tick *also run Deep* for the overnight run.
4. When it says done: **Open case**. The outcome line under the run says how many findings and whether
   aaPanel was found; the Panel tab explains itself when it is empty.
5. After a reboot the mount is gone; the Run tab shows **Remount this case's evidence** and puts it
   back exactly as intake mounted it (`gumshoe remount --case X` does the same).

Paths pasted into the UI can be Windows (`C:\...`), a mapped drive (`Z:\...`) or a share
(`\\server\share\...`): the share is opened from inside the distro with your Windows credentials.
If that is refused, map it to a drive letter in Windows or copy the item into the hopper.

## Phase D — mount the image read-only by hand  (~5 minutes)

13. Put the E01 (all segments) on the external drive, e.g. `D:\case\server.E01`.
14. Arsenal Image Mounter → **Mount image** → choose the E01 → tick **Read only** → Mount.
    Windows Disk Management now shows a new disk; note its number N (e.g. Disk 3).
15. Admin PowerShell: `wsl --mount \\.\PHYSICALDRIVEN --bare` (replace N).
    You should see "The disk was attached".
    - Error 0x80070001 or hang → unmount in Arsenal, re-mount, try again once; if it still fails, use the
      no-bridge route in `gumshoe mount-help` (B): `ewfmount` inside WSL straight from `/mnt/d/case/server.E01`.
16. In WSL, the short way: `sudo setup/wsl/mount_image.sh /dev/sdc` (the device `lsblk` shows for the
    attached disk) — it lists the partitions, activates LVM if present, picks the root filesystem, and
    mounts it at `/mnt/evidence` with `ro,noatime,noexec,nosuid,noload`. It also takes an E01 directly
    (`sudo setup/wsl/mount_image.sh /mnt/d/case/server.E01`, no Arsenal needed) or a VHDX. Use
    `--part N` / `--lv VG/LV` when it picks wrong; `sudo setup/wsl/mount_image.sh --umount` undoes it.
    The UI's "What is on /mnt/evidence?" box (shown right after a mount) tells you whether this is the
    root filesystem, which OS/host it is, and whether aaPanel is on it. If the original server kept
    `/www` on a data disk (its `/etc/fstab` says so and `/www` is empty), add that volume on top:
    `sudo setup/wsl/mount_image.sh <same-or-other-image> --part N|--lv VG/LV --at /www`, then Collect.
    The long way, if you prefer to see each step: `lsblk` → find the new device (e.g. `sdc` with
    partitions `sdc1`, `sdc2`). The Ubuntu root is usually the largest ext4 partition. Then:
    `sudo mkdir -p /mnt/evidence && sudo mount -o ro,noload,noexec,nosuid /dev/sdcN /mnt/evidence`
    `ls /mnt/evidence` should show `etc  www  var  root ...`.
    - "unknown filesystem type LVM2_member" → `sudo vgscan && sudo vgchange -ay && lsblk`, then mount
      the `/dev/mapper/...-root` device the same way.
    - `ls` shows nothing or only `lost+found` → wrong partition; `sudo umount /mnt/evidence` and try the other.

## Phase E — run the case  (collect: 1–4 hours on 50 GB, overnight on 500 GB; the rest minutes)

**The AI assistant is off unless you turn it on** (sidebar switch, saved for the machine). Everything in this
phase runs without it. The panel under the switch lists what it unlocks - Ask in plain language instead of
Find, labelled narrative sections in the report, translation of Russian/Chinese findings, the deep run's
translations and narrative, semantic search - and what each looks like without it. The report header
records whether it was on.

Big image? Before step 19 set in `config.yaml`: `logs.since` (a month before the earliest known
indicator), `logs.keep_jsonl: false`, and `dbreview.databases` (the app databases you care about).
Put the E01 on an internal or NVMe drive if one is free; USB spinning disks are the bottleneck.

17. Create the case (use the SHA-256 or MD5 from the acquisition paperwork):
    `gumshoe init --case CASE-001 --examiner "Your Name" --image /mnt/d/case/server.E01 --mount /mnt/evidence --expected-sha256 <hash> --notes "Scope: ..."`
    You should see `created case ...` and `"match": true`. `"match": false` → STOP; the image is not the
    one on the paperwork. (Hashing 50 GB from USB takes 10–20 minutes; that is normal.)
18. `gumshoe verify --case CASE-001` → must print `OK  /mnt/evidence (ext4) mounted read-only`.
    `FAIL ... NOT read-only` → `sudo umount /mnt/evidence` and redo step 16 with `-o ro,noload`.
19. `gumshoe collect --case CASE-001 --db`
    Runs UAC (longest, 30–90 min), Loki (30–60 min), GoAccess, log conversion, Chainsaw, panel DB,
    MariaDB review, then normalizes. Watch for `[tools] <name> done`. A `skipped:` line means that tool
    is missing — fix it and re-run just that tool later: `gumshoe collect --case CASE-001 --tools loki`.
    Ends with a JSON block of counts by severity.
20. `gumshoe index --case CASE-001` (a few minutes). Shows sources and chunk counts.
21. Ask questions (about a minute each with the 3B):
    `gumshoe ask --case CASE-001 "Which addresses requested files that Loki flagged, and when?"`
    Read the SOURCES list first, then the ANSWER. `supported=False` means treat it as unsupported.
    Each answer also lands in `reports/answers/NNN-*.md` with every source excerpt in full.
    To look at a cited file yourself: `gumshoe view --case CASE-001 --path /the/path` (tables, text,
    markdown; `--save` copies the original out), or the UI. To gather the cited originals into a
    hashed bundle: `gumshoe export --case CASE-001 --question NNN --name qNNN`.
    Time is free on the box: run with `--config config.thorough.yaml` to use the 7B for everything,
    intense scanning, Plaso, ClamAV, vectors and every document extracted.
22. Browser UI (optional): `gumshoe ui --case CASE-001` then open http://localhost:8501 on Windows.
    Non-English text: in the Findings tab filter **Script = cyrillic** to see what needs reading;
    `gumshoe translate --case CASE-001 --all` writes `reports/translations.md` (original next to a
    labelled machine translation; 10–60 s per finding with the 7B). Anything you will rely on still
    needs a certified translation — the machine version is for triage.
23. Report: `gumshoe report --case CASE-001 --kind triage --no-llm` for the deterministic report, or
    without `--no-llm` to add labelled AI narrative sections (7B; 10–30 minutes). Files land in
    `/opt/dfir/cases/CASE-001/reports/` (also reachable from Windows via `\\wsl$\DFIR\opt\dfir\cases\CASE-001\reports`).

### Walk-away mode

Once step 18 passes you can skip 19–23 and run one command before leaving for the night:
`gumshoe deep --case CASE-001`
It runs every tool (including the slow ones), extracts every document, builds the index with
vectors, translates all non-Latin findings with the 7B, and writes the triage/trends/IOC reports
with 7B narrative. Progress is in `reports/deep-run.log`; the end state in `reports/deep-summary.json`.
Next morning: `gumshoe ui` (fast model) to work through it; `ask --deep` when one answer deserves the 7B.

### Databases: every table as CSV

Databases tab (or `gumshoe db`). An intake scans the evidence and extracts what it finds by itself; for a
case made by hand press **Scan the evidence**, then **Extract all picks** (every data directory, sqlite and
Access file, the newest dump of each name) or pick rows. A `.sql`, `.sql.gz`, sqlite file or a whole
MariaDB/MySQL data directory dropped into the hopper becomes a database-only case (no mounting, no tools).

What comes out, under the exports folder (`<exports>\<case>\db\<source>\`, reachable from Windows):
`<database>\<table>.csv` for every table (Excel-ready: UTF-8 with BOM, header row, NULL = empty cell,
tables over 1,000,000 rows split into `.partNNN.csv`, binary values too big for a cell saved under
`<table>.blobs\`), `tables.csv` (the index: rows per table, files), `schema.sql`, `README.txt`,
`source.json` (what it was, its SHA-256, the server version and recovery level used).

How: a data directory is never copied or written - a private MariaDB (or the bundled MySQL 8.0 engine for
8.0 layouts) runs over an overlay, so crash recovery of a live-imaged server happens in the work folder,
and every table is streamed out. That server runs inside a mount namespace where everything is read-only
except its own work folder and the overlay (a seized datadir that names an absolute path - a tablespace, a
log file, `DATA DIRECTORY` - cannot write into the case folder, the exports, a Windows drive or a share),
with plugins, UDFs, persisted settings and symlinked tables disabled; the custody record says whether the
sandbox was in effect. Dumps are read as a byte stream straight to CSV (several processes on big
plain files): a 12 GB dump, a table kept on one multi-GB line or one INSERT with millions of rows all run in a
few hundred MB of memory. Dialects: mysqldump, phpMyAdmin, Navicat/HeidiSQL/SQLyog/Workbench, PostgreSQL
`--inserts`, T-SQL scripts (`[dbo].[t]`, `N'...'`, `GO`), doubled or backslash-escaped quotes, statements with
or without `;`. The escape mode is read from the dump: a `NO_BACKSLASH_ESCAPES`, PostgreSQL, T-SQL or SQLite dump
(backslash literal, quotes doubled) is parsed as such, and the log says which mode was taken and why. Comments
inside a VALUES list are whitespace; trigger/procedure bodies are skipped whole (an `INSERT` inside a trigger is
never written as data). A cell longer than Excel's limit (32,767 characters) is saved as
`<table>.blobs\rowN.column.txt` with a pointer in the cell; binary cells likewise. A row whose number of values
differs from the table's columns is kept in `<table>.rejected.csv` and counted (`rejected` in tables.csv) - never
written shifted into the table. Each source gets its own folder named `<parent>-<file>-<hash>`
(`db-dump_sw.sql-341566`), so dumps that share a long path never overwrite each other. The extraction log says
what the reader recognised (INSERTs, CREATE TABLEs, other statements skipped, malformed); if a `.sql` yields 0
tables, send its first lines (`head -c 2000`) so the dialect can be added. A row the reader cannot make sense
of is skipped and logged with its position (the rest of the statement is still read); an extraction that
stops half-way (disk full) keeps every row written so far and is marked `partial:` with the reason in
`tables.csv` and the Databases tab - re-run it after fixing the cause.
Search every exported table from the tab (name, e-mail, phone, IP ...), case-insensitive, any script.

### What is it built on: the fingerprint

Run tab → **What is it built on** (or `gumshoe fingerprint`, `gumshoe fingerprint --path D:\case\tree`). Every
intake runs it after Collect; it takes about a minute and writes `collected/fingerprint.json` plus the finding
`stack.fingerprint` (so it goes out with an export). Everything is scored: each candidate gets a percentage
(the weight of the indicators that matched over the weight of all its indicators) and the list of what matched,
naming the file or directory, so a 60 % is something you can go and look at.

- **Host**: which control panel is installed - aaPanel / BT Panel (told apart by their own text markers),
  cPanel, Plesk, DirectAdmin, CyberPanel, HestiaCP, VestaCP, ISPConfig, Webmin/Virtualmin, CloudPanel,
  1Panel, CWP, Froxlor, mdserver-web, RunCloud, ServerPilot, Forge, Ploi, Dokku, CapRover, Coolify,
  Easypanel, Cockpit, Portainer - whether the apps live in **Docker containers** (listed with image and
  command), Kubernetes; the services (nginx/Apache/OpenLiteSpeed, PHP versions, MySQL/MariaDB, PostgreSQL,
  Redis, MongoDB, Node + PM2 apps, supervisor programs, mail, Tor, VPN/xray, tunnels) and the **custom
  systemd units** (where bots and daemons get registered).
- **Applications**: every document root from the nginx/Apache/OLS vhost files (with its domains) plus the
  usual web-root layouts and nested apps. For each: the framework / CMS / admin framework with version
  (ThinkPHP 3/5/6/8, Laravel, Lumen, Symfony, CodeIgniter, Yii, CakePHP, Slim, Hyperf, Webman, Workerman,
  FastAdmin, BuildAdmin, EasyAdmin, Dcat Admin, laravel-admin, Filament, Nova, CRMEB, likeadmin, NiuShop,
  ShopXO, WHMCS, Pterodactyl, phpMyAdmin, Roundcube, Nextcloud, WordPress, Joomla, Drupal, Magento,
  PrestaShop, OpenCart, Discuz!, DedeCMS, EmpireCMS, PHPCMS, EyouCMS, Typecho, Next.js, Nuxt, NestJS,
  Express, Strapi, Django, Flask, Rails, Java, .NET, Go ...), the **packages it is built on** (composer's
  `vendor/composer/installed.json` with exact versions, composer.json, package.json, requirements.txt), the
  notable ones grouped by what they do (crypto/blockchain, trading, payments, Telegram/Discord, SMS, e-mail,
  cloud storage, real-time, geo/device, auth, scraping, exports, proxies), the UI kits (layui, AdminLTE,
  Element, Bootstrap, KLineChart, TradingView ...), the **language make-up** by bytes and by files - all
  code, and own code with vendor/node_modules/uploads left out - and the newest-changed code files.
- **Databases** (from the Databases tab exports): table prefixes and table-name signatures (FastAdmin,
  Laravel, Dcat, WordPress, WooCommerce, Joomla, Drupal, PrestaShop, OpenCart, Magento, Discuz!, DedeCMS,
  CRMEB, likeadmin, Yii, Django, Rails, Sequelize/Knex/Prisma, WHMCS, Pterodactyl, the aaPanel database)
  and the **investment / trading platform pattern** (recharge, withdraw, wallet, coin, kline, leverage,
  agent, commission, vip, bank card ... - a pattern score over table names, flagged as the finding
  `stack.platform_pattern`, never an identification of a product).

In practice the "panel" on a fraud server is rarely a hosting panel: it is an admin application, most often
FastAdmin or Dcat/laravel-admin on ThinkPHP or Laravel, and the fingerprint names it with the version,
the packages (a TRON API, a Telegram bot SDK, a payment SDK) and the tables. The percentage is only as
good as the markers: a stripped `vendor/` or renamed directories lower it; the evidence list says which
markers were missing.

### Players: who is in the data, how they connect, where the money went

Players tab (or `gumshoe players build|list|show|find|trends`). Built by every intake after the databases
are extracted (press **Build players** / **Rebuild** for a case made by hand or after extracting more
databases). No model is involved: everything is counted from the CSV tables, the logs, the panel inventory
and the extracted documents, and every fact keeps its locator (`database.table:row`, `auth.log:line`,
document path) so you can go and look.

- **Identifiers**: e-mails, phones, IPs (v4/v6), crypto wallets (Bitcoin legacy/segwit/taproot, Ethereum,
  Litecoin, Tron, XRP, Bitcoin Cash, Monero, Solana ...), transaction ids, password hashes, IBANs, card
  numbers (Luhn-checked), SSH key fingerprints, usernames, names, domains, URLs - each validated, normalised
  (`+1 (555) 010-0100` and `15550100100` are one phone), with counts, first/last seen, and where.
- **Players**: account-like rows (a row holding an e-mail or username plus a name/phone/password hash) are
  merged only over **strong** identifiers - e-mail, phone, wallet, IBAN, card, SSH key - found in the row's own
  typed columns or reached through a validated foreign key. Never over IPs, usernames, names, password hashes
  or transaction ids (shared infrastructure must not fuse people; two accounts with the same default hash are
  two accounts; a txid sits on both sides of a trade), and never over an identifier found in free text (a note
  saying "referred by bob@x" links Bob, it does not fuse him) - those **link** players without merging them. An
  identifier seen in too many account rows (an e-mail in more than 50, a phone in more than 20, a wallet in more
  than 10: a placeholder, a support line, a payout address) merges nothing. Every dossier shows **Merged over**:
  the identifier and the exact rows it joined - check it before relying on the merge. A player is a cluster of
  account rows, not a head count: one person with two e-mails is two players until something joins them.
  Foreign keys are followed when they resolve: `logins.customer_id` joins the customer (so the login's IP and
  time belong to the player) only if at least half of the sampled key values find a customer row; otherwise
  the column is left unjoined and the log says so.
- **Linked / shared**: IPs, domains, wallets, names reached through rows and log lines carrying the player's
  strong identifiers; an IP used by 8 or more players is marked **shared** (proxy, NAT, the office) instead
  of being treated as that player's.
- **Timeline**: activity per day per identifier - the dossier's bar chart; **Trends and money** shows bursts
  (days above 4× the median), new account rows per month, IPs by number of players, and the most active
  identifiers of the last week in the data.
- **Money**: rows of transaction-like tables (an amount plus a wallet/txid/account reference) summed per
  player and per currency. A row is attributed only when it names exactly one player; a row naming two
  (sender and receiver, merchant and customer) is attributed to neither - it is counted, listed in
  `unattributed_money.csv` and shown in both dossiers. A row reached only through a wallet *linked* to a
  player by co-occurrence (possibly a counterparty's address, not an account row's) is attributed but marked
  `linked` in transactions.csv and in the dossier's money line. Every wallet with its mentions and the players
  holding it.

What comes out, under `<exports>\<case>\players\` (Excel-ready): `players.csv`, `entities.csv`,
`links.csv`, `wallets.csv`, `transactions.csv`, `unattributed_money.csv`, `activity.csv`, `MANIFEST.txt`
(with the custody head at export time) and `dossiers\player-NNNNN.md` (one
Markdown dossier per player: identifiers, links, timeline, money, source rows). The dossiers are also
indexed for Ask, so "what do we know about ivan.petrov@mail.ru" cites `players://12`.

Look up an identifier (second sub-tab) to pivot on anything: where it appears, what it co-occurs with,
which players hold it. Tables are scanned in parallel; a table with more than 3,000,000 distinct
identifiers is capped (the log says so) - rare outside raw traffic logs; account and transaction rows of a
very big table are capped by keeping its first half and its last half (the newest rows survive), and the
log says "kept the first N and the last N of M".

### Findings: read, mark, export

Findings tab: filter by severity (pills), source, rule, free text and status; tick rows in the table
to read them in full below (description, excerpt, translation, the artifact itself) and to act on them
with the bar: **Flag** (with a note), **Dismiss**, **Reopen**, **Archive artifacts**, **Export…**.
Export writes `findings.md/html/csv/json` (with your notes and statuses) plus the cited files, hashed,
under `reports/exports/<name>/` in the case and - if you give a folder - copies into Windows
(`C:\DFIR\exports\<case>` by default, or the case share). Explorer reaches the case folder at
`\\wsl.localhost\DFIR\opt\dfir\cases\<case>\reports\exports`. Every mark and export is a custody
record.

## Phase F — check the work before it leaves the box  (~1 hour of reading)

24. Open the report. For every critical and high finding, open the cited file in the image
    (`less /mnt/evidence/<path>`) and confirm the excerpt is really there.
25. Every AI-narrative block: read each sentence against its cited findings; delete anything you cannot confirm.
26. `gumshoe custody --case CASE-001 --show 100` → must print `OK   chain intact ... matches the anchor` and the
    chain head (record number and hash): write the head into your notes. The anchor is a second copy of every
    record's head outside the case folder (`/opt/dfir/custody-anchors/<case>.jsonl`); a chain that was truncated
    or rewritten in place fails this check. The head also sits in every export's manifest and in the report.
27. `gumshoe archive --case CASE-001 --verify` → `"ok": true`.
28. Fill in the attestation table in the methodology note (versions from `03_verify_offline.sh` output and
    `custody.log`; dates from `case.json`).

## Phase G — close out

29. `sudo umount /mnt/evidence`; Admin PowerShell `wsl --unmount \\.\PHYSICALDRIVEN`; unmount in Arsenal.
30. Delete the database copy if space matters: `rm -rf /opt/dfir/cases/CASE-001/collected/dbcopy`
    (its hashes and the recovery level stay in the custody log).
31. Copy `/opt/dfir/cases/CASE-001` to evidence storage and hash the copy:
    `tar czf CASE-001.tgz -C /opt/dfir/cases CASE-001 && sha256sum CASE-001.tgz`.

---

## If something goes wrong

| Symptom | Do this |
| --- | --- |
| `gumshoe: command not found` | `source /opt/dfir/venv/bin/activate` or use `/opt/dfir/gumshoe/gumshoe` |
| Gumshoe.bat stops at `=== WSL distro DFIR` with **`getpwnam(root) failed 5` / `User not found` / `Wsl/WSL_E_USER_NOT_FOUND`** (or the distro will not start) | WSL cannot open the distro's virtual disk - errno 5 is an I/O error. The distro and your cases are still there: do **not** reinstall (it would stop at the same error). Usual cause: the drive holding `ext4.vhdx` (C: by default) is full, so the disk could not grow and its filesystem is dirty. Free 3-5 GB on that drive, then run **Gumshoe-Rescue.bat**: it restarts just this distro and tests it, checks and repairs the disk with `e2fsck` from a throwaway rescue distro imported from the bundle, tests again, and - only if the disk cannot be brought back - copies the cases out (read-only, no journal replay) to `<drive>:\DFIR-rescue\<date>\` and prints the reinstall steps. Nothing is deleted. Afterwards run `Gumshoe-MoveToDrive.bat` so the distro lives on a drive with room. Log: `C:\DFIR\rescue.log`. |
| Browser shows **Connection error — Is Streamlit still running? ... `streamlit run yourscript.py`** | That is Streamlit's stock dialog, not a Gumshoe command; Streamlit is not installed on Windows, it runs inside the distro. The UI server stopped - almost always because the minimized **wsl** window titled *Gumshoe UI - keep this window open* was closed (that window is the server; closing it stops the distro and anything running in it). Double-click `Gumshoe.bat`, then reload the tab (F5). A server that crashed on its own is restarted by its watchdog within seconds and the tab reconnects by itself; the reason is in `/opt/dfir/logs/ui.log` (`\\wsl.localhost\DFIR\opt\dfir\logs\ui.log`). If a Collect/intake was running when the window was closed it stopped too: Run tab → Start it again (Hopper → Remount first if the evidence mount is gone). |
| `run gumshoe verify first` | Step 18 |
| `uac: sudo: a password is required` | run `sudo -v` first, then the collect command again |
| `chainsaw ... mapping` error | compare `gumshoe/rules/chainsaw-mappings/*.yml` with `mappings/` inside `/opt/dfir/tools/chainsaw`; adjust field keys to that schema |
| GoAccess `Format errors` | aaPanel's nginx log format differs; set `tools.goaccess.log_format` in config.yaml to the nginx `log_format` string from `/mnt/evidence/www/server/nginx/conf/nginx.conf` |
| Ollama answers very slowly | confirm `ollama-pcores.cmd` was used; in config set `num_thread: 8`; ask with the 3B (default), keep the 7B for reports |
| `model unavailable` | Ollama window closed, or wrong `base_url` (step 12) |
| Windows becomes sluggish / out of memory | close the UI, run `ollama stop <model>` on Windows, lower `memory=` in `%USERPROFILE%\.wslconfig` to 4GB and `wsl --shutdown` |
| MariaDB review: `would not start at any recovery level` | read `collected/dbcopy/mariadbd.err`; often a MariaDB version mismatch between the image and the distro — note it in limitations and skip the DB review |
| Selftest fails after an edit | you changed code; `python3 gumshoe.py selftest` prints which check broke |
