# Changelog

## Unreleased

- **Fixes from the independent review of the dump reader and Players** (peer-review brief, section 9).
  (1) The row pattern could take hours on a row with an unbalanced quote or a cell of thousands of
  backslashes (exponential backtracking, re-run at every retry); it is now linear (possessive quantifiers)
  and a row that still does not match is skipped with its position logged, parsing resumes at the next
  `),(` / `);` / line end instead of swallowing the rest of the statement. (2) Parallel workers were split at
  line patterns, so a text cell containing `\n-- ` or `INSERT INTO` (a mail archive, a table holding SQL)
  could start a worker inside a string and lose or invent rows; split points now come from a quote-aware
  byte scan of statement ends, each worker is told the database in effect at its start, and the results are
  identical to the sequential reader on every fixture (mail archive, SQL-in-cells, function calls, 515 MB
  single-line table). (3) An error half-way through a dump (disk full, an undreamt-of construct) no longer
  throws away the hours of rows already written: the CSVs written so far are closed, indexed and reported as
  `partial:` with the reason. (4) No worker processes available (no `/dev/shm`, a locked-down host, a worker
  killed) → the file is read by the main process instead of failing. (5) A statement that never ends is
  bounded (8 MB, then dropped with its position in the log); a string straddling the read buffer's boundary in a
  schema statement longer than 256 KB no longer ends the statement at a `;` inside the string; `CREATE DATABASE
  /*!32312 IF NOT EXISTS*/` is recognised; backticks in table names are escaped on the live-server path;
  overlay mount options are escaped. (7) The read-only check records how the drive or share holding the image
  file is mounted (`image_holder`: usually read-write, WSL's choice - the evidence filesystem inside the image is
  what is mounted and checked read-only), so the custody record says what is guaranteed and what is not.
  (6) Players: password hashes and transaction ids no longer **merge** account rows (two accounts with the
  same default or reused hash were fused into one player, and a txid can sit on both sides of a trade); they
  still link. The promiscuity limit is per type (an e-mail in more than 50 rows, a phone in more than 20 ...).
  Every dossier now shows **Merged over**: the identifier and the exact rows it joined, so a merge can be
  checked before anyone relies on it.
- Launcher: a bundle on a drive WSL has not mounted (a USB drive plugged in after WSL started, a mapped drive) no
  longer stops Gumshoe.bat / the self-test with `wslpath failed for H:\Gumshoe-offline`: the drive is mounted into
  the distro with drvfs first.
- **Databases to CSV: fixes for the 12 GB dump that "gave nothing back".** (1) Export folders were named after the
  source's path truncated to 60 characters, so nine dumps under one long case path shared one folder and each
  extraction wiped the previous one - the 12 GB dump's tables were deleted by the 368-byte migration extracted
  after it, and Players/Databases showed 0. Folders are now `<parent>-<file>-<hash of the path>` (`db-dump_sw.sql-341566`),
  never shared, never overwritten by another source; the old shared folder is removed on re-extraction.
  (2) The MySQL dump reader streams bytes instead of lines: no line, statement or table has to fit in memory (a
  table kept on one 3 GB line, one INSERT with millions of rows, a 60 MB cell: 220 MB peak), identical rows to the
  old reader, parallel byte-range workers kept (and told which database is in effect at their start).
  (3) Dialects: phpMyAdmin rows on separate lines, Navicat/HeidiSQL/SQLyog, lowercase, `INSERT ... ON DUPLICATE KEY`,
  `REPLACE`, doubled quotes (`'it''s'`) as well as backslash escapes, statements without `;`, T-SQL scripts
  (`INSERT [dbo].[t]`, `N'...'`, `GO`), bit literals, `/*! ... */;` conditional statements, triggers/DELIMITER
  blocks; detection reads the first MB and takes any `.sql` as a dump. (4) A cell longer than Excel's 32,767
  characters is written to `<table>.blobs/rowN.column.txt` with a pointer in the cell. (5) The log says what the
  reader saw (INSERTs, CREATE TABLEs, skipped, malformed) and, when nothing was recognised, asks for the file head.
- Findings tab: the severity pills default to what the case has (a case with only info findings no longer opens
  on "0 of 7 findings shown"), and an empty result says which severities the pills are hiding.
- Remount after a reboot works for evidence on a share or a mapped drive: the recorded image paths (Windows,
  UNC or distro form) are resolved through winpath again, so `\\server\share\...` is mounted inside the distro
  (drvfs) before the image is looked for; the error names the path that was tried and why the share could not
  be opened. Second volumes that are unreachable are skipped with a note instead of failing the remount.
- Players / Databases / fingerprint: csv's 128 KB field limit is lifted everywhere exported CSVs are read (dump
  rows with serialized blobs or HTML killed the whole players build with `field larger than field limit`); a
  table that cannot be read is reported as NOT READ and the build continues; when no table can be scanned the
  log says which CSV folder is missing instead of silently reporting 0 identifiers.
- **Gumshoe-Rescue.bat** (`setup/offline/rescue.ps1`): for the WSL failure where the distro will not start
  (`getpwnam(root) failed 5`, `User not found`, `WSL_E_USER_NOT_FOUND` - the distro's virtual disk cannot be
  opened, usually because its drive is full): reports the disk, its drive's free space and the WSL version;
  restarts just that distro and tests it; checks and repairs the disk with `e2fsck` from a throwaway rescue
  distro imported from the bundle's rootfs (`wsl --mount --vhd --bare`); tests again; and only if the disk
  stays dead copies the cases and settings out of it (read-only, `noload`) to `<drive>:\DFIR-rescue\<date>\`
  and prints the reinstall steps. Nothing is unregistered or deleted; `-Force` checks a healthy disk, `-Keep`
  keeps the rescue distro, `-Everything` also copies the work folders, `-Disk`/`-RescueDir` override the
  lookups. The launcher now tells that failure apart from "not provisioned" and points to the rescue
  instead of suggesting a reinstall.
- `gumshoe ui` runs the Streamlit server under a watchdog: a server that dies (crash, out of memory) is restarted
  within 3 seconds and the browser tab reconnects by itself (9 deaths in 10 minutes stop the loop with the log
  shown); its output goes to `<cases-root>/../logs/ui.log` (`/opt/dfir/logs/ui.log` on the sandbox); the
  console window is titled "Gumshoe UI - keep this window open". `--no-watchdog` runs it bare. The runbook and
  START-HERE explain Streamlit's "Connection error" dialog (not a Gumshoe command; nothing to type in Windows).
- **Fingerprint** (`gumshoe fingerprint [--path]`, Run tab → What is it built on, a stage of every intake after
  Collect): what the host and its applications are built on, scored - every candidate with a percentage
  (matched indicator weight over total) and the evidence that matched. Host: control panels (aaPanel vs BT
  Panel by their text markers, cPanel, Plesk, DirectAdmin, CyberPanel, Hestia/Vesta, ISPConfig, Webmin/
  Virtualmin, CloudPanel, 1Panel, CWP, Froxlor, mdserver-web, RunCloud, ServerPilot, Forge, Ploi, Dokku,
  CapRover, Coolify, Easypanel, Cockpit, Portainer), Docker containers (image, command), Kubernetes,
  services (web servers, PHP versions, databases, Redis, Mongo, Node/PM2, supervisor, mail, Tor, VPN,
  tunnels), custom systemd units. Applications: document roots from the vhost files (with domains) and the
  usual layouts, nested apps; framework / CMS / admin framework with version (ThinkPHP, Laravel, Symfony,
  CodeIgniter, Yii, Hyperf, Webman, FastAdmin, BuildAdmin, Dcat, laravel-admin, Filament, Nova, CRMEB,
  likeadmin, WHMCS, Pterodactyl, phpMyAdmin, WordPress, Joomla, Drupal, Magento, PrestaShop, OpenCart,
  Discuz!, DedeCMS ..., Next/Nuxt/Nest/Express, Django, Flask, Rails, Java, .NET, Go), the packages
  (composer installed.json, composer.json, package.json, requirements.txt) with the notable ones grouped
  by purpose (crypto, trading, payments, Telegram, SMS, e-mail, cloud storage, real-time, geo, auth ...),
  UI kits, language make-up by bytes/files (all code and own code), newest code files. Databases: table
  prefixes and table-name signatures (FastAdmin, Laravel, Dcat, WordPress, Joomla, Drupal, PrestaShop,
  OpenCart, Magento, Discuz!, DedeCMS, CRMEB, likeadmin, Yii, Django, Rails, Node ORMs, WHMCS,
  Pterodactyl, aaPanel) and the investment / trading platform pattern (`stack.platform_pattern`, low).
  Written to `collected/fingerprint.json` and the `stack.fingerprint` finding; the webapp inventory
  carries the per-site stack too.
- **Players** (`gumshoe players build|list|show|find|trends`, the Players tab, a stage of every intake after
  the databases): a deterministic graph of who is in the evidence - every validated identifier (e-mail,
  phone, IPv4/IPv6, wallet addresses of the main chains with checksum validation, transaction ids, password
  hashes, IBAN, Luhn-checked cards, SSH key fingerprints, usernames, names, domains, URLs) from the CSV
  tables, the normalized logs, the panel inventory, the findings and the extracted documents, normalised
  and counted with first/last seen and a locator for every fact. Account-like rows merge into players over
  strong identifiers only (never over IPs, usernames or names; promiscuous identifiers are not glue;
  foreign keys such as `customer_id` are followed into the account table), IPs/domains/wallets attach as
  linked or shared (≥ 8 players), activity per identifier per day gives the timelines and bursts, and
  transaction-like tables are summed per player, per wallet and per currency. Stored in
  `<case>/players/players.db`, written as CSV folders plus one Markdown dossier per player under
  `<exports>/<case>/players/`, and the dossiers are indexed for Ask (`players://<id>`). Tables are scanned
  in parallel with per-table memory bounds; the merge into SQLite is bulk.
- **Databases to CSV** (`gumshoe db scan|extract|list|search`, the Databases tab, a stage of every intake):
  MariaDB/MySQL data directories are opened by a private server over an **overlay** (the evidence stays
  read-only, the server's writes - crash recovery - land in the work folder; a 100 GB datadir is not
  copied), every table is streamed to CSV; MySQL 8.0 data directories use a bundled, unpacked MySQL 8.0
  engine (`/opt/dfir/mysql8`); SQL dumps (mysqldump/phpMyAdmin, plain or gz/xz/bz2/zip) are parsed directly
  and in parallel for big plain files; PostgreSQL plain dumps, SQLite files and Access files too. Output:
  one folder per source in the exports folder, one per database, one CSV per table (UTF-8 BOM, CRLF,
  1,000,000 rows per file, NULL empty, blobs to files), `tables.csv`, `schema.sql`, `README.txt`,
  `source.json` with the source hash; search across every exported CSV. Dumps/datadirs dropped in the
  hopper become database-only cases. The DB review no longer copies the datadir.
- Folders are settings (`gumshoe settings`, Hopper → Folders in the UI, stored in
  `/opt/dfir/gumshoe-settings.json`): the hopper, the work folder for extracted images/trees and the
  exports folder can live on any drive or share, each shown with its free space. The examiner name is
  prefilled (settings → last intake → newest case → Windows account) and never blocks an intake.
  `Gumshoe-MoveToDrive.bat` moves the DFIR distro (`wsl --manage --move`), the Ollama model store
  (`OLLAMA_MODELS`) and the folders to another drive when C: is full. `gumshoe/winpath.py` holds the
  Windows/UNC path mapping shared by the CLI and the UI.
- **The hopper** (`gumshoe intake`, Run tab → Hopper): drop anything into `C:\DFIR\hopper` - E01, raw/img
  under any name, VHDX/VMDK/qcow2, zip/7z/gz/xz holding an image, tar/zip of files, an extracted folder,
  or the folder with all the disks of one server - and press Intake. Detection by content (magic bytes,
  inside archives too), extraction into the distro, read-only mount, second volumes assembled from the
  root's `/etc/fstab` (UUID/label/device order; `mount_image.sh --list`), case creation, read-only check,
  every image hashed and compared with hash files lying next to it, Collect (and Deep on request).
  `intake.json` records it all; `gumshoe remount` puts the mounts back after a reboot (Run tab button).
  Paths may be `\\server\share\...` or a mapped drive: opened from the distro with drvfs.
- **Findings explorer**: filters (severity pills, source, rule, text, status, sort), tick-to-select
  table, Flag/Dismiss/Reopen with notes (review.json + custody records), per-finding detail with the
  artifact, **Export…** to Markdown/HTML/CSV/JSON + hashed artifacts, copied to a Windows or share folder.
- Bundle: `7zip` and `afflib-tools` (split raw via affuse) added; `wsl_update.sh` installs packages an
  updated bundle carries into an already provisioned distro.
- Evidence probe (`gumshoe/probe.py`): right after a mount, and under a finished Collect/Deep, the UI
  says whether the volume is a Linux root filesystem (OS, hostname), whether aaPanel is on it and
  where, whether the original server kept `/www` (or `/home`, `/var/lib/mysql`) on another volume
  per its `/etc/fstab`, which other control panels are present, and where the database and web roots
  are. The aaPanel normalizer follows a relocated panel (`/opt/www`, `/data/www`, a data disk ...;
  finding `aapanel.relocated`) and, when the panel is absent, the `aapanel.absent` finding and the
  Panel tab explain why instead of showing nothing.
- `mount_image.sh --at /www` mounts a second volume (same image: `--lv`/`--part`, or another image,
  e.g. a data disk) on top of the mounted root; `--umount` takes everything down (`umount -R`).
  State values are shell-quoted, so paths with spaces survive.
- Offline bundle for air-gapped sandboxes (`setup/offline/`): `Gumshoe.bat` first-run installer and launcher, `wsl_provision.sh` (local apt repository + wheels, validated against a pristine Ubuntu 24.04 rootfs), `docs/OFFLINE-BUNDLE.md`.
- Shell-history review for every account (root, users, service accounts with a home): inventory
  plus per-line findings for account changes, log handling, compiling, history suppression and the
  existing suspicious-command heuristics, each with path and line number.
- Web-app inventory detects Drupal and Joomla (with versions) and finds apps nested one level below a
  site root; Drupal's `sites/default/settings.php` is read with secrets masked.
- `collect` records external tool versions (`collected/tool_versions.json` + custody record).
- `setup/wsl/mount_image.sh`: read-only mount helper for E01 (ewfmount), VHDX/VMDK (qemu-nbd) and
  raw images, with partition selection and LVM activation; `--umount` reverses it.
- `tests/testvm/`: Hyper-V builder for an aaPanel + MariaDB + WordPress test host that writes its own
  `GROUND_TRUTH.md`; `docs/TESTING.md` with the public reference image recipe and scorecard.
- Index globs cover history files in service-account homes.

## 0.1.0 — initial public release

- Case directories, image hash verification (single pass, SHA-256 + MD5), read-only mount check,
  hash-chained custody log with tamper detection.
- Runners and normalizers for UAC (bodyfile timeline in SQLite, timestomp and burst checks, Linux
  persistence checks), Loki + signature-base (two-pass), GoAccess (streamed), Chainsaw + Sigma over
  converted web and auth logs, aaPanel panel database and vhosts, PHP/WordPress inventory,
  MariaDB review on a datadir copy with crash recovery.
- Cross-source correlation.
- Document discovery and extraction (xlsx, docx, pdf, csv, md, odf, pptx, …) indexed under the
  original path with sheet/row, paragraph and page markers.
- SQLite FTS5 index with per-file encoding detection (UTF-8, Windows-1251, KOI8-R, CP866, UTF-16).
- Cited question answering with a citation guard, answer packets, sessions, case brief, examiner
  notes and pinned findings; two model tiers via Ollama.
- Archive-on-cite, viewer, filesystem browser, evidence export bundles (files, directories,
  unpacked archives) with hashed manifests.
- Labelled machine translation.
- Triage, trends and IOC reports (Markdown, HTML, CSV); unattended `deep` run.
- Profiles: `linux-aapanel`, `linux-generic`.
- Offline transfer scripts for Windows 11 + WSL2; plumbing self-test.
