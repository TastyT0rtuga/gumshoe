# Gumshoe — offline, cited forensic triage for Linux server images

[![selftest](../../actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.10%E2%80%933.13-blue)
![license](https://img.shields.io/badge/license-Apache--2.0-green)

> **Not an official product of any government agency or employer.** Gumshoe is an examiner's aid:
> established forensic tools and deterministic parsers make the findings; a local model is an **optional
> switch, off by default**, that only searches and drafts over them with mandatory citations; the examiner
> verifies everything. See [NOTICE](NOTICE).

**At a glance:** fully offline · runs on a 16 GB CPU-only workstation · evidence stays read-only ·
every finding cites a path, line and SHA-256 · hash-chained custody log · view and export any file ·
Cyrillic-aware · `deep` mode for unattended overnight runs · drop anything in the **hopper** (E01, raw,
VHDX/VMDK, zips, folders, a server's set of disks) and it is mounted, cased, hashed and run ·
**every database to Excel-ready CSV** (100 GB data directories without copying them) · **Players**: who is
in the data, how they connect, when, and where the money went · **fingerprint**: what the panel and
every site are built on, scored with the evidence.

```bash
git clone https://github.com/<you>/gumshoe && cd gumshoe
pip install -r requirements.txt
python gumshoe.py selftest          # 60 checks, no model or evidence needed
python gumshoe.py --help
```

Air-gapped install: [docs/RUNBOOK.md](docs/RUNBOOK.md). Adding evidence types: [docs/PROFILES.md](docs/PROFILES.md). Validating against images with a known answer: [docs/TESTING.md](docs/TESTING.md).
Contributing: [CONTRIBUTING.md](CONTRIBUTING.md). Security: [SECURITY.md](SECURITY.md).

Established tools do the finding. Gumshoe runs them against a read-only mount, keeps
their raw output, normalizes everything into one findings table with provenance
(path, line, excerpt, SHA-256, inode times), correlates across sources, indexes it,
answers questions with a local model under a citation guard, archives every cited
file with its hash, and writes the report a DF team writes. Every action is in a
hash-chained custody log. Nothing leaves the machine; nothing writes to the evidence.

Built first for an **aaPanel + MariaDB + Ubuntu** image analysed on a **Windows 11,
16 GB, CPU-only** sandbox through WSL2. The design doc (architecture, constraints,
model plan, integrity design) is summarized below; this file is the operator's guide.

## Profiles: one pipeline, swappable case types

The spine (custody, index, citations, archive, export, documents, memory, reports, UI, and the
Linux tool chain) is generic. A **profile** picks the evidence paths and which normalizers run:
`linux-aapanel` (default) and `linux-generic` ship today; `gumshoe --profile linux-generic init ...`
records the choice in the case. `docs/PROFILES.md` says exactly what is generic, what is specific,
how to add a case type, and what a `windows`, `macos`, `memory`, `pcap`, `cloud-logs` or `mobile`
profile would reuse and need.

## What runs on the image

| Step | Tool | Finds | Gumshoe glue |
| --- | --- | --- | --- |
| 1 | [UAC](https://github.com/tclahr/uac) `-m /mnt/evidence` | Linux triage set + bodyfile (atime/mtime/ctime/crtime) | structural checks on the collected copies (accounts, cron, systemd, `authorized_keys`, sshd/sudoers, shell histories of every account); timeline; ctime-vs-mtime timestomp check; change bursts |
| 2 | [Loki](https://github.com/Neo23x0/Loki) + [signature-base](https://github.com/Neo23x0/signature-base) | YARA / filename / hash IOC hits in web roots, panel, temp dirs, home dirs, DB plugin dir | parses the log into findings; hashes and queues each hit for archive |
| 3 | [GoAccess](https://goaccess.io/) | per-IP / path / status / day web statistics (+ its own interactive HTML dashboard) | trends tables and charts |
| 4 | [Chainsaw](https://github.com/WithSecureLabs/chainsaw) + [Sigma](https://github.com/SigmaHQ/sigma) | community rules over access logs and `auth.log` | converts logs (incl. rotated `.gz`) to JSONL in Sigma field names; per-IP failure-then-success counts |
| 5 | aaPanel reader (custom) | `default.db` operation log, panel logins, panel cron tasks, sites/FTP/DB accounts, vhost configs, panel settings | all of it; nothing else reads this database |
| 6 | MariaDB review (custom, WSL) | accounts, `mysql.func` (UDFs), WordPress admins/options, `my.cnf`, `.mysql_history` | runs a private `mariadbd` (or the bundled MySQL 8.0 engine) over a read-only **overlay** of the data directory - crash recovery lands in the work folder, nothing is copied - dumps canned queries to JSON, stops it |
| 7 | Plaso (optional) | full super-timeline | imports `psort` CSV |
| 8 | ClamAV (optional, off) | second signature engine | parses `clamscan` output; never alongside a model |

Correlation runs after all of them: a Loki hit that is also a request target in the
access logs becomes critical and gets a linked finding listing who requested it and
when; a brute-forcing address that also appears in the panel operation log raises both.

Three layers sit on top of the tools, all deterministic (no model involved) and all with a locator on
every fact:

| Layer | Command / tab | What it gives |
| --- | --- | --- |
| **Databases to CSV** | `gumshoe db scan\|extract\|search`, Databases tab | every MariaDB/MySQL data directory (5.x-10.x and 8.0; opened over an overlay, never copied, by a server confined to a read-only mount namespace), SQL dump (plain or compressed, streamed - nothing has to fit in memory - parsed in parallel at statement boundaries, escape mode detected, routine bodies skipped, rows with the wrong number of values rejected visibly, partial output kept on error), PostgreSQL dump, SQLite and Access file → one folder per source, one per database, one Excel-ready CSV per table (1,000,000 rows per file, NULL empty, blobs to files), `tables.csv`, `schema.sql`; then **explore without SQL or Docker**: one catalog of every table across every export (filter by table or column name), a paged viewer with per-column filters, search (phrase / all words / any word / regex, per-table hits, exact rows, only-in-columns) with one-click export of every matching row of every table to a folder with locators and a custody record, and an optional read-only **SQLite workbench** for whoever wants SQL |
| **Players** | `gumshoe players build\|list\|show\|find\|trends`, Players tab | every validated identifier (e-mail, phone, IPv4/IPv6, wallet addresses of the main chains with checksum validation, txids, password hashes, IBAN, Luhn-checked cards, SSH fingerprints, usernames, names, domains) from the CSV tables, logs, panel inventory, findings and documents; account rows merged into players over strong identifiers only (e-mail, phone, wallet, IBAN, card, SSH key, from the row's own columns or a validated foreign key - never IPs/usernames/names/password hashes/txids or anything found in free text, which link without merging; promiscuous identifiers are not glue; every dossier shows what it was merged over); money attributed only to a row's single player, two-party rows listed as unattributed; linked and shared IPs; activity per day; money per player, wallet and currency; CSV folders + a Markdown dossier per player, indexed for Ask as `players://<id>` |
| **Fingerprint** | `gumshoe fingerprint [--path]`, Run tab → What is it built on | the control panel (aaPanel vs BT Panel, cPanel, Plesk, DirectAdmin, CyberPanel, Hestia, ISPConfig, Webmin, CloudPanel, 1Panel, CWP ...), Docker containers, services, custom systemd units; per site (from the vhost files, with domains) the framework / CMS / admin framework with version (ThinkPHP, Laravel, Symfony, CodeIgniter, Yii, Hyperf, FastAdmin, Dcat, laravel-admin, Filament, CRMEB, WHMCS, WordPress, Joomla, Drupal, PrestaShop, OpenCart, Discuz!, DedeCMS, Next.js, Django ...), the packages it is built on with the notable ones grouped by purpose (crypto, trading, payments, Telegram, SMS ...), UI kits, language make-up by bytes/files, newest code; per database the table-name signatures and the investment/trading platform pattern. Every candidate scores matched indicators ÷ its indicators, with the matched files listed |

**New to this? Start with `docs/RUNBOOK.md`** — a numbered, do-this-then-this walkthrough
from the prep machine to the signed report, with what you should see at each step.

## Quick start (inside the WSL distro, after `setup/`)

The short way: copy the evidence into the hopper folder (`C:\DFIR\hopper`) and press **Intake** in the
UI (Run tab → Hopper), or `gumshoe intake <item> --examiner "Name"`. It detects what the item is by
content (E01, raw/dd under any name, VHDX/VMDK/qcow2, a zip/7z/gz of an image or of files, a folder, the
folder with all the disks of one server), extracts, mounts read-only, assembles second volumes from the
root's `/etc/fstab`, creates the case, checks read-only, hashes against hash files lying next to the
image, extracts every database to CSV, runs Collect, fingerprints the stack and builds the players.
The long way, step by step:

```bash
gumshoe mount-help                                   # Arsenal Image Mounter -> wsl --mount -> mount -o ro,noload
gumshoe init --case CASE-001 --examiner "Name" --image /mnt/d/case/server.E01 \
             --mount /mnt/evidence --notes "scope: ..." --expected-sha256 <from acquisition form>
gumshoe verify --case CASE-001                       # refuses to continue unless /proc/mounts shows ro
gumshoe collect --case CASE-001 --db                 # UAC, Loki, GoAccess, log conversion, Chainsaw, panel DB, MariaDB review, normalize
gumshoe db scan --case CASE-001 && gumshoe db extract --case CASE-001   # every database -> CSV folders
gumshoe fingerprint --case CASE-001                  # what the host and each site are built on, scored
gumshoe players build --case CASE-001                # identifiers, links, timelines, wallets, money
gumshoe index --case CASE-001
gumshoe ask --case CASE-001 "Which addresses requested files that Loki flagged, and when?"
gumshoe report --case CASE-001 --kind triage         # markdown + HTML + ioc.csv; archives every high/critical artifact
gumshoe ui --case CASE-001                           # browser UI on http://localhost:8501
gumshoe custody --case CASE-001 --show 50            # verify the chain
```

Windows without WSL (FTK Imager export tree): `--mode export --mount D:\Cases\CASE-001\export`;
UAC and the MariaDB review are skipped and the report's limitations section says so.

## Case directory (the only place Gumshoe writes)

```
cases/CASE-001/
  case.json                   metadata, image hashes, read-only check
  custody.log                 append-only JSONL, hash-chained (gumshoe custody)
  config.effective.yaml       the configuration this case ran with
  collected/raw/<tool>/       untouched tool output + stdout/stderr + hashes of every output file
  collected/jsonl/{web,auth}/ converted logs that Chainsaw hunted
  collected/findings.jsonl    normalized findings     collected/summary.json   counts
  collected/timeline.csv      bodyfile timeline       collected/trends.json    GoAccess summary
  collected/inventory.json    accounts, keys, cron, units, panel tables, auth stats
  collected/dbreview.json     MariaDB extracts         collected/dbcopy/        datadir copy (large; delete when done)
  index/gumshoe.db            SQLite FTS5 (+ optional vectors)
  evidence/<sha256>/          archived copies, <sha256>.json sidecars, manifest.json
  reports/                    triage-*.md/.html, trends-*, ioc.csv, questions.jsonl
```

## Evidence integrity, in one paragraph

`verify` recomputes the image hash and compares it with the acquisition record, and
refuses to proceed unless the mount is `ro`. Tools and Gumshoe only read the mount.
Every finding and every index chunk carries the artifact path, line/byte range and
SHA-256, so any sentence walks back to bytes in the image. The model only sees numbered
sources from the retrieved set; a citation outside it is removed and logged, and an
answer with no valid citation is returned as unsupported. Every cited file, and every
artifact behind a high/critical finding, is copied to `evidence/` with a sidecar
(original path, stat times, hash before and after, reason). `custody.log` chains each
record to the previous one; `gumshoe custody` detects any edit. AI narrative in reports
is labelled, cited, logged, and separate from the findings tables.

## The AI assistant: a switch, off by default

Nothing in the evidence depends on a model. Intake, mounting, collection, findings, databases to CSV, Players,
fingerprint, timeline, custody and the reports are deterministic and run without one; `llm.enabled: false` is
the default in `config.yaml`, and the sidebar switch (saved beside the cases) overrides it per machine. The
switch sits next to a panel that says what the model unlocks, so turning it on is an informed choice:

| With the model | Without it |
| --- | --- |
| **Ask** - questions in plain language over everything indexed; every answer cites its sources, claims without a citation are removed | **Find** - the same search over the same index with the same citations, no generated text |
| **Report narrative** - labelled drafting sections written from the cited findings (7B) | the report of findings, tables, timeline and custody, with no generated text (its header says so) |
| **Translation** - Russian/Chinese/Arabic findings to English, labelled as machine translation | non-Latin findings tagged by script and shown as they are |
| **Deep profile** - the walk-away run adds translations and the narrative | the walk-away run does every tool, the index and the reports |
| **Semantic search** - vectors so Ask/Find also match paraphrases | keyword search (FTS5) |

A bundle can be built without Ollama and without the models (`01_prepare_online.ps1 -Lite`, about 6 GB
smaller); the launcher and the first run then install everything else and the switch stays off until the
`ollama\` and `models\` folders are added.

### Models (Ollama on Windows, pinned to P-cores)

| Tier | Default | Use |
| --- | --- | --- |
| interactive | `qwen2.5:3b-instruct`, 4k context | questions, filtering |
| report | `qwen2.5:7b-instruct-q4_K_M`, 8k context | report sections only; the 3B is unloaded first |
| embed (optional) | `nomic-embed-text` | `gumshoe index --vectors` (slow on CPU; run once) |

Change tags in `config.yaml`. Keep one model loaded at a time (`OLLAMA_MAX_LOADED_MODELS=1`).

**A stronger model on a stronger machine** is the same three lines: pull it on the prep machine
(`01_prepare_online.ps1 -Models qwen2.5:14b-instruct-q4_K_M,...` puts it in the bundle's model store), name
it under `llm.models`, raise `num_ctx_interactive` / `num_ctx_report` (4k/8k were chosen for 16 GB with no
GPU) and `num_thread`. Ollama uses a GPU on its own when one is present. Only a change of the `embed` model
needs work - the vectors must be rebuilt (`gumshoe index --vectors`). The citation guard and every
deterministic layer are unchanged whatever the model.

## Two speeds: at the keyboard vs. walked away

| | Interactive (you are typing) | Deep (`gumshoe deep`, leave it overnight) |
| --- | --- | --- |
| Model | `llm.models.interactive` — 3B, 4k context, ~1 min per answer | `llm.models.report` — 7B, 8k context, for narrative and translations |
| Tools | whatever `collect` ran | everything: UAC, Loki **intense over every file**, GoAccess, Chainsaw, ClamAV, Plaso, MariaDB review |
| Documents | first 5,000 extracted (≤ 25 MB each) | every document (≤ 200 MB each) |
| Index | 50 MB per-file cap | 500 MB cap, plus vectors (`bge-m3`) |
| Translation | one finding at a time on request | all non-Latin findings |
| Output | answer packets | `reports/deep-run.log`, `deep-summary.json`, triage/trends/IOC reports with 7B narrative |

`gumshoe deep --case CASE-001` applies the `deep:` section of `config.yaml` for that run only
(the effective config is saved into the case), unloads models before the scanner phase so they
have the RAM, runs every stage in order with each logged to the custody chain, and keeps going
past a failed stage. `--skip-tools` redoes only the model-side stages. Use `ask --deep` for a
one-off 7B answer while staying interactive otherwise.

## Memory for the model (context, never evidence)

| Memory | What it is | Why |
| --- | --- | --- |
| Case brief | auto-generated summary (counts, top findings, key addresses, sites, apps) placed **first** in every prompt | stable prefix → Ollama's prompt cache skips re-reading it; on CPU that is most of the wait. Also makes answers case-aware |
| Examiner notes | `notes.md` in the case (sidebar editor, `gumshoe notes --add "..."`), shown as a labelled block the model may use but not cite; hashed into custody on change | your hypotheses, incident window, who is who |
| Pinned findings | `gumshoe pin --finding F-...` / Pin button: always offered as citable sources | the facts every answer should see |
| Session | `ask --session work` / the Ask tab's session: the last turns plus the chunks they cited come along | follow-ups ("and the second address?") stay grounded in the same evidence |

Every answer packet records which session, brief hash and notes hash were in play and labels each
source as retrieved, carried or pinned, so an answer is reproducible. "New session" clears the
carry-over when you change line of inquiry. `--no-memory` asks with sources only.

## Citations, viewing and assembling evidence

Every answer and every report statement points at a file in the image, and you can open
that file yourself without leaving the tool.

- **Citations.** An answer cites `[n]`; each `n` is a chunk with the original path, line (or
  sheet/row, paragraph, page) range, SHA-256 and the exact text the model saw. A citation to
  anything not retrieved is stripped. Each `ask` also writes an **answer packet**
  (`reports/answers/NNN-*.md`): question, answer, and every source excerpt in full — a
  self-contained cited record you can hand to someone.
- **Documents.** Spreadsheets (xlsx/xls/ods), Word/ODF (docx/doc/odt/rtf), PDF, CSV/TSV,
  Markdown, JSON/XML, SQL dumps and presentations are inventoried from the timeline, hashed,
  and text-extracted with location markers (`### sheet: Invoices` / `row 12`, `¶7`, `### page 3`).
  The text is indexed **under the original path**, so "which invoices mention Northwind" cites
  `/home/ubuntu/Documents/ledger.xlsx, sheet Invoices, row 2`. What the model saw is kept in
  `collected/extracted/<sha256>.txt`.
- **Viewing.** UI → Documents tab (or "View the artifact" on any finding, or "View the file" on
  any answer source): spreadsheets and CSV render as tables (sheet selector), Markdown renders,
  text/PDF/Word show extracted text, images display, and **Download original** hands you the
  bytes from the image. Every view/download archives the file with a sidecar and a custody record.
  CLI: `gumshoe view --path /www/wwwroot/site/export.xlsx` (`--save out.xlsx` copies it out).
- **Anything, not just documents.** `gumshoe ls --path /www/wwwroot/site` lists the image;
  `gumshoe view --path <any file>` previews or `--save`s it; the UI's **Browse** tab walks the
  whole filesystem and opens any file. Nothing has to be pre-extracted to be viewed or exported.
- **Assembling.** `gumshoe export --name q7 --question 7` (or `--findings F-..,F-..`, `--paths ...`)
  copies the originals into `reports/exports/q7/files/` in their original tree, with the extracted
  text, a manifest (path, SHA-256 of original and copy, timestamps, why included), a README and a
  hashed zip. A directory in `--paths` exports everything under it (a whole site root, a home
  directory); `--unpack` also unpacks zip/tar/gz archives in the set with per-member hashes. In the
  UI, add files or directories to the export set from findings, answers, the viewer or the browser
  and build the zip from the Export tab.

## The aaPanel / PHP / MariaDB stack

The **Panel** tab reconstructs, read-only, what the control panel would show: sites, domains,
bindings, FTP and database accounts (no credentials), firewall rules, panel accounts with last
login, scheduled tasks with their scripts and last output, the operation log by address and by
type, panel settings and plugins, every vhost config, and the web applications per site:
framework and version (WordPress, Laravel, plain PHP, static), configuration files with database
name/user/host and prefix (passwords and secrets masked), plugins and themes with versions, PHP
entry points, include graph summary, external host names referenced in code, `.htaccess` /
`.user.ini` files with change times, and the PHP configuration per installed version
(`disable_functions`, `allow_url_include`, `open_basedir`, `auto_prepend_file` ...). PHP source is
indexed as text, so questions about code cite file and line. Signature-based detection of PHP
stays with Loki + signature-base; the inventory here is structural.

## Non-English evidence (Cyrillic and others)

Every text read detects its encoding per file (BOM, UTF-8, then Windows-1251 / KOI8-R /
CP866 by Cyrillic density, UTF-16), records it in the index, and never fails on a stray
byte. File names in any script are handled. The search index uses SQLite's `unicode61`
tokenizer, so a Cyrillic query finds Cyrillic text (`gumshoe ask "резервное копирование"`).
Findings whose path or text carry Cyrillic, CJK or Arabic get a script tag (filter in the UI).

Translation is a labelled investigative aid, not a certified translation:

```bash
gumshoe translate --case CASE-001 --all                 # every finding with non-Latin text -> reports/translations.md
gumshoe translate --case CASE-001 --finding F-abc123    # one finding
gumshoe translate --case CASE-001 --path /root/заметки.txt   # one artifact (archived first)
```

The 7B model does the translating (Qwen2.5 reads Russian well); the prompt requires every path,
address, hash and command to be copied verbatim, and the output is checked for that — a missing
token is flagged. Originals stay next to translations in the report and in `translations.md`;
each translation is hashed and logged in the custody chain. For semantic (vector) search over
Cyrillic text use the multilingual `bge-m3` embedder instead of `nomic-embed-text`.

## Large images (hundreds of GB)

Everything that touches the whole image streams: the external tools are native code with
bounded memory, and every Python stage reads line by line and writes to disk (the bodyfile
goes into `timeline.db`, not RAM: 2 million files load in about 20 s at 36 MB peak memory).
What grows with the image is **time and disk**, so the pipeline is phased and resumable
(`gumshoe collect --tools loki` re-runs one tool).

| Stage | Scales with | 500 GB image, typical | Knobs |
| --- | --- | --- | --- |
| Image hash (`verify`) | image size, drive speed | 1–2 h from USB HDD, 20–30 min from NVMe; one pass computes SHA-256 and MD5 together | copy the E01 to an internal/NVMe drive first if you can |
| UAC | number of files | 1–3 h | profile in `config.yaml` |
| Loki | number of files (not bytes; media over 5 MB is skipped) | 2–12 h | `--intense` only over `intense_globs`; narrow `web_roots` |
| GoAccess | log bytes, streamed over a pipe (no copy on disk) | minutes per 10 GB | `logs.since/until` |
| Log conversion + Chainsaw | log bytes; JSONL is ~2× the raw logs | 1–3 h per 50 GB of logs | `logs.since/until`, `logs.keep_jsonl: false` |
| MariaDB review / Databases to CSV | datadir size | overlay, no copy; crash recovery minutes; tables stream at disk speed | `dbreview.databases`; `db extract --index` for a subset |
| Index | number and size of text files (50 MB per-file cap, sampled above) | 0.5–2 h | `index.include_globs`, `max_file_bytes` |
| Ask / report | findings count, not image size | minutes | model tiers |

Disk: plan for case storage of about 10–15 % of the image size plus the database copy.
Memory: the WSL cap of 5 GB holds; nothing in Gumshoe loads a whole log, timeline or JSONL into memory.
A multi-year log that dwarfs the incident window is the one thing worth narrowing by hand:
set `logs.since` to a month before the earliest indicator and the conversion, Chainsaw and
correlation passes shrink accordingly (the skipped line counts are recorded).

## Air-gapped sandbox: the offline bundle

`setup/offline/` turns the repository into a single folder that installs and runs Gumshoe on an air-gapped
Windows 11 machine with no network at any point: copy it over, double-click `Gumshoe.bat`. It carries
WSL and a pristine Ubuntu rootfs, the full offline package set, the Python wheels and every tool, and - in the
full variant - Ollama and the models (a lite bundle leaves those out; the AI assistant then stays off). [docs/OFFLINE-BUNDLE.md](docs/OFFLINE-BUNDLE.md) describes the layout, how it was built and
how it is verified on the sandbox.

## Validation

* `gumshoe selftest` is a **plumbing test** on a benign synthetic tree: custody chain
  and tamper detection, export check, every normalizer and converter, timeline,
  trends, FTS5 search, citation guard, `ask` degrading without a model, archive hash
  verification, report sections. It deliberately contains no attack artifacts.
* **Detection coverage** is the rule sets' job and is validated with their own material:
  Loki against signature-base's test files, Chainsaw with `chainsaw lint` over the Sigma
  rules plus a hunt on the converted JSONL of a known log, and, best of all, one pass
  over a reference image you know the ground truth for. `docs/TESTING.md` has two:
  the public OSDFCon 2019 "compromised web server" image (1.1 GB, published answer key,
  LVM-in-E01 like a real seizure) with a row-by-row scorecard, and `tests/testvm/`, which
  builds an aaPanel + MariaDB + WordPress VM with planted benign conditions and a
  generated `GROUND_TRUTH.md`.
* Every `collect` records the version of each external tool it found
  (`collected/tool_versions.json`, also in the custody log), so a run can be reproduced
  with the same builds.
* Tool command lines follow each tool's documented CLI; `docs/TOOLS.md` lists the exact
  invocation and what to check with `--help` on the box if a flag has moved.

## Limits to know before you rely on it

* A small CPU model misreads logs sometimes; the guard stops invented sources, not
  wrong readings. Verify against the cited artifact before a statement goes in a report.
* Coverage is that of the rules on the drive at the date they were pulled.
* Export mode loses SUID bits, ownership and ctime fidelity.
* The MariaDB review runs crash recovery on the case copy; force-recovery levels 3–4 skip
  rollback, so rows from uncommitted transactions may be absent. The level used is logged.
* No GeoIP by default; address lookups happen outside the sandbox.

Licensed under Apache-2.0 ([LICENSE](LICENSE)). The external tools and models keep their own licences ([NOTICE](NOTICE)).
