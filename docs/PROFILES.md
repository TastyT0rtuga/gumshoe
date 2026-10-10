# Profiles: what is generic, what is case-type specific, and how to add a case type

Gumshoe is a general evidence pipeline with a thin, swappable layer for the kind of system
being examined. A **profile** (`gumshoe/profiles/<name>.yaml`) sets the evidence paths, which
normalizers run, and which tools are on. Everything else is shared.

## Profile-independent (the spine, most of the code)

| Component | Works on |
| --- | --- |
| Case directory, image hash verification, read-only checks, hash-chained custody log | any evidence |
| Runner framework (every external tool logged with command line, exit code, output hashes) | any tool |
| Finding model with provenance (path, line/offset, excerpt, SHA-256, inode times) | any normalizer |
| SQLite FTS5 index, encoding detection (Cyrillic etc.), chunk-level citations | any text |
| Cited question answering, citation guard, answer packets, sessions, case brief, notes, pins | any case |
| Archive-on-cite, evidence export bundles (files, directories, unpacked archives) | any file |
| Document discovery and extraction (xlsx/docx/pdf/csv/md/…), viewer, browser | any filesystem |
| Machine translation of non-English text (labelled, hashed, logged) | any text |
| Reports (triage/trends/IOC), deep run, UI | any case |
| UAC + bodyfile timeline, Loki + YARA, Chainsaw + Sigma, GoAccess, auth/web log conversion | any **Linux** server |

## Case-type specific (today)

| Module | Specific to | Notes |
| --- | --- | --- |
| `normalize/aapanel.py` | aaPanel / BT panel | panel SQLite DB, panel cron scripts, vhost configs, settings |
| `dbreview.py` | MariaDB / MySQL | copy + crash recovery + canned queries; MySQL 8 works the same way |
| `normalize/webapp.py` | PHP sites (WordPress, Laravel, plain) | structural inventory; generic to any PHP host |
| `gumshoe/profiles/linux-aapanel.yaml` paths | aaPanel layout (`/www/...`) | `linux-generic` uses `/var/www`, `/var/log/nginx` ... |

## Adding a case type

1. Write `gumshoe/profiles/<name>.yaml` (paths, `normalizers:` list, tools on/off).
2. For each new artifact family, add a runner in `runners.py` (if an external tool does the work)
   and a normalizer in `normalize/` that returns `Finding`s with `with_provenance()`.
3. Register the normalizer in `collect.REGISTRY`; list it in the profile.
4. Add a sample of the tool's output under `tests/samples/` and a check in `tests/selftest.py`.

## Roadmap of profiles (what each would reuse and what it needs)

| Profile | Mounting | Collection / detection tools (all offline, established) | New normalizers | Reuses |
| --- | --- | --- | --- | --- |
| `windows` | NTFS mounts read-only in WSL (`ntfs-3g`) or AIM | **Hayabusa** and **Chainsaw** natively on EVTX (this is their home turf); Eric Zimmerman tools via Wine or run on the Windows host (MFTECmd, RECmd/RegRipper, PECmd, AmcacheParser, LECmd, JLECmd, SrumECmd); Loki + signature-base | evtx (Hayabusa CSV), registry (RECmd/RegRipper), MFT/USN timeline, prefetch/amcache/shimcache execution evidence, SRUM, users/groups, scheduled tasks, services, RDP/logon events | everything in the spine; timeline, documents, index, memory, reports |
| `macos` | APFS via `apfs-fuse` read-only, or a logical export | **mac_apt** (open source, comprehensive), **UAC** (macOS live), plist/unified-log parsers | unified logs, plists, FSEvents, KnowledgeC, login items/LaunchAgents, TCC, Safari/Chrome | spine |
| `memory` | n/a (dump file) | **Volatility 3** (pslist, netscan, malfind, cmdline, dlllist, hivelist) with JSON output; Loki on dumped modules | per-plugin normalizers into findings with PID/offset provenance | spine (DFIR-Chain pattern) |
| `pcap` | n/a | **Zeek** (conn, dns, http, ssl, files logs) + **Suricata** offline (eve.json) + Sigma via Chainsaw on JSON | Zeek logs → trends (GoAccess-like) and findings; Suricata alerts | spine |
| `cloud-logs` | n/a (exports) | **Chainsaw + Sigma cloud rules** on M365 UAL, Entra sign-ins, AWS CloudTrail, GCP audit JSON | per-source converters to Sigma field names | spine |
| `mobile` | n/a (extractions) | **iLEAPP / ALEAPP** (open source) on iOS/Android extractions; UFED/Cellebrite report import | report importers | spine |
| `linux-cpanel`, `linux-plesk`, `linux-cyberpanel`, `docker-host` | as Linux | same Linux tools | a panel reader each (like `aapanel.py`); container layers for Docker | everything in `linux-generic` |
| `postgres` / `mysql8` / `mongodb` | as Linux | the matching server on a copy | canned queries | `dbreview` pattern |
| `crypto-artifacts` (any OS) | as host | file-name/format discovery of wallet and exchange artifacts; browser profile extension stores | inventory + documents | documents, export |

Each row is a day or two of work on top of the spine, not a new tool.
