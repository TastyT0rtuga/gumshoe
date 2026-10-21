# Changelog

## Unreleased

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
