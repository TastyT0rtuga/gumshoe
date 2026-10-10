# Changelog

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
