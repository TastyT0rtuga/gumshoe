# External tools: what Gumshoe runs and how to validate it on the box

Every invocation is logged to `custody.log` (`tool_start` / `tool_end`) with the exact
command line, exit code, duration and SHA-256 of each output file. Flags below follow
the tools' documented CLIs; run `--help` on the box if a release moved one, and edit
`gumshoe/runners.py` (one function per tool).

| Tool | Source | Gumshoe runs | Output used | Validate with |
| --- | --- | --- | --- | --- |
| UAC | github.com/tclahr/uac (release tar.gz) | `uac -p ir_triage -m /mnt/evidence -s linux --hash-collected cases/<C>/collected/raw/uac` (via `sudo -n` when not root) | `bodyfile/bodyfile.txt`, collected files under the output tree | `uac --help`; a dry run on a small mounted test image; check the output tree has `bodyfile/` |
| Loki | github.com/Neo23x0/Loki (source) + signature-base | `loki.py -p <target> -l <log> --noprocscan --dontwait --csv` per target (web roots, panel, temp dirs, home dirs, DB plugin dir), then a second `--intense` pass over upload-type directories (`intense_globs`); `gumshoe deep` runs intense everywhere | `loki_NN_*.log` (CSV lines) | `loki.py --help`; run against signature-base's own test files; confirm `signature-base/yara` is populated |
| GoAccess | apt (in the distro) | `( cat/zcat <every log of the site> ) | goaccess - --log-format=COMBINED -o <site>.json -o <site>.html --no-global-config` (streamed; no merged copy on disk) | `<site>.json` (trends), `<site>.html` (open directly) | `goaccess --version`; if aaPanel's nginx uses a custom log format, pass `--log-format='...'` in `config.yaml` |
| Chainsaw | github.com/WithSecureLabs/chainsaw (release zip) | `chainsaw hunt cases/<C>/collected/jsonl/web -s tools/sigma/rules/web --mapping gumshoe/rules/chainsaw-mappings/gumshoe-web.yml --json -o web.json --skip-errors` (and `auth` with the `linux` rules) | `web.json`, `auth.json` | `chainsaw lint -r tools/sigma/rules/web --kind sigma`; a hunt on the self-test JSONL; compare the mapping files with `mappings/` shipped in the release and adjust keys if the schema differs |
| Sigma rules | github.com/SigmaHQ/sigma (clone) | read by Chainsaw | — | keep the clone date in the case notes; coverage is as of that date |
| Plaso (optional) | pip wheels | `log2timeline.py --storage-file ... /mnt/evidence` then `psort.py -o l2tcsv` | `supertimeline.csv` | slow on 50 GB; run as its own phase |
| ClamAV (optional) | apt | `clamscan -r --infected --no-summary -l clamscan.log <targets>` | `clamscan.log` | never run while a model is loaded (about 2 GB of signatures) |
| MariaDB (WSL) | apt mariadb-server | private `mariadbd` on a copy of the datadir: `--skip-networking --skip-grant-tables --skip-log-bin --innodb-force-recovery=<0,1,3,4>`; queries via `mariadb --socket` | `collected/dbreview.json` | `mariadbd --version`; check `collected/dbcopy/mariadbd.err` after a run; delete `dbcopy/` when done |
| Arsenal Image Mounter | arsenalrecon.com | by hand on Windows (read-only mount) | a `\\.\PHYSICALDRIVEn` for `wsl --mount` | Disk Management shows the disk; `lsblk` inside WSL shows `/dev/sdX` |
| ewf-tools | apt | by hand: `ewfmount image.E01 /mnt/ewf` | `/mnt/ewf/ewf1` | `ewfinfo image.E01` prints the acquisition hashes to compare with `gumshoe verify` |

## Field names in the converted logs

`collected/jsonl/web/<site>.jsonl` carries Sigma's `webserver`/`proxy` taxonomy with both
spellings the rule corpus uses: `c-ip`, `c-uri`, `c-uri-stem`/`cs-uri-stem`,
`c-uri-query`/`cs-uri-query`, `c-uri-extension`/`cs-uri-extension`, `cs-method`,
`sc-status`, `sc-bytes`/`cs-bytes`, `cs-referer`, `c-useragent`/`cs-user-agent`,
`cs-version`, `username`, `timestamp`, plus `source_file`, `line`, `site` for provenance.
`collected/jsonl/auth/auth.jsonl` carries `timestamp`, `host`, `program`, `pid`, `message`,
`source_file`, `line`; Sigma's Linux keyword rules match on `message`.

## Adding a tool

1. Add a runner in `gumshoe/runners.py` that writes under `cases/<C>/collected/raw/<tool>/`
   through `run_cmd()` (that is what logs it).
2. Add a normalizer in `gumshoe/normalize/` that returns `Finding` objects with `path`,
   `line`, `excerpt`, `rule`, and calls `with_provenance()`.
3. Register both in `gumshoe/collect.py`.
