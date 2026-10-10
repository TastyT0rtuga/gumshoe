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

## Phase D — mount the image read-only  (~5 minutes)

13. Put the E01 (all segments) on the external drive, e.g. `D:\case\server.E01`.
14. Arsenal Image Mounter → **Mount image** → choose the E01 → tick **Read only** → Mount.
    Windows Disk Management now shows a new disk; note its number N (e.g. Disk 3).
15. Admin PowerShell: `wsl --mount \\.\PHYSICALDRIVEN --bare` (replace N).
    You should see "The disk was attached".
    - Error 0x80070001 or hang → unmount in Arsenal, re-mount, try again once; if it still fails, use the
      no-bridge route in `gumshoe mount-help` (B): `ewfmount` inside WSL straight from `/mnt/d/case/server.E01`.
16. In WSL: `lsblk` → find the new device (e.g. `sdc` with partitions `sdc1`, `sdc2`). The Ubuntu root
    is usually the largest ext4 partition. Then:
    `sudo mkdir -p /mnt/evidence && sudo mount -o ro,noload,noexec,nosuid /dev/sdcN /mnt/evidence`
    `ls /mnt/evidence` should show `etc  www  var  root ...`.
    - "unknown filesystem type LVM2_member" → `sudo vgscan && sudo vgchange -ay && lsblk`, then mount
      the `/dev/mapper/...-root` device the same way.
    - `ls` shows nothing or only `lost+found` → wrong partition; `sudo umount /mnt/evidence` and try the other.

## Phase E — run the case  (collect: 1–4 hours on 50 GB, overnight on 500 GB; the rest minutes)

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

## Phase F — check the work before it leaves the box  (~1 hour of reading)

24. Open the report. For every critical and high finding, open the cited file in the image
    (`less /mnt/evidence/<path>`) and confirm the excerpt is really there.
25. Every AI-narrative block: read each sentence against its cited findings; delete anything you cannot confirm.
26. `gumshoe custody --case CASE-001 --show 100` → must print `OK   chain intact`.
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
| `run gumshoe verify first` | Step 18 |
| `uac: sudo: a password is required` | run `sudo -v` first, then the collect command again |
| `chainsaw ... mapping` error | compare `gumshoe/rules/chainsaw-mappings/*.yml` with `mappings/` inside `/opt/dfir/tools/chainsaw`; adjust field keys to that schema |
| GoAccess `Format errors` | aaPanel's nginx log format differs; set `tools.goaccess.log_format` in config.yaml to the nginx `log_format` string from `/mnt/evidence/www/server/nginx/conf/nginx.conf` |
| Ollama answers very slowly | confirm `ollama-pcores.cmd` was used; in config set `num_thread: 8`; ask with the 3B (default), keep the 7B for reports |
| `model unavailable` | Ollama window closed, or wrong `base_url` (step 12) |
| Windows becomes sluggish / out of memory | close the UI, run `ollama stop <model>` on Windows, lower `memory=` in `%USERPROFILE%\.wslconfig` to 4GB and `wsl --shutdown` |
| MariaDB review: `would not start at any recovery level` | read `collected/dbcopy/mariadbd.err`; often a MariaDB version mismatch between the image and the distro — note it in limitations and skip the DB review |
| Selftest fails after an edit | you changed code; `python3 gumshoe.py selftest` prints which check broke |
