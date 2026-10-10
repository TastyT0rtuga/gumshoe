# Testing Gumshoe against images with a known answer

`gumshoe selftest` proves the plumbing. This document is about the other half: running the whole
pipeline over an image whose contents are known, and scoring what comes out. Two routes:

| Route | What you get | Effort | Needs |
| --- | --- | --- | --- |
| **A. Public reference image** (Ali Hadi, OSDFCon 2019 "Case 1 — Compromised Web Server") | A real compromised Ubuntu/Apache/Drupal host with a published answer key; the classic Linux-forensics teaching image | 1.1 GB download, 20 minutes | internet once, WSL with `ewf-tools` |
| **B. Build your own aaPanel host** (`tests/testvm/`) | An aaPanel + MariaDB + WordPress VM with planted, benign test conditions and a generated `GROUND_TRUTH.md` — the stack Gumshoe's default profile is for | 45–60 minutes, mostly waiting on installers | Hyper-V, internet while building |

Neither route involves touching anyone else's server. Route A is a published training image;
route B is a VM you build and image yourself.

---

## Route A — the public reference image

### A.1 Get it and check it

The image is published by its author for exactly this purpose (workshop material, 2019):
<https://archive.org/details/case1-webserver>. Files and the hashes archive.org publishes:

| File | Size | MD5 | SHA-1 |
| --- | --- | --- | --- |
| `Webserver.E01` | 1,169,172,006 bytes | `94490ffee246f5401d067f77b9d7c345` | `c52cdf15c43e1c5eeaae479d37fad45325968e3c` |
| `Webserver.E01.txt` (FTK Imager log) | 1,268 bytes | `e9077cc06f81d66fd6505081e6969515` | |
| `Webserver.E01.csv` (FTK Imager file list) | 32 MB | `20f06cb48b5b545152e8bb25e2fb3fe2` | |

Two different hashes matter and people mix them up:

* **The E01 file** (what you downloaded): MD5 `94490ffe…`. This is what `gumshoe init --image … --expected-md5`
  checks — it proves your copy of the container is intact.
* **The acquired data inside it**: MD5 `03e4a40ebaf6071b346fb2bf217a9f3b`, SHA-1 `dd96a502f0978679191a0ea96548e5692fcb3a1c`
  (from the FTK Imager log; 66,064,608 sectors of a 32 GB VMware disk, acquired 2019-10-06). This is what
  `ewfverify` / `ewfinfo` report and what a case file would normally carry.

```bash
# in WSL, with the download on a Windows drive
cd /mnt/d/cases/case1
md5sum Webserver.E01                       # expect 94490ffee246f5401d067f77b9d7c345
ewfverify Webserver.E01                    # expect MD5 03e4a40e… / SHA1 dd96a502… verified
```

### A.2 Mount it (LVM inside an E01)

The root filesystem is an LVM logical volume (`VulnOSv2-vg/root`) on partition 6, and the volume
was not cleanly unmounted — the same two complications you will meet on real seizures. The helper
handles both; it mounts with `ro,noatime,noexec,nosuid,noload`:

```bash
sudo apt install -y ewf-tools sleuthkit kpartx lvm2      # once; or use the offline bundle
sudo setup/wsl/mount_image.sh /mnt/d/cases/case1/Webserver.E01 --lv VulnOSv2-vg/root
ls /mnt/evidence            # bin boot etc home lib ... var  (the workshop manual's "case1/")
```

If `--lv` is omitted the helper picks the LV named `root` on its own. `sudo setup/wsl/mount_image.sh --umount` reverses everything.

### A.3 Run the case

This host has no control panel: use the **linux-generic** profile (web root `/var/www`, logs
`/var/log/apache2`, MySQL under `/var/lib/mysql`).

```bash
gumshoe --profile linux-generic init --case CASE1 --examiner "Your Name" \
        --image /mnt/d/cases/case1/Webserver.E01 --expected-md5 94490ffee246f5401d067f77b9d7c345 \
        --mount /mnt/evidence --notes "OSDFCon 2019 Case 1 reference image; validation run"
gumshoe --case CASE1 verify
gumshoe --case CASE1 collect --db        # UAC, Loki, GoAccess, Chainsaw, normalizers, MySQL review on a copy (~20 min)
gumshoe --case CASE1 index
gumshoe --case CASE1 report
```

Or, for the unattended version with vectors, translations and the 7B report: `gumshoe --case CASE1 deep`.
The intrusion window is 5–8 October 2019; narrowing the logs with `logs.since: "2019-10-04"` /
`logs.until: "2019-10-09"` in `config.yaml` is optional — the image is small.

### A.4 Answer key and scorecard

The published solutions (workshop manual: `Workshops/Case1/Case1-Workshop Manual.pdf` in
<https://github.com/ashemery/LinuxForensics>; write-ups on Forensic Focus and elsewhere) establish:

| # | Ground truth | Where it lives on the image | Gumshoe output that should show it |
| --- | --- | --- | --- |
| 1 | Hundreds of failed SSH logins for `root` from **192.168.210.131** (a brute-force attempt) | `/var/log/auth.log`, `/var/log/btmp` | `auth.bruteforce` (medium) naming 192.168.210.131; `collected/jsonl/auth/*.jsonl`; GoAccess is not involved (SSH, not HTTP) |
| 2 | Account **`mail`** then logs in over SSH from the same address, four times, and runs `sudo su -` | `wtmp`, `auth.log`, `/var/mail/.bash_history` | `auth.bruteforce_success` (critical: accepted login from an address with ≥20 prior failures); `uac.history` for `mail` with `uac.history_command` "switch to root" |
| 3 | Account **`php`** was created with `/bin/bash` and added to `sudo`; `mail` (a service account, UID 8) was given `/bin/bash`, a password and `sudo` | `/etc/passwd`, `/etc/shadow`, `/etc/group`, `auth.log` (`useradd`, `usermod`) | `uac.service_shell` (medium) for `mail -> /bin/bash`; `uac.account_added` (high) for `php` **if** `/etc/passwd-` predates the change (it is the backup from the last account edit — check the finding either way); `auth.account_change` (high) for each `useradd`/`usermod`/`passwd` line in `auth.log`; the accounts table in `inventory.json` lists both with their shells |
| 4 | Root's history shows **`/var/log/lastlog`** was edited (vi; `lastlog.swp`/`.swpx` left behind) and references **`update.php`** and **`37292.c`** | `/root/.bash_history`, `/var/log/` | `uac.history_command` "touches a log file" / "compiles source" / "references /tmp" with line numbers; `gumshoe view --path /root/.bash_history` to read it whole |
| 5 | `37292.c` is the **overlayfs local root exploit (CVE-2015-1328)**, compiled and deleted from `/tmp` | deleted — recoverable only from the ext4 journal (`debugfs`/`ext4magic`) | **Not expected.** Gumshoe does not carve deleted files; the history lines in row 4 are the lead. Recover with the manual's Task 6 and add the result with `gumshoe notes --add` |
| 6 | Web app is **Drupal 7.26** at `/var/www/html/jabc`, vulnerable to CVE-2014-3704 ("Drupalgeddon") | `/var/www/html/jabc/includes/bootstrap.inc` | `webapp.site` for `jabc`: `drupal 7.26` (nested one level below `html`, which is why `discover_sites` looks one level down); the examiner looks the version up — Gumshoe has no CVE database |
| 7 | Three **POST** requests from 192.168.210.131 carrying a large **base64** blob; it decodes to a PHP reverse shell to 192.168.210.131:4444 | `/var/log/apache2/access.log` | `collected/web_requests_index.json` → `posts` lists the target with the IP and line numbers; `gumshoe ask "which addresses sent POST requests and to what"` cites the log lines; Chainsaw/Sigma web rules may add a hit depending on the rule set version; GoAccess trends show 192.168.210.131 among top hosts |
| 8 | Timezone and host identity (hostname `VulnOSv2`) | `/etc/timezone`, `/etc/hostname` | UAC's copies under `raw/uac/.../[root]/etc/`; `gumshoe view --path /etc/hostname`; report header |
| 9 | Nothing persistent in cron/systemd/`ld.so.preload`/`authorized_keys` (persistence here is the two sudo accounts) | — | **No** `uac.cron_suspicious`, `uac.systemd_suspicious`, `uac.ld_preload`, `uac.uid0` findings — false-positive check |

Scoring: rows 1–4 and 6–8 should appear in `findings.jsonl` / the triage report with a path and
line you can open with `gumshoe view`; row 5 is a documented gap; row 9 should stay quiet. If a row
is missing, the raw tool output is under `raw/` and the normalizer log under `logs/` — file an issue
with the finding you expected and the lines from the image that carry it.

What the LLM layer adds on top: `gumshoe ask --deep "How did the attacker get in and what did they
change?"` should produce an answer whose numbered citations resolve to rows 1, 2, 3, 6 and 7 above;
the citation guard drops anything it cannot tie to a retrieved chunk. Compare the answer against the
table, not the other way round — the table is the ground truth.

`Webserver.E01.csv` (FTK Imager's own file list) is an independent inventory of the same image; a
quick cross-check is to confirm the paths cited by Gumshoe appear in it.

---

## Route B — build the aaPanel test host

`tests/testvm/` creates a VM, turns it into an aaPanel + MariaDB 10.6 + PHP 8.1 + WordPress host,
performs ordinary administration, plants a handful of **benign** test conditions, writes
`/root/GROUND_TRUTH.md` with the UTC time of every action and the Gumshoe rule it should trigger,
and powers the VM off. The VHDX is then your evidence image.

### B.1 Create the VM (Windows host with Hyper-V; internet)

```powershell
# Administrator PowerShell, in the repo
powershell -ExecutionPolicy Bypass -File tests\testvm\01_create_vm.ps1
```

Downloads Ubuntu Server 22.04.5 (SHA-256 checked against Ubuntu's `SHA256SUMS`), creates
`gumshoe-test` (Gen 2, 4 GB, 2 vCPU, 40 GB VHDX at `C:\VMs\gumshoe-test.vhdx`, Default Switch),
starts it and opens the console. Answer the installer as the script prints (user `testadmin`,
OpenSSH yes, LVM on). Parameters: `-VmRoot`, `-MemoryGB`, `-DiskGB`, `-Switch`.

### B.2 Provision inside the VM

```powershell
$ip = (Get-VM gumshoe-test | Select -Expand NetworkAdapters | Select -Expand IPAddresses)[0]
scp tests\testvm\02_provision_aapanel.sh testadmin@${ip}:/tmp/
ssh testadmin@$ip "sudo bash /tmp/02_provision_aapanel.sh"          # stage 1: aaPanel + stack (10–20 min)
```

Stage 1 ends with a five-minute checklist in the panel UI (add the site with a database and FTP
account, add a backup cron task, log out and in). Then:

```powershell
ssh testadmin@$ip "sudo bash /tmp/02_provision_aapanel.sh seed"            # clean shutdown
ssh testadmin@$ip "sudo bash /tmp/02_provision_aapanel.sh seed --dirty"    # or: abrupt power-off (dirty journal, MariaDB crash recovery)
```

Stage 2 installs WordPress with wp-cli, writes documents (CSV, Markdown, UTF-8 and Windows-1251
Cyrillic text), generates web traffic (page views, 404s, a failed `wp-login.php` POST, a download of
a `.sql` dump left in the web root, one request with a scanner user agent), 25 failed SSH logins from
the VM to itself, and plants: a backdated file (timestomp check), the **EICAR** test file fetched
from eicar.org at run time (signature hit for Loki; never stored in this repository), a `.sql` dump in
the web root, an extra sudo user, an SSH key in `/root/.ssh/authorized_keys`, and — as
false-positive controls — an ordinary root crontab entry and an ordinary systemd unit.
`/root/GROUND_TRUTH.md` ends with the planted files' SHA-256s and the panel/site credentials.

### B.3 Image it and run

The VM is off; its disk *is* the image. Either:

* attach the VHDX straight to WSL (Admin PowerShell): `wsl --mount --vhd C:\VMs\gumshoe-test.vhdx --bare`,
  then in WSL `sudo setup/wsl/mount_image.sh /dev/sdX` (the helper handles the LVM root), or
* run `setup/wsl/mount_image.sh /mnt/c/VMs/gumshoe-test.vhdx` (qemu-nbd, read-only), or
* make a proper E01 of it first with FTK Imager (`File → Create Disk Image → Image File`) and treat
  it like any other case, hashes and all — closest to the real workflow.

```bash
gumshoe init --case TESTVM --examiner "Your Name" --mount /mnt/evidence --image /mnt/c/VMs/gumshoe-test.vhdx
gumshoe --case TESTVM verify && gumshoe --case TESTVM collect --db && gumshoe --case TESTVM index && gumshoe --case TESTVM report
gumshoe --case TESTVM view --path /root/GROUND_TRUTH.md      # the answer key, read from the image itself
```

### B.4 Scorecard

Every row of `GROUND_TRUTH.md` names the expected rule. Rows marked "should NOT be flagged" are
false-positive controls. Expected rules, in the order the script plants them:

`aapanel.settings`, `aapanel.user`, `aapanel.cron`, `webapp.site` (WordPress with version),
`db.wp_admin` ×2, `documents.inventory` (CSV/MD/TXT with a `cyrillic` tag and `cp1251` detected),
`uac.timestomp` (high, exactly one: `handover.md`), Loki signature hit on `eicar.com.txt`,
`weblog.dump_download` (high: `.sql` served with 200), `uac.account_added` (`deployer`),
`uac.authorized_keys`, `uac.history_command` for the provisioning commands root ran,
`auth.bruteforce` (25 failures ≥ threshold 20), GoAccess trends with the 404s and the scanner UA —
and **no** `uac.cron_suspicious`, `uac.systemd_suspicious`, `uac.uid0`, `uac.ld_preload`, `db.udf`.

If `--dirty` was used, `gumshoe verify` must still show `ro,noload` and the MariaDB review should
report the recovery level it needed (`db.recovery_level`) rather than failing.

---

## What a pass looks like

* `gumshoe selftest`: all checks pass (CI runs it on Python 3.10–3.13).
* Route A: rows 1–4 and 6–8 present with correct paths/lines; row 9 quiet; the deep answer cites them.
* Route B: every `GROUND_TRUTH.md` row matched; both false-positive controls quiet.
* `custody.log` verifies at the end of each run (`gumshoe verify` prints the chain state), and every
  file the report cites has a hashed copy under `archive/` whose hash matches the original on the mount.

Record the run (image hashes, tool versions from `collected/tool_versions.json`, the scorecard) in the case
notes; that record is what you hand over when someone asks how the tool was validated.
