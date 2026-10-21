"""Command line. `python gumshoe.py <command>` or, after pip install -e ., `gumshoe <command>`."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path  # noqa: F401 (used by subcommands)

from . import __version__
from .case import Case, load_config, project_root, package_dir, running_from_clone
from .mount import check_readonly, MOUNT_HELP


def _cfg(args):
    return load_config(args.config, profile=getattr(args, "profile", None))


def cmd_profiles(args):
    from .case import list_profiles
    for p in list_profiles():
        print(f"{p['name']:18s} {p['description']}")
    print("\nselect with: gumshoe --profile <name> init ...   (recorded in the case; or set `profile:` in config.yaml)")


def _case(args) -> Case:
    cfg = _cfg(args)
    cases_root = Path(args.cases_root)
    if not args.case:
        cases = sorted(p.name for p in cases_root.iterdir() if (p / "case.json").exists()) if cases_root.exists() else []
        if len(cases) == 1:
            args.case = cases[0]
        else:
            sys.exit("--case required (cases: " + (", ".join(cases) or "none") + ")")
    c = Case.open(cases_root / args.case, cfg)
    # a case keeps the profile it was created with unless --profile is given explicitly
    recorded = c.meta.get("profile")
    if recorded and recorded != cfg.get("profile") and not getattr(args, "profile", None):
        c = Case.open(cases_root / args.case, load_config(args.config, profile=recorded))
    return c


def cmd_init(args):
    cfg = _cfg(args)
    mode = args.mode
    c = Case.create(Path(args.cases_root), args.case, args.examiner, args.image, args.mount, mode, cfg, notes=args.notes or "")
    print(f"created case {c.dir}")
    if args.expected_sha256 or args.expected_md5:
        r = c.verify_image({"sha256": args.expected_sha256 or "", "md5": args.expected_md5 or ""})
        print(json.dumps(r, indent=2))


def cmd_verify(args):
    c = _case(args)
    ro = check_readonly(c.mount_root, c.mode)
    c.meta["readonly_check"] = {**ro, "at": __import__("gumshoe.integrity", fromlist=["utc_now"]).utc_now()}
    c.save_meta()
    c.custody.append("readonly_check", ro)
    print(("OK  " if ro["ok"] else "FAIL ") + ro["reason"])
    if args.expected_sha256 or args.expected_md5 or args.hash_image:
        r = c.verify_image({"sha256": args.expected_sha256 or "", "md5": args.expected_md5 or ""})
        print(json.dumps(r, indent=2))
    if not ro["ok"] and not args.force:
        sys.exit(2)


def cmd_collect(args):
    from .collect import collect_case
    c = _case(args)
    ro = c.meta.get("readonly_check") or {}
    if not ro.get("ok") and not args.force:
        sys.exit("run `gumshoe verify` first (or --force to skip the read-only check)")
    s = collect_case(c, tools=args.tools.split(",") if args.tools else None, skip=args.skip.split(",") if args.skip else None,
                     db=args.db, normalize_only=args.normalize_only)
    print(json.dumps({"total": s.get("total"), "by_severity": s.get("by_severity"), "by_source": s.get("by_source")}, indent=2))


def cmd_normalize(args):
    from .collect import normalize_all
    c = _case(args)
    normalize_all(c, only=args.only.split(",") if args.only else None)
    print(json.dumps(c.read_json("summary.json", {}).get("by_severity"), indent=2))


def cmd_dbreview(args):
    from .dbreview import review
    c = _case(args)
    from .collect import write_summary
    fs = review(c)
    existing = [f for f in c.read_findings() if f.get("source") != "dbreview"]   # replace an earlier review
    dicts = existing + [f.to_dict() for f in fs]
    c.write_findings(dicts)
    write_summary(c, dicts)
    print(f"[dbreview] {len(fs)} finding(s) merged; re-run `gumshoe index`")


def cmd_index(args):
    from .index import build
    from .llm import Ollama
    c = _case(args)
    client = Ollama(c.cfg["llm"]) if args.vectors else None
    print(json.dumps(build(c, with_vectors=args.vectors, client=client), indent=2))


def cmd_notes(args):
    from .memory import read_notes, write_notes, append_note, notes_path
    c = _case(args)
    if args.add:
        h = append_note(c, args.add)
        print(f"added; notes sha256 {h[:16]}")
    elif args.set_file:
        h = write_notes(c, Path(args.set_file).read_text("utf-8"))
        print(f"notes replaced from {args.set_file}; sha256 {h[:16]}")
    else:
        print(read_notes(c) or f"(no notes yet; edit {notes_path(c)} or use --add)")


def cmd_pin(args):
    from .memory import set_pin, read_pins
    c = _case(args)
    if args.finding:
        pins = set_pin(c, args.finding, pinned=not args.unpin)
        print("pinned:", ", ".join(pins) or "(none)")
    else:
        print("pinned:", ", ".join(read_pins(c)) or "(none)")


def cmd_session(args):
    from .memory import list_sessions, clear_session, read_session
    c = _case(args)
    if args.clear:
        clear_session(c, args.clear)
        print(f"cleared session {args.clear}")
    elif args.show:
        for t in read_session(c, args.show, last=50):
            print(f"{t['at']}  Q: {t['question']}\n{'':22s}A: {(t.get('answer') or '(no answer)')[:300]}\n")
    else:
        for s in list_sessions(c):
            print(f"{s['session']:30s} {s['turns']:4d} turns")


def cmd_ask(args):
    from .rag import ask
    c = _case(args)
    r = ask(c, args.question, k=args.k, tier="report" if args.report_model else "interactive", do_archive=not args.no_archive,
            session=args.session, use_memory=not args.no_memory)
    print("\n=== SOURCES ===")
    for s in r["sources"]:
        print(f"[{s['n']}] {s['relpath']}" + (f" lines {s['line_start']}-{s['line_end']}" if s.get("line_start") else "") +
              f"  sha256 {(s.get('sha256') or '')[:16]}")
    print("\n=== ANSWER ===")
    print(r["answer"] or "(no model answer)")
    print(f"\nsupported={r['supported']} valid={r['valid_citations']} invalid={r['invalid_citations']} archived={len(r.get('archived', []))}")
    if r.get("note"):
        print("note:", r["note"])
    print(f"answer packet (answer + every source excerpt): {r.get('packet')}")
    print(f"export the cited files: gumshoe export --case {c.meta.get('case_id')} --question {r.get('question_index')} --name q{r.get('question_index')}")


def cmd_view(args):
    from .documents import preview, open_bytes
    c = _case(args)
    if args.save:
        data = open_bytes(c, args.path, "saved copy via cli")
        if data is None:
            sys.exit("not a file on the mount")
        Path(args.save).write_bytes(data)
        print(f"wrote {args.save} ({len(data)} bytes); archived with sidecar in evidence/")
        return
    pv = preview(c, args.path)
    if pv["kind"] == "table":
        for sheet, rows in pv["sheets"].items():
            print(f"### {sheet}")
            for i, row in enumerate(rows[:args.rows], 1):
                print(f"{i:5d}: " + " | ".join(str(x) for x in row))
    elif pv["kind"] in ("text", "markdown"):
        print(pv["text"][:args.chars])
    elif pv["kind"] == "image":
        print(f"image ({pv['ext']}, {len(pv['bytes'])} bytes) — use --save to write it out, or the UI Documents tab")
    else:
        print(f"{pv['kind']}: {pv.get('note', '')}")


def cmd_export(args):
    from .export import assemble
    c = _case(args)
    r = assemble(c, args.name, paths=args.paths.split(",") if args.paths else None,
                 finding_ids=args.findings.split(",") if args.findings else None,
                 question_index=[int(x) for x in args.question.split(",")] if args.question else None,
                 unpack_archives=args.unpack)
    print(json.dumps(r, indent=2))


def cmd_ls(args):
    from .integrity import stat_times
    c = _case(args)
    base = c.abs(args.path)
    if not base.exists():
        sys.exit(f"no such path on the mount: {args.path}")
    if base.is_file():
        st = stat_times(base)
        print(f"{st['size']:>12}  {st['mtime']}  {st['ctime']}  {args.path}")
        return
    rows = []
    for p in sorted(base.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
        try:
            st = stat_times(p)
        except OSError:
            continue
        rows.append((p.is_dir(), st["size"], st["mtime"], st["ctime"], p.name))
    print(f"{len(rows)} entries in {args.path}")
    for is_dir, size, mt, ct, name in rows[:args.max]:
        print(f"{'d' if is_dir else '-'} {size:>12}  {mt}  {ct}  {name}{'/' if is_dir else ''}")
    if len(rows) > args.max:
        print(f"... {len(rows) - args.max} more (use --max)")


def cmd_intake(args):
    """Drop anything -> case: detect, extract, mount (+ second volumes), create, verify, collect [, deep]."""
    from .intake import Intake
    cfg = _cfg(args)
    examiner = args.examiner or cfg.get("examiner") or os.environ.get("GUMSHOE_EXAMINER") or ""
    if not examiner:
        sys.exit("--examiner is required (or set examiner: in config.yaml)")
    it = Intake(Path(args.cases_root), cfg, examiner)
    case = it.run(Path(args.path), case_id=args.case or None, deep=args.deep, replace_mount=args.replace_mount,
                  hash_images=not args.no_hash, notes=args.notes or "")
    print(json.dumps({"case": case.meta.get("case_id"), "mode": case.mode, "root": str(case.mount_root)}, indent=2))


def cmd_hopper(args):
    """What is lying in the hopper and what each item is."""
    from .intake import scan_hopper, human
    from .settings import hopper_dir
    hop, note = hopper_dir(Path(args.cases_root))
    if note and not args.path:
        print("note:", note)
    items = scan_hopper(Path(args.path) if args.path else hop)
    if args.json:
        print(json.dumps(items, indent=2, default=str))
        return
    if not items:
        print("hopper is empty")
    for it in items:
        print(f"{it['name']:50.50s} {it['kind']:10s} {human(it.get('size', 0)):>10s}  {it.get('format', '')}")
        for n in it.get("notes", []):
            print(f"{'':50s} {n}")


def cmd_settings(args):
    """Show or change the examiner settings (hopper / work / exports folders, examiner name)."""
    from . import settings as cfgstore
    changes = {k: getattr(args, k) for k in ("hopper", "work", "exports", "examiner") if getattr(args, k) is not None}
    if changes:
        cfgstore.save(Path(args.cases_root), changes)
    cur = cfgstore.load(Path(args.cases_root))
    print(json.dumps({**cur, "_file": str(cfgstore.settings_path(Path(args.cases_root)))}, indent=2))


def cmd_remount(args):
    """After a reboot: mount a case's evidence again exactly as intake did."""
    from .intake import remount
    c = _case(args)
    r = remount(c, replace_mount=args.replace_mount)
    print(json.dumps({"images": r.get("images"), "volumes": [v.get("mountpoint") for v in r.get("volumes", []) if v.get("mounted")]}, indent=2))


def cmd_deep(args):
    from .deep import run
    cfg = _cfg(args)
    c = _case(args)
    r = run(c.dir, cfg, skip_tools=args.skip_tools, no_vectors=args.no_vectors)
    print(json.dumps({k: v for k, v in r.items() if k != "stages"}, indent=2))
    for s in r.get("stages", []):
        print(f"  {'ok  ' if s['ok'] else 'FAIL'} {s['seconds']:>8.1f}s  {s['stage']}" + (f"  — {s['error']}" if not s["ok"] else ""))


def cmd_documents(args):
    from .documents import run as docs_run
    c = _case(args)
    if args.list:
        doc = c.read_json("documents.json", {}) or {}
        for it in doc.get("items", []):
            if args.kind and it["kind"] != args.kind:
                continue
            ex = it.get("extracted") or {}
            print(f"{it['kind']:12s} {it['size']:>10d}  {it['mtime']}  {'text' if ex.get('text_file') else '-':4s}  {it['path']}")
        print(f"\n{doc.get('count', 0)} files, {doc.get('extracted', 0)} extracted; by kind {doc.get('by_kind')}")
        return
    fs = docs_run(c)
    print(fs[0].title if fs else "no documents")
    print("re-run `gumshoe index` to make them searchable/citable")


def cmd_report(args):
    from .report import build
    c = _case(args)
    out = build(c, kind=args.kind, with_llm=(None if args.llm is None else args.llm))
    print(out)


def cmd_translate(args):
    from .translate import translate_findings, translate_artifact
    c = _case(args)
    tier = "interactive" if args.fast else "report"
    if args.path:
        r = translate_artifact(c, args.path, tier=tier)
        print(r.get("translation") or r.get("error"))
        print(f"\nmodel={r.get('model')} encoding={r.get('encoding')} chars={r.get('chars')}")
        return
    ids = args.finding.split(",") if args.finding else None
    r = translate_findings(c, finding_ids=ids, all_non_latin=args.all, tier=tier)
    print(json.dumps(r, indent=2))


def cmd_archive(args):
    from .archive import archive, archive_findings, verify_archive
    c = _case(args)
    if args.verify:
        print(json.dumps(verify_archive(c), indent=2))
    elif args.findings:
        archive_findings(c, args.min_severity)
    elif args.path:
        sc = archive(c, args.path, args.reason or "manual")
        print(json.dumps(sc, indent=2, default=str) if sc else "not a file on the mount")
    else:
        sys.exit("give --path, --findings or --verify")


def cmd_custody(args):
    c = _case(args)
    ok, n, bad, msg = c.custody.verify()
    print(("OK   " if ok else "FAIL ") + msg + (f" (first bad seq {bad})" if bad else ""))
    if args.show:
        for r in c.custody.tail(args.show):
            print(f"{r.seq:5d} {r.ts} {r.action:20s} {json.dumps(r.details, default=str)[:160]}")
    if not ok:
        sys.exit(2)


def cmd_status(args):
    from .llm import Ollama
    c = _case(args)
    s = c.read_json("summary.json", {}) or {}
    ol = Ollama(c.cfg["llm"])
    st = {
        "case": c.meta.get("case_id"), "mode": c.mode, "mount_root": str(c.mount_root),
        "image_verified": (c.meta.get("image_hashes") or {}).get("match"),
        "readonly": (c.meta.get("readonly_check") or {}).get("ok"),
        "findings": s.get("total"), "by_severity": s.get("by_severity"),
        "index": c.index_db.exists(), "ollama": ol.available(), "models": ol.models()[:10],
        "custody": c.custody.verify()[3],
    }
    print(json.dumps(st, indent=2))


def cmd_ui(args):
    import subprocess
    cfg = _cfg(args)
    app = package_dir() / "ui" / "app.py"
    # 0.0.0.0, not the default IPv6 wildcard: under WSL only an IPv4 listener is reachable from Windows
    # (NAT localhost forwarding and mirrored networking both speak 127.0.0.1 only)
    cmd = [sys.executable, "-m", "streamlit", "run", str(app), "--server.headless", "true", "--browser.gatherUsageStats", "false",
           "--server.port", str(args.port), "--server.address", getattr(args, "address", None) or "0.0.0.0",
           "--client.toolbarMode", "viewer"]          # keeps the menu with Settings > Theme; no Deploy, no developer items
    theme = (getattr(args, "theme", None) or (cfg.get("ui", {}) or {}).get("theme") or "auto").lower()
    if theme in ("light", "dark"):
        cmd += ["--theme.base", theme]
    cmd += ["--", "--cases-root", str(Path(args.cases_root).resolve()), "--config", str(args.config or "")]
    subprocess.call(cmd)


def cmd_selftest(args):
    from tests.selftest import run_selftest
    ok = run_selftest(verbose=True)
    sys.exit(0 if ok else 1)


def cmd_mount_help(args):
    print(MOUNT_HELP)


def main(argv=None):
    p = argparse.ArgumentParser(prog="gumshoe", description=f"Gumshoe {__version__}: offline, cited forensic triage")
    p.add_argument("--config", default=str((project_root() if running_from_clone() else Path.cwd()) / "config.yaml"))
    p.add_argument("--cases-root", default=str((project_root() if running_from_clone() else Path.cwd()) / "cases"))
    p.add_argument("--case", help="case id (directory name under cases/)")
    p.add_argument("--profile", help="evidence profile (see `gumshoe profiles`); default from config.yaml or linux-aapanel")
    # the same options are accepted after the subcommand too (gumshoe init --case X ...)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", default=argparse.SUPPRESS)
    common.add_argument("--cases-root", default=argparse.SUPPRESS)
    common.add_argument("--case", default=argparse.SUPPRESS)
    common.add_argument("--profile", default=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="cmd", required=True, parser_class=lambda **kw: argparse.ArgumentParser(parents=[common], **kw))

    s = sub.add_parser("init", help="create a case"); s.set_defaults(fn=cmd_init)
    s.add_argument("--examiner", required=True); s.add_argument("--image", help="path to E01/raw image (for hashing)")
    s.add_argument("--mount", required=True, help="read-only mount root (or export folder)")
    s.add_argument("--mode", choices=["mount", "export"], default="mount"); s.add_argument("--notes", help="scope/objectives")
    s.add_argument("--expected-sha256"); s.add_argument("--expected-md5")

    s = sub.add_parser("verify", help="check the mount is read-only; optionally hash the image"); s.set_defaults(fn=cmd_verify)
    s.add_argument("--hash-image", action="store_true"); s.add_argument("--expected-sha256"); s.add_argument("--expected-md5")
    s.add_argument("--force", action="store_true")

    s = sub.add_parser("collect", help="run tools and normalize"); s.set_defaults(fn=cmd_collect)
    s.add_argument("--tools", help="comma list: uac,loki,goaccess,chainsaw,clamav,plaso (default: enabled in config)")
    s.add_argument("--skip", help="comma list of tools to skip"); s.add_argument("--normalize-only", action="store_true")
    s.add_argument("--db", action="store_true", help="also run the MariaDB read-only review (WSL)"); s.add_argument("--force", action="store_true")

    s = sub.add_parser("normalize", help="re-run normalizers on existing raw output"); s.set_defaults(fn=cmd_normalize)
    s.add_argument("--only")

    s = sub.add_parser("dbreview", help="MariaDB read-only review (needs mariadbd in WSL)"); s.set_defaults(fn=cmd_dbreview)

    s = sub.add_parser("index", help="build the search index"); s.set_defaults(fn=cmd_index)
    s.add_argument("--vectors", action="store_true", help="also embed chunks with Ollama (slow on CPU)")

    s = sub.add_parser("ask", help="ask a cited question (fast 3B by default; --deep for the 7B)"); s.set_defaults(fn=cmd_ask)
    s.add_argument("question"); s.add_argument("-k", type=int)
    s.add_argument("--deep", "--report-model", dest="report_model", action="store_true", help="use the deep/report tier model")
    s.add_argument("--no-archive", action="store_true")
    s.add_argument("--session", help="name a session so follow-up questions carry the previous turns and their cited sources")
    s.add_argument("--no-memory", action="store_true", help="omit the case brief, examiner notes and pinned findings from the prompt")

    s = sub.add_parser("notes", help="examiner notes the model sees as labelled context (never as evidence)"); s.set_defaults(fn=cmd_notes)
    s.add_argument("--add", help="append one line"); s.add_argument("--set-file", help="replace notes with this file's content")

    s = sub.add_parser("pin", help="pin a finding so it is always offered as a citable source"); s.set_defaults(fn=cmd_pin)
    s.add_argument("--finding"); s.add_argument("--unpin", action="store_true")

    s = sub.add_parser("session", help="list / show / clear question sessions"); s.set_defaults(fn=cmd_session)
    s.add_argument("--show"); s.add_argument("--clear")

    s = sub.add_parser("report", help="generate a report"); s.set_defaults(fn=cmd_report)
    s.add_argument("--kind", choices=["triage", "trends", "ioc"], default="triage")
    s.add_argument("--llm", dest="llm", action="store_true", default=None); s.add_argument("--no-llm", dest="llm", action="store_false")

    s = sub.add_parser("view", help="view a file from the image (table/text/markdown preview; --save to copy it out)"); s.set_defaults(fn=cmd_view)
    s.add_argument("--path", required=True, help="mount-relative path, e.g. /www/wwwroot/site/export.xlsx")
    s.add_argument("--save", help="write the original bytes to this local file"); s.add_argument("--rows", type=int, default=200)
    s.add_argument("--chars", type=int, default=20000)

    s = sub.add_parser("export", help="assemble the original files behind findings/answers/paths (files OR whole directories) into a hashed bundle"); s.set_defaults(fn=cmd_export)
    s.add_argument("--name", required=True); s.add_argument("--paths", help="comma list of mount-relative paths; a directory exports everything under it")
    s.add_argument("--findings", help="comma list of finding ids"); s.add_argument("--question", help="comma list of question numbers (see reports/questions.jsonl)")
    s.add_argument("--unpack", action="store_true", help="also unpack zip/tar/gz archives in the set (safe extraction, per-member hashes)")

    s = sub.add_parser("ls", help="list a directory (or stat a file) on the mounted image"); s.set_defaults(fn=cmd_ls)
    s.add_argument("--path", default="/"); s.add_argument("--max", type=int, default=500)

    s = sub.add_parser("intake", help="drop anything (E01, raw/img, vhdx, zip/7z/gz of an image or of files, a folder, a folder of disks) -> mounted, cased, verified, collected"); s.set_defaults(fn=cmd_intake)
    s.add_argument("path", help="file or folder (Windows paths are accepted inside WSL as /mnt/c/...)")
    s.add_argument("--examiner"); s.add_argument("--notes")
    s.add_argument("--deep", action="store_true", help="run the deep stage after collect")
    s.add_argument("--replace-mount", action="store_true", help="unmount whatever is mounted now first")
    s.add_argument("--no-hash", action="store_true", help="skip hashing the images (not recommended)")
    s = sub.add_parser("hopper", help="list what is in the hopper folder and what each item is"); s.set_defaults(fn=cmd_hopper)
    s.add_argument("--path", help="folder to scan (default C:\\DFIR\\hopper = /mnt/c/DFIR/hopper)"); s.add_argument("--json", action="store_true")
    s = sub.add_parser("settings", help="show or set the hopper / work / exports folders and the examiner name"); s.set_defaults(fn=cmd_settings)
    s.add_argument("--hopper"); s.add_argument("--work"); s.add_argument("--exports"); s.add_argument("--examiner")
    s = sub.add_parser("remount", help="after a reboot: mount a case's evidence again as intake did"); s.set_defaults(fn=cmd_remount)
    s.add_argument("--replace-mount", action="store_true")
    s = sub.add_parser("deep", help="unattended deep run: every tool, every document, vectors, translations, 7B report (leave it overnight)"); s.set_defaults(fn=cmd_deep)
    s.add_argument("--skip-tools", action="store_true", help="tools already ran; redo normalize/index/translate/report only")
    s.add_argument("--no-vectors", action="store_true")

    s = sub.add_parser("documents", help="inventory + extract text from spreadsheets, PDFs, Word/ODF, CSV, Markdown ..."); s.set_defaults(fn=cmd_documents)
    s.add_argument("--list", action="store_true"); s.add_argument("--kind", help="spreadsheet|document|pdf|table|text|data|sql|presentation|image")

    s = sub.add_parser("translate", help="machine-translate non-English evidence text (labelled, logged)"); s.set_defaults(fn=cmd_translate)
    s.add_argument("--finding", help="comma list of finding ids"); s.add_argument("--all", action="store_true", help="every finding with non-Latin text")
    s.add_argument("--path", help="translate one text artifact from the image"); s.add_argument("--fast", action="store_true", help="use the 3B instead of the 7B")

    s = sub.add_parser("archive", help="archive artifacts"); s.set_defaults(fn=cmd_archive)
    s.add_argument("--path"); s.add_argument("--reason"); s.add_argument("--findings", action="store_true")
    s.add_argument("--min-severity", default="high"); s.add_argument("--verify", action="store_true")

    s = sub.add_parser("custody", help="verify / show the custody chain"); s.set_defaults(fn=cmd_custody)
    s.add_argument("--show", type=int, default=0)

    s = sub.add_parser("status", help="case status"); s.set_defaults(fn=cmd_status)
    s = sub.add_parser("ui", help="launch the browser UI"); s.set_defaults(fn=cmd_ui); s.add_argument("--port", type=int, default=8501)
    s.add_argument("--address", default=None, help="bind address (default 0.0.0.0; use 127.0.0.1 on a native Linux box to keep it local)")
    s.add_argument("--theme", choices=["auto", "light", "dark"], default=None, help="UI theme (default: ui.theme in config.yaml, else follow the browser)")
    s = sub.add_parser("selftest", help="run the bundled self-test"); s.set_defaults(fn=cmd_selftest)
    s = sub.add_parser("mount-help", help="print mount instructions"); s.set_defaults(fn=cmd_mount_help)
    s = sub.add_parser("profiles", help="list evidence profiles"); s.set_defaults(fn=cmd_profiles)

    args = p.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
