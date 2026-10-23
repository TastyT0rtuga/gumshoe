"""The database explorer on a small case built from an inline dump: catalog, search modes, exact rows, exports with custody,
the SQLite workbench and read-only SQL. `python tests/explorer_check.py` - needs no evidence, model or network."""
import csv, json, shutil, sys, tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from gumshoe import dbexplore, dbexport  # noqa: E402
from gumshoe.case import Case, load_config  # noqa: E402

DUMP = """CREATE TABLE `users` (`id` int, `email` varchar(100), `name` varchar(100), `phone` varchar(30), `notes` text);
INSERT INTO `users` VALUES (1,'alice@x.example','Alice A','+1 555 010 0101','vip'),(2,'bob@x.example','Bob B','+1 555 010 0102',''),
(3,'carol@x.example','Carol C','+1 555 010 0103','referred by alice@x.example; line two\\nof the note'),(4,'dave@x.example','Dave D','+1 555 010 0104','');
CREATE TABLE `orders` (`id` int, `user_id` int, `amount` decimal(12,2), `wallet` varchar(80));
INSERT INTO `orders` VALUES (10,1,'100.00','bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq'),(11,2,'5.50','1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2'),(12,1,'7.00','');
CREATE TABLE `logs` (`id` int, `line` text);
INSERT INTO `logs` VALUES (1,'login alice from 10.0.0.1'),(2,'login bob from 10.0.0.2'),(3,'ALICE changed password');
"""

ok = True


def check(name, cond, detail=""):
    global ok
    ok = ok and bool(cond)
    print(("  [PASS] " if cond else "  [FAIL] ") + name + (f" - {detail}" if detail and not cond else ""))


tmp = Path(tempfile.mkdtemp(prefix="gx-"))
cases = tmp / "cases"
cases.mkdir()
cfg = load_config(None)
case = Case.create(cases, "X1", "tester", None, str(tmp / "evidence"), "export", cfg)
sql = tmp / "dump.sql"
sql.write_text(DUMP, "utf-8")
out = case.dir / "db" / "x"
out.mkdir(parents=True)
r = dbexport.extract_dump(sql, out, lambda s: None)
with open(out / "tables.csv", "w", newline="", encoding="utf-8-sig") as f:
    w = csv.writer(f, lineterminator="\r\n")
    w.writerow(["database", "table", "rows", "columns", "files", "bytes", "blobs", "rejected", "error"])
    for t in r["tables"]:
        w.writerow([t["database"], t["table"], t["rows"], t.get("columns", ""), "; ".join(t.get("files", [])), t.get("bytes", ""), t.get("blobs", 0), t.get("rejected", 0), t.get("error", "")])
(out / "source.json").write_text(json.dumps({"kind": "mysql-dump", "source": str(sql), "out": str(out), "tables": r["tables"], "name": "x"}), "utf-8")

cat = dbexplore.catalog(case)
check("catalog lists every table with columns", {t["table"] for t in cat} == {"users", "orders", "logs"} and next(t for t in cat if t["table"] == "users")["columns"] == ["id", "email", "name", "phone", "notes"])
hits = dbexplore.search_counts(case, "alice", "phrase", cat=cat)
check("counts: 'alice' is in users and logs (case-insensitive)", {h["table"] for h in hits} == {"users", "logs"}, str(hits))
users = next(t for t in cat if t["table"] == "users")
check("exact rows: phrase 'alice' matches Alice's row and Carol's note", dbexplore.search_rows(users, "alice", "phrase")["matched"] == 2)
check("mode all: 'alice vip' needs both words in a row", dbexplore.search_rows(users, "alice vip", "all")["matched"] == 1)
check("mode any: 'bob dave' matches two rows", dbexplore.search_rows(users, "bob dave", "any")["matched"] == 2)
check("regex: phones ending 0101|0104", dbexplore.search_rows(users, r"010[14]$", "regex")["matched"] == 2)
check("columns: 'alice' only in the notes column -> Carol's row only", dbexplore.search_rows(users, "alice", "phrase", columns=["notes"])["matched"] == 1)
rr = dbexplore.search_rows(users, "line two", "phrase")
check("a cell with a newline matches as one row, with its locator", rr["matched"] == 1 and rr["rows"][0][1] == 4 and "\n" in rr["rows"][0][6], str(rr["rows"]))
pg = dbexplore.page(users, 1, 2, {"email": "x.example"})
check("page 2 of 2 rows with a column filter", [row[2] for row in pg["rows"]] == ["2", "3"] and pg["more"] is True)
ex = dbexplore.export_search(case, "alice", "phrase", log=lambda s: None)
files = sorted(p.name for p in Path(ex["out"]).iterdir())
check("export_search writes one CSV per matching table + summary + query.json + README", ex["matching_rows"] == 4 and ex["tables_with_matches"] == 2 and "summary.csv" in files and "query.json" in files, str(files))
with open(Path(ex["out"]) / "x.dump.users.csv", encoding="utf-8-sig", newline="") as f:
    rows = list(csv.reader(f))
check("the exported rows carry _file/_line and the table's columns", rows[0][:3] == ["_file", "_line", "id"] and len(rows) == 3)
sel = dbexplore.export_tables(case, ["x/dump/orders"], log=lambda s: None)
check("export_tables copies the table with a manifest", sel["files"] == 1 and (Path(sel["out"]) / "manifest.csv").exists())
lt = dbexplore.load_tables(case, ["x/dump/users", "x/dump/orders"], log=lambda s: None)
check("workbench loads two tables", sorted(d["name"] for d in lt["loaded"]) == ["dump__orders", "dump__users"])
q = dbexplore.sql(case, 'SELECT u.email, SUM(CAST(o.amount AS REAL)) AS total FROM dump__users u JOIN dump__orders o ON o.user_id = u.id GROUP BY u.email ORDER BY total DESC')
check("read-only SQL join works", not q.get("error") and q["rows"][0] == ["alice@x.example", 107.0], str(q))
check("writes are refused", dbexplore.sql(case, "DELETE FROM dump__users").get("error"))
check("UPDATE through a CTE is refused too", dbexplore.sql(case, "WITH x AS (SELECT 1) UPDATE dump__users SET name='x'").get("error"))
pg2 = dbexplore.sql_page(case, "x/dump/orders", 0, 10, None, "amount", True, numeric=True)
check("numeric sort puts 100.00 before 7.00 before 5.50", [r[4] for r in pg2["rows"]] == ["100.00", "7.00", "5.50"], str(pg2["rows"]))
acts = [r.action for r in case.custody.tail(10)]
check("custody records for the search export, the table export and the load", {"db_search_export", "db_tables_exported", "db_workbench_loaded"} <= set(acts), str(acts))
n = dbexplore.unload(case)
check("unload drops the tables", n == 2 and not dbexplore.loaded(case))
shutil.rmtree(tmp, ignore_errors=True)
print("explorer check:", "OK" if ok else "FAILED")
sys.exit(0 if ok else 1)
