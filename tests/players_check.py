"""Players on a small case with two databases that share table names (review of build p): foreign keys resolve inside
their own database, mentions are kept per table, money goes to the right person. `python tests/players_check.py`."""
import csv, json, shutil, sys, tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from gumshoe import dbexport, players  # noqa: E402
from gumshoe.case import Case, load_config  # noqa: E402

DUMP = """CREATE DATABASE `app1`;
USE `app1`;
CREATE TABLE `users` (`id` int, `email` varchar(100), `name` varchar(100), `phone` varchar(30));
INSERT INTO `users` VALUES (1,'alice_app1@example.com','Alice One','+1 555 010 0201');
CREATE TABLE `orders` (`id` int, `user_id` int, `amount` decimal(12,2), `currency` varchar(8), `created_at` datetime);
INSERT INTO `orders` VALUES (10,1,'100.00','USD','2024-05-01 10:00:00');
CREATE TABLE `audit_logs` (`id` int, `who` varchar(100), `what` text, `ts` datetime);
INSERT INTO `audit_logs` VALUES (1,'alice_app1@example.com','login','2024-05-02 10:00:00'),(2,'alice_app1@example.com','export','2024-05-03 10:00:00'),(3,'alice_app1@example.com','logout','2024-05-04 10:00:00');
CREATE DATABASE `app2`;
USE `app2`;
CREATE TABLE `users` (`id` int, `email` varchar(100), `name` varchar(100), `phone` varchar(30));
INSERT INTO `users` VALUES (1,'bob_app2@example.com','Bob Two','+1 555 010 0202');
CREATE TABLE `orders` (`id` int, `user_id` int, `amount` decimal(12,2), `currency` varchar(8), `created_at` datetime);
INSERT INTO `orders` VALUES (20,1,'999.00','EUR','2024-06-01 10:00:00');
"""

ok = True


def check(name, cond, detail=""):
    global ok
    ok = ok and bool(cond)
    print(("  [PASS] " if cond else "  [FAIL] ") + name + (f" - {detail}" if detail and not cond else ""))


tmp = Path(tempfile.mkdtemp(prefix="gp-"))
cases = tmp / "cases"
cases.mkdir()
case = Case.create(cases, "P1", "tester", None, str(tmp / "evidence"), "export", load_config(None))
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
check("two databases extracted with their own users/orders", sorted((t["database"], t["table"]) for t in r["tables"]) == [("app1", "audit_logs"), ("app1", "orders"), ("app1", "users"), ("app2", "orders"), ("app2", "users")])

logs = []
players.build(case, logs.append, workers=1)
con = players.open_db(case)
by_mail = {}
for pid, label in con.execute("SELECT id, label FROM players"):
    mails = [r[0] for r in con.execute("SELECT e.value FROM player_entities pe JOIN entities e ON e.id=pe.entity_id WHERE pe.player_id=? AND e.type='email' AND pe.role='strong'", (pid,))]
    for m in mails:
        by_mail[m] = pid
check("two players, one per database", con.execute("SELECT COUNT(*) FROM players").fetchone()[0] == 2 and set(by_mail) == {"alice_app1@example.com", "bob_app2@example.com"}, str(by_mail))
money = {pid: [(r[0], r[1]) for r in con.execute("SELECT amount, currency FROM money WHERE player_id=?", (pid,))] for pid in by_mail.values()}
check("app1.orders.user_id joins app1.users, not app2.users: Alice gets 100 USD, Bob 999 EUR",
      money.get(by_mail.get("alice_app1@example.com")) == [(100.0, "USD")] and money.get(by_mail.get("bob_app2@example.com")) == [(999.0, "EUR")], str(money))
eid = con.execute("SELECT id FROM entities WHERE value='alice_app1@example.com'").fetchone()[0]
ments = [(r[0], r[1]) for r in con.execute("SELECT source, count FROM mentions WHERE entity_id=? ORDER BY source", (eid,))]
mm = {s.split(":")[-1]: c for s, c in ments}
check("mentions kept per table: alice's e-mail has a users mention, an audit_logs mention (3 rows) and the order joined to her",
      mm == {"app1.users": 1, "app1.audit_logs": 3, "app1.orders": 1}, str(ments))
check("no unresolved-key warning for the right joins", not any("not joined" in l for l in logs), str([l for l in logs if "not joined" in l]))
con.close()
shutil.rmtree(tmp, ignore_errors=True)
print("players check:", "OK" if ok else "FAILED")
sys.exit(0 if ok else 1)
