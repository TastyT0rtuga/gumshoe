"""Dialect battery for the streaming dump reader: each fixture is a dump text plus the rows it must produce,
parsed sequentially and by the parallel byte-range workers (`python tests/dump_dialects.py`; add a fixture when a
dump yields 0 tables). Every fixture is also run through 7-byte, 64-byte, 4 KB and 64 KB read chunks, so a row,
string or statement cut by the buffer boundary is exercised at every position."""
import csv, shutil, sys, tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from gumshoe import dbexport  # noqa: E402

FIX = {}

FIX["mysqldump"] = ("""-- MySQL dump 10.13  Distrib 8.0.36
/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `email` varchar(190) DEFAULT NULL,
  `note` text,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB;
/*!40101 SET character_set_client = @saved_cs_client */;
LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES (1,'a@x.com','it\\'s; fine'),(2,NULL,'semi;colon, (paren)'),(3,'c@x.com','line\\nbreak');
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;
""", {"dump.users": [["1", "a@x.com", "it's; fine"], ["2", "", "semi;colon, (paren)"], ["3", "c@x.com", "line\nbreak"]]})

FIX["phpmyadmin"] = ("""-- phpMyAdmin SQL Dump
-- version 5.2.1
SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";

CREATE TABLE `orders` (
  `id` int(11) NOT NULL,
  `amount` decimal(10,2) NOT NULL,
  `wallet` varchar(64) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `orders` (`id`, `amount`, `wallet`) VALUES
(1, 10.50, 'bc1qxyz'),
(2, -3.00, NULL),
(3, 0.00, 'TRX9abc');
COMMIT;
""", {"dump.orders": [["1", "10.50", "bc1qxyz"], ["2", "-3.00", ""], ["3", "0.00", "TRX9abc"]]})

FIX["navicat"] = ("""/*
 Navicat Premium Data Transfer
 Source Server Type    : MySQL
*/
SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;
-- ----------------------------
-- Table structure for fa_user
-- ----------------------------
DROP TABLE IF EXISTS `fa_user`;
CREATE TABLE `fa_user`  (
  `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT,
  `username` varchar(32) NULL DEFAULT '',
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB;
-- ----------------------------
-- Records of fa_user
-- ----------------------------
INSERT INTO `fa_user` VALUES (1, 'admin');
INSERT INTO `fa_user` VALUES (2, 'ivan');
SET FOREIGN_KEY_CHECKS = 1;
""", {"dump.fa_user": [["1", "admin"], ["2", "ivan"]]})

FIX["lowercase_noheader_dup"] = ("""create table t (a int, b varchar(10));
insert into t (a, b) values (1,'x'),(2,'y') on duplicate key update b=values(b);
insert into t values (3,'z');
""", {"dump.t": [["1", "x"], ["2", "y"], ["3", "z"]]})

FIX["tsql"] = ("""USE [Shop]
GO
SET IDENTITY_INSERT [dbo].[Customers] ON
GO
INSERT [dbo].[Customers] ([Id], [Name], [Email]) VALUES (1, N'Иван', N'ivan@x.ru')
GO
INSERT [dbo].[Customers] ([Id], [Name], [Email]) VALUES (2, N'O''Brien', NULL)
GO
SET IDENTITY_INSERT [dbo].[Customers] OFF
GO
""", {"dbo.Customers": [["1", "Иван", "ivan@x.ru"], ["2", "O'Brien", ""]]})

FIX["doubled_quotes_no_semicolons"] = ("""CREATE TABLE "pets" ("id" integer, "name" text)
INSERT INTO "pets" VALUES (1, 'Rex''s bone')
INSERT INTO "pets" VALUES (2, 'Tom')
""", {"dump.pets": [["1", "Rex's bone"], ["2", "Tom"]]})

FIX["db_prefix_and_use"] = ("""CREATE DATABASE IF NOT EXISTS `app1`;
USE `app1`;
CREATE TABLE `k` (`v` int);
INSERT INTO `k` VALUES (1);
INSERT INTO `app2`.`k` VALUES (2);
USE app3;
INSERT INTO k VALUES (3);
""", {"app1.k": [["1"]], "app2.k": [["2"]], "app3.k": [["3"]]})

FIX["trigger_and_binary"] = ("""CREATE TABLE `b` (`id` int, `h` varbinary(16), `bit` bit(1), `t` text);
INSERT INTO `b` VALUES (1,_binary 'ab',b'1',0x48656C6C6F),(2,X'00FF',b'0','x');
DELIMITER ;;
/*!50003 CREATE*/ /*!50003 TRIGGER `tr` BEFORE INSERT ON `b` FOR EACH ROW BEGIN
  INSERT INTO log VALUES (NEW.id, 'inserted');
END */;;
DELIMITER ;
INSERT INTO `b` VALUES (3,NULL,NULL,'after trigger');
""", {"dump.b": [["1", "ab", "1", "Hello"], ["2", "0x00FF", "0", "x"], ["3", "", "", "after trigger"]], "_allow_extra": ["dump.log"]})

FIX["one_line_table_no_newline_at_all"] = ("CREATE TABLE `o` (`i` int, `s` varchar(20)); INSERT INTO `o` VALUES " + ",".join(f"({i},'row {i}')" for i in range(20000)) + ";",
                                             {"dump.o": [[str(i), f"row {i}"] for i in range(20000)]})

FIX["empty_values_and_trailing_junk"] = ("""CREATE TABLE `e` (`a` int);
INSERT INTO `e` VALUES ;
INSERT INTO `e` VALUES (1)
INSERT INTO `e` VALUES (2);
-- final comment without newline""", {"dump.e": [["1"], ["2"]]})

FIX["multibyte_cut"] = ("CREATE TABLE `m` (`s` text);\nINSERT INTO `m` VALUES " + ",".join("('" + "ü" * 50 + "')" for _ in range(5000)) + ";\n",
                        {"dump.m": [["ü" * 50]] * 5000})

FIX["semicolons_in_schema_strings"] = ("""SET @saved = 'a;b';
CREATE TABLE `c` (`id` int COMMENT 'semi;colon', `v` text COMMENT "dq;also", `w` int) ENGINE=InnoDB COMMENT='t;c';
INSERT INTO `c` VALUES (1,'x;y',2),(2,'z',3);
CREATE TABLE `d` (`k` int);
INSERT INTO `d` VALUES (9);
""", {"dump.c": [["1", "x;y", "2"], ["2", "z", "3"]], "dump.d": [["9"]], "_headers": {"dump.c": ["id", "v", "w"], "dump.d": ["k"]}})

FIX["lone_quote_in_skipped_statement"] = ("""CREATE TABLE `e` (`a` int);
SET @broken = 'no closing quote here;
INSERT INTO `e` VALUES (1);
INSERT INTO `e` VALUES (2);
""", {"dump.e": [["1"], ["2"]]})

# a schema statement longer than the 256 KB head window whose string straddles the buffer boundary: the ';' inside the
# comment must not end the CREATE TABLE early (chunk sizes >= 4096 in the small-chunk harness; 7-byte chunks would be quadratic)
FIX["long_create_string_across_boundary"] = ("CREATE TABLE `big` (`id` int COMMENT '" + "x;y " * 80000 + "', `v` text);\nINSERT INTO `big` VALUES (1,'a'),(2,'b');\n",
                                             {"dump.big": [["1", "a"], ["2", "b"]], "_headers": {"dump.big": ["id", "v"]}, "_min_chunk": 4096})


def read_headers(out: Path):
    heads = {}
    for f in sorted(out.rglob("*.csv")):
        key = f"{f.parent.name}.{f.name.split('.')[0]}"
        with open(f, encoding="utf-8-sig", newline="") as fh:
            heads.setdefault(key, next(csv.reader(fh), None))
    return heads


def read_rows(out: Path):
    got = {}
    for f in sorted(out.rglob("*.csv")):
        key = f"{f.parent.name}.{f.name.split('.')[0]}"
        with open(f, encoding="utf-8-sig", newline="") as fh:
            rd = csv.reader(fh)
            next(rd, None)
            got.setdefault(key, []).extend(list(rd))
    return got


ok_all = True
for name, (text, expected) in FIX.items():
    d = Path(tempfile.mkdtemp(prefix="dial-"))
    src = d / "dump.sql"
    src.write_text(text, encoding="utf-8")
    out = d / "out"
    out.mkdir()
    logs = []
    for mode in ("seq", "par"):
        if out.exists():
            shutil.rmtree(out)
        out.mkdir()
        if mode == "seq":
            r = dbexport.extract_dump(src, out, logs.append)
        else:
            r = dbexport.extract_dump_parallel(src, out, logs.append, workers=3)
        got = read_rows(out)
        heads = read_headers(out)
        for k, h in expected.get("_headers", {}).items():
            if heads.get(k) != h:
                print(f"BAD {name:38s} {mode}: header of {k} = {heads.get(k)} expected {h}")
                ok_all = False
        allow = set(expected.get("_allow_extra", []))
        exp = {k: v for k, v in expected.items() if not k.startswith("_")}
        extra = {k for k in got if k not in exp and k not in allow}
        bad = [k for k in exp if got.get(k) != exp[k]]
        status = "OK " if not bad and not extra else "BAD"
        if status == "BAD":
            ok_all = False
        print(f"{status} {name:38s} {mode}: tables {sorted(got)} " + ("" if status == "OK " else f"| wrong {bad} extra {sorted(extra)}"))
        for k in bad[:2]:
            print("      expected", exp[k][:3], "\n      got     ", (got.get(k) or [])[:3])
    with open(d / "dump.sql", "rb") as fh:
        pass
    shutil.rmtree(d)
print("ALL OK" if ok_all else "FAILURES")


def run_chunked(text: str, chunk: int):
    """Rows and headers from parse_mysql_dump fed `chunk`-byte pieces (the production chunk is 4 MB)."""
    d = Path(tempfile.mkdtemp(prefix="chk-"))
    src = d / "dump.sql"
    src.write_text(text, encoding="utf-8")
    out = d / "out"
    writers, columns = {}, {}

    def writer_for(db, table, cols):
        key = (db, table)
        if key not in writers:
            writers[key] = dbexport.TableWriter(out / dbexport.slug(db), dbexport.slug(table), cols or columns.get(key) or [], 10**9)
        return writers[key]

    def on_create(db, table, text):
        columns[(db, table)] = dbexport.columns_from_create(text)
        if (db, table) in writers and not writers[(db, table)].columns:
            writers[(db, table)].columns = columns[(db, table)]

    dbexport.parse_mysql_dump(dbexport._byte_chunks(src, 0, src.stat().st_size, chunk), writer_for, on_create, None, None)
    got, heads = {}, {}
    for (db, table), w in writers.items():
        w.close()
        rows = []
        for f in sorted((out / dbexport.slug(db)).glob(dbexport.slug(table) + "*.csv")):
            with open(f, encoding="utf-8-sig", newline="") as fh:
                rd = csv.reader(fh)
                heads.setdefault(f"{db}.{table}", next(rd, None))
                rows += list(rd)
        got[f"{db}.{table}"] = rows
    shutil.rmtree(d)
    return got, heads


for chunk in (7, 64, 4096, 65536):
    for name, (text, expected) in FIX.items():
        if chunk < expected.get("_min_chunk", 0):
            continue
        got, heads = run_chunked(text, chunk)
        exp = {k: v for k, v in expected.items() if not k.startswith("_")}
        wrong = [k for k in exp if got.get(k) != exp[k]]
        wrong += [f"{k} header {heads.get(k)}" for k, h in expected.get("_headers", {}).items() if heads.get(k) != h]
        if wrong:
            ok_all = False
            print(f"BAD {name:38s} chunk={chunk}: {wrong}")
print("small chunks:", "ALL OK" if ok_all else "FAILURES")
sys.exit(0 if ok_all else 1)
