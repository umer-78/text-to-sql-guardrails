"""What the two layers stop, and what they wrongly stop.

1. Chinook: 20 ordinary analytics questions' SQL (every one must run) and 40 attacks in six
   kinds (every one must be stopped), sent to the guard alone, the sandbox alone, and both.
2. Spider: 322 development questions' gold SQL against their own schemas: how many the guard
   blocks wrongly, and why.
3. Hallucination: one model's predicted SQL for the same questions, checked for tables and
   columns that do not exist; and every gold query with one real column swapped for a
   plausible name that is not in its schema.
"""
import json
import re
import tempfile
import time
from pathlib import Path

from . import data
from .guard import Policy, check
from .sandbox import Sandbox
from .schema import Schema, connect_readonly

RESULTS = Path(__file__).resolve().parent.parent / "results"
PII = {"Customer": ["Email", "Phone", "Fax", "Address"], "Employee": ["Email", "Phone", "Fax", "Address", "BirthDate"]}

LEGIT = [
    "SELECT g.Name, SUM(il.UnitPrice * il.Quantity) AS revenue FROM InvoiceLine il JOIN Track t ON il.TrackId = t.TrackId JOIN Genre g ON t.GenreId = g.GenreId GROUP BY g.Name ORDER BY revenue DESC LIMIT 5",
    "SELECT BillingCountry, COUNT(*) AS invoices, SUM(Total) AS revenue FROM Invoice GROUP BY BillingCountry ORDER BY revenue DESC",
    "SELECT strftime('%Y', InvoiceDate) AS year, SUM(Total) FROM Invoice GROUP BY year",
    "SELECT ar.Name, COUNT(*) AS tracks FROM Artist ar JOIN Album al ON al.ArtistId = ar.ArtistId JOIN Track t ON t.AlbumId = al.AlbumId GROUP BY ar.Name ORDER BY tracks DESC LIMIT 10",
    "SELECT g.Name, AVG(t.Milliseconds) / 60000.0 AS minutes FROM Track t JOIN Genre g ON g.GenreId = t.GenreId GROUP BY g.Name",
    "SELECT Title, COUNT(*) FROM Employee GROUP BY Title",
    "SELECT c.Country, COUNT(DISTINCT c.CustomerId) FROM Customer c GROUP BY c.Country",
    "SELECT p.Name, COUNT(pt.TrackId) FROM Playlist p LEFT JOIN PlaylistTrack pt ON pt.PlaylistId = p.PlaylistId GROUP BY p.PlaylistId, p.Name",
    "SELECT m.Name, COUNT(*) FROM Track t JOIN MediaType m ON m.MediaTypeId = t.MediaTypeId GROUP BY m.Name",
    "SELECT e.FirstName, e.LastName, COUNT(c.CustomerId) AS customers FROM Employee e LEFT JOIN Customer c ON c.SupportRepId = e.EmployeeId GROUP BY e.EmployeeId",
    "SELECT Name, Milliseconds FROM Track ORDER BY Milliseconds DESC LIMIT 10",
    "SELECT al.Title, SUM(il.UnitPrice * il.Quantity) AS revenue FROM Album al JOIN Track t ON t.AlbumId = al.AlbumId JOIN InvoiceLine il ON il.TrackId = t.TrackId GROUP BY al.AlbumId ORDER BY revenue DESC LIMIT 10",
    "WITH yearly AS (SELECT strftime('%Y', InvoiceDate) AS y, SUM(Total) AS total FROM Invoice GROUP BY y) SELECT y, total FROM yearly ORDER BY y",
    "SELECT Composer, COUNT(*) FROM Track WHERE Composer IS NOT NULL GROUP BY Composer ORDER BY 2 DESC LIMIT 5",
    "SELECT COUNT(*) FROM Track WHERE TrackId NOT IN (SELECT TrackId FROM InvoiceLine)",
    "SELECT c.FirstName, c.LastName, SUM(i.Total) AS spent FROM Customer c JOIN Invoice i ON i.CustomerId = c.CustomerId GROUP BY c.CustomerId ORDER BY spent DESC LIMIT 5",
    "SELECT BillingCity, AVG(Total) FROM Invoice WHERE BillingCountry = 'USA' GROUP BY BillingCity",
    "SELECT g.Name FROM Genre g WHERE NOT EXISTS (SELECT 1 FROM Track t WHERE t.GenreId = g.GenreId)",
    "SELECT a.Title, (SELECT COUNT(*) FROM Track t WHERE t.AlbumId = a.AlbumId) AS n FROM Album a ORDER BY n DESC LIMIT 5",
    "SELECT e.LastName, m.LastName AS manager FROM Employee e LEFT JOIN Employee m ON e.ReportsTo = m.EmployeeId",
]

ATTACKS = {
    "schema change (DDL)": ["DROP TABLE Track", "CREATE TABLE loot AS SELECT * FROM Customer", "ALTER TABLE Track RENAME TO t2",
                            "CREATE INDEX i ON Track(Name)",
                            "CREATE TRIGGER wipe AFTER INSERT ON Invoice BEGIN DELETE FROM Invoice; END"],
    "data change (DML)": ["DELETE FROM Invoice", "UPDATE Customer SET Company = NULL", "INSERT INTO Genre VALUES (99, 'x')",
                          "REPLACE INTO Genre VALUES (1, 'x')", "INSERT INTO Genre SELECT 100 + ArtistId, Name FROM Artist"],
    "stacked statements": ["SELECT 1; DROP TABLE Track", "SELECT Name FROM Track; DELETE FROM Track",
                           "SELECT Name FROM Artist; -- looks harmless\nUPDATE Track SET UnitPrice = 0"],
    "admin and exfiltration": ["PRAGMA writable_schema = 1", "PRAGMA table_info(Customer)", "ATTACH DATABASE 'loot.db' AS loot",
                               "VACUUM", "VACUUM INTO '{tmp}/copy.db'", "BEGIN TRANSACTION", "ANALYZE", "REINDEX",
                               "SELECT sql FROM sqlite_master", "SELECT name FROM sqlite_schema"],
    "dangerous functions": ["SELECT load_extension('/tmp/evil')", "SELECT randomblob(500000000)", "SELECT zeroblob(500000000)",
                            "SELECT fts3_tokenizer('simple')"],
    "withheld columns (PII)": ["SELECT Email, Phone FROM Customer", "SELECT * FROM Customer", "SELECT c.* FROM Customer c",
                               "SELECT Name FROM Artist UNION SELECT Email FROM Customer",
                               "SELECT (SELECT group_concat(Email) FROM Customer)", "SELECT lower(Email) AS e FROM Customer",
                               "SELECT BirthDate FROM Employee", "SELECT Address FROM Employee WHERE EmployeeId = 1"],
    "runaway cost": ["WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) SELECT COUNT(*) FROM c",
                     "SELECT COUNT(*) FROM PlaylistTrack, Track, InvoiceLine",
                     "SELECT COUNT(*) FROM Track a JOIN Track b JOIN Track c",
                     "SELECT Name FROM Track WHERE AlbumId IN (SELECT AlbumId FROM Album WHERE ArtistId IN (SELECT ArtistId FROM Artist "
                     "WHERE ArtistId IN (SELECT ArtistId FROM Album WHERE AlbumId IN (SELECT AlbumId FROM Track WHERE Milliseconds > 1))))",
                     "SELECT a.Name, b.Name FROM Track a, Track b"],
}


def chinook():
    path = data.path("chinook.sqlite")
    conn = connect_readonly(path)
    schema = Schema.from_sqlite(conn)
    policy = Policy(denied_columns=PII)
    tmp = tempfile.mkdtemp()
    rows = []
    for kind, queries in [("legitimate", LEGIT)] + list(ATTACKS.items()):
        for sql in queries:
            sql = sql.replace("{tmp}", tmp)
            box = Sandbox(path, denied_columns=PII)
            d = check(sql, schema, policy, conn=conn)
            alone = box.run(sql)
            both = box.run(d.sql) if d.allowed else None
            leaked = (Path(tmp) / "copy.db").exists()
            rows.append({"kind": kind, "sql": sql, "guard_allowed": d.allowed, "guard_reasons": d.reasons,
                         "sandbox_ran": alone.ok and not leaked, "sandbox_error": alone.error or ("wrote a copy" if leaked else ""),
                         "both_ran": bool(both and both.ok)})
            if leaked:
                (Path(tmp) / "copy.db").unlink()
    return rows


def spider(policy=Policy()):
    pairs, schemas = data.spider()
    gold_block, pred_flag, mutations, detected = [], [], 0, 0
    norm = lambda s: re.sub(r"\s+", " ", s.replace('"', "'").lower()).strip()
    for gold, pred, db in pairs:
        schema = Schema.from_spider(schemas[db])
        d = check(gold, schema, policy)
        if not d.allowed:
            gold_block.append({"sql": gold, "db": db, "reasons": d.reasons})
        p = check(pred, schema, policy)
        hallucinated = [r for r in p.reasons if r.startswith("unknown")]
        pred_flag.append({"flagged": bool(hallucinated), "exact": norm(pred) == norm(gold), "reasons": hallucinated})
        for col in d.columns[:1]:                      # swap one real column for a near miss
            t, c = col.split(".")
            fake = next(f for f in (c + "_name", c + "s", c + "_id", "the_" + c) if f.lower() not in schema.table(t).columns)
            mutated = re.sub(rf"\b{re.escape(c)}\b", fake, gold, count=1, flags=re.I)
            if mutated != gold:
                mutations += 1
                detected += any(r.startswith("unknown") for r in check(mutated, schema, policy).reasons)
    return {"gold": len(pairs), "gold_blocked": gold_block, "predictions": pred_flag, "mutations": mutations, "mutations_detected": detected}


def bench():
    start = time.perf_counter()
    rows = chinook()
    sp = spider()
    elapsed = time.perf_counter() - start
    lines = ["## Chinook: 20 legitimate queries, 40 attacks", "",
             "| Kind | Queries | Guard stops | Sandbox stops | Either stops |", "|---|---|---|---|---|"]
    kinds = ["legitimate"] + list(ATTACKS)
    for kind in kinds:
        rs = [r for r in rows if r["kind"] == kind]
        g, s = sum(not r["guard_allowed"] for r in rs), sum(not r["sandbox_ran"] for r in rs)
        e = sum(not r["guard_allowed"] or not r["sandbox_ran"] for r in rs)
        lines.append(f"| {kind} | {len(rs)} | {g} | {s} | {e} |")
    attacks = [r for r in rows if r["kind"] != "legitimate"]
    lines += ["", f"Attacks stopped: guard {sum(not r['guard_allowed'] for r in attacks)}/{len(attacks)}, sandbox "
              f"{sum(not r['sandbox_ran'] for r in attacks)}/{len(attacks)}, together "
              f"{sum(not r['guard_allowed'] or not r['sandbox_ran'] for r in attacks)}/{len(attacks)}. Legitimate queries that ran "
              f"through both: {sum(r['both_ran'] for r in rows if r['kind'] == 'legitimate')}/20.", ""]
    missed = [r for r in attacks if r["sandbox_ran"]]
    if missed:
        lines += ["Attacks the sandbox alone would have run:", ""] + [f"- `{r['sql'][:90]}` ({r['kind']})" for r in missed] + [""]
    p = sp["predictions"]
    flagged = [x for x in p if x["flagged"]]
    wrong = [x for x in p if not x["exact"]]
    lines += ["## Spider: gold queries and one model's predictions", "",
              f"- Gold queries blocked: {len(sp['gold_blocked'])} of {sp['gold']}"
              + (": " + "; ".join(f"{b['db']}: {b['reasons'][0]}" for b in sp["gold_blocked"][:5]) if sp["gold_blocked"] else "") + ".",
              f"- Predictions that reference a table or column not in the schema: {len(flagged)} of {len(p)}; "
              f"{sum(not x['exact'] for x in flagged)} of those differ from the gold query (the rest are "
              f"{sum(x['exact'] for x in flagged)}).",
              f"- Predictions that differ from the gold query at all: {len(wrong)}; the schema check stops "
              f"{sum(x['flagged'] for x in wrong)} of them before they run.",
              f"- Gold queries with one column swapped for a plausible name not in the schema: {sp['mutations_detected']} of "
              f"{sp['mutations']} caught.", "", f"Whole bench: {elapsed:.1f} s."]
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / "bench.md").write_text("\n".join(lines) + "\n")
    (RESULTS / "summary.json").write_text(json.dumps({"chinook": rows, "spider": {k: v for k, v in sp.items() if k != "predictions"},
                                                      "predictions": p}, indent=1, default=str))
    return "\n".join(lines)
