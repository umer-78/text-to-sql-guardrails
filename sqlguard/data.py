"""Downloaded on first use into SQLGUARD_DATA (default ~/.cache/sqlguard): the Chinook sample
database (a music store: 11 tables, 15,607 rows), and from Spider's test-suite evaluation
repository, 322 development questions' gold SQL, one model's predicted SQL for the same
questions, and every Spider database's schema."""
import json
import os
import time
import urllib.request
from pathlib import Path

FILES = {"chinook.sqlite": "https://raw.githubusercontent.com/lerocha/chinook-database/master/ChinookDatabase/DataSources/Chinook_Sqlite.sqlite",
         "gold.txt": "https://raw.githubusercontent.com/taoyds/test-suite-sql-eval/master/evaluation_examples/gold.txt",
         "predict.txt": "https://raw.githubusercontent.com/taoyds/test-suite-sql-eval/master/evaluation_examples/predict.txt",
         "tables.json": "https://raw.githubusercontent.com/taoyds/test-suite-sql-eval/master/tables.json"}


def path(name, tries=4):
    folder = Path(os.environ.get("SQLGUARD_DATA", Path.home() / ".cache" / "sqlguard"))
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / name
    if not target.exists():
        for attempt in range(tries):
            try:
                with urllib.request.urlopen(FILES[name], timeout=120) as r:
                    target.write_bytes(r.read())
                break
            except OSError:
                if attempt == tries - 1:
                    raise
                time.sleep(2 ** attempt)
    return target


def spider():
    """[(gold sql, predicted sql, db_id)] and {db_id: schema entry}."""
    gold = [line.rsplit("\t", 1) for line in path("gold.txt").read_text().splitlines() if line.strip()]
    pred = [line.strip() for line in path("predict.txt").read_text().splitlines() if line.strip()]
    schemas = {e["db_id"]: e for e in json.loads(path("tables.json").read_text())}
    return [(g, p, db) for (g, db), p in zip(gold, pred)], schemas
