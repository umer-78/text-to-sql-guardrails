"""python -m sqlguard.demo   write the live demo's data (docs/data.json): every Chinook query of the bench
with the guard's full decision (reasons, the SQL it would run, estimated rows scanned), the sandbox's
outcome from results/summary.json, the schema (names and row counts only) and the Spider numbers."""
import json
from pathlib import Path

from . import data
from .bench import ATTACKS, LEGIT, PII
from .guard import Policy, check
from .schema import Schema, connect_readonly

ROOT = Path(__file__).resolve().parent.parent


def build(out=ROOT / "docs"):
    summary = json.loads((ROOT / "results" / "summary.json").read_text())
    conn = connect_readonly(data.path("chinook.sqlite"))
    schema, policy = Schema.from_sqlite(conn), Policy(denied_columns=PII)
    queries = [(k, q) for k, qs in [("legitimate", LEGIT)] + list(ATTACKS.items()) for q in qs]
    rows = []
    for (kind, sql), ran in zip(queries, summary["chinook"]):
        sql = sql.replace("{tmp}", "/tmp/out")
        d = check(sql, schema, policy, conn=conn)
        rows.append({"kind": kind, "sql": sql, "allowed": d.allowed, "reasons": d.reasons, "runs": d.sql if d.allowed else None,
                     "tables": d.tables, "columns": d.columns, "scanned": d.estimated_rows_scanned,
                     "sandbox_ran": ran["sandbox_ran"], "sandbox_error": ran["sandbox_error"].replace(str(Path("/tmp")), "/tmp")})
    tables = [{"name": t.name, "rows": t.rows, "columns": [c[0] for c in t.columns.values()], "withheld": PII.get(t.name, [])}
              for t in schema.tables.values()]
    out.mkdir(exist_ok=True)
    (out / "data.json").write_text(json.dumps({"queries": rows, "tables": tables, "policy": {"row_limit": policy.row_limit,
        "max_depth": policy.max_depth, "max_rows_scanned": policy.max_rows_scanned}, "spider": summary["spider"],
        "predictions": {"total": len(summary["predictions"]), "flagged": sum(p["flagged"] for p in summary["predictions"]),
                        "differ": sum(not p["exact"] for p in summary["predictions"])}}, indent=1))
    print(f"wrote {out / 'data.json'}: {len(rows)} queries, {len(tables)} tables")


if __name__ == "__main__":
    build()
