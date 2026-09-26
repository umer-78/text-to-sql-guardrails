# text-to-sql-guardrails

Let an LLM write SQL against a real database without letting it damage anything, leak anything, or answer from tables that don't exist. Every generated query passes through two independent layers:

1. **The guard** parses the SQL (sqlglot) and blocks:
   - anything but a single read-only query, and dangerous functions;
   - subqueries nested more than 3 deep, and recursive CTEs;
   - unknown tables and columns (a hallucinated schema), and system tables;
   - columns the policy withholds, including through `SELECT *`;
   - plans that `EXPLAIN QUERY PLAN` says would scan too many rows.

   Queries that pass get a row limit, and every block says why.
2. **The sandbox** makes the database refuse on its own:
   - a read-only connection with `query_only`;
   - an authorizer that allows reading and nothing else, and hides withheld columns;
   - caps on value size and attached databases;
   - a budget of VM steps that aborts runaway queries.

The generator (a schema-aware prompt with only the relevant tables, clarification when a glossary term is ambiguous, JSON output with SQL, explanation, confidence and tables) plugs into any OpenAI-compatible model. It is not measured here, since the repository runs without API keys. Whatever it returns goes through both layers.

## Results

`python -m sqlguard bench` (about a second).

**Chinook** is a music-store database: 11 tables, 15,607 rows. The suite has 20 ordinary analytics queries that must run, and 40 attacks that must be stopped.

| Kind | Queries | Guard stops | Sandbox stops | Either stops |
|---|---|---|---|---|
| legitimate | 20 | 0 | 0 | 0 |
| schema change (DDL) | 5 | 5 | 5 | 5 |
| data change (DML) | 5 | 5 | 5 | 5 |
| stacked statements | 3 | 3 | 3 | 3 |
| admin and exfiltration (PRAGMA, ATTACH, `VACUUM INTO`, `sqlite_master`, …) | 10 | 10 | 10 | 10 |
| dangerous functions (`load_extension`, `randomblob`, …) | 4 | 4 | 4 | 4 |
| withheld columns (PII: direct, `*`, `UNION`, subquery, wrapped in a function) | 8 | 8 | 8 | 8 |
| runaway cost (recursive CTE, cartesian joins, deep nesting) | 5 | 5 | 3 | 5 |

- **The guard stops 40 of 40 attacks, and all 20 legitimate queries run through both layers.**
- **The sandbox alone stops 38.** The two it lets run are policy rather than damage: a five-level nested query, and a 12-million-row self-join it cuts off at the row limit. That is why there are two layers: either one can miss, and each covers the other.

**Spider** has 322 development questions with gold SQL, checked against their own databases' schemas, and one model's recorded predictions for the same questions.

- **Gold queries wrongly blocked: 0 of 322.** The 3 the guard rejects contain `! =` with a space, which SQLite rejects too (a typo in Spider's gold file).
- **Hallucinated schema in real predictions: 8 of 322** reference a table or column that doesn't exist, and all 8 are wrong. That is 8 of the 308 predictions that differ from gold. The rest are wrong in ways a schema check can't see (values, logic), which is what the result checks and a verifier are for.
- **Planted hallucinations: 308 of 308 caught.** Each gold query had one real column swapped for a plausible name not in its schema.

## How it works

```python
from sqlguard.guard import Policy, check
from sqlguard.sandbox import Sandbox
from sqlguard.schema import Schema, connect_readonly
from sqlguard.verify import describe, result_warnings

conn = connect_readonly("chinook.sqlite")
schema = Schema.from_sqlite(conn)
policy = Policy(row_limit=1000, max_depth=3, max_rows_scanned=10_000_000,
                denied_columns={"Customer": ["Email", "Phone"]})
decision = check(llm_sql, schema, policy, conn=conn)       # .allowed, .reasons, .sql (with LIMIT), .tables
if decision.allowed:
    result = Sandbox("chinook.sqlite", denied_columns=policy.denied_columns).run(decision.sql)
    print(describe(decision.sql), result_warnings(result, policy.row_limit))
```

- `sqlguard/guard.py`: the rules. Double-quoted names that are not columns count as string literals, which is how SQLite reads them, so they are not flagged.
- `sqlguard/sandbox.py`: the database-side refusals.
- `sqlguard/verify.py`: what the SQL does in words the user can check, plus warnings from the result (no rows, empty columns, truncated totals).
- `sqlguard/generate.py`: the schema-aware prompt, relevance filter and ambiguity check.
- `sqlguard/bench.py`: the suites above.

```bash
pip install -e '.[dev]'
pytest -q
python -m sqlguard bench
```

Chinook and Spider's evaluation files are downloaded on first use into `~/.cache/sqlguard`; nothing is committed.
