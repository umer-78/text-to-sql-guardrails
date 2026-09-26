"""The guardrail layer: every generated query is parsed and checked before it runs.

Blocked: anything but a single read-only query (DDL, DML, PRAGMA, ATTACH, VACUUM,
transactions, several statements), dangerous functions, subqueries nested deeper than
`max_depth`, recursive CTEs, tables and columns that do not exist (a hallucinated schema),
system tables, columns the policy withholds (PII, including via SELECT *), and queries whose
plan (EXPLAIN QUERY PLAN) would scan more than `max_rows_scanned` rows. Queries that pass get
a row limit. Every rule is configurable, and every decision says why.
"""
import logging
import re
from dataclasses import dataclass, field

import sqlglot
from sqlglot import exp

logging.getLogger("sqlglot").setLevel(logging.ERROR)     # it warns when it falls back to a raw command; we block those anyway

DENIED_FUNCTIONS = {"load_extension", "readfile", "writefile", "edit", "fts3_tokenizer", "randomblob", "zeroblob",
                    "sqlite_compileoption_get", "sqlite_offset"}
WRITE_NODES = tuple(getattr(exp, n) for n in ("Insert", "Update", "Delete", "Create", "Drop", "Alter", "AlterTable", "Command",
                                             "Pragma", "Merge", "TruncateTable", "Transaction", "Commit", "Rollback", "Attach",
                                             "Detach", "Set", "Copy", "LoadData", "Use") if hasattr(exp, n))


@dataclass
class Policy:
    row_limit: int = 1000
    max_depth: int = 3
    max_rows_scanned: int = 10_000_000
    allow_recursive: bool = False
    denied_columns: dict = field(default_factory=dict)       # table -> [columns] no query may read


@dataclass
class Decision:
    allowed: bool
    sql: str
    reasons: list = field(default_factory=list)
    tables: list = field(default_factory=list)
    columns: list = field(default_factory=list)
    estimated_rows_scanned: int = None


def depth(node):
    d, p = 0, node.parent
    while p is not None:
        d += isinstance(p, exp.Select)
        p = p.parent
    return d


def check(sql, schema, policy=None, conn=None):
    policy = policy or Policy()
    try:
        statements = [s for s in sqlglot.parse(sql, read="sqlite") if s is not None]
    except sqlglot.errors.ParseError as e:
        return Decision(False, sql, [f"does not parse: {str(e).splitlines()[0][:120]}"])
    if len(statements) != 1:
        return Decision(False, sql, [f"{len(statements)} statements; exactly one query is allowed"])
    tree = statements[0]
    reasons = []
    if not isinstance(tree, (exp.Select, exp.SetOperation)) or any(isinstance(n, WRITE_NODES) for n in tree.walk()):
        return Decision(False, sql, [f"{tree.key.upper()} statements are not allowed; only read-only queries run"])
    for f in tree.find_all(exp.Func):
        name = (f.name if isinstance(f, exp.Anonymous) else f.sql_name()).lower()
        if name in DENIED_FUNCTIONS:
            reasons.append(f"function {name}() is not allowed")
    deepest = max((depth(s) for s in tree.find_all(exp.Select)), default=0)
    if deepest > policy.max_depth:
        reasons.append(f"subqueries nested {deepest} deep; the limit is {policy.max_depth}")
    if any(w.args.get("recursive") for w in tree.find_all(exp.With)) and not policy.allow_recursive:
        reasons.append("recursive CTEs are not allowed")

    ctes = {c.alias_or_name.lower() for c in tree.find_all(exp.CTE)}
    derived = {s.alias_or_name.lower() for s in tree.find_all(exp.Subquery) if s.alias_or_name}
    aliases, tables = {}, []
    for t in tree.find_all(exp.Table):
        name = t.name.lower()
        if name in ctes:
            continue
        if name.startswith("sqlite_"):
            reasons.append(f"system table {t.name} is not allowed")
            continue
        if schema.table(name) is None:
            reasons.append(f"unknown table {t.name} (not in the schema)")
            continue
        tables.append(schema.table(name).name)
        aliases[t.alias_or_name.lower()] = name
        aliases[name] = name
    outputs = {e.alias.lower() for s in tree.find_all(exp.Select) for e in s.expressions if e.alias}
    columns = set()
    for c in tree.find_all(exp.Column):
        if isinstance(c.this, exp.Star):
            continue
        name, qual = c.name.lower(), c.table.lower()
        quoted = isinstance(c.this, exp.Identifier) and c.this.quoted
        if qual:
            if qual in aliases:
                if name not in schema.table(aliases[qual]).columns:
                    reasons.append(f"unknown column {c.table}.{c.name} (not in {schema.table(aliases[qual]).name})")
                    continue
                columns.add((aliases[qual], name))
            elif qual not in ctes | derived:
                reasons.append(f"unknown table or alias {c.table}")
            continue
        owners = [t for t in set(aliases.values()) if name in schema.table(t).columns]
        if owners:
            columns.update((t, name) for t in owners)
        elif name not in outputs and not (ctes or derived) and not quoted:
            # a double-quoted name that is no column is a string literal to SQLite, not a hallucination
            reasons.append(f"unknown column {c.name} (in none of {', '.join(sorted(set(tables))) or 'the tables used'})")
    denied = {(t.lower(), col.lower()) for t, cols in policy.denied_columns.items() for col in cols}
    for t, col in sorted(columns & denied):
        reasons.append(f"column {schema.table(t).name}.{schema.table(t).columns[col][0]} is withheld by policy")
    for star in tree.find_all(exp.Star):
        parent = star.parent
        qual = parent.table.lower() if isinstance(parent, exp.Column) else ""
        exposed = [aliases[qual]] if qual in aliases else ([] if qual else sorted(set(aliases.values())))
        if isinstance(parent, exp.Count):
            continue
        for t in exposed:
            hidden = [schema.table(t).columns[c][0] for c in schema.table(t).columns if (t, c) in denied]
            if hidden:
                reasons.append(f"SELECT * on {schema.table(t).name} would expose {', '.join(hidden)}")
    decision = Decision(not reasons, sql, reasons, sorted(set(tables)), sorted(f"{schema.table(t).name}.{c}" for t, c in columns))
    if reasons:
        return decision
    decision.sql = with_limit(tree, policy.row_limit)
    if conn is not None:
        decision.estimated_rows_scanned = scan_estimate(conn, decision.sql, schema, aliases)
        if decision.estimated_rows_scanned > policy.max_rows_scanned:
            decision.allowed = False
            decision.reasons.append(f"the plan scans about {decision.estimated_rows_scanned:,} rows; the limit is "
                                    f"{policy.max_rows_scanned:,}")
    return decision


def with_limit(tree, n):
    limit = tree.args.get("limit")
    value = limit.expression if limit is not None else None
    if isinstance(value, exp.Literal) and value.is_int and int(value.this) <= n:
        return tree.sql(dialect="sqlite")
    return f"SELECT * FROM ({tree.sql(dialect='sqlite')}) LIMIT {n}"


def scan_estimate(conn, sql, schema, aliases):
    """Rows read by the plan's full scans (of a table, or of a covering index: still every row),
    multiplied as nested loops multiply them. SEARCH steps use an index and are not counted."""
    total = 1
    for *_, detail in conn.execute(f"EXPLAIN QUERY PLAN {sql}"):
        m = re.match(r"SCAN (\w+)", detail)
        if m:
            t = schema.table(aliases.get(m.group(1).lower(), m.group(1)))
            if t is not None and t.rows:
                total *= t.rows
    return int(min(total, 10 ** 18)) if total > 1 else 0
