"""Checks after generation: what the SQL does, in words a user can check against their
question, and warnings from the result itself. (Unknown tables and columns, the plainest
hallucination, are caught earlier by the guard.)"""
from sqlglot import exp, parse_one


def describe(sql):
    tree = parse_one(sql, read="sqlite")
    select = tree if isinstance(tree, exp.Select) else tree.find(exp.Select)
    parts = [f"Reads {', '.join(e.sql(dialect='sqlite') for e in select.expressions)}",
             f"from {', '.join(sorted({t.name for t in tree.find_all(exp.Table)}))}"]
    if select.args.get("where"):
        parts.append(f"where {select.args['where'].this.sql(dialect='sqlite')}")
    if select.args.get("group"):
        parts.append(f"per {', '.join(g.sql(dialect='sqlite') for g in select.args['group'].expressions)}")
    if select.args.get("order"):
        parts.append(f"ordered by {', '.join(o.sql(dialect='sqlite') for o in select.args['order'].expressions)}")
    return " ".join(parts) + "."


def result_warnings(result, row_limit):
    out = []
    if result.ok and not result.rows:
        out.append("no rows: check the filters against the question before answering 'none'")
    if result.ok and result.rows:
        for i, col in enumerate(result.columns):
            if all(r[i] is None for r in result.rows):
                out.append(f"column {col} is empty in every row")
    if result.truncated:
        out.append(f"cut off at {row_limit} rows; totals computed from these rows would be wrong")
    return out
