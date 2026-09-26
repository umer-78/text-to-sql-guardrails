"""The database as the rest of the system sees it: tables, columns and their types, keys, row
counts and a few sample values for low-cardinality text columns (for disambiguation in the
prompt). Read from a live SQLite database, or from Spider's schema file."""
import sqlite3
from dataclasses import dataclass, field


@dataclass
class Table:
    name: str
    columns: dict                      # lower-case name -> (original name, type)
    rows: int = None
    samples: dict = field(default_factory=dict)


@dataclass
class Schema:
    tables: dict                       # lower-case name -> Table
    foreign_keys: list = field(default_factory=list)    # (table, column, referenced table, referenced column)

    def table(self, name):
        return self.tables.get(name.lower())

    def describe(self, names=None):
        """The schema as prompt text, optionally only some tables."""
        lines = []
        for t in self.tables.values():
            if names is None or t.name.lower() in names:
                cols = ", ".join(f"{n} {ty}" + (f" (e.g. {', '.join(map(str, t.samples[k]))})" if k in t.samples else "")
                                 for k, (n, ty) in t.columns.items())
                lines.append(f"{t.name}({cols})")
        lines += [f"{a}.{b} -> {c}.{d}" for a, b, c, d in self.foreign_keys
                  if names is None or (a.lower() in names and c.lower() in names)]
        return "\n".join(lines)

    @classmethod
    def from_sqlite(cls, conn, samples=5, max_distinct=12):
        tables, fks = {}, []
        names = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")]
        for name in names:
            cols = {r[1].lower(): (r[1], r[2]) for r in conn.execute(f'PRAGMA table_info("{name}")')}
            t = Table(name, cols, conn.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0])
            for key, (col, ty) in cols.items():
                if "CHAR" in ty.upper() or "TEXT" in ty.upper():
                    values = [r[0] for r in conn.execute(f'SELECT DISTINCT "{col}" FROM "{name}" LIMIT {max_distinct + 1}')]
                    if len(values) <= max_distinct:
                        t.samples[key] = values[:samples]
            tables[name.lower()] = t
            fks += [(name, r[3], r[2], r[4]) for r in conn.execute(f'PRAGMA foreign_key_list("{name}")')]
        return cls(tables, fks)

    @classmethod
    def from_spider(cls, entry):
        tables = {t.lower(): Table(t, {}) for t in entry["table_names_original"]}
        names = entry["table_names_original"]
        for (ti, col), ty in zip(entry["column_names_original"], entry["column_types"]):
            if ti >= 0:
                tables[names[ti].lower()].columns[col.lower()] = (col, ty)
        cols = entry["column_names_original"]
        fks = [(names[cols[a][0]], cols[a][1], names[cols[b][0]], cols[b][1]) for a, b in entry["foreign_keys"]]
        return cls(tables, fks)


def connect_readonly(path):
    return sqlite3.connect(f"file:{path}?mode=ro", uri=True, check_same_thread=False)
