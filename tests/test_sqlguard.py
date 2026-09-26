import sqlite3

import pytest

from sqlguard.generate import ambiguous, relevant_tables
from sqlguard.guard import Policy, check
from sqlguard.sandbox import Sandbox
from sqlguard.schema import Schema
from sqlguard.verify import describe, result_warnings

PII = {"customer": ["email"]}


@pytest.fixture()
def db(tmp_path):
    path = tmp_path / "shop.db"
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE customer (id INTEGER PRIMARY KEY, name TEXT, country TEXT, email TEXT);
        CREATE TABLE orders (id INTEGER PRIMARY KEY, customer_id INTEGER REFERENCES customer(id), total REAL);
        INSERT INTO customer VALUES (1, 'Ann', 'UK', 'ann@x.com'), (2, 'Bo', 'US', 'bo@x.com');
        INSERT INTO orders VALUES (1, 1, 10.0), (2, 1, 5.0), (3, 2, 7.5);""")
    conn.commit()
    return path, Schema.from_sqlite(conn)


def test_only_one_read_only_query_passes(db):
    _, schema = db
    for sql in ("DROP TABLE orders", "DELETE FROM orders", "UPDATE customer SET name = 'x'", "PRAGMA table_info(customer)",
                "SELECT 1; DROP TABLE orders", "ATTACH DATABASE 'x.db' AS x", "SELECT randomblob(10)"):
        assert not check(sql, schema).allowed, sql
    ok = check("SELECT country, SUM(total) FROM orders o JOIN customer c ON c.id = o.customer_id GROUP BY country", schema)
    assert ok.allowed and ok.sql.endswith("LIMIT 1000") and ok.tables == ["customer", "orders"]


def test_schema_hallucinations_are_named(db):
    _, schema = db
    d = check("SELECT full_name FROM customer", schema)
    assert not d.allowed and "unknown column full_name" in d.reasons[0]
    assert "unknown table" in check("SELECT * FROM invoices", schema).reasons[0]
    assert check('SELECT name FROM customer WHERE country = "UK"', schema).allowed    # SQLite reads "UK" as a string


def test_policy_rules(db):
    _, schema = db
    policy = Policy(denied_columns=PII, max_depth=1)
    assert not check("SELECT email FROM customer", schema, policy).allowed
    assert "would expose email" in check("SELECT * FROM customer", schema, policy).reasons[0]
    assert check("SELECT COUNT(*) FROM customer", schema, policy).allowed
    deep = "SELECT name FROM customer WHERE id IN (SELECT customer_id FROM orders WHERE id IN (SELECT id FROM orders))"
    assert "nested 2 deep" in check(deep, schema, policy).reasons[0]
    assert not check("WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) SELECT x FROM c", schema).allowed


def test_sandbox_refuses_on_its_own(db):
    path, _ = db
    box = Sandbox(path, denied_columns=PII, max_steps=100_000)
    assert box.run("SELECT name FROM customer").ok
    for sql in ("DELETE FROM orders", "SELECT email FROM customer", "PRAGMA table_info(customer)",
                "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) SELECT COUNT(*) FROM c"):
        assert not box.run(sql).ok, sql
    assert sqlite3.connect(path).execute("SELECT COUNT(*) FROM orders").fetchone()[0] == 3


def test_prompting_helpers_and_result_checks(db):
    path, schema = db
    assert "orders" in relevant_tables("total order value per country", schema)
    assert "revenue" in ambiguous("What was revenue last year?", {"revenue": {"gross": "SUM(total)", "net": "SUM(total) - refunds"}})
    assert describe("SELECT name FROM customer WHERE country = 'UK' ORDER BY name").startswith("Reads name from customer where")
    empty = Sandbox(path).run("SELECT name FROM customer WHERE country = 'FR'")
    assert result_warnings(empty, 1000)[0].startswith("no rows")
