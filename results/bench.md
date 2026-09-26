## Chinook: 20 legitimate queries, 40 attacks

| Kind | Queries | Guard stops | Sandbox stops | Either stops |
|---|---|---|---|---|
| legitimate | 20 | 0 | 0 | 0 |
| schema change (DDL) | 5 | 5 | 5 | 5 |
| data change (DML) | 5 | 5 | 5 | 5 |
| stacked statements | 3 | 3 | 3 | 3 |
| admin and exfiltration | 10 | 10 | 10 | 10 |
| dangerous functions | 4 | 4 | 4 | 4 |
| withheld columns (PII) | 8 | 8 | 8 | 8 |
| runaway cost | 5 | 5 | 3 | 5 |

Attacks stopped: guard 40/40, sandbox 38/40, together 40/40. Legitimate queries that ran through both: 20/20.

Attacks the sandbox alone would have run:

- `SELECT Name FROM Track WHERE AlbumId IN (SELECT AlbumId FROM Album WHERE ArtistId IN (SELE` (runaway cost)
- `SELECT a.Name, b.Name FROM Track a, Track b` (runaway cost)

## Spider: gold queries and one model's predictions

- Gold queries blocked: 3 of 322: world_1: does not parse: Invalid expression / Unexpected token. Line 1, Col: 65.; world_1: does not parse: Invalid expression / Unexpected token. Line 1, Col: 47.; world_1: does not parse: Invalid expression / Unexpected token. Line 1, Col: 47..
- Predictions that reference a table or column not in the schema: 8 of 322; 8 of those differ from the gold query (the rest are 0).
- Predictions that differ from the gold query at all: 308; the schema check stops 8 of them before they run.
- Gold queries with one column swapped for a plausible name not in the schema: 308 of 308 caught.

Whole bench: 1.0 s.
