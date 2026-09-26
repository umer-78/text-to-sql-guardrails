"""Question to SQL: a schema-aware prompt with only the relevant tables, a clarification
request when a glossary term is ambiguous, and structured output from any OpenAI-compatible
model (SQL, explanation, confidence, tables used). Pluggable; not measured in this
repository, which runs without API keys. Whatever it returns goes through the guard."""
import json
import re
import urllib.request

PROMPT = """You write SQLite for this schema:
{schema}

Examples:
{examples}

Question: {question}
Reply with JSON: {{"sql": "...", "explanation": "...", "confidence": 0-1, "tables": [...]}}"""


def words(text):
    return {w for w in re.findall(r"[a-z]+", re.sub(r"([a-z])([A-Z])", r"\1 \2", text).lower()) if len(w) > 2}


def relevant_tables(question, schema, keep=4):
    """Tables whose names, columns or sample values share words with the question, plus their foreign-key neighbours."""
    q = words(question)
    score = {k: len(q & (words(t.name) | {w for c, _ in t.columns.values() for w in words(c)} |
                         {w for vs in t.samples.values() for v in vs for w in words(str(v))}))
             for k, t in schema.tables.items()}
    top = {k for k, s in sorted(score.items(), key=lambda kv: -kv[1])[:keep] if s > 0}
    for a, _, b, _ in schema.foreign_keys:
        if a.lower() in top and score.get(b.lower(), 0) > 0:
            top.add(b.lower())
    return top


def ambiguous(question, glossary):
    """glossary: {term: {interpretation: sql fragment}}. Terms in the question with more than one meaning."""
    return {term: meanings for term, meanings in glossary.items()
            if len(meanings) > 1 and re.search(rf"\b{re.escape(term)}\b", question, re.I)}


def generate(question, schema, examples, model, base_url, api_key, glossary=None, timeout=60):
    unclear = ambiguous(question, glossary or {})
    if unclear:
        return {"clarify": {term: list(m) for term, m in unclear.items()}}
    prompt = PROMPT.format(schema=schema.describe(relevant_tables(question, schema)), question=question,
                           examples="\n".join(f"Q: {q}\nSQL: {s}" for q, s in examples))
    body = {"model": model, "temperature": 0, "response_format": {"type": "json_object"},
            "messages": [{"role": "user", "content": prompt}]}
    req = urllib.request.Request(base_url.rstrip("/") + "/chat/completions", json.dumps(body).encode(),
                                 {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(json.loads(r.read())["choices"][0]["message"]["content"])
