import { $, bars, esc, fail, int, kpis, load, select, table } from './kit.js';

try {
  const d = await load();
  const Q = d.queries, attacks = Q.filter((q) => q.kind !== 'legitimate'), legit = Q.filter((q) => q.kind === 'legitimate');
  kpis($('#kpis'), [
    { label: 'Attacks the guard stopped', value: `${attacks.filter((q) => !q.allowed).length}/${attacks.length}`, note: 'DDL, DML, stacked statements, exfiltration, PII, runaway cost' },
    { label: 'Legitimate queries let through', value: `${legit.filter((q) => q.allowed).length}/${legit.length}`, note: 'joins, aggregates, CTEs, subqueries' },
    { label: 'Read-only sandbox alone', value: `${attacks.filter((q) => !q.sandbox_ran).length}/${attacks.length}`, note: `it ran ${attacks.filter((q) => q.sandbox_ran).length} anyway (${[...new Set(attacks.filter((q) => q.sandbox_ran).map((q) => q.kind))].join(', ')}): its timeout only catches what runs long` },
    { label: 'Invented columns caught', value: `${d.spider.mutations_detected}/${d.spider.mutations}`, note: 'Spider gold queries with a column swapped for a name not in the schema' },
  ]);
  const kinds = [...new Set(Q.map((q) => q.kind))];
  const card = (q) => `<article class="q"><div class="qhead"><span class="pill ${q.allowed ? 'ok' : 'no'}">${q.allowed ? 'allowed' : 'blocked'}</span><span class="muted small">${esc(q.kind)}</span>` +
    `<span class="small ${q.sandbox_ran ? (q.kind === 'legitimate' ? 'muted' : 'err') : 'muted'}">sandbox alone: ${q.sandbox_ran ? 'ran it' : 'refused'}</span></div>` +
    `<pre class="box">${esc(q.sql)}</pre>` +
    (q.reasons.length ? `<ul class="plain small">${q.reasons.map((r) => `<li>${esc(r)}</li>`).join('')}</ul>` : '') +
    (q.allowed ? `<p class="small muted">Runs as <code>${esc(q.runs)}</code>${q.scanned != null ? ` · plan scans about ${int(q.scanned)} rows` : ''} · reads ${esc(q.columns.join(', '))}</p>` : '') +
    (!q.sandbox_ran && q.sandbox_error ? `<p class="small muted">Sandbox: ${esc(q.sandbox_error)}</p>` : '') + '</article>';
  select($('#kind'), [['all', `all ${Q.length} queries`], ['attacks', `the ${attacks.length} attacks`], ...kinds.map((k) => [k, `${k} (${Q.filter((q) => q.kind === k).length})`])], 'runaway cost', (k) => {
    const rows = k === 'all' ? Q : k === 'attacks' ? attacks : Q.filter((q) => q.kind === k);
    $('#list').innerHTML = rows.map(card).join('');
  });

  $('#polSub').innerHTML = `Row limit ${int(d.policy.row_limit)}, subqueries at most ${d.policy.max_depth} deep, plans up to ${int(d.policy.max_rows_scanned)} rows scanned. Struck-through columns are withheld: no query may read them, including through <code>SELECT *</code>.`;
  table($('#schema'), [
    { key: 'name', label: 'Table' },
    { key: 'rows', label: 'Rows', num: true, fmt: int },
    { key: 'cols', label: 'Columns', html: true },
  ], d.tables.map((t) => ({ ...t, cols: t.columns.map((c) => (t.withheld.includes(c) ? `<s class="err">${esc(c)}</s>` : esc(c))).join(', ') })));
  bars($('#spider'), [
    { label: 'swapped column caught', title: 'gold queries with one column swapped for a name not in the schema', value: d.spider.mutations_detected / d.spider.mutations, text: `${d.spider.mutations_detected}/${d.spider.mutations}` },
    { label: 'unknown name', title: 'predictions that name a table or column not in the schema', value: d.predictions.flagged / d.predictions.total, text: `${d.predictions.flagged}/${d.predictions.total}`, color: 'var(--c5)' },
    { label: 'unlike gold', title: 'predictions that differ from the gold query', value: d.predictions.differ / d.predictions.total, text: `${d.predictions.differ}/${d.predictions.total}`, color: 'var(--c6)', dim: true },
    { label: 'gold blocked', title: 'gold queries the guard blocked', value: d.spider.gold_blocked.length / d.spider.gold, text: `${d.spider.gold_blocked.length}/${d.spider.gold}`, color: 'var(--c6)', dim: true },
  ], { max: 1 });
  $('#spider').insertAdjacentHTML('beforeend', `<p class="small muted">Most wrong predictions use real tables and columns, so a schema check cannot see them; it stops the ${d.predictions.flagged} that name something that does not exist before they run. The ${d.spider.gold_blocked.length} gold queries blocked use <code>! =</code>, which does not parse.</p>`);
} catch (err) {
  fail(err);
}
