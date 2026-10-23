// Staging test for quarantine-recover-by-agent.sql and quarantine-recovery-rollback.sql, on a
// throwaway in-memory Postgres (PGlite) built from the repository's own migrations. Never
// connects to any real database.
//
//   mkdir /tmp/pglite && cd /tmp/pglite && npm init -y && npm i @electric-sql/pglite@0.2.17
//   node docs/runbooks/sql/verify-quarantine-recovery.mjs /tmp/pglite backend/sql [path/to/2026-10-29_p24_wazuh_sources.sql]
//
// The optional third argument adds the P24 migration (applied in production) so the alerts table
// has the same columns as production. P3 (triage columns, alert_events) is always applied.
import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const [pkgDir, sqlDir, p24] = process.argv.slice(2);
const here = dirname(fileURLToPath(import.meta.url));
const RECOVER = readFileSync(join(here, 'quarantine-recover-by-agent.sql'), 'utf8');
const ROLLBACK = readFileSync(join(here, 'quarantine-recovery-rollback.sql'), 'utf8');
const { PGlite } = await import(join(pkgDir, 'node_modules', '@electric-sql', 'pglite', 'dist', 'index.js').replace(/\\/g, '/').replace(/^([A-Za-z]):/, 'file:///$1:'));

const MIGRATIONS = ['2026-10-09_alerts_pipeline.sql', '2026-10-09_alerts_ingest_seq.sql', '2026-10-09_alert_retention.sql', '2026-10-14_p1_quarantine.sql', '2026-10-14_p3_secops_ai.sql'];
const CUTOFF = '2026-10-20T00:00:00Z'; // in the past for any machine running this
let failures = 0;
const check = (ok, label) => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}`); if (!ok) failures++; };

/** The recovery script with its parameter rows replaced. */
function script(rows) {
    const values = rows.map((r) => `  ('${r.org ?? 'cybernovr'}', '${r.agent}', '${r.name}', ${r.expected}, '${r.cutoff ?? CUTOFF}', ${r.dry ?? false})`).join(',\n');
    const out = RECOVER.replace(/INSERT INTO recover_params \(org_id, agent_id, agent_name, expected, cutoff, dry_run\) VALUES[\s\S]*?;\r?\n/, `INSERT INTO recover_params (org_id, agent_id, agent_name, expected, cutoff, dry_run) VALUES\n${values};\n`);
    if (out === RECOVER) throw new Error('parameter block not found');
    return out;
}
/** The rollback script for a run. */
function rollback(runId, dry = false) {
    const out = ROLLBACK.replace("('00000000-0000-0000-0000-000000000000', true)", `('${runId}', ${dry})`);
    if (out === ROLLBACK) throw new Error('rollback parameter not found');
    return out;
}

const qrow = (id, agent, name, { groups = agent === '000' ? [] : ['default'], reason = 'unmapped_group', location = 'EventChannel', received = '2026-10-15T14:36:05Z', level = 5, event = '2026-10-15T14:35:59.123Z' } = {}) => ({
    id, groups, reason, received,
    alert: { wazuh_alert_id: id, rule_id: '61021', rule_level: level, rule_description: `rule for ${id}`, agent_id: agent, agent_name: name, agent_ip: null,
             severity: level >= 13 ? 'critical' : level >= 10 ? 'high' : level >= 7 ? 'medium' : 'low', mitre_ids: id.endsWith('m') ? ['T1110'] : null,
             wazuh_groups: groups, location, raw: { id, full_log: `log ${id}`, agent: { id: agent } }, raw_truncated: false, event_time: event },
});

async function fresh(rows, extra = '') {
    const db = new PGlite();
    await db.exec(`CREATE SCHEMA auth; CREATE FUNCTION auth.role() RETURNS text LANGUAGE sql AS $$ SELECT 'service_role'::text $$; CREATE ROLE anon; CREATE ROLE authenticated;
                   CREATE TABLE public.organisations (slug text PRIMARY KEY, name text); INSERT INTO public.organisations VALUES ('cybernovr', 'Cybernovr'), ('other', 'Other');
                   CREATE TABLE public.cases (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), org_id text, case_number text);`);
    for (const f of MIGRATIONS) await db.exec(readFileSync(join(sqlDir, f), 'utf8'));
    if (p24) await db.exec(readFileSync(p24, 'utf8'));
    await db.exec(`INSERT INTO public.wazuh_group_org_map (wazuh_group, org_id) VALUES ('cybernovr', 'cybernovr');`);
    for (const r of rows) {
        await db.query(`INSERT INTO public.alert_quarantine (wazuh_alert_id, wazuh_groups, reason, alert, received_at) VALUES ($1, $2, $3, $4, $5)`, [r.id, r.groups, r.reason, r.alert, r.received]);
    }
    if (extra) await db.exec(extra);
    return db;
}
async function run(db, sql) {
    try { await db.exec(sql); return { ok: true }; } catch (e) { await db.exec('ROLLBACK').catch(() => undefined); return { ok: false, error: e.message }; }
}
const count = async (db, q) => Number((await db.query(q)).rows[0].n);
const QCOLS = 'SELECT wazuh_alert_id, wazuh_groups, reason, alert, received_at, last_seen_at FROM alert_quarantine ORDER BY 1';
const PRESTORED = `INSERT INTO public.alerts (org_id, wazuh_alert_id, severity, event_time, rule_description) VALUES ('cybernovr', 'a012-2', 'low', '2026-10-15T14:35:59Z', 'stored earlier');`;

// Representative data: production's five agents (small counts), and rows that must stay.
const BASE = [
    qrow('a011-1', '011', 'DESKTOP-FBC0TFT'), qrow('a011-2m', '011', 'DESKTOP-FBC0TFT', { level: 10 }),
    qrow('a012-1', '012', 'PARTYJOLLOF'), qrow('a012-2', '012', 'PARTYJOLLOF'), qrow('a012-3', '012', 'PARTYJOLLOF'),
    qrow('a013-1', '013', 'Aliyat'),
    qrow('a014-1', '014', 'Mac.lan'),
    qrow('a000-1', '000', 'novrsoc-security', { location: 'rootcheck' }), qrow('a000-2', '000', 'novrsoc-security', { location: 'netstat listening ports' }),
    qrow('s000-fw', '000', 'novrsoc-security', { location: '10.0.0.4' }),   // syslog from a device: stays
    qrow('x099-1', '099', 'someone-else'),                                  // another agent: stays
    qrow('a012-late', '012', 'PARTYJOLLOF', { received: '2026-10-21T06:00:00Z' }), // after the cutoff: stays
];
const PARAMS = [
    { agent: '011', name: 'DESKTOP-FBC0TFT', expected: 2 }, { agent: '012', name: 'PARTYJOLLOF', expected: 3 },
    { agent: '013', name: 'Aliyat', expected: 1 }, { agent: '014', name: 'Mac.lan', expected: 1 }, { agent: '000', name: 'novrsoc-security', expected: 2 },
];
const QTOTAL = BASE.length;

// 1. Dry run: every check and the insert run, then everything is rolled back.
{
    const db = await fresh(BASE);
    const r = await run(db, script(PARAMS.map((p) => ({ ...p, dry: true }))));
    check(!r.ok && /DRY RUN OK — rolled back\. Would release 9 alert\(s\) to cybernovr \(9 new, 0 already stored\)/.test(r.error), `dry run reports and rolls back (${r.error?.slice(0, 100)})`);
    check(await count(db, 'SELECT count(*) n FROM alerts') === 0 && await count(db, 'SELECT count(*) n FROM alert_quarantine') === QTOTAL, 'dry run changed nothing');
    check((await db.query("SELECT to_regclass('public.alert_quarantine_recovery_log') t")).rows[0].t === null, 'dry run leaves no recovery log table');
}

// 2. Real run, with one alert already stored for cybernovr (a duplicate).
{
    const db = await fresh(BASE, PRESTORED);
    const r = await run(db, script(PARAMS));
    check(r.ok, `approved run commits (${r.error ?? ''})`);
    const rows = (await db.query(`SELECT wazuh_alert_id, org_id, rule_level, severity, mitre_ids, event_time, received_at, raw FROM alerts ORDER BY wazuh_alert_id`)).rows;
    check(rows.length === 9 && rows.every((a) => a.org_id === 'cybernovr'), '9 alerts under cybernovr (8 new + 1 already stored)');
    const a = rows.find((x) => x.wazuh_alert_id === 'a011-2m');
    check(a && new Date(a.event_time).toISOString() === '2026-10-15T14:35:59.123Z', 'original event_time kept (ms precision)');
    check(a && new Date(a.received_at).toISOString() === '2026-10-15T14:36:05.000Z', 'received_at = original quarantine receipt');
    check(a && a.raw.id === 'a011-2m' && a.raw.full_log === 'log a011-2m' && a.rule_level === 10 && a.severity === 'high' && a.mitre_ids?.[0] === 'T1110', 'alert id, raw payload, level, severity and MITRE kept');
    check((await db.query(`SELECT rule_description FROM alerts WHERE wazuh_alert_id = 'a012-2'`)).rows[0].rule_description === 'stored earlier', 'an existing alert is never overwritten');
    const left = (await db.query(`SELECT wazuh_alert_id FROM alert_quarantine ORDER BY 1`)).rows.map((x) => x.wazuh_alert_id);
    check(JSON.stringify(left) === JSON.stringify(['a012-late', 's000-fw', 'x099-1']), `quarantine keeps the late row, manager syslog and other agents (${left})`);
    check(await count(db, 'SELECT count(*) n FROM alert_quarantine_recovery_log') === 9, 'every released row is in the recovery log');
    const again = await run(db, script(PARAMS));
    check(!again.ok && /0 row\(s\) selected, 2 expected/.test(again.error), 'a repeat run with stale counts aborts instead of doing anything');
    const noop = await run(db, script(PARAMS.map((p) => ({ ...p, expected: 0 }))));
    check(noop.ok && await count(db, 'SELECT count(*) n FROM alerts') === 9, 'idempotent: expected 0 commits nothing new');
}

// 3. Rollback: restores the quarantine exactly, removes only what the run inserted.
{
    const db = await fresh(BASE, PRESTORED);
    const before = (await db.query(QCOLS)).rows;
    check((await run(db, script(PARAMS))).ok, 'recovery before rollback');
    const runIds = (await db.query('SELECT DISTINCT run_id FROM alert_quarantine_recovery_log')).rows.map((r) => r.run_id);
    check(runIds.length === 1, 'one run id logged');
    check(await count(db, 'SELECT count(*) n FROM alert_quarantine_recovery_log WHERE NOT inserted') === 1, 'the already-stored alert is logged as not inserted');
    const dry = await run(db, rollback(runIds[0], true));
    check(!dry.ok && /DRY RUN OK — rolled back\. Would restore 9 quarantine row\(s\) and remove 8 alert\(s\)/.test(dry.error), `rollback dry run reports (${dry.error?.slice(0, 100)})`);
    check(await count(db, 'SELECT count(*) n FROM alerts') === 9, '  … and changes nothing');
    const rb = await run(db, rollback(runIds[0]));
    check(rb.ok, `rollback commits (${rb.error ?? ''})`);
    const after = (await db.query(QCOLS)).rows;
    check(JSON.stringify(after) === JSON.stringify(before), 'quarantine is exactly as before the recovery (payload, reason, groups, times)');
    const al = (await db.query('SELECT wazuh_alert_id, rule_description FROM alerts')).rows;
    check(al.length === 1 && al[0].wazuh_alert_id === 'a012-2' && al[0].rule_description === 'stored earlier', 'only the pre-existing alert remains');
    const twice = await run(db, rollback(runIds[0]));
    check(!twice.ok && /no entries to roll back/.test(twice.error), 'a run cannot be rolled back twice');
}

// 4. Rollback refuses once a recovered alert has been acted on (each way it can be).
for (const [label, sql] of [
    ['status changed', "UPDATE alerts SET status = 'triaged' WHERE wazuh_alert_id = 'a013-1'"],
    ['assigned', "UPDATE alerts SET assigned_to = 'ana@cybernovr.test' WHERE wazuh_alert_id = 'a013-1'"],
    ['triage history', "INSERT INTO alert_events (alert_id, org_id, actor, action) SELECT id, org_id, 'ana', 'note' FROM alerts WHERE wazuh_alert_id = 'a013-1'"],
    ['linked to a case', "INSERT INTO cases (org_id, case_number) VALUES ('cybernovr', 'C-1'); UPDATE alerts SET case_id = (SELECT id FROM cases LIMIT 1) WHERE wazuh_alert_id = 'a013-1'"],
]) {
    const db = await fresh(BASE);
    check((await run(db, script(PARAMS))).ok, `recovery (${label})`);
    const runId = (await db.query('SELECT DISTINCT run_id FROM alert_quarantine_recovery_log')).rows[0].run_id;
    await db.exec(sql);
    const r = await run(db, rollback(runId));
    check(!r.ok && /1 recovered alert\(s\) have been triaged, assigned or cased/.test(r.error), `rollback refuses: ${label}`);
    check(await count(db, 'SELECT count(*) n FROM alerts') === 9 && await count(db, 'SELECT count(*) n FROM alert_quarantine') === 3, '  … and changes nothing');
}

// 5. Every abort condition of the recovery leaves the database exactly as it was.
const ABORTS = [
    ['unknown organisation', BASE, '', PARAMS.map((p) => ({ ...p, org: 'nope' })), /unknown organisation: nope/],
    ['unexpected count', BASE, '', PARAMS.map((p) => (p.agent === '012' ? { ...p, expected: 4 } : p)), /agent 012: 3 row\(s\) selected, 4 expected/],
    ['agent name mismatch (id reused)', [...BASE, qrow('a013-x', '013', 'NEW-LAPTOP')], '', PARAMS.map((p) => (p.agent === '013' ? { ...p, expected: 2 } : p)), /agent 013: 1 row\(s\) carry a name other than Aliyat/],
    ['ambiguous ownership', [...BASE, qrow('a014-amb', '014', 'Mac.lan', { reason: 'ambiguous_org', groups: ['default', 'x'] })], '', PARAMS.map((p) => (p.agent === '014' ? { ...p, expected: 2 } : p)), /agent 014: 1 row\(s\) quarantined for a reason other than unmapped_group/],
    ['row lists a mapped group', [...BASE, qrow('a011-map', '011', 'DESKTOP-FBC0TFT', { groups: ['default', 'cybernovr'] })], '', PARAMS.map((p) => (p.agent === '011' ? { ...p, expected: 3 } : p)), /agent 011: 1 row\(s\) list a Wazuh group mapped/],
    ['id already stored under another organisation', BASE, `INSERT INTO public.alerts (org_id, wazuh_alert_id, severity, event_time) VALUES ('other', 'a013-1', 'low', now());`, PARAMS, /conflict: 1 alert id\(s\) already stored under another organisation/],
    ['two organisations in one run', BASE, '', PARAMS.map((p, i) => (i === 0 ? { ...p, org: 'other' } : p)), /exactly one organisation per run/],
    ['cutoff in the future', BASE, '', PARAMS.map((p) => ({ ...p, cutoff: '2999-01-01T00:00:00Z' })), /is in the future/],
    ['insert failure mid-transaction', [...BASE.filter((r) => r.id !== 'a014-1'), { ...qrow('a014-1', '014', 'Mac.lan'), alert: { ...qrow('a014-1', '014', 'Mac.lan').alert, severity: 'bogus' } }], '', PARAMS, /alerts_severity_check|violates check constraint/],
];
for (const [label, rows, extra, params, expect] of ABORTS) {
    const db = await fresh(rows, extra);
    const beforeQ = (await db.query(QCOLS)).rows;
    const beforeA = await count(db, 'SELECT count(*) n FROM alerts');
    const r = await run(db, script(params));
    check(!r.ok && expect.test(r.error), `aborts: ${label} (${r.error?.slice(0, 100)})`);
    check(JSON.stringify((await db.query(QCOLS)).rows) === JSON.stringify(beforeQ) && await count(db, 'SELECT count(*) n FROM alerts') === beforeA, '  … and changes nothing');
}

console.log(failures ? `\n${failures} check(s) FAILED` : '\nall checks passed');
process.exit(failures ? 1 : 0);
