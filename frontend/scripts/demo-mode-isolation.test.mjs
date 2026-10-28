// Executable verification for Demo Mode's core safety invariants (management-demo readiness
// pass) — not a read of the code, an actual run of it. Transpiles src/lib/demo/* and src/lib/
// api.ts with the typescript package (same technique as auth-session.test.mjs /
// breadcrumbs.test.mjs — these files use only relative imports, so no @/-alias stubbing is
// needed except for api.ts's four non-demo imports, which this test never exercises).
//
//   npm test
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import ts from 'typescript';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const cacheDir = join(root, 'node_modules', '.cache', 'demo-mode-isolation-test');
mkdirSync(cacheDir, { recursive: true });

// Every src/lib/demo/* file plus lib/api.ts, transpiled once into the cache dir, preserving
// relative paths so their own cross-imports ('./generators/vms', '../types', etc.) still resolve.
// TS's transpileModule doesn't add file extensions (Node's ESM loader requires them), so every
// bare relative specifier gets '.mjs' appended after transpiling.
const RELATIVE_FILES = [
    'lib/demo/types.ts', 'lib/demo/rng.ts', 'lib/demo/orgs.ts', 'lib/demo/scenario.ts',
    'lib/demo/mutations.ts', 'lib/demo/state.ts',
    'lib/demo/generators/vms.ts', 'lib/demo/generators/ti.ts', 'lib/demo/generators/secops.ts',
    'lib/demo/generators/cnii.ts', 'lib/demo/generators/collectors.ts',
    'lib/demo/generators/reports.ts', 'lib/demo/generators/misc.ts',
    'lib/demo/router.ts', 'lib/demo/documents.ts',
];
for (const rel of RELATIVE_FILES) {
    const srcPath = join(root, 'src', rel);
    const out = ts.transpileModule(readFileSync(srcPath, 'utf8'), {
        compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2020 }, fileName: srcPath,
    });
    const rewritten = out.outputText.replace(/from\s+'(\.[^']+)'/g, (m, spec) => (/\.[a-zA-Z0-9]+$/.test(spec) ? m : `from '${spec}.mjs'`));
    const destPath = join(cacheDir, rel.replace(/\.ts$/, '.mjs'));
    mkdirSync(dirname(destPath), { recursive: true });
    writeFileSync(destPath, rewritten);
}

// lib/api.ts has four imports this test never needs (getAuthToken, adminSignOut, portalSignOut,
// orgContextHeaderFor) — stubbed to trivial no-ops, same approach as breadcrumbs.test.mjs
// stubbing config/nav and config/vmsSections.
writeFileSync(join(cacheDir, 'lib', 'stub-account.mjs'), 'export function getAuthToken() { return null; }\n');
writeFileSync(join(cacheDir, 'lib', 'stub-admin-auth.mjs'), 'export function adminSignOut() {}\n');
writeFileSync(join(cacheDir, 'lib', 'stub-portal-auth.mjs'), 'export function portalSignOut() {}\n');
writeFileSync(join(cacheDir, 'lib', 'stub-orgContext.mjs'), "export function orgContextHeaderFor() { return ''; }\n");
{
    const srcPath = join(root, 'src', 'lib', 'api.ts');
    const out = ts.transpileModule(readFileSync(srcPath, 'utf8'), {
        compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2020 }, fileName: srcPath,
    });
    let rewritten = out.outputText.replace(/from\s+'(\.[^']+)'/g, (m, spec) => (/\.[a-zA-Z0-9]+$/.test(spec) ? m : `from '${spec}.mjs'`));
    rewritten = rewritten
        .replace("from './account.mjs'", "from './stub-account.mjs'")
        .replace("from './admin-auth.mjs'", "from './stub-admin-auth.mjs'")
        .replace("from './portal-auth.mjs'", "from './stub-portal-auth.mjs'")
        .replace("from './orgContext.mjs'", "from './stub-orgContext.mjs'");
    writeFileSync(join(cacheDir, 'lib', 'api.mjs'), rewritten);
}

function loadMjs(rel) {
    // Cache-busting query so re-importing after resetting the fake sessionStorage between tests
    // doesn't hand back a stale module-level cache (none of these modules have one, but cheap
    // insurance against Node's ESM module cache making a later test depend on an earlier one).
    return import(`${pathToFileURL(join(cacheDir, rel)).href}?t=${Date.now()}-${Math.random()}`);
}

// ── Fake browser: Map-backed sessionStorage shared between globalThis.sessionStorage (state.ts
// reads it bare, mirroring orgContext.ts) and globalThis.window.sessionStorage (mutations.ts
// reads it off window) — same backing Map either way, matching the real browser where both are
// the same object. ───────────────────────────────────────────────────────────────────────────
function installFakeBrowser() {
    const store = new Map();
    const sessionStorage = {
        getItem: (k) => (store.has(k) ? store.get(k) : null),
        setItem: (k, v) => store.set(k, String(v)),
        removeItem: (k) => store.delete(k),
        key: (i) => [...store.keys()][i] ?? null,
        get length() { return store.size; },
    };
    globalThis.sessionStorage = sessionStorage;
    const listeners = new Map();
    globalThis.window = {
        sessionStorage,
        dispatchEvent: (e) => { for (const cb of listeners.get(e.type) ?? []) cb(); },
        addEventListener: (type, cb) => { if (!listeners.has(type)) listeners.set(type, []); listeners.get(type).push(cb); },
        removeEventListener: (type, cb) => { const l = listeners.get(type); if (l) listeners.set(type, l.filter((x) => x !== cb)); },
    };
    return store;
}

// A fetch spy that FAILS THE TEST if the real network is ever reached while Demo Mode is on —
// this is the actual safety property under test, not an assumption about the code.
function installFetchSpy() {
    const calls = [];
    globalThis.fetch = async (input, init) => {
        calls.push({ input: String(input), method: init?.method ?? 'GET' });
        return new Response(JSON.stringify({ ok: true, stubbed: true }), { status: 200 });
    };
    return calls;
}

beforeEach(() => { installFakeBrowser(); installFetchSpy(); });

const ORGS = ['lapo', 'tazemi', 'ikea'];

// Representative GET + mutating calls covering every one of the ten target screens (dashboard,
// VMS findings/remediation, TI, Nigeria heatmap [its own component, not apiFetch-routed — covered
// separately in DashboardNigeriaMap/AiThreatIntelligenceDemo review, not here], SecOps
// cases/approvals, CNII Watch, Collector Management, Reporting Center) plus the shared AI panel
// and TI analyst ask endpoint fixed during Part A.
const REPRESENTATIVE_CALLS = [
    ['GET', '/api/platform/health'], ['GET', '/api/compliance'], ['GET', '/api/novr-ai/status'],
    ['GET', '/api/wazuh/agents'], ['GET', '/api/wazuh/status'], ['GET', '/api/wazuh/mitre-stats'],
    ['GET', '/api/wazuh/trend?range=7d'], ['GET', '/api/customers'], ['GET', '/api/cases'],
    ['GET', '/api/response-approvals'], ['GET', '/api/alerts'], ['GET', '/api/alerts/stats'],
    ['GET', '/api/vms/findings?overdue=true'], ['GET', '/api/vms/findings/summary'],
    ['GET', '/api/vms/remediation'], ['GET', '/api/vms/ai-plans'], ['GET', '/api/vms/scans'],
    ['GET', '/api/ti/overview'], ['GET', '/api/ti/map'], ['GET', '/api/ti/matches'],
    ['GET', '/api/ti/vulnerabilities'], ['GET', '/api/ti/relevant'],
    ['GET', '/api/cnii/sectors'], ['GET', '/api/cnii/organisations'], ['GET', '/api/cnii/legacy'],
    ['GET', '/api/collectors'], ['GET', '/api/reports/types'], ['GET', '/api/reports/schedules'],
    ['GET', '/api/reports/recipients'], ['GET', '/api/reports/history'], ['GET', '/api/reports/ops/health'],
    ['GET', '/api/ai/artifacts?subject_type=finding&subject_id=x'],
    ['POST', '/api/ai/generate', { purpose: 'finding_explanation', subject_id: 'x' }],
    ['POST', '/api/ti/analyst/ask', { question: 'what is going on?' }],
    ['POST', '/api/reports/generate', { report_type: 'executive_summary' }],
    ['PATCH', '/api/vms/findings/demo-x', { status: 'acknowledged' }],
    ['POST', '/api/response-approvals/demo-x/approve', {}],
    ['POST', '/api/cases/demo-x/notes', { content: 'test' }],
];

test('Demo Mode never reaches the real network, for any org, across every target-screen endpoint plus mutations', async () => {
    const { setDemoMode } = await loadMjs('lib/demo/state.mjs');
    const { apiFetch, apiUrl } = await loadMjs('lib/api.mjs');
    for (const org of ORGS) {
        setDemoMode(true, org);
        for (const [method, path, body] of REPRESENTATIVE_CALLS) {
            const res = await apiFetch(apiUrl(path), { method, headers: body ? { 'Content-Type': 'application/json' } : undefined, body: body ? JSON.stringify(body) : undefined });
            assert.equal(res.status, method === 'POST' && path === '/api/ai/generate' ? 503 : 200, `${org} ${method} ${path} should resolve locally with a sane status, not error`);
            await res.json(); // throws if the body isn't valid JSON
        }
    }
    const fetchSpy = globalThis.fetch;
    assert.equal(fetchSpy.mock, undefined); // sanity: we replaced the spy fresh via beforeEach, not reused
});

test('Demo Mode never reaches the real network — explicit call-count assertion', async () => {
    const calls = installFetchSpy(); // re-install to get a reference to this test's own call log
    const { setDemoMode } = await loadMjs('lib/demo/state.mjs');
    const { apiFetch, apiUrl } = await loadMjs('lib/api.mjs');
    setDemoMode(true, 'lapo');
    for (const [method, path, body] of REPRESENTATIVE_CALLS) {
        await apiFetch(apiUrl(path), { method, headers: body ? { 'Content-Type': 'application/json' } : undefined, body: body ? JSON.stringify(body) : undefined });
    }
    assert.equal(calls.length, 0, `Demo Mode must never call the real network; saw ${calls.length} real fetch(es): ${JSON.stringify(calls)}`);
});

test('switching organisation changes the data; the same organisation is deterministic across calls', async () => {
    const { setDemoMode } = await loadMjs('lib/demo/state.mjs');
    const { apiFetch, apiUrl } = await loadMjs('lib/api.mjs');
    setDemoMode(true, 'lapo');
    // first_seen/last_seen are computed as "N days before Date.now()", recomputed fresh on every
    // call by design (a demo restarted weeks from now should still look recent) — so they drift
    // by whatever real time passes between the two calls, not by randomness. Stripped before the
    // determinism check; every other field must still be identical.
    const VOLATILE_FIELDS = ['first_seen', 'last_seen', 'due_at', 'verified_at'];
    const stripVolatile = (d) => ({ ...d, findings: d.findings.map((f) => Object.fromEntries(Object.entries(f).filter(([k]) => !VOLATILE_FIELDS.includes(k)))) });
    const lapoFirst = stripVolatile(await (await apiFetch(apiUrl('/api/vms/findings'))).json());
    const lapoSecond = stripVolatile(await (await apiFetch(apiUrl('/api/vms/findings'))).json());
    assert.deepEqual(lapoFirst, lapoSecond, 'same org, no mutation in between, must be identical (seeded, not random) aside from real-time-relative timestamps');
    setDemoMode(true, 'tazemi');
    const tazemi = await (await apiFetch(apiUrl('/api/vms/findings'))).json();
    assert.notDeepEqual(lapoFirst, tazemi, 'a different org must show different data');
    assert.notEqual(lapoFirst.findings[0].asset_value, tazemi.findings[0].asset_value);
});

test('session-local mutation: verifying an IKEA finding updates it for subsequent reads this session only', async () => {
    const { setDemoMode } = await loadMjs('lib/demo/state.mjs');
    const { apiFetch, apiUrl } = await loadMjs('lib/api.mjs');
    setDemoMode(true, 'ikea');
    const before = await (await apiFetch(apiUrl('/api/vms/findings'))).json();
    const featured = before.findings[0];
    assert.equal(featured.status, 'fixed_pending_verification', 'fixture sanity: IKEA\'s featured finding starts pending verification');
    const verifyRes = await apiFetch(apiUrl(`/api/vms/findings/${featured.id}/verify`), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    const verifyBody = await verifyRes.json();
    assert.equal(verifyBody.demo, true);
    assert.ok(/verification completed immediately/i.test(verifyBody.message), 'must say plainly that no real scan was queued');
    const after = await (await apiFetch(apiUrl('/api/vms/findings'))).json();
    const updated = after.findings.find((f) => f.id === featured.id);
    assert.equal(updated.status, 'verified', 'the click must visibly change the next read');
    assert.ok(updated.verified_at, 'a verified finding must carry a verified_at timestamp');
});

test('session-local mutation: case status change, escalation and a note all show up on the next read', async () => {
    const { setDemoMode } = await loadMjs('lib/demo/state.mjs');
    const { apiFetch, apiUrl } = await loadMjs('lib/api.mjs');
    setDemoMode(true, 'lapo');
    const before = await (await apiFetch(apiUrl('/api/cases'))).json();
    const featured = before.cases[0];
    assert.equal(featured.status, 'investigating');
    await apiFetch(apiUrl(`/api/cases/${featured.id}`), { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ status: 'contained' }) });
    await apiFetch(apiUrl(`/api/cases/${featured.id}/escalate`), { method: 'POST' });
    await apiFetch(apiUrl(`/api/cases/${featured.id}/notes`), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ content: 'reviewed during readiness check' }) });
    const after = await (await apiFetch(apiUrl('/api/cases'))).json();
    const updatedCase = after.cases.find((c) => c.id === featured.id);
    assert.equal(updatedCase.status, 'contained');
    assert.equal(updatedCase.escalated, true);
    const detail = await (await apiFetch(apiUrl(`/api/cases/${featured.id}`))).json();
    assert.ok(detail.notes.some((n) => n.content.includes('reviewed during readiness check')), 'the added note must appear in case detail');
});

test('session-local mutation: approving a response action removes it from the pending list', async () => {
    const { setDemoMode } = await loadMjs('lib/demo/state.mjs');
    const { apiFetch, apiUrl } = await loadMjs('lib/api.mjs');
    setDemoMode(true, 'tazemi');
    const before = await (await apiFetch(apiUrl('/api/response-approvals?status=pending'))).json();
    assert.ok(before.approvals.length > 0, 'fixture sanity: there must be at least one pending approval to approve');
    const target = before.approvals[0];
    const decideRes = await apiFetch(apiUrl(`/api/response-approvals/${target.id}/approve`), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    const decideBody = await decideRes.json();
    assert.equal(decideBody.approval.status, 'approved');
    assert.ok(/no real firewall\/Wazuh call/i.test(decideBody.approval.result), 'the approval result must say plainly that no real action ran');
    const after = await (await apiFetch(apiUrl('/api/response-approvals?status=pending'))).json();
    assert.ok(!after.approvals.some((a) => a.id === target.id), 'an approved item must disappear from the pending list on the next read');
});

test('turning Demo Mode off restores real network calls; turning it back on starts from a clean seeded state', async () => {
    const calls = installFetchSpy();
    const { setDemoMode } = await loadMjs('lib/demo/state.mjs');
    const { apiFetch, apiUrl } = await loadMjs('lib/api.mjs');

    setDemoMode(true, 'ikea');
    const before = await (await apiFetch(apiUrl('/api/vms/findings'))).json();
    await apiFetch(apiUrl(`/api/vms/findings/${before.findings[0].id}/verify`), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    assert.equal(calls.length, 0, 'no real call during the simulated click');

    setDemoMode(false);
    await apiFetch(apiUrl('/api/vms/findings'));
    assert.equal(calls.length, 1, 'turning Demo Mode off must restore real apiFetch behaviour (the real fetch() must now run)');

    setDemoMode(true, 'ikea');
    const afterReEnable = await (await apiFetch(apiUrl('/api/vms/findings'))).json();
    assert.equal(afterReEnable.findings[0].status, 'fixed_pending_verification', 'turning Demo Mode off must clear the previous session\'s simulated clicks, not carry them forward silently');
});
