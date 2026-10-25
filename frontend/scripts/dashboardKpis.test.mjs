// Unit tests for src/lib/dashboardKpis.ts's honest-failure-state display logic (2026 redesign,
// Stage 4 main dashboard). Covers the three states every dashboard KPI must distinguish: a real
// value, "still loading", and "load failed" — the last two must never render as a false 0.
//
//   npm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import ts from 'typescript';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const cacheDir = join(root, 'node_modules', '.cache', 'dashboard-kpis-test');
mkdirSync(cacheDir, { recursive: true });

const src = readFileSync(join(root, 'src', 'lib', 'dashboardKpis.ts'), 'utf8');
const out = ts.transpileModule(src, { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2020 }, fileName: join(root, 'src', 'lib', 'dashboardKpis.ts') });
const file = join(cacheDir, 'dashboardKpis.mjs');
writeFileSync(file, out.outputText);
const { platformHealthDisplay, honestCountDisplay, openCasesDisplay } = await import(pathToFileURL(file).href);

test('platform health: non-super_admin sees "not available for your role", never a red 0%', () => {
    const r = platformHealthDisplay(false, null);
    assert.equal(r.pct, '—');
    assert.equal(r.type, 'purple');
    assert.equal(r.sub, 'not available for your role');
});

test('platform health: super_admin before the first response sees "checking…", not 0%', () => {
    const r = platformHealthDisplay(true, null);
    assert.equal(r.pct, '—');
    assert.equal(r.sub, 'checking…');
});

test('platform health: a failed fetch surfaces its reason, not a fabricated 0%', () => {
    const r = platformHealthDisplay(true, { overall: 'unknown', services: [], error: 'Could not reach the backend' });
    assert.equal(r.pct, '—');
    assert.equal(r.type, 'purple');
    assert.equal(r.sub, 'Could not reach the backend');
});

test('platform health: operational is 100% green with the services tally', () => {
    const r = platformHealthDisplay(true, { overall: 'operational', services: [{ status: 'up' }, { status: 'up' }] });
    assert.equal(r.pct, '100%');
    assert.equal(r.type, 'green');
    assert.equal(r.sub, '2/2 services up');
});

test('platform health: degraded computes the up/total percentage, orange', () => {
    const r = platformHealthDisplay(true, { overall: 'degraded', services: [{ status: 'up' }, { status: 'down' }] });
    assert.equal(r.pct, '50%');
    assert.equal(r.type, 'orange');
    assert.equal(r.sub, '1/2 services up');
});

test('platform health: anything else (e.g. "down") is 0% red, not silently "unknown"', () => {
    const r = platformHealthDisplay(true, { overall: 'down', services: [{ status: 'down' }] });
    assert.equal(r.pct, '0%');
    assert.equal(r.type, 'red');
});

test('honest count: a real value (including zero) renders as itself with the ok subtitle', () => {
    assert.deepEqual(honestCountDisplay(0, false, 'organisations'), { value: '0', sub: 'organisations' });
    assert.deepEqual(honestCountDisplay(7, false, 'organisations'), { value: '7', sub: 'organisations' });
});

test('honest count: null + not yet failed is "checking…", never "0"', () => {
    assert.deepEqual(honestCountDisplay(null, false, 'organisations'), { value: '—', sub: 'checking…' });
});

test('honest count: null + failed says "unavailable", never "0"', () => {
    assert.deepEqual(honestCountDisplay(null, true, 'organisations'), { value: '—', sub: 'unavailable' });
});

test('open cases: a real load carries the total and the critical sub-count', () => {
    assert.deepEqual(openCasesDisplay({ total: 12, critical: 3 }, false), { value: '12', sub: '3 critical' });
});

test('open cases: zero open cases is a real "0", distinct from an unreadable "—"', () => {
    assert.deepEqual(openCasesDisplay({ total: 0, critical: 0 }, false), { value: '0', sub: '0 critical' });
});

test('open cases: a failed load is "—" / "unavailable", never a false "0"', () => {
    assert.deepEqual(openCasesDisplay(null, true), { value: '—', sub: 'unavailable' });
});

test('open cases: still loading is "—" / "checking…"', () => {
    assert.deepEqual(openCasesDisplay(null, false), { value: '—', sub: 'checking…' });
});
