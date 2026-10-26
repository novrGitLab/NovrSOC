// Unit tests for src/lib/priorityQueue.ts — the dashboard's Priority Action Queue composition
// and "My Cases" filter (2026 redesign, Stage 1/3 R3.2). Covers: distinct per-source labelling
// (never merged into a fabricated count), severity ordering, the "My Cases" identifier match,
// and that a missing source is never silently treated as an empty one.
//
//   npm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import ts from 'typescript';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const cacheDir = join(root, 'node_modules', '.cache', 'priority-queue-test');
mkdirSync(cacheDir, { recursive: true });

const src = readFileSync(join(root, 'src', 'lib', 'priorityQueue.ts'), 'utf8');
const out = ts.transpileModule(src, { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2020 }, fileName: join(root, 'src', 'lib', 'priorityQueue.ts') });
const file = join(cacheDir, 'priorityQueue.mjs');
writeFileSync(file, out.outputText);
const { buildPriorityItems, filterMyCases, priorityFailedSources } = await import(pathToFileURL(file).href);

const watTime = (iso) => `at ${iso}`;

const criticalCase = { id: 'c1', name: 'Ransomware on DC01', asset: 'DC01', severity: 'critical', status: 'Open', assignedTo: 'Ada Lovelace' };
const highCase = { id: 'c2', name: 'Suspicious login', asset: 'web-01', severity: 'high', status: 'Investigating', assignedTo: null };
const lowCase = { id: 'c3', name: 'Port scan', asset: 'fw-01', severity: 'low', status: 'Open', assignedTo: 'Ada Lovelace' };
const approval = { id: 'a1', action: 'block_ip', target: '203.0.113.5', target_label: 'Suspicious external IP', requested_at: '2026-01-01T00:00:00Z' };
const overdue = { id: 'f1', title: 'Unpatched OpenSSL', asset_value: 'web-01', scanner_severity: 'high', priority: 'P1' };

test('cases below high severity never enter the queue', () => {
    const items = buildPriorityItems([criticalCase, highCase, lowCase], [], [], watTime);
    assert.deepEqual(items.map((i) => i.id), ['c1', 'c2']);
});

test('each record type keeps its own kind label — never merged into one count', () => {
    const items = buildPriorityItems([criticalCase], [approval], [overdue], watTime);
    assert.deepEqual(new Set(items.map((i) => i.kind)), new Set(['case', 'approval', 'remediation']));
    assert.equal(items.length, 3, 'three distinct records stay three rows, not one combined count');
});

test('items are sorted by severity, with the un-severitised approval row placed last', () => {
    const items = buildPriorityItems([highCase], [approval], [overdue], watTime);
    // highCase=high, overdue finding=high, approval=null → both severitised rows before the approval
    assert.equal(items[2].kind, 'approval');
    assert.ok(items.slice(0, 2).every((i) => i.severity === 'high'));
});

test('an approval shows its target label (falling back to the raw target) and the formatted request time', () => {
    const items = buildPriorityItems([], [approval], [], watTime);
    assert.equal(items[0].title, 'Suspicious external IP');
    assert.equal(items[0].href, '/admin/secops/approvals');
    assert.ok(items[0].meta.includes('at 2026-01-01T00:00:00Z'));
    assert.ok(items[0].meta.startsWith('block ip'), 'underscores in the action are humanised');
});

test('an overdue finding links to VMS findings and carries its asset and priority', () => {
    const items = buildPriorityItems([], [], [overdue], watTime);
    assert.equal(items[0].href, '/admin/vms/findings');
    assert.equal(items[0].meta, 'web-01 · P1');
});

test('a null list from any source is treated as empty, not a crash', () => {
    assert.deepEqual(buildPriorityItems(null, null, null, watTime), []);
});

test('priorityFailedSources names exactly the sources that failed, in a fixed order', () => {
    assert.deepEqual(priorityFailedSources(false, false, false), []);
    assert.deepEqual(priorityFailedSources(true, false, false), ['cases']);
    assert.deepEqual(priorityFailedSources(false, true, true), ['approvals', 'VMS findings']);
    assert.deepEqual(priorityFailedSources(true, true, true), ['cases', 'approvals', 'VMS findings']);
});

test('My Cases: matches the stored assignee name exactly, leaves unassigned and other analysts\' cases out', () => {
    const cases = [criticalCase, highCase, lowCase];
    const mine = filterMyCases(cases, true, 'Ada Lovelace');
    assert.deepEqual(mine.map((c) => c.id), ['c1', 'c3']);
});

test('My Cases: off (or no identifier) returns the list unchanged, never drops it to empty', () => {
    const cases = [criticalCase, highCase];
    assert.deepEqual(filterMyCases(cases, false, 'Ada Lovelace'), cases);
    assert.deepEqual(filterMyCases(cases, true, ''), []);
});

test('My Cases: a null case list (still loading / failed) stays null rather than becoming a false empty queue', () => {
    assert.equal(filterMyCases(null, true, 'Ada Lovelace'), null);
});
