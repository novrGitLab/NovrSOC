// Unit tests for the Threat Intelligence report's pure helpers (brief: "Threat Intelligence
// Frontend Transformation" §5 Reports). No DOM, no fetch, no React.
//
//   npm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import ts from 'typescript';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const cacheDir = join(root, 'node_modules', '.cache', 'ti-report-test');
mkdirSync(cacheDir, { recursive: true });

const src = readFileSync(join(root, 'src', 'components', 'features', 'ti', 'report', 'reportHelpers.ts'), 'utf8');
const out = ts.transpileModule(src, { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2020 }, fileName: join(root, 'src', 'components', 'features', 'ti', 'report', 'reportHelpers.ts') });
const file = join(cacheDir, 'reportHelpers.mjs');
writeFileSync(file, out.outputText);
const { tiReportId, mergeTrend } = await import(pathToFileURL(file).href);

test('tiReportId is deterministic for the same org/days/minute and distinguishes periods', () => {
    const at = new Date('2026-03-05T14:32:00Z');
    const id = tiReportId('Acme Corp', 30, at);
    assert.match(id, /^TIR-ACMECORP-\d{12}-30D$/);
    assert.equal(tiReportId('Acme Corp', 30, at), id);
    assert.notEqual(tiReportId('Acme Corp', 7, at), id);
});

test('tiReportId falls back to ORG when the slug has no usable characters', () => {
    assert.match(tiReportId('', 30, new Date('2026-03-05T14:32:00Z')), /^TIR-ORG-/);
    assert.match(tiReportId('***', 30, new Date('2026-03-05T14:32:00Z')), /^TIR-ORG-/);
});

test('mergeTrend unions both series\' days, filling the other series with 0 rather than dropping the day', () => {
    const rows = mergeTrend(
        [{ day: '2026-03-01', count: 3 }, { day: '2026-03-02', count: 5 }],
        [{ day: '2026-03-02', count: 1 }, { day: '2026-03-03', count: 2 }],
    );
    assert.deepEqual(rows, [
        { day: '2026-03-01', indicators: 3, matches: 0 },
        { day: '2026-03-02', indicators: 5, matches: 1 },
        { day: '2026-03-03', indicators: 0, matches: 2 },
    ]);
});

test('mergeTrend on two empty series is an empty array, not an error', () => {
    assert.deepEqual(mergeTrend([], []), []);
});

test('mergeTrend sorts days ascending regardless of input order', () => {
    const rows = mergeTrend([{ day: '2026-03-03', count: 1 }, { day: '2026-03-01', count: 1 }], []);
    assert.deepEqual(rows.map((r) => r.day), ['2026-03-01', '2026-03-03']);
});
