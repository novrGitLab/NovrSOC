// Unit tests for src/lib/tiReportInsights.ts's keyRecommendations — the Threat Intelligence
// Executive report's "key recommendations" (R3.3D). Every assertion checks the figure named in
// the sentence is the exact figure passed in; none of this is reachable only by rendering the page.
//
//   npm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import ts from 'typescript';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const cacheDir = join(root, 'node_modules', '.cache', 'ti-report-insights-test');
mkdirSync(cacheDir, { recursive: true });

const src = readFileSync(join(root, 'src', 'lib', 'tiReportInsights.ts'), 'utf8');
const out = ts.transpileModule(src, { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2020 }, fileName: join(root, 'src', 'lib', 'tiReportInsights.ts') });
const file = join(cacheDir, 'tiReportInsights.mjs');
writeFileSync(file, out.outputText);
const { keyRecommendations } = await import(pathToFileURL(file).href);

const clean = { relevant: { by_tier: { critical: 0, high: 0, medium: 0, low: 0 } }, kev: { new_in_period: 0, your_open_findings: 0 }, matches: { verified: 0, total: 0 }, engine: { correlation_last_run_at: '2026-10-26T00:00:00Z' } };

test('nothing to flag: one honest line, never an empty list', () => {
    assert.deepEqual(keyRecommendations(clean), ["No critical- or high-relevance intelligence currently applies to this organisation's records."]);
});

test('critical-tier relevance is named first with the real count', () => {
    const r = { ...clean, relevant: { by_tier: { ...clean.relevant.by_tier, critical: 2 } } };
    assert.match(keyRecommendations(r)[0], /^2 indicator matches rate as critical relevance/);
});

test('singular wording for exactly one', () => {
    const r = { ...clean, relevant: { by_tier: { ...clean.relevant.by_tier, critical: 1, high: 1 } } };
    const lines = keyRecommendations(r);
    assert.match(lines[0], /^1 indicator match rates as critical relevance/);
    assert.match(lines[1], /^1 further match rates as high relevance/);
});

test('KEV affecting open findings cites the real count', () => {
    const r = { ...clean, kev: { new_in_period: 3, your_open_findings: 2 } };
    assert.match(keyRecommendations(r)[0], /^2 open findings are affected by a CVE newly added/);
});

test('verified associations are reported as a fraction of total current matches', () => {
    const r = { ...clean, matches: { verified: 3, total: 10 } };
    assert.match(keyRecommendations(r)[0], /^3 of 10 current matches are a verified association/);
});

test('engine not yet run is flagged, and only when it has not run', () => {
    const notRun = { ...clean, engine: { correlation_last_run_at: null } };
    assert.match(keyRecommendations(notRun)[0], /correlation engine.*has not reported a completed run/);
    assert.deepEqual(keyRecommendations(clean), ["No critical- or high-relevance intelligence currently applies to this organisation's records."]);
});

test('order: critical, then high, then KEV, then verified, then engine health', () => {
    const r = {
        relevant: { by_tier: { critical: 1, high: 1, medium: 0, low: 0 } },
        kev: { new_in_period: 1, your_open_findings: 1 },
        matches: { verified: 2, total: 5 },
        engine: { correlation_last_run_at: null },
    };
    const lines = keyRecommendations(r);
    assert.equal(lines.length, 5);
    assert.match(lines[0], /critical relevance/);
    assert.match(lines[1], /high relevance/);
    assert.match(lines[2], /Known Exploited/);
    assert.match(lines[3], /verified association/);
    assert.match(lines[4], /correlation engine/);
});
