// Unit tests for src/lib/vmsReportInsights.ts's keyRecommendations — the VMS Executive report's
// "key recommendations" (R3.3A Stage 1). Every assertion checks the figure named in the sentence
// is the exact figure passed in; none of this is reachable only by rendering the page.
//
//   npm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import ts from 'typescript';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const cacheDir = join(root, 'node_modules', '.cache', 'vms-report-insights-test');
mkdirSync(cacheDir, { recursive: true });

const src = readFileSync(join(root, 'src', 'lib', 'vmsReportInsights.ts'), 'utf8');
const out = ts.transpileModule(src, { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2020 }, fileName: join(root, 'src', 'lib', 'vmsReportInsights.ts') });
const file = join(cacheDir, 'vmsReportInsights.mjs');
writeFileSync(file, out.outputText);
const { keyRecommendations } = await import(pathToFileURL(file).href);

const clean = { open_now: { total: 0, by_severity: {}, overdue: 0, known_exploited: 0, affected_assets: 0 }, compliance: { overall_impact: 'No impact', frameworks: {} } };

test('nothing open: one honest "nothing to flag" line, never an empty list', () => {
    assert.deepEqual(keyRecommendations(clean), ['No critical findings, overdue items or known-exploited vulnerabilities are currently open.']);
});

test('known-exploited findings are named first and use the real count', () => {
    const r = { ...clean, open_now: { ...clean.open_now, known_exploited: 3 } };
    const lines = keyRecommendations(r);
    assert.match(lines[0], /^3 open findings are on CISA's Known Exploited Vulnerabilities list/);
});

test('singular wording for exactly one', () => {
    const r = { ...clean, open_now: { ...clean.open_now, known_exploited: 1, overdue: 1 } };
    const lines = keyRecommendations(r);
    assert.match(lines[0], /^1 open finding is on CISA/);
    assert.match(lines[1], /^1 open finding is past its remediation deadline\.$/);
});

test('critical severity cites both the count and the affected-asset count', () => {
    const r = { ...clean, open_now: { ...clean.open_now, by_severity: { critical: 5 }, affected_assets: 3 } };
    const lines = keyRecommendations(r);
    assert.match(lines[0], /^5 open critical-severity findings across 3 affected assets\.$/);
});

test('awaiting verification only appears when closure data is available and the count is a real number', () => {
    const notAvailable = { ...clean, closure: { available: false, note: 'unreadable' } };
    assert.deepEqual(keyRecommendations(notAvailable), keyRecommendations(clean));
    const zero = { ...clean, closure: { available: true, awaiting_verification_now: 0 } };
    assert.deepEqual(keyRecommendations(zero), keyRecommendations(clean));
    const some = { ...clean, closure: { available: true, awaiting_verification_now: 4 } };
    assert.match(keyRecommendations(some)[0], /^4 findings are marked fixed and awaiting verification/);
});

test('a non-"No impact" compliance result is surfaced with an explicit "not a compliance determination" caveat', () => {
    const r = { ...clean, compliance: { overall_impact: 'Medium impact', frameworks: { 'ISO 27001': { failing: 1, at_risk: 0 }, GDPR: { failing: 0, at_risk: 1 } } } };
    const lines = keyRecommendations(r);
    assert.match(lines[0], /"Medium impact" compliance impact across 2 frameworks/);
    assert.match(lines[0], /not a compliance determination/);
});

test('order: known-exploited, then overdue, then critical, then unverified, then compliance', () => {
    const r = {
        open_now: { total: 10, by_severity: { critical: 2 }, overdue: 1, known_exploited: 1, affected_assets: 2 },
        closure: { available: true, awaiting_verification_now: 1 },
        compliance: { overall_impact: 'Low impact', frameworks: { CBN: { failing: 1, at_risk: 0 } } },
    };
    const lines = keyRecommendations(r);
    assert.equal(lines.length, 5);
    assert.match(lines[0], /Known Exploited/);
    assert.match(lines[1], /remediation deadline/);
    assert.match(lines[2], /critical-severity/);
    assert.match(lines[3], /awaiting verification/);
    assert.match(lines[4], /compliance impact/);
});
