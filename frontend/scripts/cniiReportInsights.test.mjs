// Unit tests for src/lib/cniiReportInsights.ts — the CNII Watch Executive report's "key
// recommendations" (R3.3B Stage 6). Covers: the monitoring-state line always comes first since it
// changes how much to trust everything else, a verified TI association is never confused with a
// contextual-only one, and a fully clean organisation gets one honest line, never an empty list.
//
//   npm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import ts from 'typescript';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const cacheDir = join(root, 'node_modules', '.cache', 'cnii-report-insights-test');
mkdirSync(cacheDir, { recursive: true });

const src = readFileSync(join(root, 'src', 'lib', 'cniiReportInsights.ts'), 'utf8');
const out = ts.transpileModule(src, { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2020 }, fileName: join(root, 'src', 'lib', 'cniiReportInsights.ts') });
const file = join(cacheDir, 'cniiReportInsights.mjs');
writeFileSync(file, out.outputText);
const { keyRecommendations } = await import(pathToFileURL(file).href);

const clean = { coverage_state: 'connected_fresh', critical_high: 0, kev_open: 0, assets_requiring_attention: 0, threat_intelligence: { total: 0, verified: 0, contextual: 0 }, remediation_open: 0, remediation_closed: 0 };

test('a fully clean, connected organisation gets one honest line, never an empty list', () => {
    assert.deepEqual(keyRecommendations(clean), ['No critical/high exposure, known-exploited vulnerabilities or verified threat intelligence associations are currently open, and monitoring is receiving telemetry.']);
});

test('connected_fresh adds no monitoring-gap line at all', () => {
    const r = { ...clean, critical_high: 1, assets_requiring_attention: 1 };
    assert.equal(keyRecommendations(r).some((l) => /monitoring|collection|scope/i.test(l)), false);
});

for (const [state, pattern] of [
    ['connected_stale', /stale/],
    ['configured_not_receiving', /no passive collection has ever run/],
    ['not_connected', /no active authorised scope/],
    ['unknown', /could not be determined/],
]) {
    test(`${state} is named for what it actually is, and comes first`, () => {
        const lines = keyRecommendations({ ...clean, coverage_state: state, critical_high: 1, assets_requiring_attention: 1 });
        assert.match(lines[0], pattern);
    });
}

test('a verified threat intelligence association is never confused with a contextual-only one', () => {
    const verified = keyRecommendations({ ...clean, threat_intelligence: { total: 2, verified: 2, contextual: 0 } });
    assert.match(verified[0], /2 verified threat intelligence associations/);
    const contextual = keyRecommendations({ ...clean, threat_intelligence: { total: 3, verified: 0, contextual: 3 } });
    assert.ok(!contextual.some((l) => /verified threat intelligence/.test(l)));
    assert.match(contextual[0], /3 contextual-only threat intelligence matches/);
});

test('KEV and critical/high exposure each cite their own real count', () => {
    const r = keyRecommendations({ ...clean, kev_open: 2, critical_high: 5, assets_requiring_attention: 3 });
    assert.match(r[0], /^2 open findings? on CISA's Known Exploited Vulnerabilities list\.$/);
    assert.match(r[1], /^5 open critical or high severity findings across 3 assets requiring attention\.$/);
});

test('remediation progress is flagged only below 50%, with the real numerator and denominator', () => {
    const low = keyRecommendations({ ...clean, remediation_open: 8, remediation_closed: 2 });
    assert.match(low[0], /Remediation progress is 20% \(2 of 10 findings closed\)/);
    const high = keyRecommendations({ ...clean, remediation_open: 2, remediation_closed: 8 });
    assert.ok(!high.some((l) => /Remediation progress/.test(l)));
});

test('ordering: monitoring state, then verified TI, then KEV, then critical/high, then remediation', () => {
    const r = keyRecommendations({
        coverage_state: 'connected_stale', critical_high: 1, kev_open: 1, assets_requiring_attention: 1,
        threat_intelligence: { total: 1, verified: 1, contextual: 0 }, remediation_open: 9, remediation_closed: 1,
    });
    assert.equal(r.length, 5);
    assert.match(r[0], /stale/);
    assert.match(r[1], /verified threat intelligence/);
    assert.match(r[2], /Known Exploited/);
    assert.match(r[3], /critical or high/);
    assert.match(r[4], /Remediation progress/);
});
