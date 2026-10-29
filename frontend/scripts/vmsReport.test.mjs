// Unit tests for the Vulnerability Management report's pure helpers (brief: "Professional
// Vulnerability Reporting UI") — risk aggregation, severity counts, CVSS formatting, and the
// client-side compliance mapping port. No DOM, no fetch, no React.
//
//   npm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import ts from 'typescript';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const cacheDir = join(root, 'node_modules', '.cache', 'vms-report-test');
mkdirSync(cacheDir, { recursive: true });

function transpile(relPath, outName) {
    const src = readFileSync(join(root, ...relPath), 'utf8');
    const out = ts.transpileModule(src, { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2020 }, fileName: join(root, ...relPath) });
    const file = join(cacheDir, outName);
    writeFileSync(file, out.outputText);
    return pathToFileURL(file).href;
}

const { severityCounts, cvssDistribution, riskBand, meanRiskScore, formatCvss, reportId, affectedAssetCount, remediationStatusCounts } =
    await import(transpile(['src', 'components', 'features', 'vms', 'report', 'reportHelpers.ts'], 'reportHelpers.mjs'));
const { mapCVEToCompliance, REPORT_FRAMEWORKS } = await import(transpile(['src', 'lib', 'complianceMapping.ts'], 'complianceMapping.mjs'));

// --- severityCounts ---------------------------------------------------------------------------

test('severityCounts tallies each bucket and ignores unknown/null severities', () => {
    const counts = severityCounts([
        { scanner_severity: 'critical' }, { scanner_severity: 'critical' }, { scanner_severity: 'high' },
        { scanner_severity: 'medium' }, { scanner_severity: 'low' }, { scanner_severity: 'info' },
        { scanner_severity: null }, { scanner_severity: 'not-a-real-severity' },
    ]);
    assert.deepEqual(counts, { critical: 2, high: 1, medium: 1, low: 1, info: 1 });
});

test('severityCounts on an empty list is all zeros, not an error', () => {
    assert.deepEqual(severityCounts([]), { critical: 0, high: 0, medium: 0, low: 0, info: 0 });
});

// --- cvssDistribution --------------------------------------------------------------------------

test('cvssDistribution rounds into whole-number bands and separates missing CVSS from band 0', () => {
    const dist = cvssDistribution([
        { scanner_cvss: 9.8 }, { scanner_cvss: 9.4 }, { scanner_cvss: 0 }, { scanner_cvss: null }, { scanner_cvss: null },
    ]);
    assert.equal(dist.noCvss, 2);
    assert.equal(dist.bands.find((b) => b.score === 10).count, 1); // 9.8 rounds to 10
    assert.equal(dist.bands.find((b) => b.score === 9).count, 1);  // 9.4 rounds to 9
    assert.equal(dist.bands.find((b) => b.score === 0).count, 1);
    assert.equal(dist.bands.reduce((a, b) => a + b.count, 0), 3);
});

test('cvssDistribution clamps out-of-range scores into 0-10', () => {
    const dist = cvssDistribution([{ scanner_cvss: 10.0 }, { scanner_cvss: -1 }]);
    assert.equal(dist.bands.find((b) => b.score === 10).count, 1);
    assert.equal(dist.bands.find((b) => b.score === 0).count, 1);
});

// --- riskBand / meanRiskScore ------------------------------------------------------------------

test('riskBand mirrors lib/riskScore.ts\'s own P1/P2/P3 thresholds (80/60/35)', () => {
    assert.equal(riskBand(null), 'Not available');
    assert.equal(riskBand(0), 'Minimal');
    assert.equal(riskBand(34.9), 'Low');
    assert.equal(riskBand(35), 'Medium');
    assert.equal(riskBand(59.9), 'Medium');
    assert.equal(riskBand(60), 'High');
    assert.equal(riskBand(79.9), 'High');
    assert.equal(riskBand(80), 'Critical');
    assert.equal(riskBand(100), 'Critical');
});

test('meanRiskScore returns null (never 0) when no finding has a computed score', () => {
    assert.equal(meanRiskScore([{ risk_score: null }, { risk_score: null }]), null);
    assert.equal(meanRiskScore([]), null);
});

test('meanRiskScore averages only the scored findings and rounds to one decimal', () => {
    assert.equal(meanRiskScore([{ risk_score: 80 }, { risk_score: null }, { risk_score: 50 }]), 65);
    assert.equal(meanRiskScore([{ risk_score: 10 }, { risk_score: 11 }, { risk_score: 11 }]), 10.7);
});

// --- formatCvss ----------------------------------------------------------------------------------

test('formatCvss never asserts a version or vector the data does not carry', () => {
    assert.equal(formatCvss(null, null, null), 'Not available');
    assert.equal(formatCvss(9.8, null, null), 'CVSS: 9.8 — version not reported by the scanner');
    assert.equal(formatCvss(9.8, '3.1', null), 'CVSS v3.1: 9.8');
    assert.equal(formatCvss(9.8, '3.1', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 'CVSS v3.1: 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)');
    assert.equal(formatCvss(8.2, '4.0', 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'), 'CVSS v4.0: 8.2 (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N)');
});

// --- reportId --------------------------------------------------------------------------------

test('reportId is deterministic for the same org/days/minute and distinguishes periods', () => {
    const at = new Date('2026-03-05T14:32:00Z');
    const id = reportId('Acme Corp', 30, at);
    assert.match(id, /^VMR-ACMECORP-\d{12}-30D$/);
    assert.equal(reportId('Acme Corp', 30, at), id);
    assert.notEqual(reportId('Acme Corp', 7, at), id);
});

test('reportId falls back to ORG when the slug has no usable characters', () => {
    assert.match(reportId('', 30, new Date('2026-03-05T14:32:00Z')), /^VMR-ORG-/);
    assert.match(reportId('***', 30, new Date('2026-03-05T14:32:00Z')), /^VMR-ORG-/);
});

// --- affectedAssetCount -----------------------------------------------------------------------

test('affectedAssetCount counts distinct assets, not findings', () => {
    assert.equal(affectedAssetCount([{ asset_value: '10.0.0.1' }, { asset_value: '10.0.0.1' }, { asset_value: '10.0.0.2' }]), 2);
    assert.equal(affectedAssetCount([]), 0);
});

// --- remediationStatusCounts ------------------------------------------------------------------

test('remediationStatusCounts buckets by status and flags only genuinely-overdue open work', () => {
    const now = Date.parse('2026-03-05T00:00:00Z');
    const counts = remediationStatusCounts([
        { status: 'open', due_at: '2026-03-01T00:00:00Z' },       // overdue
        { status: 'in_progress', due_at: '2026-04-01T00:00:00Z' }, // not yet due
        { status: 'fixed_pending_verification', due_at: null },
        { status: 'verified', due_at: '2026-03-01T00:00:00Z' },    // past due but verified: not overdue
        { status: 'risk_accepted', due_at: '2026-03-01T00:00:00Z' }, // past due but accepted: not overdue
        { status: 'reopened', due_at: null },
    ], now);
    assert.equal(counts.open, 2); // 'open' + 'reopened'
    assert.equal(counts.in_progress, 1);
    assert.equal(counts.fixed_pending_verification, 1);
    assert.equal(counts.verified, 1);
    assert.equal(counts.risk_accepted, 1);
    assert.equal(counts.overdue, 1);
});

// --- mapCVEToCompliance (frontend port) ---------------------------------------------------------

test('low/medium/unknown severity maps to nothing — never a manufactured impact', () => {
    assert.deepEqual(mapCVEToCompliance({ severity: 'low' }), []);
    assert.deepEqual(mapCVEToCompliance({ severity: 'medium' }), []);
    assert.deepEqual(mapCVEToCompliance({ severity: null, cvss: null }), []);
});

test('high severity maps to all seven high-severity frameworks, including CIS Controls', () => {
    const impacts = mapCVEToCompliance({ severity: 'high' });
    assert.deepEqual(new Set(impacts.map((i) => i.framework)), new Set(['ISO 27001', 'PCI-DSS', 'NDPA', 'NIST CSF', 'GDPR', 'NCC', 'CIS Controls']));
    assert.ok(!impacts.some((i) => i.framework === 'CBN'));
});

test('critical severity additionally adds CBN', () => {
    const impacts = mapCVEToCompliance({ severity: 'critical' });
    assert.ok(impacts.some((i) => i.framework === 'CBN' && i.status === 'FAIL'));
});

test('CIS Controls cites Safeguard 7.7 as FAIL and 7.1 as AT RISK, never the other way round', () => {
    const impacts = mapCVEToCompliance({ severity: 'high' }).filter((i) => i.framework === 'CIS Controls');
    const byControl = Object.fromEntries(impacts.map((i) => [i.control, i.status]));
    assert.equal(byControl['7.7 — Remediate Detected Vulnerabilities'], 'FAIL');
    assert.equal(byControl['7.1 — Establish and Maintain a Vulnerability Management Process'], 'AT RISK');
});

test('a crypto-related package adds the PCI-DSS Req 4.2.1 at-risk note', () => {
    const impacts = mapCVEToCompliance({ severity: 'high', package: 'openssl' });
    assert.ok(impacts.some((i) => i.framework === 'PCI-DSS' && i.control.startsWith('Req 4.2.1')));
});

test('REPORT_FRAMEWORKS scopes the report\'s Compliance Impact section to exactly four frameworks', () => {
    assert.deepEqual([...REPORT_FRAMEWORKS], ['ISO 27001', 'NIST CSF', 'PCI-DSS', 'CIS Controls']);
});
