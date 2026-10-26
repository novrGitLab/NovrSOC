// services/complianceMapping.ts — a deterministic severity→control rules table, not an audit.
// Covers the pre-existing ISO/PCI/NDPA/CBN behaviour (locking it in, since this module had no
// test coverage before R3.3A) and the frameworks added for R3.3A Stage 5 (NIST CSF, GDPR, NCC).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mapCVEToCompliance, getComplianceImpact } from '../complianceMapping';

test('low, unknown and medium severity map to nothing — never a manufactured impact', () => {
    assert.deepEqual(mapCVEToCompliance({ severity: 'low' }), []);
    assert.deepEqual(mapCVEToCompliance({ severity: 'medium' }), []);
    assert.deepEqual(mapCVEToCompliance({}), []); // no severity, no cvss → unknown
});

test('CVSS fallback bands match FIRST\'s v3 bands when severity text is absent', () => {
    assert.equal(mapCVEToCompliance({ cvss: 9.8 }).length > 0, true, 'cvss 9.8 is critical');
    assert.equal(mapCVEToCompliance({ cvss: 7.0 }).length > 0, true, 'cvss 7.0 is high');
    assert.deepEqual(mapCVEToCompliance({ cvss: 3.9 }), [], 'cvss 3.9 is low');
});

test('high severity maps to ISO 27001, PCI-DSS, NDPA, NIST CSF, GDPR and NCC — not CBN', () => {
    const impacts = mapCVEToCompliance({ severity: 'high' });
    const frameworks = impacts.map((i) => i.framework);
    assert.deepEqual(new Set(frameworks), new Set(['ISO 27001', 'PCI-DSS', 'NDPA', 'NIST CSF', 'GDPR', 'NCC']));
    assert.equal(frameworks.includes('CBN'), false, 'CBN is critical-only');
});

test('critical severity adds CBN on top of the six high-severity frameworks', () => {
    const impacts = mapCVEToCompliance({ severity: 'critical' });
    const frameworks = impacts.map((i) => i.framework);
    assert.deepEqual(new Set(frameworks), new Set(['ISO 27001', 'PCI-DSS', 'NDPA', 'NIST CSF', 'GDPR', 'NCC', 'CBN']));
});

test('NIST CSF is PR.PS-02 (patching), never ID.RA-1 — a recorded finding proves identification worked', () => {
    const impacts = mapCVEToCompliance({ severity: 'critical' });
    const nist = impacts.filter((i) => i.framework === 'NIST CSF');
    assert.equal(nist.length, 1);
    assert.match(nist[0].control, /PR\.PS-02/);
    assert.equal(nist[0].status, 'FAIL');
    assert.doesNotMatch(nist[0].control, /ID\.RA-1/);
});

test('GDPR cites Art. 32(1)(b) and is AT RISK, not FAIL — a vulnerability is not itself a legal breach finding', () => {
    const impacts = mapCVEToCompliance({ severity: 'high' });
    const gdpr = impacts.find((i) => i.framework === 'GDPR');
    assert.ok(gdpr);
    assert.match(gdpr!.control, /Art\. 32\(1\)\(b\)/);
    assert.equal(gdpr!.status, 'AT RISK');
});

test('NCC names the regulator and domain precisely without inventing a specific clause number', () => {
    const impacts = mapCVEToCompliance({ severity: 'high' });
    const ncc = impacts.find((i) => i.framework === 'NCC');
    assert.ok(ncc);
    assert.match(ncc!.control, /Nigerian Communications Sector/);
    assert.equal(ncc!.status, 'AT RISK');
});

test('an internet-facing crypto package adds the extra PCI-DSS 4.2.1 control, independent of the others', () => {
    const impacts = mapCVEToCompliance({ severity: 'high', package: 'openssl' });
    assert.equal(impacts.filter((i) => i.framework === 'PCI-DSS').length, 2);
    assert.ok(impacts.some((i) => /4\.2\.1/.test(i.control)));
});

test('getComplianceImpact dedupes repeated controls and counts unmapped low-severity vulnerabilities', () => {
    const summary = getComplianceImpact([
        { severity: 'critical' }, { severity: 'critical' }, // same controls twice — dedupe, not double-count
        { severity: 'low' }, // unmapped
    ]);
    assert.equal(summary.unmapped, 1);
    assert.equal(summary.frameworks['ISO 27001'].controls.length, 1);
    assert.equal(summary.frameworks['ISO 27001'].failing, 2, 'the FAIL tally still counts every vulnerability');
});

test('overall_impact bands by distinct failing controls, not by vulnerability count', () => {
    assert.equal(getComplianceImpact([]).overall_impact, 'No impact');
    // FAIL-status controls are ISO 27001 A.8.8, PCI-DSS 6.3.3 and NIST CSF PR.PS-02 (NDPA, GDPR
    // and NCC are AT RISK, not FAIL) = 3 distinct failing controls for any high-severity vuln.
    assert.equal(getComplianceImpact([{ severity: 'high' }]).overall_impact, 'Medium impact');
    assert.equal(getComplianceImpact([{ severity: 'critical' }]).overall_impact, 'Medium impact'); // + CBN = 4 failing, still under 6
});

test('the summary never claims to be an audit result', () => {
    assert.match(getComplianceImpact([{ severity: 'critical' }]).note, /[Nn]ot an audit result/);
});
