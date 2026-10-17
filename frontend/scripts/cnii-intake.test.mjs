// Unit tests for src/lib/cnii-intake.ts: input checks, bulk splitting, and that every status the CNII
// pages show is derived from stored fields — a suggestion is never shown as a confirmation, and scan
// authorisation is never implied by CNII confirmation.
//
//   npm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import ts from 'typescript';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const cacheDir = join(root, 'node_modules', '.cache', 'cnii-intake-test');
mkdirSync(cacheDir, { recursive: true });
const src = join(root, 'src', 'lib', 'cnii-intake.ts');
const out = ts.transpileModule(readFileSync(src, 'utf8'), { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2020 }, fileName: src });
writeFileSync(join(cacheDir, 'cnii-intake.mjs'), out.outputText);
const m = await import(pathToFileURL(join(cacheDir, 'cnii-intake.mjs')).href);

const base = { id: 's', value: 'portal.grid.test', kind: 'domain', status: 'candidate', basis: null, reason: '', org_id: null, sector_id: null, subfield: null, ips: [],
    resolution: { resolved_at: '2026-10-17T00:00:00Z', errors: [], truncated: false, addresses: [] }, evidence: [], suggestion: null,
    decided_by: null, decided_at: null, submitted_by: 'a', submitted_at: '2026-10-17T00:00:00Z', updated_at: '2026-10-17T00:00:00Z', authorisation: null };

test('input: one domain or IP per entry; bulk split matches the backend format', () => {
    for (const ok of ['portal.grid.test', '196.1.2.3', '2001:db8::1', 'Example.GOV.ng.']) assert.equal(m.intakeInputError(ok), null, ok);
    for (const bad of ['https://grid.test', 'grid.test/x', '*.grid.test', '196.1.2.0/24', '', 'localhost']) assert.ok(m.intakeInputError(bad), bad);
    assert.deepEqual(m.splitEntries('a.test, b.test;c.test\n196.1.2.3  '), ['a.test', 'b.test', 'c.test', '196.1.2.3']);
});

test('statuses come from stored fields: review, sector and authorisation are kept apart', () => {
    assert.equal(m.CNII_STATUS.candidate.label, 'Requires review');
    assert.deepEqual(m.sectorContext(base), { text: 'Unknown / Requires review', kind: 'unknown' });
    assert.equal(m.sectorContext({ ...base, suggestion: { sectorId: 'power', subfield: '', note: '' } }).kind, 'suggested');
    assert.match(m.sectorContext({ ...base, suggestion: { sectorId: 'power', subfield: '', note: '' } }).text, /\(suggested\)/);
    assert.equal(m.sectorContext({ ...base, basis: 'manual_registration', sector_id: 'power' }).kind, 'claimed');
    assert.equal(m.sectorContext({ ...base, status: 'confirmed', sector_id: 'power', basis: 'analyst_confirmed' }).kind, 'confirmed');
    // Confirmation is not permission to scan.
    assert.equal(m.authState({ ...base, status: 'candidate' }).key, 'not_applicable');
    assert.equal(m.authState({ ...base, status: 'confirmed', basis: 'analyst_confirmed' }).key, 'awaiting');
    assert.equal(m.authState({ ...base, status: 'confirmed', basis: 'authorised_scope' }).key, 'vms_scope');
    const a = { scope_ids: [], targets: [], approved_addresses: [], reference: 'r', evidence: 'e', activities: { discovery: true, ports: true, vuln: false }, approved_by: 'm', approved_at: '2026-10-01T00:00:00Z', expires_at: '2026-11-01T00:00:00Z', revoked_by: null, revoked_at: null };
    const now = Date.parse('2026-10-17T00:00:00Z');
    assert.equal(m.authState({ ...base, status: 'confirmed', authorisation: a }, now).key, 'authorised');
    assert.equal(m.authState({ ...base, status: 'confirmed', authorisation: a }, Date.parse('2026-11-02T00:00:00Z')).key, 'expired');
    assert.equal(m.authState({ ...base, status: 'confirmed', authorisation: { ...a, revoked_at: '2026-10-10T00:00:00Z', revoked_by: 'm' } }, now).key, 'revoked');
    assert.equal(m.scanTypes(a), 'Discovery · Port scan');
});

test('network context is the operator, gaps are named, evidence is grouped by kind', () => {
    assert.equal(m.networkContext(base), 'No registry data');
    const addr = (ip, b = {}) => ({ ip, ptr: [], asn: null, holder: null, public: true, reserved: false, covered_by: [], ...b });
    const s = { ...base, resolution: { ...base.resolution, addresses: [addr('196.1.2.3', { asn: '37282', holder: 'Example Net', covered_by: [{ org_id: 'org-c', scope: 'ip 196.1.2.3' }] }), addr('196.1.2.4', { covered_by: [{ org_id: 'org-b', scope: 'ip' }] })] } };
    assert.equal(m.networkContext(s), 'AS37282 Example Net');
    const gaps = m.gapsOf(s);
    assert.ok(gaps.some((g) => /different organisations/.test(g)));
    assert.ok(gaps.includes('Operating organisation unknown'));
    assert.ok(m.gapsOf({ ...base, resolution: { ...base.resolution, errors: ['A lookup: ETIMEOUT'] } }).some((g) => /DNS: A lookup/.test(g)));
    const g = m.evidenceGroups({ ...base, evidence: [{ kind: 'registry', detail: '', source: 'ripestat', strength: 'context' }, { kind: 'authorised_scope', detail: '', source: 'vms_scopes', strength: 'trusted' }, { kind: 'manual_registration', detail: '', source: 'analyst', strength: 'supporting' }] });
    assert.deepEqual([g.facts.length, g.records.length, g.human.length], [1, 1, 1]);
});

test('authorisation expiry: a date within 1..90 days', () => {
    const now = Date.parse('2026-10-17T12:00:00Z');
    assert.equal(m.daysUntil('2026-10-18', 90, now), 2);
    assert.equal(m.daysUntil('2026-10-17', 90, now), 1);
    assert.equal(m.daysUntil('2027-02-01', 90, now), null, 'beyond 90 days');
    assert.equal(m.daysUntil('2026-10-10', 90, now), null, 'in the past');
    assert.equal(m.daysUntil('nonsense', 90, now), null);
});
