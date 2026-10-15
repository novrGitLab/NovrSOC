// Phase P9 scope and evidence model: passive-only scope entries and AS numbers, the passive_osint
// job kind (never given to the scanner worker), expiry, the evidence-class priority cap, and passive
// CVE claims that dedupe, never reopen and are upgraded when a scanner confirms them. Fake
// PostgREST only; nothing on the network is touched. Names are reserved test domains/ranges.
process.env.JWT_SECRET = 'cnii-scope-test-secret';
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'VMS_WORKER_TOKEN', 'WAZUH_HOST', 'WAZUH_INDEXER_HOST']) delete process.env[k];

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { requireAuth } from '../../middleware/auth';
import { startFakePostgrest, type FakePostgrest, type Row } from './fakePostgrest';
import vmsRouter, { activityOf } from '../vms';
import vmsWorkerRouter from '../vmsWorker';
import { riskScore } from '../../lib/riskScore';
import { inScope, validateScopeValue, type ScopeEntry } from '../../lib/vmsScope';
import { ingestPassiveClaims, ingestFindings } from '../../services/vmsFindings';

const A = 'org-a';
const WT = 'w'.repeat(40);
let db: FakePostgrest;
let server: Server;
let base = '';
const realLog = { log: console.log, warn: console.warn, error: console.error };
const tok = (role: string, org = A) => jwt.sign({ sub: randomUUID(), email: `${role}@${org}.test`, role, org_id: org }, process.env.JWT_SECRET!);
const MGR = tok('soc_manager');
const AN = tok('analyst');
async function http(method: string, path: string, bearer?: string, body?: unknown) {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (bearer) headers.Authorization = `Bearer ${bearer}`;
    const r = await fetch(`${base}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    return { status: r.status, data: await r.json().catch(() => null) };
}
const future = (d = 30) => new Date(Date.now() + d * 86_400_000).toISOString();
const scopeBody = (b: Record<string, unknown>) => ({ authorization_reference: 'LOA-2026-017', expires_at: future(), ...b });

before(async () => {
    db = await startFakePostgrest(
        { vms_scopes: [], vms_scan_jobs: [], vms_assets: [], vms_findings: [], vms_finding_evidence: [], vms_finding_events: [], cve_intel: [] },
        {},
        {
            vms_scopes: { status: 'active', allow_discovery: true, approved_at: new Date().toISOString() },
            vms_scan_jobs: { status: 'queued', attempts: 0, cancel_requested: false, progress: {}, purpose: 'assessment', requested_at: new Date().toISOString() },
            vms_assets: { status: 'active', exposure: 'internet', criticality: 'medium', confidence: 'confirmed', hostnames: [], ips: [], dns: {}, discovery_sources: [] },
            vms_findings: { status: 'open', evidence_class: 'scanner_check', detected_by: [], cve_ids: [], references_urls: [], risk_factors: {}, due_manual: false },
            cve_intel: { kev: false },
        },
        {
            vms_claim_job: (args, tables) => {
                const j = tables.vms_scan_jobs.find((x) => x.status === 'queued' && (args.p_kinds as string[]).includes(String(x.kind)));
                if (!j) return [];
                Object.assign(j, { status: 'running', worker_id: args.p_worker, started_at: new Date().toISOString(), heartbeat_at: new Date().toISOString(), attempts: 1 });
                return [j];
            },
        },
    );
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    process.env.VMS_WORKER_TOKEN = WT;
    const app = express();
    app.use('/api/vms/worker', express.json(), vmsWorkerRouter);
    app.use(express.json());
    app.use('/api/vms', requireAuth, vmsRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});
after(async () => { Object.assign(console, realLog); server.close(); await db.close(); });
beforeEach(() => { for (const t of Object.keys(db.tables)) db.tables[t].length = 0; });

test('scope rules: passive is allowed by any active entry; discovery needs allow_discovery; AS numbers cover nothing', () => {
    const e = (b: Partial<ScopeEntry>): ScopeEntry => ({ id: randomUUID(), org_id: A, kind: 'domain', value: 'cnii.test', include_subdomains: true, allow_port_scan: false, allow_vuln_scan: false, status: 'active', expires_at: future(), ...b });
    const passiveOnly = [e({ allow_discovery: false })];
    assert.equal(inScope('www.cnii.test', passiveOnly, 'passive'), true);
    for (const a of ['discovery', 'ports', 'vuln'] as const) assert.equal(inScope('www.cnii.test', passiveOnly, a), false, a);
    // Rows written before P9 have no allow_discovery and keep their meaning.
    assert.equal(inScope('www.cnii.test', [e({})], 'discovery'), true);
    assert.equal(inScope('www.cnii.test', [e({ expires_at: new Date(Date.now() - 1000).toISOString() })], 'passive'), false, 'expired');
    assert.equal(inScope('192.0.2.1', [e({ kind: 'asn', value: 'AS64500', allow_discovery: false })], 'passive'), false);
    assert.deepEqual(validateScopeValue('asn', 'as64500'), { ok: true, value: 'AS64500' });
    assert.equal(validateScopeValue('asn', 'AS0').ok, false);
    assert.equal(activityOf('passive_osint'), 'passive');
});

test('scope API: AS numbers and passive-only entries never authorise touching a target', async () => {
    assert.equal((await http('POST', '/api/vms/scopes', MGR, scopeBody({ kind: 'asn', value: 'AS64500', allow_port_scan: true }))).status, 400);
    const asn = await http('POST', '/api/vms/scopes', MGR, scopeBody({ kind: 'asn', value: '64500' }));
    assert.equal(asn.status, 201);
    assert.equal(asn.data.scope.value, 'AS64500');
    assert.equal(asn.data.scope.allow_discovery, false);
    const dom = await http('POST', '/api/vms/scopes', MGR, scopeBody({ kind: 'domain', value: 'cnii.test', allow_discovery: false }));
    assert.equal(dom.data.scope.allow_discovery, false);
    assert.equal((await http('POST', '/api/vms/scopes', AN, scopeBody({ kind: 'domain', value: 'other.test' }))).status, 403, 'analysts cannot approve scope');

    assert.equal((await http('POST', '/api/vms/scans', AN, { scope_id: dom.data.scope.id, kind: 'discovery' })).status, 403);
    assert.equal((await http('POST', '/api/vms/scans', AN, { scope_id: dom.data.scope.id, kind: 'ports' })).status, 403);
    assert.equal((await http('POST', '/api/vms/scans', AN, { scope_id: asn.data.scope.id, kind: 'discovery' })).status, 403);
    const p1 = await http('POST', '/api/vms/scans', AN, { scope_id: dom.data.scope.id, kind: 'passive_osint', targets: ['www.cnii.test'] });
    assert.equal(p1.status, 201);
    assert.equal((await http('POST', '/api/vms/scans', AN, { scope_id: dom.data.scope.id, kind: 'passive_osint', targets: ['cnii.example'] })).status, 400, 'outside the entry');
    const p2 = await http('POST', '/api/vms/scans', AN, { scope_id: asn.data.scope.id, kind: 'passive_osint' });
    assert.deepEqual(p2.data.scan.targets, ['AS64500']);

    // The scanner worker never receives passive jobs, and learns that these entries are passive-only.
    const c = await http('POST', '/api/vms/worker/claim', WT, { worker_id: 'w1', kinds: ['discovery', 'ports', 'passive_osint'] });
    assert.equal(c.data.job, null);
    assert.equal(db.tables.vms_scan_jobs.filter((j) => j.status === 'queued').length, 2);
});

test('expired scope: no new passive job', async () => {
    const s = await http('POST', '/api/vms/scopes', MGR, scopeBody({ kind: 'domain', value: 'cnii.test', allow_discovery: false }));
    (db.tables.vms_scopes[0] as Row).expires_at = new Date(Date.now() - 1000).toISOString();
    const r = await http('POST', '/api/vms/scans', AN, { scope_id: s.data.scope.id, kind: 'passive_osint' });
    assert.equal(r.status, 400);
    assert.match(r.data.error, /not active/);
});

test('risk: unconfirmed evidence is never above P3; the factors say why', () => {
    const base = { scanner_severity: 'critical' as const, cvss: 9.8, kev: true, epss: 0.9, exposure: 'internet' as const, criticality: 'critical' as const };
    assert.equal(riskScore(base).priority, 'P1');
    for (const ev of ['version_match', 'intelligence'] as const) {
        const r = riskScore({ ...base, evidence_class: ev });
        assert.equal(r.priority, 'P3');
        assert.equal(r.score, riskScore(base).score, 'the score itself is unchanged');
        assert.deepEqual(r.factors.evidence, { basis: ev, confirmed: false, capped_from: 'P1' });
        assert.match(String(r.factors.rule), /capped at P3 until a scanner confirms it/);
    }
    assert.equal(riskScore({ ...base, evidence_class: 'package_inventory' }).priority, 'P1');
});

test('passive claims: one version_match finding per CVE, every sighting kept, upgraded by a scanner, never reopened', async () => {
    const asset = (db.tables.vms_assets.push({ id: randomUUID(), org_id: A, asset_type: 'host', value: 'portal.cnii.test', exposure: 'internet', criticality: 'critical' }), db.tables.vms_assets[0]);
    db.tables.cve_intel.push({ cve_id: 'CVE-2024-3400', cvss_score: 10, kev: true, kev_checked_at: new Date().toISOString(), nvd_fetched_at: new Date().toISOString(), epss_fetched_at: new Date().toISOString() });
    const ref = { id: String(asset.id), type: 'host', value: 'portal.cnii.test' };
    const claim = { source: 'spiderfoot:sfp_shodan', cve: 'cve-2024-3400', cvss: 10, severity: 'critical' as const };

    const r1 = await ingestPassiveClaims(A, null, ref, [claim, { ...claim, cve: 'not-a-cve' }]);
    assert.deepEqual(r1, { new_findings: 1, sightings: 0, rejected_invalid: 1 });
    const f = db.tables.vms_findings[0];
    assert.equal(f.evidence_class, 'version_match');
    assert.equal(f.source_class, 'passive_intel');
    assert.equal(f.priority, 'P3', 'KEV on an internet-facing critical asset, but unconfirmed');
    assert.match(String(f.title), /not confirmed/);

    const r2 = await ingestPassiveClaims(A, null, ref, [claim]);
    assert.deepEqual(r2, { new_findings: 0, sightings: 1, rejected_invalid: 0 });
    assert.equal(db.tables.vms_findings.length, 1);
    assert.equal(db.tables.vms_finding_evidence.length, 2);

    // A Nuclei check on the same CVE and asset confirms it: scanner_check, priority recomputed.
    const scope: ScopeEntry = { id: randomUUID(), org_id: A, kind: 'domain', value: 'cnii.test', include_subdomains: true, allow_port_scan: true, allow_vuln_scan: true, status: 'active', expires_at: future() };
    await ingestFindings({ id: randomUUID(), org_id: A }, [{ type: 'finding', host: 'portal.cnii.test', port: null, scanner: 'nuclei', rule_id: 'CVE-2024-3400', title: 'PAN-OS GlobalProtect command injection', severity: 'critical', cve_ids: ['CVE-2024-3400'] }], [scope]);
    assert.equal(db.tables.vms_findings.length, 1);
    assert.equal(f.evidence_class, 'scanner_check');
    assert.equal(f.priority, 'P1');
    assert.ok(db.tables.vms_finding_events.some((e) => e.action === 'evidence' && e.to_value === 'scanner_check'));

    // Later passive sightings do not downgrade it, move its last_seen, or reopen it once verified.
    const seen = f.last_seen;
    f.status = 'verified';
    await ingestPassiveClaims(A, null, ref, [claim]);
    assert.equal(f.evidence_class, 'scanner_check');
    assert.equal(f.last_seen, seen);
    assert.equal(f.status, 'verified');
    assert.equal(db.tables.vms_finding_evidence.length, 4, 'the sighting is still recorded');
});
