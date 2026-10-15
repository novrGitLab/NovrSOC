// Phase P9 passive collection: scope re-checks, what becomes an asset and what stays a related
// host, observations with source/confidence/sighting counts, unconfirmed CVE claims, personal data
// dropped, source failures reported, the runner's claim/heartbeat/cancel, and health checks that
// keep the passive runner apart from the scanner worker. Fake PostgREST and fake sources only:
// nothing on the network is touched, and no Wazuh setting exists in this process.
process.env.JWT_SECRET = 'cnii-passive-test-secret';
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'SPIDERFOOT_URL', 'OPENCTI_URL', 'OPENCTI_TOKEN', 'WAZUH_HOST', 'WAZUH_INDEXER_HOST', 'WAZUH_API_PASSWORD', 'CNII_PASSIVE_ENABLED']) delete process.env[k];

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'crypto';
import { startFakePostgrest, type FakePostgrest, type Row } from '../../routes/__tests__/fakePostgrest';
import { runPassiveJob, passiveOutcome, fromCrtsh, type PassiveDeps } from '../cniiPassive';
import { runOnePassiveJob } from '../../jobs/cniiPassiveJob';
import { plaintextTransport, cniiChecks, vmsChecks } from '../pipelineHealth';
import type { ScopeEntry } from '../../lib/vmsScope';
import type { SpiderFootResult } from '../../lib/spiderfoot';

const A = 'org-a';
let db: FakePostgrest;
const realLog = { log: console.log, warn: console.warn, error: console.error };
const future = (d = 30) => new Date(Date.now() + d * 86_400_000).toISOString();

before(async () => {
    db = await startFakePostgrest(
        { vms_scopes: [], vms_scan_jobs: [], vms_assets: [], vms_asset_events: [], vms_observations: [], vms_services: [], vms_findings: [], vms_finding_evidence: [], vms_finding_events: [], cve_intel: [], vms_scan_schedules: [], vms_wazuh_sync: [] },
        {},
        {
            vms_assets: { status: 'active', exposure: 'unknown', criticality: 'medium', confidence: 'confirmed', hostnames: [], ips: [], dns: {}, discovery_sources: [] },
            vms_findings: { status: 'open', evidence_class: 'scanner_check', detected_by: [], cve_ids: [], references_urls: [], risk_factors: {}, due_manual: false },
            vms_scan_jobs: { status: 'queued', attempts: 0, cancel_requested: false, progress: {}, requested_at: new Date().toISOString() },
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
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});
after(async () => { Object.assign(console, realLog); await db.close(); });
beforeEach(() => { for (const t of Object.keys(db.tables)) db.tables[t].length = 0; });

const scope = (b: Partial<ScopeEntry> = {}): ScopeEntry => {
    const s: ScopeEntry = { id: randomUUID(), org_id: A, kind: 'domain', value: 'cnii.test', include_subdomains: true, allow_discovery: false, allow_port_scan: false, allow_vuln_scan: false, status: 'active', expires_at: future(), ...b };
    db.tables.vms_scopes.push(s as unknown as Row);
    return s;
};
const sfResult = (over: Partial<SpiderFootResult> = {}): SpiderFootResult => ({
    scanId: 'S1', status: 'FINISHED', hostname: 'portal.cnii.test', owner: 'CNII Test Agency', org: 'CNII Test Agency', asn: 'AS64500', country: 'NG',
    domains: ['cnii.test'], subdomains: ['api.cnii.test', 'cdn.provider.test'], openPorts: [443, 8443],
    vulns: [{ cve: 'CVE-2023-44487', cvss: 7.5, severity: 'high' }], threatIntel: [],
    emails: ['person@cnii.test'], phones: ['+234 800 000 0000'], sslCerts: ['CN=portal.cnii.test'], warnings: [], raw: [], ...over,
});
const deps = (over: Partial<PassiveDeps> = {}): PassiveDeps => ({
    spiderfoot: async () => sfResult(),
    crtsh: async () => [
        { id: 1, name_value: 'cnii.test\nwww.cnii.test\n*.cnii.test', common_name: 'cnii.test', issuer_name: 'C=US, O=Test CA', serial_number: '0a1b', not_after: '2027-01-01' },
        { id: 2, name_value: 'mail.cnii.test\nphish-cnii.other.test', serial_number: '0c2d' },
    ],
    resolve: async () => ({ a: ['192.0.2.10'], aaaa: [], cname: [] }),
    asn: async () => ({ asn: 'AS64500', holder: 'CNII-TEST-AS', is_announced: true, authoritative_rir: 'afrinic', is_afrinic: true, top_country: 'NG', prefix_count: 2, prefixes: ['192.0.2.0/24', '198.51.100.0/24'] }),
    ...over,
});
const job = (targets: string[]) => ({ id: randomUUID(), org_id: A, targets });
const assetValues = () => db.tables.vms_assets.map((a) => `${a.value}:${a.confidence}`).sort();

test('crt.sh: names under the domain only, wildcards dropped', () => {
    const r = fromCrtsh('cnii.test', [{ id: 1, name_value: '*.cnii.test\nwww.cnii.test\nwww.cnii.test.evil.test\nCNII.test' }]);
    assert.deepEqual(r.names, ['cnii.test', 'www.cnii.test']);
});

test('a domain: CT names inside scope become probable assets; outside names stay related hosts', async () => {
    const s = [scope()];
    const sum = await runPassiveJob(job(['cnii.test']), s, deps());
    assert.deepEqual(assetValues(), ['api.cnii.test:probable', 'cnii.test:confirmed', 'mail.cnii.test:probable', 'www.cnii.test:probable']);
    const rel = db.tables.vms_observations.filter((o) => o.kind === 'related_host').map((o) => o.key);
    assert.deepEqual(rel.sort(), ['cdn.provider.test']);
    assert.equal(sum.related_outside_scope, 1);
    // Third-party open ports are observations, never our own service inventory.
    assert.equal(db.tables.vms_services.length, 0);
    const svc = db.tables.vms_observations.filter((o) => o.kind === 'service');
    assert.deepEqual(svc.map((o) => o.key).sort(), ['tcp/443', 'tcp/8443']);
    assert.ok(svc.every((o) => o.source === 'spiderfoot:third_party_scan' && o.confidence === 'medium'));
    // Personal data SpiderFoot found is not stored anywhere.
    const all = JSON.stringify(db.tables);
    assert.ok(!all.includes('person@cnii.test') && !all.includes('+234 800'));
    // DNS answer is stored on the asset; CVE claim is an unconfirmed finding.
    const root = db.tables.vms_assets.find((a) => a.value === 'cnii.test')!;
    assert.deepEqual(root.ips, ['192.0.2.10']);
    assert.equal(db.tables.vms_findings.length, 1);
    assert.equal(db.tables.vms_findings[0].evidence_class, 'version_match');
    assert.ok(['P3', 'P4'].includes(String(db.tables.vms_findings[0].priority)));
    assert.equal(sum.sources.opencti.ok, 0, 'OpenCTI is not asked about hostnames');
    assert.deepEqual(passiveOutcome(sum), { status: 'succeeded', error: null });
});

test('a repeated run moves sightings forward without duplicating anything', async () => {
    const s = [scope()];
    await runPassiveJob(job(['cnii.test']), s, deps());
    const counts = () => [db.tables.vms_assets.length, db.tables.vms_observations.length, db.tables.vms_findings.length];
    const before = counts();
    const sum = await runPassiveJob(job(['cnii.test']), s, deps());
    assert.deepEqual(counts(), before);
    assert.equal(sum.observations_new, 0);
    assert.ok(db.tables.vms_observations.every((o) => o.seen_count === 2));
    assert.equal(db.tables.vms_finding_evidence.length, 2, 'both sightings of the CVE claim kept');
});

test('sources that fail or are not configured are reported; the rest still run', async () => {
    const s = [scope({ kind: 'ip', value: '192.0.2.10', include_subdomains: false })];
    const sum = await runPassiveJob(job(['192.0.2.10']), s, deps({ spiderfoot: async () => { throw new Error('SpiderFoot at http://sf could not be reached'); }, opencti: undefined }));
    assert.equal(sum.sources.spiderfoot.failed, 1);
    assert.match(sum.sources.spiderfoot.errors[0], /could not be reached/);
    assert.equal(sum.sources.opencti.not_configured, 1);
    const out = passiveOutcome(sum);
    assert.equal(out.status, 'failed');
    assert.match(String(out.error), /spiderfoot: SpiderFoot at http:\/\/sf could not be reached; opencti: not configured/);
    // OpenCTI answering is enough for the job to count as having run.
    const ok = await runPassiveJob(job(['192.0.2.10']), s, deps({ spiderfoot: undefined, opencti: async () => ({ threatIntel: [{ source: 'OpenCTI', description: 'Indicator: 192.0.2.10 [malicious-activity]', severity: 'high' }], raw: {} }) }));
    assert.equal(passiveOutcome(ok).status, 'succeeded');
    assert.ok(db.tables.vms_observations.some((o) => o.source === 'opencti' && o.kind === 'reputation'));
});

test('targets outside active scope are never looked up', async () => {
    const called: string[] = [];
    const s = scope({ status: 'revoked' });
    const sum = await runPassiveJob(job(['cnii.test', 'other.test']), [s], deps({ spiderfoot: async (t) => { called.push(t); return sfResult(); }, crtsh: async (d) => { called.push(d); return []; } }));
    assert.deepEqual(called, []);
    assert.equal(sum.out_of_scope, 2);
    assert.equal(db.tables.vms_assets.length, 0);
    assert.deepEqual(passiveOutcome(sum), { status: 'failed', error: 'No target is inside an active scope any more' });
});

test('an AS number: holder and announced prefixes as observations, nothing else', async () => {
    const s = [scope({ kind: 'asn', value: 'AS64500', include_subdomains: false })];
    const sum = await runPassiveJob(job(['AS64500']), s, deps({ spiderfoot: async () => { throw new Error('must not be called'); } }));
    assert.deepEqual(assetValues(), ['AS64500:confirmed']);
    assert.deepEqual(db.tables.vms_observations.filter((o) => o.kind === 'announced_prefix').map((o) => o.key).sort(), ['192.0.2.0/24', '198.51.100.0/24']);
    assert.equal(sum.sources.spiderfoot.failed, 0);
});

test('runner: claims only passive jobs, records the summary, stops when cancelled', async () => {
    const s = scope();
    db.tables.vms_scan_jobs.push({ id: randomUUID(), org_id: A, scope_id: s.id, kind: 'discovery', targets: ['cnii.test'], status: 'queued', cancel_requested: false });
    const pj: Row = { id: randomUUID(), org_id: A, scope_id: s.id, kind: 'passive_osint', targets: ['cnii.test'], status: 'queued', cancel_requested: false };
    db.tables.vms_scan_jobs.push(pj);
    const id = await runOnePassiveJob(deps());
    assert.equal(id, pj.id);
    assert.equal(pj.status, 'succeeded');
    assert.equal(pj.worker_id, 'novrsoc-passive');
    assert.equal((pj.summary as Row).targets, 1);
    assert.equal(db.tables.vms_scan_jobs[0].status, 'queued', 'the worker\'s discovery job is untouched');
    assert.equal(await runOnePassiveJob(deps()), null);

    const cj: Row = { id: randomUUID(), org_id: A, scope_id: s.id, kind: 'passive_osint', targets: ['cnii.test', 'www.cnii.test'], status: 'queued', cancel_requested: false };
    db.tables.vms_scan_jobs.push(cj);
    await runOnePassiveJob(deps({ crtsh: async () => { cj.cancel_requested = true; return []; } }));
    assert.equal(cj.status, 'cancelled');
    assert.equal((cj.summary as Row).targets, 2);
});

test('health: plain http across a network is flagged; the passive runner is not the scanner worker', async () => {
    assert.equal(plaintextTransport('http://203.0.113.5:5001'), true);
    assert.equal(plaintextTransport('http://10.0.0.5:5001'), false);
    assert.equal(plaintextTransport('http://localhost:8080'), false);
    assert.equal(plaintextTransport('https://203.0.113.5'), false);
    const s = scope();
    db.tables.vms_scan_jobs.push({ id: randomUUID(), org_id: A, scope_id: s.id, kind: 'passive_osint', targets: [], status: 'running', worker_id: 'novrsoc-passive', heartbeat_at: new Date().toISOString() });
    const scanner = (await vmsChecks()).find((c) => c.name === 'VMS scanner')!;
    assert.equal(scanner.status, 'off', 'no scanner worker has ever connected');
    process.env.SPIDERFOOT_URL = 'http://203.0.113.5:5001';
    try {
        const c = await cniiChecks();
        assert.equal(c.find((x) => x.name === 'SpiderFoot (passive)')!.status, 'degraded');
        assert.equal(c.find((x) => x.name === 'OpenCTI connection')!.status, 'off');
    } finally { delete process.env.SPIDERFOOT_URL; }
});
