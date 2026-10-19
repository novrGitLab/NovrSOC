// Phase P9 CNII sector briefing: only staff may ask; the model receives only the requested
// sector's organisations, with each finding marked confirmed or not and the data gaps listed;
// references the model invents are removed and reported; the output is stored as advice and
// changes nothing. A fake model client; no network.
process.env.JWT_SECRET = 'ai-cnii-test-secret';
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'NVIDIA_API_KEY', 'AI_MODEL', 'SPIDERFOOT_URL', 'OPENCTI_URL', 'OPENCTI_TOKEN', 'MISP_URL', 'MISP_API_KEY']) delete process.env[k];

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import { requireAuth } from '../../middleware/auth';
import { startFakePostgrest, type FakePostgrest } from './fakePostgrest';
import aiRouter from '../ai';
import { setAiClientForTests, type AiClient } from '../../services/ai';

let db: FakePostgrest;
let server: Server;
let base = '';
const realLog = { log: console.log, warn: console.warn, error: console.error };
const tok = (role: string, org = 'cybernovr') => jwt.sign({ sub: randomUUID(), email: `${role}@${org}.test`, role, org_id: org }, process.env.JWT_SECRET!);
async function gen(bearer: string, subject: string) {
    const r = await fetch(`${base}/api/ai/generate`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${bearer}` }, body: JSON.stringify({ purpose: 'cnii_sector_briefing', subject_id: subject }) });
    return { status: r.status, data: await r.json().catch(() => null) };
}
const calls: { messages: { content: string }[] }[] = [];
let findingRef = '';
const fake: AiClient = {
    chat: { completions: { create: (async (params: { messages: { content: string }[] }) => {
        calls.push(params);
        return {
            model: 'nvidia/nemotron-3-super-120b-a12b', usage: { prompt_tokens: 900, completion_tokens: 200 },
            choices: [{ finish_reason: 'stop', message: { role: 'assistant', content: JSON.stringify({
                period: '7d', sector: 'ict', headline: 'One confirmed internet-facing issue; one unconfirmed claim',
                posture_summary: 's',
                statements: [{ statement: 'A KEV CVE was confirmed on portal.a.test', basis: 'platform_record', evidence_refs: [findingRef, 'finding:invented-123'] }],
                emerging_risks: [{ risk: 'r', confirmed: true, evidence_refs: [findingRef] }],
                organisation_actions: [{ org_id: 'org-a', action: 'Patch PAN-OS', priority: 'high', requires_approval: true, evidence_refs: [findingRef] }],
                data_gaps: ['org-b has no active scope'], confidence: 'medium',
            }) } }],
        };
    }) as never } },
};

before(async () => {
    const now = new Date().toISOString();
    db = await startFakePostgrest(
        { ai_requests: [], ai_artifacts: [], cnii_org_profiles: [], vms_assets: [], vms_findings: [], ti_matches: [], vms_scopes: [], vms_scan_jobs: [], cve_intel: [], vms_asset_events: [], ti_feeds: [] },
        { 'ti_matches.ti_indicators': 'indicator_id' },
        { ai_artifacts: { status: 'draft', created_at: now } },
    );
    db.tables.cnii_org_profiles.push(
        { org_id: 'org-a', sector_id: 'ict', designation: 'designated' },
        { org_id: 'org-b', sector_id: 'ict', designation: 'candidate' },
        { org_id: 'org-power', sector_id: 'power', designation: 'designated' },
    );
    db.tables.vms_scopes.push({ id: randomUUID(), org_id: 'org-a', status: 'active', expires_at: new Date(Date.now() + 86_400_000 * 30).toISOString(), allow_discovery: false });
    const confirmed = { id: randomUUID(), org_id: 'org-a', asset_value: 'portal.a.test', title: 'PAN-OS command injection', cve_ids: ['CVE-2024-3400'], priority: 'P1', risk_score: 95, evidence_class: 'scanner_check', status: 'open', first_seen: now };
    findingRef = `finding:${confirmed.id}`;
    db.tables.vms_findings.push(
        confirmed,
        { id: randomUUID(), org_id: 'org-a', asset_value: 'mail.a.test', title: 'CVE-2023-44487 reported by spiderfoot:sfp_shodan: version match, not confirmed', cve_ids: ['CVE-2023-44487'], priority: 'P3', risk_score: 70, evidence_class: 'version_match', status: 'open', first_seen: now },
        { id: randomUUID(), org_id: 'org-power', asset_value: 'scada.power.test', title: 'Other sector finding', cve_ids: [], priority: 'P1', risk_score: 99, evidence_class: 'scanner_check', status: 'open', first_seen: now },
    );
    db.tables.cve_intel.push({ cve_id: 'CVE-2024-3400', kev: true, cvss_score: 10 });
    db.tables.ti_feeds.push({ id: 'opencti', name: 'OpenCTI', enabled: true, last_success_at: null, last_error: null });
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'test-service-key';
    const app = express();
    app.use(express.json());
    app.use('/api/ai', requireAuth, aiRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    for (const k of ['log', 'warn', 'error'] as const) console[k] = () => undefined;
});
after(async () => { Object.assign(console, realLog); setAiClientForTests(null); server.close(); await db.close(); });

test('sector briefing: staff only; unconfigured AI says so', async () => {
    assert.equal((await gen(tok('executive', 'org-a'), 'ict:7d')).status, 403);
    assert.equal((await gen(tok('portal_user', 'org-a'), 'ict:7d')).status, 403);
    const r = await gen(tok('analyst'), 'ict:7d');
    assert.equal(r.status, 503);
    assert.match(r.data.error, /not configured/);
    assert.equal((await gen(tok('analyst'), 'atlantis:7d')).status, 404);
    assert.equal((await gen(tok('analyst'), 'ict:1y')).status, 404);
});

test('sector briefing: only the sector\'s records, confirmed vs unconfirmed marked, gaps listed, invented refs removed, nothing changed', async () => {
    setAiClientForTests(fake);
    const findingsBefore = JSON.stringify(db.tables.vms_findings);
    const r = await gen(tok('analyst'), 'ict:7d');
    assert.equal(r.status, 200);
    const content = calls.at(-1)!.messages[1].content;
    assert.ok(content.includes('portal.a.test') && content.includes('mail.a.test'));
    assert.ok(!content.includes('scada.power.test') && !content.includes('org-power'), 'another sector leaked into the prompt');
    assert.match(content, /"evidence_class":"version_match"[^}]*"confirmed":false/);
    assert.match(content, /org-b: no active authorised scope/);
    assert.match(content, /Threat feed opencti is not configured/);
    assert.match(content, /never say a system IS vulnerable on that basis/);
    assert.deepEqual(r.data.artifact.content.invalid_refs, ['finding:invented-123']);
    assert.deepEqual(r.data.artifact.content.statements[0].evidence_refs, [findingRef]);
    assert.equal(JSON.stringify(db.tables.vms_findings), findingsBefore, 'advice only: no record changed');
    assert.equal(db.tables.ai_artifacts.length, 1);
    assert.equal(db.tables.ai_artifacts[0].org_id, 'cybernovr', 'stored under the requester\'s organisation');
});
