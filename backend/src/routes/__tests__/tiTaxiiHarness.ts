// TAXII interoperability harness (phase P25): the real TAXII 2.1 router over a fake PostgREST
// seeded with synthetic intelligence, so an independent TAXII client (scripts/ti/taxii_client_check.py,
// using the OASIS-maintained taxii2-client) can be run against it. Not a test file; run with
//   npx tsx src/routes/__tests__/tiTaxiiHarness.ts
// It prints one JSON line {url, username, password, collections, expected} and serves until killed.
// Synthetic fixtures only — never live intelligence.
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'MISP_URL', 'MISP_API_KEY']) delete process.env[k];

import express from 'express';
import type { AddressInfo } from 'net';
import { randomUUID } from 'crypto';
import { startFakePostgrest, type Row } from './fakePostgrest';
import { storeRecords, type SourceRecord } from '../../services/threatInfo';
import { uuidv5, STIX_NAMESPACE } from '../../services/stix';
import { COLLECTIONS } from '../../services/tiPolicy';

async function main() {
    const db = await startFakePostgrest(
        {
            ti_feeds: ['threatfox', 'urlhaus', 'feodo', 'misp', 'cisa_kev'].map((id) => ({ id, name: id, url: 'x', enabled: true, validity_days: id === 'cisa_kev' ? null : 30 })),
            ti_feed_runs: [], ti_indicators: [], ti_indicator_sources: [], ti_taxii_clients: [],
        },
        {},
        { ti_indicators: { status: 'active', tags: [], malware_families: [], threat_types: [], mitre_techniques: [], source_count: 0 } as Row, ti_taxii_clients: { enabled: true, revoked_at: null } as Row },
    );
    process.env.SUPABASE_URL = db.url;
    process.env.SUPABASE_SERVICE_KEY = 'harness';
    const { default: taxiiRouter, hashSecret } = await import('../taxii');
    const r = (over: Partial<SourceRecord>): SourceRecord => ({ type: 'ip', value: '198.51.100.1', source_ref: 'x', confidence: null, first_seen: '2026-10-20T00:00:00.000Z', last_seen: '2026-10-29T00:00:00.000Z', tags: [], malware: null, threat_type: null, context: {}, ...over });
    const quiet = console.log; console.log = () => undefined;
    await storeRecords('feodo', Array.from({ length: 25 }, (_, i) => r({ value: `203.0.113.${i + 1}`, source_ref: `203.0.113.${i + 1}:443`, malware: 'QakBot', threat_type: 'botnet_cc' })), 30);
    await storeRecords('threatfox', [r({ type: 'domain', value: 'c2.example.test', source_ref: '424242', malware: 'AsyncRAT', threat_type: 'botnet_cc', tags: ['rat'], confidence: 75 }), r({ type: 'sha256', value: 'a'.repeat(64), source_ref: '424243', malware: 'AsyncRAT', threat_type: 'payload' })], 30);
    await storeRecords('urlhaus', [r({ type: 'url', value: "http://bad.example.test/it's.exe", source_ref: '9001', threat_type: 'malware_download' })], 30);
    await storeRecords('misp', [r({ type: 'domain', value: 'red.example.test', source_ref: 'm1', tlp: 'red', distribution: 0, context: { comment: 'RED' } })], 30);
    await storeRecords('cisa_kev', [r({ type: 'cve', value: 'CVE-2024-3400', source_ref: 'CVE-2024-3400', threat_type: 'known_exploited_vulnerability', context: { vendor: 'Palo Alto Networks', product: 'PAN-OS', name: 'Command injection', required_action: 'Apply updates', due_date: '2024-04-19' } })], null);
    console.log = quiet;
    for (const row of db.tables.ti_indicators) row.stix_uuid = uuidv5(`${row.type}:${row.value}`, STIX_NAMESPACE);
    const username = 'taxii_harness';
    const password = randomUUID();
    db.tables.ti_taxii_clients.push({ id: randomUUID(), name: 'Harness', key_id: username, secret_hash: hashSecret(password), collections: COLLECTIONS.map((c) => c.id), max_tlp: 'clear', enabled: true, revoked_at: null });

    const app = express();
    app.use('/taxii2', taxiiRouter);
    const server = app.listen(0, '127.0.0.1', () => {
        const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/taxii2/`;
        // 25 Feodo + 2 ThreatFox + 1 URLhaus shareable; the RED MISP domain is not.
        process.stdout.write(`${JSON.stringify({ url, username, password, collections: COLLECTIONS.map((c) => ({ id: c.id, alias: c.alias })), expected: { indicators: 28, vulnerabilities: 1, never: `indicator--${uuidv5('domain:red.example.test', STIX_NAMESPACE)}` } })}\n`);
    });
}
void main();
