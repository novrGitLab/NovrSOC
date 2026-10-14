// Phase P1: every /api mount in index.ts must require a login, or be listed here with the reason
// it doesn't. A new mount added without a gate fails this test, so the open-route problem the
// 2026-10-13 audit found (the Wazuh agent list served to anyone at /api/assets) can't quietly
// come back. "Gated in router" entries are checked too: their router file must apply a gate.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'fs';
import path from 'path';

const SRC = path.join(__dirname, '..', '..');
const index = readFileSync(path.join(SRC, 'index.ts'), 'utf8');
const GATE = /requireAuth|requirePermission|requireRole|requireOrg/;

// Mounts with no login gate on the mount itself, and why. Keep this list short.
const NO_MOUNT_GATE: Record<string, { reason: string; router?: string }> = {
    '/api': { reason: 'global rate limiter, not a route' },
    '/api/auth': { reason: 'sign-in itself (plus its rate limiter and bot protection)' },
    '/api/portal/auth': { reason: 'portal sign-in rate limiter' },
    '/api/portal': { reason: 'portal sign-in proxy; its data routes forward the caller\'s own token' },
    '/api/public': { reason: 'landing-page scanner, intentionally public, rate limited' },
    '/api/contact': { reason: 'public contact form (write-only)' },
    '/api/ingest': { reason: 'machine credential (ALERT_INGEST_TOKEN)', router: 'routes/ingest.ts' },
    '/api/export/v1': { reason: 'machine credential (vendor export token + IP allow-list)', router: 'routes/exportApi.ts' },
    '/api/wazuh': { reason: 'gated in router (alerts:read)', router: 'routes/wazuh.ts' },
    '/api/mitre': { reason: 'gated in router (alerts:read)', router: 'routes/mitre.ts' },
    '/api/alerts': { reason: 'gated per route', router: 'routes/alertStore.ts' },
    '/api/threats': { reason: 'gated per route', router: 'routes/threatManagement.ts' },
    '/api/soar': { reason: 'gated per route; /enrich uses the SOAR engine token', router: 'routes/soar.ts' },
    '/api/search': { reason: 'gated per route', router: 'routes/search.ts' },
    '/api/test': { reason: 'gated per route', router: 'routes/test.ts' },
    '/api/notifications': { reason: 'gated per route', router: 'routes/notifications.ts' },
    '/api/playbooks': { reason: 'gated in router (requireAuth + requireOrg)', router: 'routes/playbooks.ts' },
    '/api/email-security': { reason: 'gated in router; the Microsoft 365 consent callback must be public', router: 'routes/emailSecurity.ts' },
    '/api/email': { reason: 'gated per route; the Mailgun DMARC inbox uses its own signature', router: 'routes/email.ts' },
    '/api/email-proxy': { reason: 'gated per route; the mail-gateway feed uses its own token', router: 'routes/emailProxy.ts' },
    '/api/vms/worker': { reason: 'machine credential (VMS_WORKER_TOKEN) for the scanner worker', router: 'routes/vmsWorker.ts' },
};

const mounts = [...index.matchAll(/^app\.use\('(\/api[^']*)'(.*)$/gm)].map((m) => ({ path: m[1], rest: m[2] }));

test('index.ts has the expected /api mounts to check', () => {
    assert.ok(mounts.length >= 40, `found only ${mounts.length} mounts — did the parsing break?`);
});

test('every /api mount is gated, or listed with its reason', () => {
    const ungated = mounts.filter((m) => !GATE.test(m.rest) && !(m.path in NO_MOUNT_GATE)).map((m) => m.path);
    assert.deepEqual(ungated, [], `mounted without a login gate: ${ungated.join(', ')}`);
});

test('routes found open in the 2026-10-13 audit now require a login', () => {
    for (const p of ['/api/assets', '/api/org-cti', '/api/brand', '/api/brand/domains', '/api/dns', '/api/geo', '/api/threat', '/api/cti', '/api/urlscan', '/api/webscan', '/api/recovery']) {
        const m = mounts.find((x) => x.path === p);
        assert.ok(m, `${p} is not mounted`);
        assert.match(m.rest, GATE, `${p} has no gate`);
    }
    assert.match(mounts.find((m) => m.path === '/api/assets')!.rest, /requirePermission\('alerts:read'\)/);
    assert.match(mounts.find((m) => m.path === '/api/org-cti')!.rest, /requireOrg/);
});

test('"gated in router" entries really apply a gate in their router', () => {
    for (const [p, { router }] of Object.entries(NO_MOUNT_GATE)) {
        if (!router) continue;
        const src = readFileSync(path.join(SRC, router), 'utf8');
        const hasGate = GATE.test(src) || /requireIngestToken|requireWorkerToken|authenticate|requireEngineToken|verify/i.test(src);
        assert.ok(hasGate, `${p}: ${router} applies no gate`);
    }
});

test('no route falls back to a default organisation', () => {
    const orgCti = readFileSync(path.join(SRC, 'routes/orgCTI.ts'), 'utf8');
    assert.doesNotMatch(orgCti, /\|\|\s*'cybernovr'/);
});
