// Microsoft 365 onboarding: sign-in → verified tenant (ID token tid) → per-tenant admin consent.
// Real router, in-memory store, Microsoft's token endpoint and Graph stubbed — no network.
process.env.JWT_SECRET = 'm365-onboarding-test-secret';
process.env.EMAILSEC_JOBS_DISABLED = 'true';
Object.assign(process.env, { M365_CLIENT_ID: 'app-client-id', M365_CLIENT_SECRET: 'app-secret', M365_REDIRECT_URI: 'https://api.test/cb', FRONTEND_URL: 'https://app.test' });
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY', 'WAZUH_INDEXER_HOST']) delete process.env[k];

import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import emailSecurityRouter from '../../../routes/emailSecurity';
import { createMemoryDb, setDb } from '../db';
import { setConnectorFetch } from '../connectors/http';
import { validateIdTokenClaims, M365IdentityError } from '../connectors/m365Onboarding';

const db = createMemoryDb();
const TENANT_A = '11111111-1111-4111-8111-111111111111';
const TENANT_B = '22222222-2222-4222-8222-222222222222';
let base = '';
let server: Server;
let idTokenFor: (nonce: string) => string = () => '';
let tokenRequests: URLSearchParams[] = [];

const staff = (org: string) => jwt.sign({ sub: randomUUID(), email: `mgr@${org}.test`, role: 'soc_manager', org_id: org }, process.env.JWT_SECRET!);
const idToken = (over: Record<string, unknown>, nonce: string) => jwt.sign({
    aud: 'app-client-id', iss: `https://login.microsoftonline.com/${TENANT_A}/v2.0`, tid: TENANT_A, oid: 'user-oid', preferred_username: 'admin@tenant-a.test',
    nonce, exp: Math.floor(Date.now() / 1000) + 600, ...over,
}, 'microsoft-signs-this-not-us');

async function start(org: string) {
    const r = await fetch(`${base}/api/email-security/messaging/connections/microsoft365/start`, { method: 'POST', headers: { Authorization: `Bearer ${staff(org)}` } });
    const d = await r.json();
    const u = new URL(d.authorize_url);
    return { url: u, state: u.searchParams.get('state')!, nonce: u.searchParams.get('nonce')! };
}
const callback = async (q: Record<string, string>) => {
    const r = await fetch(`${base}/api/email-security/messaging/connections/microsoft365/callback?${new URLSearchParams(q)}`, { redirect: 'manual' });
    return r.headers.get('location') ?? '';
};
before(() => {
    setDb(db);
    setConnectorFetch(async (input, init) => {
        const u = String(input);
        if (u.endsWith('/organizations/oauth2/v2.0/token')) {
            const body = new URLSearchParams(String(init?.body));
            tokenRequests.push(body);
            // The nonce isn't sent back by the client; the test fixture closes over the latest one.
            return Response.json({ id_token: idTokenFor(lastNonce), token_type: 'Bearer' });
        }
        if (/\/oauth2\/v2\.0\/token$/.test(u)) return Response.json({ access_token: jwt.sign({ roles: ['SecurityAlert.Read.All'] }, 'k'), expires_in: 3600 });
        if (u.includes('/security/alerts_v2')) return Response.json({ value: [] });
        return new Response('{}', { status: 404 });
    });
    const app = express();
    app.use(express.json());
    app.use('/api/email-security', emailSecurityRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
after(() => { server.close(); setDb(null); setConnectorFetch(null); });
let lastNonce = '';
const dec = (u: string) => decodeURIComponent(u.replace(/\+/g, ' '));
beforeEach(() => { tokenRequests = []; });
// Track the nonce of the most recent start() so the stubbed token endpoint can embed it.
const origStart = start;
async function startTracked(org: string) { const s = await origStart(org); lastNonce = s.nonce; return s; }

async function signInTracked(org: string, claims: Record<string, unknown> = {}, nonceOverride?: string) {
    const s = await startTracked(org);
    idTokenFor = (nonce) => idToken(claims, nonceOverride ?? nonce);
    return { ...s, next: await callback({ code: 'auth-code', state: s.state }) };
}

// ── ID token validation (unit) ──

test('ID token: valid claims give the verified tenant', () => {
    const t = idToken({}, 'n1');
    assert.equal(validateIdTokenClaims(t, { clientId: 'app-client-id', nonce: 'n1' }).tid, TENANT_A);
});

test('ID token: missing tid, wrong audience, wrong issuer, expired, nonce mismatch are rejected', () => {
    const bad = (over: Record<string, unknown>, nonce = 'n1') => assert.throws(() => validateIdTokenClaims(idToken(over, 'n1'), { clientId: 'app-client-id', nonce }), M365IdentityError);
    bad({ tid: undefined });
    bad({ tid: 'not-a-guid' });
    bad({ aud: 'someone-elses-app' });
    bad({ iss: `https://login.microsoftonline.com/${TENANT_B}/v2.0` }); // issuer tenant ≠ tid
    bad({ exp: Math.floor(Date.now() / 1000) - 3600 });
    bad({}, 'different-nonce');
    assert.throws(() => validateIdTokenClaims('garbage', { clientId: 'app-client-id', nonce: 'n1' }), M365IdentityError);
});

// ── Full flow ──

test('start issues a sign-in link (openid only) bound to a signed state and nonce', async () => {
    const s = await startTracked('org-a');
    assert.equal(s.url.origin + s.url.pathname, 'https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize');
    assert.equal(s.url.searchParams.get('scope'), 'openid');
    assert.equal(s.url.searchParams.get('client_id'), 'app-client-id');
    const st = jwt.verify(s.state, process.env.JWT_SECRET!) as { p: string; nonce: string };
    assert.equal(st.p, 'm365-signin');
    assert.equal(st.nonce, s.nonce);
});

test('valid tenant: sign-in → consent for THAT tenant → connected with the verified tenant id', async () => {
    const { next } = await signInTracked('org-a');
    const consent = new URL(next);
    assert.equal(consent.pathname, `/${TENANT_A}/v2.0/adminconsent`, 'consent is requested for the signed-in tenant only');
    assert.equal(tokenRequests[0].get('grant_type'), 'authorization_code');
    assert.equal(tokenRequests[0].get('scope'), 'openid');
    const done = await callback({ admin_consent: 'True', tenant: TENANT_A, state: consent.searchParams.get('state')! });
    assert.match(done, /result=connected/);
    const [row] = await db.select<{ tenant_id: string; org_id: string }>('messaging_connections', { filters: [{ col: 'org_id', op: 'eq', value: 'org-a' }] });
    assert.equal(row.tenant_id, TENANT_A);
});

test('wrong / forged tenant: a consent callback naming another tenant is refused', async () => {
    const { next } = await signInTracked('org-w');
    const state = new URL(next).searchParams.get('state')!;
    const r = await callback({ admin_consent: 'True', tenant: TENANT_B, state });
    assert.match(r, /result=error/);
    assert.match(dec(r), /different tenant/);
    assert.equal((await db.select('messaging_connections', { filters: [{ col: 'org_id', op: 'eq', value: 'org-w' }] })).length, 0);
});

test('missing tenant on the consent callback is refused', async () => {
    const { next } = await signInTracked('org-m');
    const r = await callback({ admin_consent: 'True', state: new URL(next).searchParams.get('state')! });
    assert.match(dec(r), /did not return a tenant/);
});

test('sign-in whose ID token has no tenant, or a mismatched nonce, never reaches consent', async () => {
    assert.match(dec((await signInTracked('org-n', { tid: undefined })).next), /result=error.*tenant/);
    assert.match(dec((await signInTracked('org-n', {}, 'replayed-nonce')).next), /result=error.*nonce/);
});

test('modified state: a tampered or self-made state is refused', async () => {
    const { next } = await signInTracked('org-t');
    const good = new URL(next).searchParams.get('state')!;
    const [h, p, sig] = good.split('.');
    const claims = JSON.parse(Buffer.from(p, 'base64url').toString());
    const tampered = `${h}.${Buffer.from(JSON.stringify({ ...claims, tid: TENANT_B })).toString('base64url')}.${sig}`;
    assert.match(await callback({ admin_consent: 'True', tenant: TENANT_B, state: tampered }), /expired\+or\+was\+not\+issued/);
    const forged = jwt.sign({ ...claims, tid: TENANT_B }, 'attacker-secret');
    assert.match(await callback({ admin_consent: 'True', tenant: TENANT_B, state: forged }), /expired\+or\+was\+not\+issued/);
    // A consent-step state can't be used to skip sign-in with a different flow marker either.
    const wrongFlow = jwt.sign({ ...claims, p: 'microsoft365' }, process.env.JWT_SECRET!);
    assert.match(await callback({ admin_consent: 'True', tenant: TENANT_A, state: wrongFlow }), /expired\+or\+was\+not\+issued/);
});

test('expired state is refused', async () => {
    const expired = jwt.sign({ org: 'org-x', sub: 'x', p: 'm365-consent', tid: TENANT_A, oid: null, exp: Math.floor(Date.now() / 1000) - 60 }, process.env.JWT_SECRET!);
    assert.match(await callback({ admin_consent: 'True', tenant: TENANT_A, state: expired }), /expired\+or\+was\+not\+issued/);
    const expiredSignIn = jwt.sign({ org: 'org-x', sub: 'x', p: 'm365-signin', nonce: 'n', exp: Math.floor(Date.now() / 1000) - 60 }, process.env.JWT_SECRET!);
    assert.match(await callback({ code: 'c', state: expiredSignIn }), /expired\+or\+was\+not\+issued/);
});

test('a tenant verified for one organisation cannot be connected by another', async () => {
    // org-b's admin genuinely signs in to TENANT_A (e.g. a guest there) — still refused, org-a owns it.
    const { next } = await signInTracked('org-b');
    const r = await callback({ admin_consent: 'True', tenant: TENANT_A, state: new URL(next).searchParams.get('state')! });
    assert.match(dec(r), /already connected to a different organisation/);
});

test('Microsoft errors on either step are shown, not treated as success', async () => {
    const s = await startTracked('org-e');
    assert.match(dec(await callback({ error: 'access_denied', error_description: 'The user cancelled', state: s.state })), /result=error.*access_denied/);
});
