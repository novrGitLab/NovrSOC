// Unit tests for the client-side session helpers audited in the Release 2 client-auth pass:
//   src/lib/jwt.ts        base64URL-safe JWT payload/expiry decoding
//   src/lib/account.ts    getAuthToken() — which of the two session tokens an API call uses
//   src/lib/admin-auth.ts / src/lib/portal-auth.ts — expiry-aware "is this session live" checks
//
// None of these modules use the `@/` alias, so they are transpiled directly (no stubbing needed,
// unlike nav.ts/breadcrumbs.ts). A minimal localStorage + window shim stands in for the DOM.
//
//   npm test
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import ts from 'typescript';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const cacheDir = join(root, 'node_modules', '.cache', 'auth-session-test');
mkdirSync(cacheDir, { recursive: true });

// admin-auth.ts and portal-auth.ts both import './jwt' (no extension); Node's ESM loader needs
// the real file extension, so every transpiled output gets that one relative specifier rewritten.
function transpile(name) {
    const source = join(root, 'src', 'lib', `${name}.ts`);
    const out = ts.transpileModule(readFileSync(source, 'utf8'), {
        compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2020 },
        fileName: source,
    });
    const file = join(cacheDir, `${name}.mjs`);
    writeFileSync(file, out.outputText.replace("from './jwt'", "from './jwt.mjs'"));
    return file;
}
transpile('jwt');
function load(name) {
    const file = transpile(name);
    // Cache-busting query so re-requiring after a localStorage reset doesn't hit Node's ESM cache.
    return import(`${pathToFileURL(file).href}?t=${Date.now()}-${Math.random()}`);
}

// ── A tiny fake localStorage + window, matching what each lib's `typeof window === 'undefined'`
// guards expect (see admin-auth.ts / portal-auth.ts / account.ts). ──────────────────────────────
function installFakeBrowser(pathname = '/') {
    const store = new Map();
    globalThis.localStorage = {
        getItem: (k) => (store.has(k) ? store.get(k) : null),
        setItem: (k, v) => store.set(k, String(v)),
        removeItem: (k) => store.delete(k),
    };
    globalThis.window = { location: { pathname, href: '' } };
    return store;
}
beforeEach(() => installFakeBrowser());

// issueToken()'s own encoding (backend/src/routes/auth.ts): base64URL per segment, via Buffer.
const b64url = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
const makeToken = (payload) => `${b64url({ alg: 'HS256', typ: 'JWT' })}.${b64url(payload)}.sig`;
const future = (s = 3600) => Math.floor(Date.now() / 1000) + s;
const past = (s = 3600) => Math.floor(Date.now() / 1000) - s;

test('decodeJwtPayload: reads a base64URL payload that plain atob() cannot — the backend always encodes this way', async () => {
    const { decodeJwtPayload } = await load('jwt');
    // '>>>>>>>>' is chosen because its base64URL encoding is verified to contain '-' (confirmed
    // against Node's own Buffer('base64url') output) — exercising exactly the character plain
    // atob() throws on.
    const token = makeToken({ sub: 'u1', role: 'super_admin', note: '>>>>>>>>', exp: future() });
    assert.ok(/[-_]/.test(token.split('.')[1]), 'fixture sanity: this payload really does need base64URL decoding');
    const payload = decodeJwtPayload(token);
    assert.equal(payload?.sub, 'u1');
    assert.equal(payload?.role, 'super_admin');
});

test('decodeJwtExpiry / isJwtLive: future exp is live, past exp is not, missing exp is treated as live', async () => {
    const { decodeJwtExpiry, isJwtLive } = await load('jwt');
    const live = makeToken({ exp: future() });
    const dead = makeToken({ exp: past() });
    const noExp = makeToken({ sub: 'u1' });
    assert.ok(decodeJwtExpiry(live) > Date.now());
    assert.ok(isJwtLive(live));
    assert.equal(isJwtLive(dead), false);
    assert.equal(decodeJwtExpiry(noExp), null);
    assert.ok(isJwtLive(noExp), 'no exp claim at all is not treated as expired — the backend still enforces its own checks');
});

test('getAuthToken: an /admin path always uses admin_token, even when portal_token also exists', async () => {
    installFakeBrowser('/admin/dashboard');
    localStorage.setItem('admin_token', 'ADMIN');
    localStorage.setItem('portal_token', 'PORTAL');
    const { getAuthToken } = await load('account');
    assert.equal(getAuthToken(), 'ADMIN', 'a staff session must never send its client-portal token to an admin route');
});

test('getAuthToken: a /client path always uses portal_token, even when admin_token also exists', async () => {
    installFakeBrowser('/client/vms');
    localStorage.setItem('admin_token', 'ADMIN');
    localStorage.setItem('portal_token', 'PORTAL');
    const { getAuthToken } = await load('account');
    assert.equal(getAuthToken(), 'PORTAL');
});

test('getAuthToken: outside /admin and /client (shared/public routes), falls back to whichever exists', async () => {
    installFakeBrowser('/status');
    localStorage.setItem('portal_token', 'PORTAL');
    const { getAuthToken } = await load('account');
    assert.equal(getAuthToken(), 'PORTAL');
});

test('isAdminAuthenticated: true for a live token, false for an expired or missing one', async () => {
    const { isAdminAuthenticated } = await load('admin-auth');
    assert.equal(isAdminAuthenticated(), false, 'no token at all');
    localStorage.setItem('admin_token', makeToken({ role: 'super_admin', exp: future() }));
    assert.equal(isAdminAuthenticated(), true);
    localStorage.setItem('admin_token', makeToken({ role: 'super_admin', exp: past() }));
    assert.equal(isAdminAuthenticated(), false, 'an expired token must not read as authenticated — it used to (presence-only check)');
});

test('getAdminUser: decodes name/email/role/company from a base64URL-only payload; falls back cleanly with no token', async () => {
    const { getAdminUser } = await load('admin-auth');
    assert.equal(getAdminUser().role, 'Administrator', 'fallback role when signed out');
    localStorage.setItem('admin_token', makeToken({ name: 'Zoe', email: 'zoe@example.com', role: 'super_admin', company: 'Cybernovr', note: '>>>>>>>>', exp: future() }));
    const user = getAdminUser();
    assert.deepEqual(user, { name: 'Zoe', email: 'zoe@example.com', role: 'super_admin', company: 'Cybernovr' });
});

test('isPortalAuthenticated: true for a live token, false for an expired or missing one', async () => {
    const { isPortalAuthenticated } = await load('portal-auth');
    assert.equal(isPortalAuthenticated(), false);
    localStorage.setItem('portal_token', makeToken({ role: 'portal_user', exp: future() }));
    assert.equal(isPortalAuthenticated(), true);
    localStorage.setItem('portal_token', makeToken({ role: 'portal_user', exp: past() }));
    assert.equal(isPortalAuthenticated(), false);
});

test('setPortalSession / portalSignOut: round-trips the session and clears exactly its own two keys', async () => {
    const { setPortalSession, getPortalToken, getPortalUser, portalSignOut } = await load('portal-auth');
    localStorage.setItem('admin_token', 'UNRELATED_ADMIN_SESSION');
    setPortalSession('TOKEN123', { userId: 'u1', name: 'Zoe', email: 'zoe@example.com', orgId: 'cybernovr', orgName: 'Cybernovr', orgIndustry: null, orgPlan: null, portalRole: 'Client', wazuhGroup: null });
    assert.equal(getPortalToken(), 'TOKEN123');
    assert.equal(getPortalUser()?.orgId, 'cybernovr', 'orgId is the organisation slug (a string), not a numeric id');
    globalThis.window.location.href = '';
    portalSignOut();
    assert.equal(getPortalToken(), null);
    assert.equal(localStorage.getItem('admin_token'), 'UNRELATED_ADMIN_SESSION', 'signing out of the portal session must not touch an unrelated admin session in the same browser');
    assert.equal(globalThis.window.location.href, '/client/login');
});
