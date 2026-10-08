// /api/playbooks tenant isolation. The real router with an in-memory stand-in for the Supabase
// query builder — nothing here touches a real database.
process.env.JWT_SECRET = 'playbooks-test-secret';
for (const k of ['SUPABASE_URL', 'SUPABASE_SERVICE_KEY']) delete process.env[k];

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import type { SupabaseClient } from '@supabase/supabase-js';
import playbooksRouter, { setPlaybooksClient } from '../playbooks';

type Row = Record<string, unknown>;
const tables: Record<string, Row[]> = { playbooks: [], cases: [], playbook_steps: [{ step_id: 'block_ip', name: 'Block IP', description: null, category: 'containment' }] };

/** Minimal chainable stand-in for supabase-js: select / insert / update / delete + eq / in / maybeSingle. */
function fakeClient(): SupabaseClient {
    const from = (table: string) => {
        let op: 'select' | 'insert' | 'update' | 'delete' = 'select';
        let payload: Row | Row[] | null = null;
        const filters: ((r: Row) => boolean)[] = [];
        const rows = () => (tables[table] ??= []);
        const run = () => {
            if (op === 'insert') {
                const ins = (Array.isArray(payload) ? payload : [payload!]).map((r) => ({ id: randomUUID(), ...r }));
                rows().push(...ins);
                return { data: ins, error: null };
            }
            const hit = rows().filter((r) => filters.every((f) => f(r)));
            if (op === 'update') { hit.forEach((r) => Object.assign(r, payload)); return { data: hit, error: null }; }
            if (op === 'delete') { tables[table] = rows().filter((r) => !hit.includes(r)); return { data: hit, error: null }; }
            return { data: hit, error: null };
        };
        const q: Record<string, unknown> = {
            select: () => q,
            insert: (p: Row | Row[]) => { op = 'insert'; payload = p; return q; },
            update: (p: Row) => { op = 'update'; payload = p; return q; },
            delete: () => { op = 'delete'; return q; },
            eq: (c: string, v: unknown) => { filters.push((r) => r[c] === v); return q; },
            in: (c: string, v: unknown[]) => { filters.push((r) => v.includes(r[c])); return q; },
            maybeSingle: async () => { const r = run(); return { data: (r.data as Row[])[0] ?? null, error: null }; },
            single: async () => { const r = run(); return { data: (r.data as Row[])[0] ?? null, error: (r.data as Row[]).length ? null : { message: 'no rows' } }; },
            then: (ok: (v: unknown) => unknown, bad?: (e: unknown) => unknown) => Promise.resolve(run()).then(ok, bad),
        };
        return q;
    };
    return { from } as unknown as SupabaseClient;
}

let base = '';
let server: Server;
const tok = (role: string, org?: string) => jwt.sign({ sub: randomUUID(), email: `${role}@${org ?? 'none'}.test`, role, ...(org ? { org_id: org } : {}) }, process.env.JWT_SECRET!);
async function call(method: string, path: string, opts: { role?: string; org?: string; body?: unknown } = {}) {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (opts.role) headers.Authorization = `Bearer ${tok(opts.role, opts.org)}`;
    const r = await fetch(`${base}/api/playbooks${path}`, { method, headers, body: opts.body === undefined ? undefined : JSON.stringify(opts.body) });
    return { status: r.status, data: await r.json().catch(() => null) };
}
const orgRows = (org: string) => tables.playbooks.filter((p) => p.org_id === org);

before(() => {
    setPlaybooksClient(fakeClient());
    tables.playbooks.push({ id: 'pb-b1', org_id: 'org-b', name: 'Org B private playbook', severity: 'high', steps: [] });
    tables.cases.push({ id: '11111111-1111-4111-8111-111111111111', org_id: 'org-b' }, { id: '22222222-2222-4222-8222-222222222222', org_id: 'org-a' });
    const app = express();
    app.use(express.json());
    app.use('/api/playbooks', playbooksRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
after(() => { server.close(); setPlaybooksClient(null); });

test('unauthenticated → 401 on every route, and nothing is seeded', async () => {
    for (const [m, p] of [['GET', '/'], ['GET', '/?org_id=org-z'], ['GET', '/steps'], ['POST', '/'], ['PUT', '/pb-b1'], ['DELETE', '/pb-b1'], ['POST', '/pb-b1/run']] as const) {
        assert.equal((await call(m, p, { body: m === 'GET' ? undefined : {} })).status, 401, `${m} ${p}`);
    }
    assert.equal(orgRows('org-z').length, 0);
    assert.equal((await call('GET', '/', { role: 'portal_user', org: 'org-a' })).status, 403, 'portal tokens are not staff');
});

test('a token without an org → 403 on every route, never a default organisation', async () => {
    for (const [m, p] of [['GET', '/'], ['GET', '/steps'], ['POST', '/'], ['PUT', '/pb-b1'], ['DELETE', '/pb-b1'], ['POST', '/pb-b1/run']] as const) {
        const r = await call(m, p, { role: 'super_admin', body: m === 'GET' ? undefined : {} });
        assert.equal(r.status, 403, `${m} ${p}`);
        assert.match(r.data.error, /No organisation/);
    }
    assert.equal(orgRows('cybernovr').length, 0, 'nothing seeded for a fallback org');
});

test('org A reading org A → allowed (defaults seeded for its own organisation)', async () => {
    const r = await call('GET', '/', { role: 'analyst', org: 'org-a' });
    assert.equal(r.status, 200);
    assert.ok(r.data.playbooks.length > 0);
    assert.ok(r.data.playbooks.every((p: Row) => p.org_id === 'org-a'));
    assert.equal((await call('GET', '/?org_id=org-a', { role: 'analyst', org: 'org-a' })).status, 200, 'naming your own org is fine');
});

test('org A requesting org B → 403, never org B data, and no seeding for org B', async () => {
    for (const role of ['analyst', 'soc_manager', 'executive']) {
        const r = await call('GET', '/?org_id=org-b', { role, org: 'org-a' });
        assert.equal(r.status, 403, role);
        assert.ok(!JSON.stringify(r.data).includes('Org B private playbook'));
    }
    assert.equal((await call('GET', '/?org_id=org-new', { role: 'soc_manager', org: 'org-a' })).status, 403);
    assert.equal(orgRows('org-new').length, 0, 'seeding cannot be triggered for another organisation');
});

test('org A cannot modify, delete or run org B\'s playbook (looks like not found)', async () => {
    assert.equal((await call('PUT', '/pb-b1', { role: 'soc_manager', org: 'org-a', body: { name: 'hijacked' } })).status, 404);
    assert.equal((await call('DELETE', '/pb-b1', { role: 'soc_manager', org: 'org-a' })).status, 404);
    assert.equal((await call('POST', '/pb-b1/run', { role: 'analyst', org: 'org-a', body: { case_id: '22222222-2222-4222-8222-222222222222' } })).status, 404);
    const b = tables.playbooks.find((p) => p.id === 'pb-b1')!;
    assert.equal(b.name, 'Org B private playbook', 'untouched');
    // …nor attach its own playbook to another organisation's case.
    const ownPb = orgRows('org-a')[0];
    assert.equal((await call('POST', `/${ownPb.id}/run`, { role: 'analyst', org: 'org-a', body: { case_id: '11111111-1111-4111-8111-111111111111' } })).status, 404);
});

test('org B can still manage its own playbook', async () => {
    const r = await call('PUT', '/pb-b1', { role: 'soc_manager', org: 'org-b', body: { description: 'updated by owner' } });
    assert.equal(r.status, 200);
    assert.equal(r.data.playbook.description, 'updated by owner');
});

test('cross-org access only for super_admin (existing RBAC), read-only, and never seeds', async () => {
    const r = await call('GET', '/?org_id=org-b', { role: 'super_admin', org: 'org-a' });
    assert.equal(r.status, 200);
    assert.deepEqual(r.data.playbooks.map((p: Row) => p.id), ['pb-b1']);
    const empty = await call('GET', '/?org_id=org-unseeded', { role: 'super_admin', org: 'org-a' });
    assert.equal(empty.status, 200);
    assert.deepEqual(empty.data.playbooks, []);
    assert.equal(orgRows('org-unseeded').length, 0, 'a platform admin viewing an org does not seed it');
});

test('creating a playbook always uses the caller\'s organisation, whatever the body says', async () => {
    const r = await call('POST', '/', { role: 'soc_manager', org: 'org-a', body: { name: 'New', severity: 'low', org_id: 'org-b' } });
    assert.equal(r.status, 201);
    assert.equal(r.data.playbook.org_id, 'org-a');
});
