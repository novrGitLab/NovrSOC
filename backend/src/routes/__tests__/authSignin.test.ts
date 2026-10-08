// POST /api/auth/signin — the env-configured admin login fails closed: with DEV_ADMIN_EMAIL or
// DEV_ADMIN_PASSWORD unset, no credentials produce a token (there is no hardcoded fallback).
// Outbound fetch is refused, so the fall-through proxy to APP_API_BASE_URL never leaves the process.
process.env.JWT_SECRET = 'auth-signin-test-secret';
for (const k of ['DEV_ADMIN_EMAIL', 'DEV_ADMIN_PASSWORD', 'APP_API_BASE_URL', 'SUPABASE_URL', 'SUPABASE_SERVICE_KEY']) delete process.env[k];

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import jwt from 'jsonwebtoken';
import type { AddressInfo } from 'net';
import type { Server } from 'http';
import authRouter from '../auth';

let base = '';
let server: Server;
const realFetch = globalThis.fetch;

async function signin(email: string, password: string) {
    const r = await realFetch(`${base}/api/auth/signin`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password }) });
    return { status: r.status, data: await r.json().catch(() => null) };
}

before(() => {
    globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
        const url = String(input instanceof Request ? input.url : input);
        if (url.startsWith('http://127.0.0.1')) return realFetch(input, init);
        throw new Error(`external call blocked in tests: ${url}`);
    }) as typeof fetch;
    const app = express();
    app.use(express.json());
    app.use('/api/auth', authRouter);
    server = app.listen(0);
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
after(() => { server.close(); globalThis.fetch = realFetch; });

test('with DEV_ADMIN_* unset, no credentials issue a token (including blank ones)', async () => {
    for (const [email, password] of [['', ''], ['admin@example.test', 'anything'], ['rayne@cybernovr.com', 'guess']]) {
        const r = await signin(email, password);
        assert.notEqual(r.status, 200, `${email}`);
        assert.equal(r.data?.token, undefined);
    }
});

test('with DEV_ADMIN_* set, only the configured pair signs in', async () => {
    process.env.DEV_ADMIN_EMAIL = 'admin@example.test';
    process.env.DEV_ADMIN_PASSWORD = 'correct horse battery staple';
    try {
        const wrong = await signin('admin@example.test', 'wrong');
        assert.equal(wrong.data?.token, undefined);
        const ok = await signin('admin@example.test', 'correct horse battery staple');
        assert.equal(ok.status, 200);
        const claims = jwt.verify(ok.data.token, process.env.JWT_SECRET!) as { role: string };
        assert.ok(claims.role);
    } finally {
        delete process.env.DEV_ADMIN_EMAIL;
        delete process.env.DEV_ADMIN_PASSWORD;
    }
});
