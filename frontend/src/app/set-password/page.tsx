'use client';

// Set (or reset) a staff account's password from a one-time link a super_admin issued
// (POST /api/admin/users/:id/password-link). The token travels in the URL fragment (#token=…),
// which the browser never sends to a server, and is posted once to POST /api/auth/set-password.

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { apiUrl, apiFetch } from '@/lib/api';
import { AuthField } from '@/components/auth/AuthField';
import { Logo } from '@/components/shared/Logo';

const MIN = 12;

export default function SetPasswordPage() {
    const [token, setToken] = useState<string | null>(null);
    const [password, setPassword] = useState('');
    const [confirm, setConfirm] = useState('');
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [done, setDone] = useState<string | null>(null);
    // Client portal accounts (P21) sign in at /client/login.
    const [portal, setPortal] = useState(false);

    useEffect(() => {
        const t = new URLSearchParams(window.location.hash.slice(1)).get('token');
        // eslint-disable-next-line react-hooks/set-state-in-effect -- the fragment is only readable in the browser
        setToken(t && /^[A-Za-z0-9_-]{43}$/.test(t) ? t : '');
        // Drop the token from the address bar and history once read.
        window.history.replaceState(null, '', window.location.pathname);
    }, []);

    const submit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError(null);
        if (password.length < MIN) { setError(`Use at least ${MIN} characters.`); return; }
        if (password !== confirm) { setError('The two passwords do not match.'); return; }
        setBusy(true);
        try {
            const r = await apiFetch(apiUrl('/api/auth/set-password'), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token, password }) });
            const d = await r.json().catch(() => null);
            if (!r.ok) { setError(d?.error ?? `Could not set the password (HTTP ${r.status}).`); return; }
            setPortal(d?.portal === true);
            setDone(d?.email ?? 'your account');
        } catch {
            setError('Could not reach the server. Try again.');
        } finally {
            setBusy(false);
        }
    };

    return (
        <main className="min-h-screen flex items-center justify-center bg-background p-4">
            <div className="w-full max-w-sm bg-card border border-border rounded-2xl p-6 space-y-5">
                <Logo size="md" />
                {done ? (
                    <div className="space-y-3">
                        <h1 className="text-lg font-black text-foreground">Password set</h1>
                        <p className="text-sm text-foreground-muted">You can now sign in as {done}.</p>
                        <Link href={portal ? '/client/login' : '/login'} className="inline-block text-sm font-bold text-white bg-purple rounded-lg px-4 py-2">{portal ? 'Go to the client portal' : 'Go to sign in'}</Link>
                    </div>
                ) : token === '' ? (
                    <div className="space-y-2">
                        <h1 className="text-lg font-black text-foreground">Link not valid</h1>
                        <p className="text-sm text-foreground-muted">Open the full link you were sent, or ask your administrator for a new one.</p>
                    </div>
                ) : (
                    <form onSubmit={submit} className="space-y-4">
                        <div>
                            <h1 className="text-lg font-black text-foreground">Set your password</h1>
                            <p className="text-xs text-foreground-muted mt-1">At least {MIN} characters. The link works once and expires after 72 hours.</p>
                        </div>
                        <AuthField label="New password" type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} />
                        <AuthField label="Confirm password" type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
                        {error && <p role="alert" className="text-xs text-red-500 font-semibold">{error}</p>}
                        <button type="submit" disabled={busy || token === null} className="w-full text-sm font-bold text-white bg-purple rounded-xl py-3 disabled:opacity-50">
                            {busy ? 'Saving…' : 'Set password'}
                        </button>
                    </form>
                )}
            </div>
        </main>
    );
}
