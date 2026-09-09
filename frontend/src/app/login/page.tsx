'use client';

import { useState } from 'react';
import dynamic from 'next/dynamic';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { Eye, EyeOff } from 'lucide-react';
import type { CredentialResponse } from '@react-oauth/google';
import { apiUrl, apiFetch } from '@/lib/api';

const GoogleLogin = dynamic(
    () => import('@react-oauth/google').then((m) => ({ default: m.GoogleLogin })),
    { ssr: false }
);
import { AuthField } from '@/components/auth/AuthField';
import { NigeriaLoginMap } from '@/components/auth/NigeriaLoginMap';
import { Logo } from '@/components/shared/Logo';

// Read as a full static expression, not destructured — Next.js inlines NEXT_PUBLIC_* vars at
// build time by textual substitution, so `process.env.NEXT_PUBLIC_GOOGLE_OAUTH_ENABLED` has to
// appear verbatim to be replaced.
const googleOAuthEnabled = process.env.NEXT_PUBLIC_GOOGLE_OAUTH_ENABLED === 'true';

export default function AdminLoginPage() {
    const router = useRouter();
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [showPassword, setShowPassword] = useState(false);
    const [submitting, setSubmitting] = useState(false);
    const [error, setError] = useState<string | null>(null);
    // Honeypot — hidden from real users via CSS + tabIndex/autoComplete below; a bot filling
    // out every visible field programmatically fills this one too. Backend rejects any
    // request with this set (middleware/auth.ts's botProtection).
    const [gotcha, setGotcha] = useState('');

    const submit = async (e: React.FormEvent) => {
        e.preventDefault();
        setSubmitting(true);
        setError(null);
        try {
            const res = await apiFetch(apiUrl('/api/auth/signin'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password, _gotcha: gotcha }),
            });
            const data = await res.json();
            if (!res.ok || !data.token) {
                setError('Invalid credentials');
                setSubmitting(false);
                return;
            }
            localStorage.setItem('admin_token', data.token);
            router.push('/admin/dashboard');
            // Deliberately NOT resetting `submitting` here (no `finally`) — router.push()
            // returns as soon as the navigation is *requested*, not once /admin/dashboard has
            // actually rendered (confirmed live: on a slow/first-compile transition this can
            // take several seconds). Clearing the disabled/"Signing in…" state immediately
            // flips the button back to normal while the app is still mid-navigation, which
            // reads as "nothing happened" / login silently failing even though it succeeded —
            // this is what was actually being reported as "not redirecting." Leaving the button
            // disabled through the transition (it unmounts with the page anyway once
            // /admin/dashboard takes over) fixes that without touching the request/token logic.
        } catch {
            setError('Invalid credentials');
            setSubmitting(false);
        }
    };

    const handleGoogleSuccess = async (credentialResponse: CredentialResponse) => {
        setError(null);
        try {
            const res = await apiFetch(apiUrl('/api/auth/google'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ credential: credentialResponse.credential }),
            });
            const data = await res.json();
            if (!res.ok || !data.token) {
                setError('Google sign-in failed. Please try again.');
                return;
            }
            localStorage.setItem('admin_token', data.token);
            router.push('/admin/dashboard');
        } catch {
            setError('Google sign-in failed. Please try again.');
        }
    };

    return (
        <div className="min-h-screen flex">
            {/* Left panel — form */}
            <div className="w-full lg:w-2/5 flex flex-col justify-between bg-white p-10 lg:p-16 min-h-screen">

                {/* Top — logo */}
                <Logo size="md" />

                {/* Middle — form */}
                <div className="w-full max-w-sm mx-auto">
                    <h1 className="font-black text-3xl text-foreground mb-2 tracking-tight">Welcome back</h1>
                    <p className="text-foreground-muted text-sm mb-8">Sign in to your NovrSOC workspace</p>

                    <form onSubmit={submit} className="space-y-4">
                        <input
                            type="text"
                            name="_gotcha"
                            value={gotcha}
                            onChange={(e) => setGotcha(e.target.value)}
                            className="hidden"
                            tabIndex={-1}
                            autoComplete="off"
                            aria-hidden="true"
                        />
                        <AuthField
                            label="Work Email"
                            type="email"
                            required
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            error={Boolean(error)}
                            placeholder="rayne@cybernovr.com"
                        />
                        <div className="relative">
                            <AuthField
                                label="Password"
                                type={showPassword ? 'text' : 'password'}
                                required
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                error={Boolean(error)}
                                className="pr-10"
                            />
                            <button
                                type="button"
                                onClick={() => setShowPassword((v) => !v)}
                                className="absolute right-3 top-9 text-foreground-muted hover:text-foreground transition-colors"
                                aria-label={showPassword ? 'Hide password' : 'Show password'}
                            >
                                {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                            </button>
                        </div>

                        <div className="text-right">
                            <Link href="/admin/dashboard" className="text-xs font-semibold text-purple hover:underline">
                                Forgot password?
                            </Link>
                        </div>

                        {error && <p className="text-xs text-red-500 text-center">{error}</p>}

                        <button
                            type="submit"
                            disabled={submitting}
                            className="w-full bg-purple hover:bg-purple-hover text-white font-bold py-3.5 rounded-xl transition-all text-sm uppercase tracking-wider disabled:opacity-50 disabled:cursor-not-allowed"
                        >
                            {submitting ? 'Signing in…' : 'Sign In'}
                        </button>
                    </form>

                    {/* Google Sign-In is hidden unless NEXT_PUBLIC_GOOGLE_OAUTH_ENABLED === 'true'.
                        Rendering it before the OAuth client is configured produces a 403 from
                        Google (origin not allowlisted) and a dead-looking button, which is worse
                        than not offering the option at all.

                        To turn it on, add BOTH of these origins in Google Cloud Console →
                        APIs & Services → Credentials → the OAuth 2.0 Client ID → Authorised
                        JavaScript origins:
                            https://novr-soc.vercel.app
                            http://localhost:3000
                        then set NEXT_PUBLIC_GOOGLE_OAUTH_ENABLED=true in Vercel and redeploy. */}
                    {googleOAuthEnabled && (
                        <>
                            <div className="flex items-center gap-3 my-6">
                                <div className="flex-1 h-px bg-border" />
                                <span className="text-foreground-muted text-xs">OR</span>
                                <div className="flex-1 h-px bg-border" />
                            </div>

                            <div className="w-full border border-border rounded-xl hover:border-purple/30 hover:bg-[#F5F0FF] transition-all">
                                <GoogleLogin
                                    onSuccess={handleGoogleSuccess}
                                    onError={() => setError('Google sign-in failed. Please try again.')}
                                    useOneTap={false}
                                    theme="outline"
                                    size="large"
                                    width="100%"
                                />
                            </div>
                        </>
                    )}
                </div>

                {/* Bottom — footer note */}
                <div className="text-center">
                    <p className="text-foreground-muted text-xs">
                        Client? Access your portal at{' '}
                        <Link href="/client/login" className="text-purple hover:underline">/client/login</Link>
                    </p>
                    <p className="text-grey-300 text-xs mt-2">Powered by Cybernovr</p>
                </div>
            </div>

            {/* Right panel — Nigeria map */}
            <NigeriaLoginMap />
        </div>
    );
}
