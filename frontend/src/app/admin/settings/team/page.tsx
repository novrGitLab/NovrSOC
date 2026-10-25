'use client';

import { useState } from 'react';
import { UserPlus, Search } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { getAdminUser } from '@/lib/admin-auth';
import { useTeamPresence, PresenceStats, PresenceCards, relativeTime, type TeamMemberPresence } from '@/components/features/TeamPresence';

// Team — live status on top (heartbeat presence), then the roster. The roster is the real
// platform_users table; invitations, password links and enable/disable call the real staff
// account endpoints (POST/PATCH /api/admin/users — super_admin only, same as this whole page).

type Role = 'super_admin' | 'soc_manager' | 'analyst' | 'executive';
const ROLE_BADGE: Record<string, string> = {
    super_admin: 'bg-purple/10 text-purple',
    soc_manager: 'bg-blue/10 text-blue',
    analyst: 'bg-green/10 text-green',
    executive: 'bg-amber/10 text-amber',
    viewer: 'bg-card-muted text-foreground-muted',
};
const ROLE_LABEL: Record<string, string> = {
    super_admin: 'Super Admin', soc_manager: 'SOC Manager', analyst: 'Analyst', executive: 'Executive', viewer: 'Viewer',
};

export default function TeamPage() {
    const { data, error, now, reload } = useTeamPresence();
    const isSuperAdmin = getAdminUser().role === 'super_admin';
    const [search, setSearch] = useState('');
    const [showInviteModal, setShowInviteModal] = useState(false);
    const [inviteEmail, setInviteEmail] = useState('');
    const [inviteName, setInviteName] = useState('');
    const [inviteRole, setInviteRole] = useState<Role>('analyst');
    const [inviting, setInviting] = useState(false);
    const [inviteError, setInviteError] = useState<string | null>(null);
    const [link, setLink] = useState<{ email: string; url: string; expires_at: string } | null>(null);
    const [acctMsg, setAcctMsg] = useState<string | null>(null);

    const members = data?.members ?? [];
    const filtered = members.filter((u) =>
        u.name.toLowerCase().includes(search.toLowerCase()) ||
        u.email.toLowerCase().includes(search.toLowerCase())
    );

    const sendInvite = async () => {
        if (!inviteEmail.trim()) return;
        setInviting(true);
        setInviteError(null);
        try {
            const created = await apiFetch(apiUrl('/api/admin/users'), {
                method: 'POST', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: inviteEmail.trim(), name: inviteName.trim() || undefined, role: inviteRole }),
            });
            const createdBody = await created.json().catch(() => null);
            if (!created.ok) { setInviteError(createdBody?.error ?? `HTTP ${created.status}`); return; }
            const linkRes = await apiFetch(apiUrl(`/api/admin/users/${createdBody.user.id}/password-link`), {
                method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ purpose: 'invite' }),
            });
            const linkBody = await linkRes.json().catch(() => null);
            setShowInviteModal(false);
            setInviteEmail(''); setInviteName(''); setInviteRole('analyst');
            if (linkRes.ok) setLink({ email: createdBody.user.email, url: linkBody.url, expires_at: linkBody.expires_at });
            else setAcctMsg(`${createdBody.user.email} was created, but the invite link could not be issued: ${linkBody?.error ?? `HTTP ${linkRes.status}`}`);
            reload();
        } catch {
            setInviteError('Could not reach the backend');
        } finally {
            setInviting(false);
        }
    };

    const accountAction = async (u: TeamMemberPresence, kind: 'link' | 'disable' | 'enable') => {
        setAcctMsg(null);
        try {
            const r = kind === 'link'
                ? await apiFetch(apiUrl(`/api/admin/users/${u.id}/password-link`), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ purpose: u.account_status === 'invited' ? 'invite' : 'reset' }) })
                : await apiFetch(apiUrl(`/api/admin/users/${u.id}`), { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ status: kind === 'disable' ? 'disabled' : 'active' }) });
            const d = await r.json().catch(() => null);
            if (!r.ok) { setAcctMsg(d?.error ?? `HTTP ${r.status}`); return; }
            if (kind === 'link') setLink({ email: u.email, url: d.url, expires_at: d.expires_at });
            else reload();
        } catch {
            setAcctMsg('Could not reach the backend');
        }
    };

    return (
        <div className="space-y-5">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-lg font-black text-foreground">Team Members</h1>
                    <p className="text-xs text-foreground-muted">Administration · Live status, activity and access</p>
                </div>
                {isSuperAdmin && (
                    <button
                        onClick={() => { setShowInviteModal(true); setInviteError(null); }}
                        className="flex items-center gap-2 bg-orange hover:bg-orange-hover text-white font-bold px-4 py-2.5 rounded-lg text-sm transition-colors"
                    >
                        <UserPlus size={14} />
                        Invite Member
                    </button>
                )}
            </div>

            {/* Live Team Status */}
            <section className="space-y-3">
                <div className="flex items-baseline justify-between gap-2 flex-wrap">
                    <h2 className="text-sm font-bold text-foreground">Live Team Status</h2>
                    <p className="text-[10px] text-foreground-muted">Online = active in the last 5 minutes · Away = tab in the background · refreshes every minute</p>
                </div>
                {error ? (
                    <p role="alert" className="text-xs text-red-500 bg-red-500/5 border border-red-500/30 rounded-lg px-3 py-2">{error}</p>
                ) : !data ? (
                    <div className="h-24 bg-card-muted/60 rounded-xl animate-pulse" />
                ) : (
                    <>
                        <PresenceStats members={members} />
                        <PresenceCards members={members} now={now} />
                        {data.history === 'since_restart' && (
                            <p className="text-[10px] text-foreground-muted">
                                Activity history covers only the time since the backend last restarted. Run backend/sql/2026-09-team-presence.sql in Supabase to keep it across restarts.
                            </p>
                        )}
                    </>
                )}
            </section>

            {/* Search */}
            <div className="relative">
                <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-foreground-muted" />
                <input
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    placeholder="Search by name or email..."
                    aria-label="Search team"
                    className="w-full max-w-sm pl-9 pr-4 py-2.5 border border-border rounded-lg text-sm bg-card
                               focus:outline-none focus:border-purple focus:ring-2 focus:ring-purple/10"
                />
            </div>

            {acctMsg && <p role="alert" className="text-xs text-red-500 font-semibold">{acctMsg}</p>}
            {link && (
                <div className="bg-card border border-border rounded-xl p-4 space-y-2">
                    <p className="text-xs font-bold text-foreground">Password link for {link.email} (shown once; expires {new Date(link.expires_at).toLocaleString()})</p>
                    <code className="block bg-card-muted border border-border rounded-lg px-3 py-2 text-[11px] font-mono break-all select-all">{link.url}</code>
                    <div className="flex gap-2">
                        <button onClick={() => { void navigator.clipboard.writeText(link.url); }} className="text-[11px] font-bold text-white bg-purple rounded-lg px-3 py-1.5">Copy</button>
                        <button onClick={() => setLink(null)} className="text-[11px] font-bold text-foreground border border-border rounded-lg px-3 py-1.5">Done</button>
                    </div>
                    <p className="text-[10px] text-foreground-muted">Send it to them directly. It works once; issuing a new link cancels this one.</p>
                </div>
            )}

            {/* Team table */}
            <div className="bg-card border border-border rounded-xl overflow-x-auto">
                <table className="w-full min-w-[640px]">
                    <thead>
                        <tr className="bg-foreground">
                            <th className="px-4 py-3 text-left text-xs font-semibold text-white">Member</th>
                            <th className="px-4 py-3 text-left text-xs font-semibold text-white">Role</th>
                            <th className="px-4 py-3 text-left text-xs font-semibold text-white">Account</th>
                            <th className="px-4 py-3 text-left text-xs font-semibold text-white">Last Active</th>
                            {isSuperAdmin && <th className="px-4 py-3 text-left text-xs font-semibold text-white">Actions</th>}
                        </tr>
                    </thead>
                    <tbody>
                        {!data ? (
                            <tr><td colSpan={5} className="px-4 py-10 text-center text-xs text-foreground-muted">{error ? 'Team unavailable.' : 'Loading team…'}</td></tr>
                        ) : filtered.length === 0 ? (
                            <tr>
                                <td colSpan={5} className="px-4 py-10 text-center text-xs text-foreground-muted">
                                    {search ? <>No team members match &ldquo;{search}&rdquo;.</> : 'No team members yet.'}
                                </td>
                            </tr>
                        ) : filtered.map((user, i) => (
                            <tr key={user.email} className={`border-b border-border last:border-0 ${i % 2 === 0 ? 'bg-card' : 'bg-card-muted'}`}>
                                <td className="px-4 py-3">
                                    <div className="flex items-center gap-3">
                                        <div className="w-8 h-8 rounded-full bg-purple text-white text-xs font-bold flex items-center justify-center flex-shrink-0">
                                            {user.name.split(/[\s@.]+/).filter(Boolean).map((p) => p[0]).join('').toUpperCase().slice(0, 2)}
                                        </div>
                                        <div>
                                            <div className="font-semibold text-sm text-foreground">{user.name}</div>
                                            <div className="text-xs text-foreground-muted">{user.email}</div>
                                        </div>
                                    </div>
                                </td>
                                <td className="px-4 py-3">
                                    <span className={`text-[10px] font-bold px-2 py-1 rounded-full uppercase ${ROLE_BADGE[user.role] ?? ROLE_BADGE.viewer}`}>
                                        {ROLE_LABEL[user.role] ?? user.role}
                                    </span>
                                </td>
                                <td className="px-4 py-3">
                                    <span className={`text-[10px] font-bold px-2 py-1 rounded-full uppercase ${user.account_status === 'disabled' ? 'bg-red-500/10 text-red-500' : user.account_status === 'invited' ? 'bg-amber/10 text-amber' : 'bg-green-500/10 text-green-600'}`}>
                                        {user.account_status}
                                    </span>
                                </td>
                                <td className="px-4 py-3 text-xs text-foreground-muted">{user.status === 'offline' ? relativeTime(user.last_active, now) : 'Now'}</td>
                                {isSuperAdmin && (
                                    <td className="px-4 py-3">
                                        <div className="flex items-center gap-2">
                                            {user.account_status !== 'disabled' && (
                                                <button onClick={() => void accountAction(user, 'link')} className="text-[10px] font-bold text-foreground border border-border rounded-lg px-2 py-1 whitespace-nowrap">
                                                    {user.account_status === 'invited' ? 'Invite link' : 'Reset link'}
                                                </button>
                                            )}
                                            <button
                                                onClick={() => { if (user.account_status !== 'disabled' && !window.confirm(`Disable ${user.email}? They will not be able to sign in.`)) return; void accountAction(user, user.account_status === 'disabled' ? 'enable' : 'disable'); }}
                                                className={`text-[10px] font-bold rounded-lg px-2 py-1 whitespace-nowrap ${user.account_status === 'disabled' ? 'text-foreground border border-border' : 'text-red-500'}`}
                                            >
                                                {user.account_status === 'disabled' ? 'Enable' : 'Disable'}
                                            </button>
                                        </div>
                                    </td>
                                )}
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
            <p className="text-[10px] text-foreground-muted">Roster from the platform_users table.</p>

            {/* Invite Modal */}
            {showInviteModal && (
                <div className="fixed inset-0 bg-black/40 backdrop-blur-sm z-50 flex items-center justify-center p-4">
                    <div className="bg-card rounded-2xl shadow-xl w-full max-w-md border border-border">
                        <div className="px-6 py-4 border-b border-border flex items-center justify-between">
                            <h2 className="font-bold text-base text-foreground">Invite Team Member</h2>
                            <button onClick={() => setShowInviteModal(false)} className="text-foreground-muted hover:text-foreground" aria-label="Close">✕</button>
                        </div>
                        <div className="p-6 space-y-4">
                            <div>
                                <label htmlFor="invite-name" className="block text-xs font-semibold text-foreground-muted uppercase tracking-wider mb-1.5">Name</label>
                                <input
                                    id="invite-name" type="text" value={inviteName}
                                    onChange={(e) => setInviteName(e.target.value)}
                                    className="w-full border border-border rounded-lg px-3 py-2.5 text-sm bg-card focus:outline-none focus:border-purple focus:ring-2 focus:ring-purple/10"
                                    placeholder="Jane Analyst"
                                />
                            </div>
                            <div>
                                <label htmlFor="invite-email" className="block text-xs font-semibold text-foreground-muted uppercase tracking-wider mb-1.5">
                                    Email Address
                                </label>
                                <input
                                    id="invite-email" type="email" value={inviteEmail}
                                    onChange={(e) => setInviteEmail(e.target.value)}
                                    className="w-full border border-border rounded-lg px-3 py-2.5 text-sm bg-card
                                               focus:outline-none focus:border-purple focus:ring-2 focus:ring-purple/10"
                                    placeholder="analyst@company.com"
                                />
                            </div>
                            <div>
                                <label htmlFor="invite-role" className="block text-xs font-semibold text-foreground-muted uppercase tracking-wider mb-1.5">
                                    Role
                                </label>
                                <select
                                    id="invite-role" value={inviteRole} onChange={(e) => setInviteRole(e.target.value as Role)}
                                    className="w-full border border-border rounded-lg px-3 py-2.5 text-sm bg-card focus:outline-none focus:border-purple"
                                >
                                    <option value="analyst">SOC Analyst — can view and action alerts</option>
                                    <option value="soc_manager">SOC Manager — manages the team and playbooks</option>
                                    <option value="executive">Executive — reports and posture</option>
                                    <option value="super_admin">Super Admin — full platform access</option>
                                </select>
                            </div>
                            {inviteRole === 'super_admin' && (
                                <p className="text-xs text-amber-700 bg-amber-500/10 border border-amber-500/30 rounded-lg p-3">
                                    Super Admin has full platform access across every organisation. Only invite someone you&apos;d trust with your own account.
                                </p>
                            )}
                            {inviteError && <p role="alert" className="text-xs text-red-500 font-semibold">{inviteError}</p>}
                            <p className="text-[10px] text-foreground-muted">
                                No email is sent automatically — a one-time sign-in link is shown here once the account is created, for you to send them directly.
                            </p>
                        </div>
                        <div className="px-6 py-4 border-t border-border flex justify-end gap-3">
                            <button onClick={() => setShowInviteModal(false)} className="text-sm text-foreground-muted px-4 py-2 rounded-lg hover:bg-card-muted">
                                Close
                            </button>
                            <button onClick={() => void sendInvite()} disabled={inviting || !inviteEmail.trim()} className="text-sm font-bold bg-orange hover:bg-orange-hover text-white px-5 py-2 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed">
                                {inviting ? 'Creating…' : 'Create & Get Link'}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
