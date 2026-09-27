'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { apiUrl, apiFetch } from '@/lib/api';

// Team presence (GET /api/admin/team/presence): live status from heartbeats, plus last active,
// 7-day activity, open cases assigned and response time this week — all real. Exports:
//   useTeamPresence()      — the data, refreshed every 60s
//   PresenceStats          — the stat row
//   PresenceCards          — analyst cards
//   TeamPresenceWidget     — self-fetching stat row, for Security Assessment

export type PresenceStatus = 'online' | 'away' | 'offline';
export interface TeamMemberPresence {
    email: string; name: string; role: string; account_status: string; status: PresenceStatus;
    last_active: string | null; active_days: string[]; cases_assigned: number;
    avg_response_hrs: number | null; response_sample: number;
}
export interface PresenceData { members: TeamMemberPresence[]; history: 'database' | 'since_restart'; generated_at: string }

const REFRESH_MS = 60_000;
const EXEC_ROLES = new Set(['executive']);

export function useTeamPresence() {
    const [data, setData] = useState<PresenceData | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [now, setNow] = useState(() => Date.now());
    useEffect(() => {
        let active = true;
        const load = () => apiFetch(apiUrl('/api/admin/team/presence'), { cache: 'no-store' })
            .then(async (r) => {
                const d = await r.json().catch(() => null);
                if (!active) return;
                if (!r.ok || !d) { setError(r.status === 403 ? 'Team presence is visible to managers and executives.' : d?.error ?? `HTTP ${r.status}`); return; }
                setError(null);
                setData(d as PresenceData);
                setNow(Date.now());
            })
            .catch(() => { if (active) setError('Could not reach the backend'); });
        void load();
        const id = setInterval(load, REFRESH_MS);
        return () => { active = false; clearInterval(id); };
    }, []);
    return { data, error, now };
}

export function relativeTime(iso: string | null, now: number): string {
    if (!iso) return 'Never';
    const mins = Math.floor((now - Date.parse(iso)) / 60_000);
    if (mins < 1) return 'Just now';
    if (mins < 60) return `${mins} minute${mins === 1 ? '' : 's'} ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs} hour${hrs === 1 ? '' : 's'} ago`;
    const days = Math.floor(hrs / 24);
    return days === 1 ? 'Yesterday' : `${days} days ago`;
}

const DOT: Record<PresenceStatus, { cls: string; label: string }> = {
    online: { cls: 'bg-green', label: 'Online' },
    away: { cls: 'bg-amber-500', label: 'Away' },
    offline: { cls: 'bg-grey-300', label: 'Offline' },
};

export function PresenceStats({ members }: { members: TeamMemberPresence[] }) {
    const analysts = members.filter((m) => !EXEC_ROLES.has(m.role));
    const execs = members.filter((m) => EXEC_ROLES.has(m.role));
    const tiles = [
        { label: 'Analysts Online', value: analysts.filter((m) => m.status !== 'offline').length, colour: '#16A34A' },
        { label: 'Analysts Offline', value: analysts.filter((m) => m.status === 'offline').length, colour: '#7A8099' },
        { label: 'Executives Online', value: execs.filter((m) => m.status !== 'offline').length, colour: '#2B3BCC' },
        { label: 'Active This Week', value: members.filter((m) => m.active_days.length > 0).length, colour: '#1C1F2E' },
    ];
    return (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {tiles.map((t) => (
                <div key={t.label} className="bg-card border border-border rounded-xl p-4">
                    <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">{t.label}</p>
                    <p className="text-2xl font-black mt-1" style={{ color: t.colour }}>{t.value}</p>
                </div>
            ))}
        </div>
    );
}

// The last 7 WAT days, oldest first, as YYYY-MM-DD.
function lastSevenDays(now: number): string[] {
    return Array.from({ length: 7 }, (_, i) => new Date(now + 3600_000 - (6 - i) * 86_400_000).toISOString().slice(0, 10));
}

export function PresenceCards({ members, now }: { members: TeamMemberPresence[]; now: number }) {
    const days = lastSevenDays(now);
    return (
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-3">
            {members.map((m) => {
                const dot = DOT[m.status];
                const initials = m.name.split(/[\s@.]+/).filter(Boolean).map((p) => p[0]).join('').toUpperCase().slice(0, 2);
                return (
                    <div key={m.email} className="bg-card border border-border rounded-xl p-4 space-y-3">
                        <div className="flex items-center gap-3">
                            <div className="relative shrink-0">
                                <div className="w-10 h-10 rounded-full text-white text-sm font-bold flex items-center justify-center" style={{ backgroundColor: '#6B1FA8' }}>{initials}</div>
                                <span className={`absolute -bottom-0.5 -right-0.5 w-3 h-3 rounded-full border-2 border-card ${dot.cls}`} aria-hidden />
                            </div>
                            <div className="min-w-0">
                                <p className="text-sm font-bold text-foreground truncate">{m.name}</p>
                                <p className="text-[11px] text-foreground-muted capitalize">{m.role.replace('_', ' ')}</p>
                            </div>
                            <span className="ml-auto text-[10px] font-bold text-foreground-muted flex items-center gap-1.5 shrink-0">
                                <span className={`w-2 h-2 rounded-full ${dot.cls}`} aria-hidden /> {dot.label}
                            </span>
                        </div>
                        <dl className="grid grid-cols-3 gap-2 text-center">
                            <div><dt className="text-[9px] uppercase tracking-wider text-foreground-muted">Last seen</dt><dd className="text-[11px] font-bold text-foreground">{m.status === 'offline' ? relativeTime(m.last_active, now) : 'Now'}</dd></div>
                            <div><dt className="text-[9px] uppercase tracking-wider text-foreground-muted">Open cases</dt><dd className="text-[11px] font-bold text-foreground"><Link href="/admin/secops/cases" className="hover:underline">{m.cases_assigned}</Link></dd></div>
                            <div><dt className="text-[9px] uppercase tracking-wider text-foreground-muted">Avg response</dt><dd className="text-[11px] font-bold text-foreground" title={m.response_sample ? `${m.response_sample} case${m.response_sample === 1 ? '' : 's'} this week` : 'No cases actioned this week'}>{m.avg_response_hrs === null ? '—' : `${m.avg_response_hrs}h`}</dd></div>
                        </dl>
                        <div>
                            <p className="text-[9px] uppercase tracking-wider text-foreground-muted mb-1">Active days (last 7)</p>
                            <div className="flex gap-1" role="img" aria-label={`Active on ${m.active_days.filter((d) => days.includes(d)).length} of the last 7 days`}>
                                {days.map((d) => {
                                    const on = m.active_days.includes(d);
                                    const label = new Intl.DateTimeFormat('en-GB', { weekday: 'short', day: '2-digit', timeZone: 'UTC' }).format(new Date(`${d}T00:00:00Z`));
                                    return <span key={d} title={`${label}: ${on ? 'active' : 'no activity'}`} className="flex-1 h-4 rounded-sm" style={{ backgroundColor: on ? '#2B3BCC' : 'var(--color-card-muted, #EEF0F6)' }} />;
                                })}
                            </div>
                        </div>
                    </div>
                );
            })}
        </div>
    );
}

/** Stat row only — self-fetching, for embedding on other pages. */
export function TeamPresenceWidget() {
    const { data, error } = useTeamPresence();
    if (error) return null; // not permitted / unreachable: the host page carries on without it
    return (
        <div className="space-y-1.5">
            <div className="flex items-center justify-between">
                <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">SOC team right now</p>
                <Link href="/admin/settings/team" className="text-[10px] font-bold text-purple hover:underline">Team →</Link>
            </div>
            {data ? <PresenceStats members={data.members} /> : <div className="h-20 bg-card-muted/60 rounded-xl animate-pulse" />}
        </div>
    );
}
