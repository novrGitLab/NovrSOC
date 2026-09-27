// Team presence — who is signed in right now, and how active each person has been.
//
// Live status comes from heartbeats (POST /api/auth/heartbeat, every 2 minutes while the admin
// app is open) held in memory: presence is short-lived by nature, and a backend restart simply
// shows people offline until their next heartbeat (≤ 2 minutes).
//   Online  — heartbeat within 5 minutes from a visible tab
//   Away    — heartbeat within 5 minutes, tab hidden
//   Offline — no heartbeat for 5 minutes, or signed out
//
// History survives restarts only once backend/sql/2026-09-team-presence.sql has been run:
// platform_users.last_active and public.user_activity_days (one row per person per active WAT
// day, for the 7-day heatmap). Until then those writes fail quietly, reads fall back to what
// has been seen since the last restart, and the response says which applies.
import { getSupabase } from './geoEnrichment';

const ONLINE_WINDOW_MS = 5 * 60_000;

interface Live { lastBeat: number; visible: boolean; signedOut: boolean }
const live = new Map<string, Live>();
const memoryDays = new Map<string, Set<string>>(); // email -> WAT days seen since restart

// Whether the optional history schema exists; learned on first write, re-checked hourly.
let historySupported: boolean | null = null;
let historyCheckedAt = 0;

const watDay = (ms: number) => new Date(ms + 3600_000).toISOString().slice(0, 10);

export async function recordPresence(email: string, event: 'login' | 'heartbeat' | 'logout', visible = true): Promise<void> {
    const key = email.toLowerCase();
    const now = Date.now();
    live.set(key, { lastBeat: now, visible, signedOut: event === 'logout' });
    const supabase = getSupabase();
    if (event === 'logout') {
        if (supabase && historySupported !== false) await supabase.from('platform_users').update({ is_online: false }).ilike('email', key);
        return;
    }

    const day = watDay(now);
    const seen = memoryDays.get(key) ?? new Set<string>();
    const firstToday = !seen.has(day);
    seen.add(day);
    memoryDays.set(key, seen);

    if (!supabase) return;
    if (event === 'login') {
        // last_login already exists on platform_users.
        await supabase.from('platform_users').update({ last_login: new Date(now).toISOString() }).ilike('email', key);
    }
    if (historySupported === false && now - historyCheckedAt < 3600_000) return;
    // last_active on every heartbeat; the activity row only once per day per person.
    const [a, b] = await Promise.all([
        supabase.from('platform_users').update({ last_active: new Date(now).toISOString(), is_online: true }).ilike('email', key),
        firstToday || event === 'login'
            ? supabase.from('user_activity_days').upsert({ email: key, day }, { onConflict: 'email,day' })
            : Promise.resolve({ error: null }),
    ]);
    historySupported = !a.error && !b.error;
    historyCheckedAt = now;
}

export type PresenceStatus = 'online' | 'away' | 'offline';

export interface TeamMemberPresence {
    email: string;
    name: string;
    role: string;
    account_status: string;
    status: PresenceStatus;
    last_active: string | null;
    active_days: string[];          // WAT dates (YYYY-MM-DD) in the last 7 days
    cases_assigned: number;         // open cases assigned to them
    avg_response_hrs: number | null; // this week: case created -> their first action on it
    response_sample: number;
}

function statusFor(email: string): PresenceStatus {
    const l = live.get(email);
    if (!l || l.signedOut || Date.now() - l.lastBeat > ONLINE_WINDOW_MS) return 'offline';
    return l.visible ? 'online' : 'away';
}

export async function teamPresence(): Promise<{ members: TeamMemberPresence[]; history: 'database' | 'since_restart' }> {
    const supabase = getSupabase();
    if (!supabase) return { members: [], history: 'since_restart' };
    const now = Date.now();
    const weekAgo = new Date(now - 7 * 24 * 3600_000);
    const days = Array.from({ length: 7 }, (_, i) => watDay(now - (6 - i) * 24 * 3600_000));

    const [usersRes, daysRes, openRes] = await Promise.all([
        supabase.from('platform_users').select('*'),
        supabase.from('user_activity_days').select('email, day').gte('day', days[0]),
        supabase.from('cases').select('assigned_to').neq('status', 'resolved').not('assigned_to', 'is', null),
    ]);
    const users = (usersRes.data ?? []) as { email: string; name: string | null; role: string; status: string | null; last_login: string | null; last_active?: string | null }[];
    const history: 'database' | 'since_restart' = daysRes.error ? 'since_restart' : 'database';

    const openByName = new Map<string, number>();
    for (const c of openRes.data ?? []) openByName.set(c.assigned_to, (openByName.get(c.assigned_to) ?? 0) + 1);

    // Response time this week: for each case, the analyst's first manual timeline entry.
    const emails = users.map((u) => u.email.toLowerCase());
    const { data: tl } = emails.length
        ? await supabase.from('case_timeline').select('case_id, actor, created_at').eq('automated', false)
            .gte('created_at', weekAgo.toISOString()).in('actor', emails).order('created_at')
        : { data: [] as { case_id: string; actor: string; created_at: string }[] };
    const firstByCase = new Map<string, { actor: string; at: number }>();
    for (const t of tl ?? []) if (!firstByCase.has(`${t.actor}|${t.case_id}`)) firstByCase.set(`${t.actor}|${t.case_id}`, { actor: t.actor, at: Date.parse(t.created_at) });
    const caseIds = [...new Set([...firstByCase.keys()].map((k) => k.split('|')[1]))];
    const { data: created } = caseIds.length
        ? await supabase.from('cases').select('id, created_at').in('id', caseIds.slice(0, 500))
        : { data: [] as { id: string; created_at: string }[] };
    const createdAt = new Map((created ?? []).map((c) => [c.id, Date.parse(c.created_at)]));

    const members = users.map((u) => {
        const email = u.email.toLowerCase();
        const dbDays = (daysRes.data ?? []).filter((d) => d.email === email).map((d) => d.day);
        const activeDays = [...new Set([...(history === 'database' ? dbDays : []), ...(memoryDays.get(email) ?? [])])].filter((d) => d >= days[0]).sort();
        const beat = live.get(email)?.lastBeat;
        const lastActive = [beat ? new Date(beat).toISOString() : null, u.last_active ?? null, u.last_login]
            .filter((x): x is string => !!x).sort().at(-1) ?? null;
        const responses = [...firstByCase.entries()]
            .filter(([k]) => k.startsWith(`${email}|`))
            .map(([k, v]) => { const c = createdAt.get(k.split('|')[1]); return c ? v.at - c : NaN; })
            .filter((ms) => Number.isFinite(ms) && ms >= 0);
        return {
            email,
            name: u.name || u.email,
            role: u.role,
            account_status: u.status ?? 'active',
            status: statusFor(email),
            last_active: lastActive,
            active_days: activeDays,
            cases_assigned: openByName.get(u.name || '') ?? 0,
            avg_response_hrs: responses.length ? Math.round((responses.reduce((s, x) => s + x, 0) / responses.length / 3600_000) * 10) / 10 : null,
            response_sample: responses.length,
        };
    });
    return { members, history };
}
