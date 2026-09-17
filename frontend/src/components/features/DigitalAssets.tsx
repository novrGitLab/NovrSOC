'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { Monitor, WifiOff } from 'lucide-react';
import { getPortalContext } from '@/lib/portal-context';
import { apiUrl, apiFetch } from '@/lib/api';

interface Agent {
    id: string;
    name: string;
    ip: string | null;
    status: string;
    lastSeen: string | null;
    os: string | null;
    group: string;
}

const STATUS_BADGE: Record<string, string> = {
    active: 'bg-blue/10 text-blue border-blue/30',
    disconnected: 'bg-card-muted text-foreground-muted border-border',
    pending: 'bg-grey-100 text-amber border-amber/30',
    never_connected: 'bg-card-muted text-foreground-muted border-border',
};

function formatLastSeen(iso: string | null): string {
    if (!iso) return '—';
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return '—';
    return d.toLocaleString('en-GB', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' });
}

// GET /api/wazuh/agents (routes/wazuh.ts) only ever returns Shape 1 today — this also accepts
// a raw Wazuh Manager API passthrough shape defensively, in case that ever changes.
function normalizeAgents(data: unknown): Agent[] {
    const d = data as { agents?: unknown; data?: { affected_items?: unknown[] } } | null;
    if (Array.isArray(d?.agents)) return d.agents as Agent[];
    if (Array.isArray(d?.data?.affected_items)) {
        return d.data.affected_items.map((raw): Agent => {
            const a = raw as { id?: string; name?: string; ip?: string; status?: string; lastKeepAlive?: string; last_keepalive?: string; os?: { name?: string; full?: string }; group?: string | string[] };
            return {
                id: String(a.id ?? ''),
                name: a.name ?? '',
                ip: a.ip ?? null,
                status: a.status ?? 'never_connected',
                lastSeen: a.lastKeepAlive ?? a.last_keepalive ?? null,
                os: a.os?.name ?? a.os?.full ?? null,
                group: Array.isArray(a.group) ? a.group.join(', ') : (a.group ?? 'default'),
            };
        });
    }
    return [];
}

export function DigitalAssets() {
    const router = useRouter();
    const [search, setSearch] = useState('');
    const [agents, setAgents] = useState<Agent[] | null>(null);
    // Distinguishes "fetched successfully, zero agents enrolled" from "couldn't reach Wazuh
    // at all" — both used to render as the same "No assets registered yet." message, which
    // reads as "you have no assets" when the real story might be "we don't know."
    const [fetchFailed, setFetchFailed] = useState(false);

    useEffect(() => {
        // Deliberately NOT dropping the ?group= filter — this component is shared between
        // /admin/infra/assets and /client/infra/assets (app/admin & app/client both import
        // this same DigitalAssets). getPortalContext().wazuhGroup is already null for admin
        // users (they authenticate via admin_token, not the portal_token that carries
        // wazuhGroup — see lib/portal-context.ts), so admin's fetch is already unfiltered
        // today. Removing the filter unconditionally would instead break tenant isolation for
        // every client-portal user, who'd start seeing every other client's agents too.
        const group = getPortalContext().wazuhGroup;
        apiFetch(apiUrl(`/api/wazuh/agents${group ? `?group=${encodeURIComponent(group)}` : ''}`), { cache: 'no-store', signal: AbortSignal.timeout(10000) })
            .then(r => {
                if (!r.ok) throw new Error(`HTTP ${r.status}`);
                return r.json();
            })
            .then(data => setAgents(normalizeAgents(data)))
            .catch(() => {
                setAgents([]);
                setFetchFailed(true);
            });
    }, []);

    const filtered = (agents ?? []).filter(a => {
        if (!search) return true;
        const q = search.toLowerCase();
        return a.name.toLowerCase().includes(q) || (a.ip ?? '').includes(q);
    });

    const loading = agents === null;
    const total = agents?.length ?? 0;
    const online = agents?.filter(a => a.status === 'active').length ?? 0;

    return (
            <div className="space-y-4">
                <div>
                    <h1 className="text-lg font-black text-foreground">Asset Inventory</h1>
                    <p className="text-xs text-foreground-muted">Assets & Risk · Endpoints registered via the Wazuh agent</p>
                </div>

                {/* KPIs */}
                <div className="grid grid-cols-3 gap-3">
                    {[
                        { label: 'Total Assets', v: loading ? '...' : String(total), color: 'text-foreground' },
                        { label: 'Online', v: loading ? '...' : String(online), color: 'text-blue' },
                        { label: 'Offline', v: loading ? '...' : String(total - online), color: 'text-foreground-muted' },
                    ].map(k => (
                        <div key={k.label} className="bg-card border border-border rounded-xl p-3">
                            <div className="h-[3px] bg-blue from-blue via-blue to-red-500 -mt-3 -mx-3 mb-2 rounded-t-xl" />
                            <p className="text-[9px] font-bold text-foreground-muted uppercase tracking-wider">{k.label}</p>
                            <p className={`text-lg font-black ${k.color}`}>{k.v}</p>
                        </div>
                    ))}
                </div>

                {/* Search */}
                <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search assets, IPs…"
                    className="w-56 bg-card border border-border rounded-lg px-3 py-2 text-xs focus:outline-none focus:ring-2 focus:ring-blue/20 focus:border-blue text-foreground placeholder:text-foreground-muted" />

                <div className="bg-card border border-border rounded-xl overflow-hidden">
                    <div className="h-[3px] bg-blue from-blue via-blue to-red-500" />
                    {loading ? (
                        <div className="p-6 space-y-2">{Array.from({ length: 4 }).map((_, i) => <div key={i} className="h-6 bg-card-muted rounded animate-pulse" />)}</div>
                    ) : filtered.length === 0 ? (
                        <div className="text-center py-16">
                            <div className="w-12 h-12 rounded-full bg-[#F5F0FF] flex items-center justify-center mx-auto mb-4">
                                {fetchFailed
                                    ? <WifiOff size={20} className="text-red" />
                                    : <Monitor size={20} className="text-purple" />}
                            </div>
                            <h3 className="font-semibold text-sm text-foreground mb-1">
                                {fetchFailed ? 'Wazuh unreachable' : (search ? 'No matching assets' : 'No agents found')}
                            </h3>
                            <p className="text-xs text-foreground-muted max-w-xs mx-auto">
                                {fetchFailed
                                    ? 'Could not reach the Wazuh Manager to list enrolled agents. This is a connectivity problem, not necessarily an empty inventory — try again shortly.'
                                    : search
                                        ? 'No assets match your search.'
                                        : 'No agents are currently enrolled. Install the Wazuh agent on a device and point it at your organisation\'s configured Wazuh manager to see it appear here automatically.'}
                            </p>
                        </div>
                    ) : (
                        <div className="overflow-x-auto">
                            <table className="w-full text-xs">
                                <thead>
                                    <tr className="border-b border-border">
                                        {['Asset Name', 'IP', 'OS', 'Group', 'Status', 'Last Seen'].map(h => (
                                            <th key={h} className="text-left px-4 py-3 text-[10px] font-bold text-foreground-muted uppercase tracking-wider whitespace-nowrap">{h}</th>
                                        ))}
                                    </tr>
                                </thead>
                                <tbody>
                                    {filtered.map(a => (
                                        <tr
                                            key={a.id}
                                            // Whole row navigates to the asset detail page. Uses
                                            // router.push rather than wrapping each cell in a
                                            // <Link>, which is the only way to keep a valid
                                            // table structure (an <a> cannot wrap <td>s).
                                            onClick={() => router.push(`/admin/infra/assets/${encodeURIComponent(a.id)}`)}
                                            onKeyDown={(e) => { if (e.key === 'Enter') router.push(`/admin/infra/assets/${encodeURIComponent(a.id)}`); }}
                                            tabIndex={0}
                                            role="link"
                                            aria-label={`Open details for ${a.name}`}
                                            className="border-b border-border hover:bg-card-muted transition-colors cursor-pointer focus:outline-none focus:bg-card-muted"
                                        >
                                            <td className="px-4 py-2.5 font-bold text-foreground whitespace-nowrap">{a.name}</td>
                                            <td className="px-4 py-2.5 font-mono text-foreground-muted text-[10px]">{a.ip ?? '—'}</td>
                                            <td className="px-4 py-2.5 text-foreground-muted text-[10px]">{a.os ?? '—'}</td>
                                            <td className="px-4 py-2.5 text-foreground-muted">{a.group}</td>
                                            <td className="px-4 py-2.5">
                                                <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${STATUS_BADGE[a.status] ?? STATUS_BADGE.disconnected}`}>{a.status}</span>
                                            </td>
                                            <td className="px-4 py-2.5 text-foreground-muted whitespace-nowrap">{formatLastSeen(a.lastSeen)}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                    {!loading && filtered.length > 0 && (
                        <div className="px-4 py-3 border-t border-border">
                            <p className="text-[10px] text-foreground-muted">Showing {filtered.length} of {total} assets</p>
                        </div>
                    )}
                </div>
            </div>
    );
}
