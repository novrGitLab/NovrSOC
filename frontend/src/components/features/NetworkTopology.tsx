'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { Network, Server, AlertTriangle, ShieldCheck, Router, WifiOff } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { findFirewallAgent, type WazuhAgentSummary } from '@/lib/firewallAgent';

// Network topology, powered by the OPNsense firewall.
//
// Everything shown is read live: whether the firewall is connected comes from the Wazuh agent
// list (GET /api/wazuh/agents), and its events from that agent's own alerts
// (GET /api/wazuh/agents/:id/alerts). The previous version of this page drew a hardcoded
// set of "connections" — including a malicious one — none of which were real, so it has been
// replaced rather than moved.
//
// DHCP lease inventory and a traffic-flow map need OPNsense's logs decoded on the manager.
// Until those decoders exist the page says so, instead of drawing links it can't back up.

interface AgentAlert {
    timestamp: string;
    description: string;
    level: number;
    rule_id: string | number;
    mitre_tactic: string | null;
    source_ip: string | null;
}

type State =
    | { kind: 'loading' }
    | { kind: 'error'; message: string }
    | { kind: 'ready'; agents: WazuhAgentSummary[]; firewall: WazuhAgentSummary | null };

const wat = (iso: string | null | undefined) =>
    iso ? `${new Date(iso).toLocaleString('en-GB', { timeZone: 'Africa/Lagos', day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' })} WAT` : '—';

const LEVEL_STYLE = (level: number) =>
    level >= 13 ? 'bg-red-500/10 text-red-500' : level >= 10 ? 'bg-orange/10 text-orange' : level >= 7 ? 'bg-amber-500/10 text-amber-500' : 'bg-card-muted text-foreground-muted';

const WILL_SHOW = [
    { icon: '📱', title: 'All connected devices', desc: 'Every device on the network, from DHCP leases' },
    { icon: '🔀', title: 'Traffic flows', desc: 'Which devices communicate with each other and the internet' },
    { icon: '🛡️', title: 'Firewall rules', desc: 'Active rules allowing and blocking traffic' },
    { icon: '🚨', title: 'IDS alerts', desc: 'Suricata intrusion detection alerts' },
];

export function NetworkTopology() {
    const [state, setState] = useState<State>({ kind: 'loading' });
    const [alerts, setAlerts] = useState<{ agentId: string; items: AgentAlert[]; error?: string } | null>(null);

    useEffect(() => {
        apiFetch(apiUrl('/api/wazuh/agents'), { cache: 'no-store' })
            .then(async (r) => {
                const data = await r.json().catch(() => null);
                if (!r.ok || !data) throw new Error(`Wazuh agent list unavailable (HTTP ${r.status})`);
                const agents: WazuhAgentSummary[] = Array.isArray(data.agents) ? data.agents : [];
                setState({ kind: 'ready', agents, firewall: findFirewallAgent(agents) });
            })
            .catch((e: unknown) => setState({ kind: 'error', message: e instanceof Error ? e.message : 'Could not reach the backend' }));
    }, []);

    const firewall = state.kind === 'ready' ? state.firewall : null;
    const firewallId = firewall?.id ?? null;

    useEffect(() => {
        if (!firewallId) return;
        apiFetch(apiUrl(`/api/wazuh/agents/${firewallId}/alerts?limit=25`), { cache: 'no-store' })
            .then((r) => r.json())
            .then((d) => setAlerts({ agentId: firewallId, items: Array.isArray(d?.alerts) ? d.alerts : [], error: d?.error }))
            .catch(() => setAlerts({ agentId: firewallId, items: [], error: 'Could not load firewall events' }));
    }, [firewallId]);

    if (state.kind === 'loading') {
        return <div className="space-y-3">{Array.from({ length: 3 }).map((_, i) => <div key={i} className="h-24 bg-card-muted/60 rounded-xl animate-pulse" />)}</div>;
    }

    if (state.kind === 'error') {
        return (
            <div className="max-w-2xl mx-auto py-12 text-center">
                <AlertTriangle className="w-8 h-8 text-red-500 mx-auto mb-3" />
                <h1 className="text-lg font-black text-foreground mb-1">Network Topology</h1>
                <p className="text-xs text-foreground-muted">Could not check for the firewall: {state.message}. The page can&apos;t tell whether OPNsense is connected until the Wazuh agent list loads.</p>
            </div>
        );
    }

    // ── Not connected ────────────────────────────────────────────────────────────────────
    if (!firewall) {
        return (
            <div className="max-w-2xl mx-auto py-12 text-center">
                <div className="w-16 h-16 bg-amber-500/10 rounded-2xl flex items-center justify-center mx-auto mb-5">
                    <Network className="w-8 h-8 text-amber-500" />
                </div>
                <h1 className="text-2xl font-black text-foreground mb-2">Network Topology</h1>
                <p className="text-sm text-foreground-muted mb-6">
                    Network topology maps every device, traffic flow and connection on your network. It is powered by the OPNsense firewall integration.
                </p>

                <div className="bg-amber-500/5 border border-amber-500/30 rounded-2xl p-5 mb-6 text-left">
                    <p className="text-sm font-bold text-amber-600 mb-1">OPNsense not connected</p>
                    <p className="text-xs text-foreground-muted mb-3">
                        None of the {state.agents.length} Wazuh agent{state.agents.length === 1 ? '' : 's'} is an OPNsense firewall, so there is no network data to show yet. Nothing on this page is simulated.
                    </p>
                    <Link href="/admin/infra/opnsense-setup" className="text-xs text-purple font-bold hover:underline">Set up OPNsense →</Link>
                </div>

                <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider mb-2 text-left">What this will show once connected</p>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-left">
                    {WILL_SHOW.map((f) => (
                        <div key={f.title} className="bg-card border border-border rounded-xl p-4">
                            <div className="text-2xl mb-2" aria-hidden>{f.icon}</div>
                            <p className="text-xs font-bold text-foreground mb-1">{f.title}</p>
                            <p className="text-[10px] text-foreground-muted">{f.desc}</p>
                        </div>
                    ))}
                </div>
            </div>
        );
    }

    // ── Connected (registered) ───────────────────────────────────────────────────────────
    const online = firewall.status === 'active';
    const fwAlerts = alerts?.agentId === firewall.id ? alerts : null;
    const others = state.agents.filter((a) => a.id !== firewall.id);

    return (
        <div className="space-y-5">
            <div className="flex items-start justify-between gap-3 flex-wrap">
                <div>
                    <h1 className="text-2xl font-black text-foreground">Network Topology</h1>
                    <p className="text-sm text-foreground-muted mt-1">Live network view from OPNsense</p>
                </div>
                <div className={`flex items-center gap-2 border rounded-xl px-4 py-2 ${online ? 'bg-green/10 border-green/30' : 'bg-red-500/5 border-red-500/30'}`}>
                    {online ? <span className="w-2 h-2 rounded-full bg-green animate-pulse" /> : <WifiOff size={13} className="text-red-500" />}
                    <span className={`text-xs font-bold ${online ? 'text-green' : 'text-red-500'}`}>
                        {online ? 'OPNsense connected' : `OPNsense ${firewall.status.replace('_', ' ')} — last seen ${wat(firewall.lastSeen)}`}
                    </span>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                <div className="bg-card border border-border rounded-xl p-5">
                    <div className="flex items-center gap-2 mb-3">
                        <Router size={16} className="text-purple" />
                        <h2 className="text-sm font-bold text-foreground">Firewall</h2>
                    </div>
                    <dl className="text-xs space-y-2">
                        {[
                            ['Agent', `${firewall.name} (${firewall.id})`],
                            ['Address', firewall.ip || '—'],
                            ['OS', firewall.os || '—'],
                            ['Status', firewall.status],
                            ['Last seen', wat(firewall.lastSeen)],
                        ].map(([k, v]) => (
                            <div key={k} className="flex justify-between gap-3">
                                <dt className="text-foreground-muted">{k}</dt>
                                <dd className="font-bold text-foreground text-right break-all">{v}</dd>
                            </div>
                        ))}
                    </dl>
                    <Link href={`/admin/infra/assets/${firewall.id}`} className="inline-block mt-4 text-[11px] font-bold text-purple hover:underline">Open asset detail →</Link>
                </div>

                <div className="lg:col-span-2 bg-card border border-border rounded-xl p-5">
                    <div className="flex items-center gap-2 mb-3">
                        <ShieldCheck size={16} className="text-orange" />
                        <h2 className="text-sm font-bold text-foreground">Firewall &amp; IDS events</h2>
                        <span className="text-[10px] text-foreground-muted ml-auto">Wazuh alerts from the firewall agent</span>
                    </div>
                    {fwAlerts === null ? (
                        <div className="space-y-2">{Array.from({ length: 4 }).map((_, i) => <div key={i} className="h-8 bg-card-muted rounded animate-pulse" />)}</div>
                    ) : fwAlerts.error ? (
                        <p className="text-xs text-red-500">{fwAlerts.error}</p>
                    ) : fwAlerts.items.length === 0 ? (
                        <p className="text-xs text-foreground-muted py-4">No alerts from the firewall yet. Suricata and filter-log events appear here once their decoders fire on the manager.</p>
                    ) : (
                        <div className="divide-y divide-border">
                            {fwAlerts.items.map((a, i) => (
                                <div key={`${a.timestamp}-${i}`} className="flex items-center gap-3 py-2 text-xs">
                                    <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded shrink-0 ${LEVEL_STYLE(a.level)}`}>L{a.level}</span>
                                    <span className="text-foreground flex-1 min-w-0 truncate" title={a.description}>{a.description}</span>
                                    {a.source_ip && <span className="font-mono text-[10px] text-foreground-muted shrink-0">{a.source_ip}</span>}
                                    <span className="text-[10px] text-foreground-muted shrink-0 whitespace-nowrap">{wat(a.timestamp)}</span>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            </div>

            <div className="bg-card border border-border rounded-xl p-5">
                <div className="flex items-center gap-2 mb-3">
                    <Server size={16} className="text-blue" />
                    <h2 className="text-sm font-bold text-foreground">Monitored endpoints</h2>
                    <span className="text-[10px] text-foreground-muted ml-auto">{others.length} other Wazuh agent{others.length === 1 ? '' : 's'}</span>
                </div>
                {others.length === 0 ? (
                    <p className="text-xs text-foreground-muted">No other agents registered.</p>
                ) : (
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                        {others.map((a) => (
                            <Link key={a.id} href={`/admin/infra/assets/${a.id}`} className="flex items-center gap-2.5 p-3 rounded-lg border border-border hover:border-purple/40 transition-colors">
                                <span className={`w-2 h-2 rounded-full shrink-0 ${a.status === 'active' ? 'bg-green' : 'bg-foreground-muted'}`} />
                                <div className="min-w-0">
                                    <p className="text-xs font-bold text-foreground truncate">{a.name}</p>
                                    <p className="text-[10px] text-foreground-muted font-mono truncate">{a.ip || '—'} · {a.status}</p>
                                </div>
                            </Link>
                        ))}
                    </div>
                )}
                <p className="text-[10px] text-foreground-muted mt-3">
                    These are the endpoints Wazuh monitors. The device inventory from DHCP leases and the traffic-flow map need OPNsense&apos;s DHCP and filter logs decoded on the manager — not built yet, so no links between devices are drawn.
                </p>
            </div>
        </div>
    );
}
