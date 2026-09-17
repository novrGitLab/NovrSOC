'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { Cloud } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';

// Cloud asset monitoring.
//
// Two kinds of content here, kept visually and structurally separate so they can never be
// confused for one another:
//
//   REAL      — the self-hosted tab lists actual Wazuh agents from GET /api/wazuh/agents. These
//               are machines genuinely being monitored today, so they are shown plainly.
//   PREVIEW   — the AWS tab shows example resources to illustrate what a connected account looks
//               like. They are behind a blur, under an explicit "example data" overlay, on a page
//               banner that says nothing is connected. Never remove that labelling: an EC2 list
//               that looks real would have an operator believing their AWS account is monitored.
//
// No AWS/Azure/GCP integration exists yet, so the Connect buttons are disabled rather than
// wired to a flow that would fail.

interface Agent {
    id: string;
    name: string;
    ip: string | null;
    status: string;
    os: string | null;
    group: string;
}

type ProviderId = 'aws' | 'azure' | 'gcp' | 'selfhosted';

const PROVIDERS: Array<{ id: ProviderId; name: string; icon: string; services: string[]; connected: boolean }> = [
    { id: 'selfhosted', name: 'Self-Hosted', icon: '🖥️', services: ['Wazuh agents', 'VPN endpoints'], connected: true },
    { id: 'aws', name: 'Amazon Web Services', icon: '☁️', services: ['EC2', 'S3', 'RDS', 'Lambda', 'CloudTrail', 'GuardDuty'], connected: false },
    { id: 'azure', name: 'Microsoft Azure', icon: '🔷', services: ['Virtual Machines', 'Blob Storage', 'Entra ID', 'Defender'], connected: false },
    { id: 'gcp', name: 'Google Cloud Platform', icon: '🌐', services: ['Compute Engine', 'Cloud Storage', 'Cloud Logging', 'Security Command Center'], connected: false },
];

// Illustrative only — see the header comment. Values are obviously-placeholder (x.x octets,
// truncated ids) so a screenshot can never be mistaken for a real inventory.
const EXAMPLE_AWS_ASSETS = [
    { id: 'i-0abc…456', kind: 'EC2 Instance', name: 'example-api-server', region: 'af-south-1 (Cape Town)', status: 'running', detail: 'Ubuntu 22.04 · 172.31.x.x', alerts: 0 },
    { id: 'i-0def…012', kind: 'EC2 Instance', name: 'example-db-server', region: 'af-south-1 (Cape Town)', status: 'running', detail: 'Amazon Linux 2 · private only', alerts: 2 },
    { id: 's3-example-logs', kind: 'S3 Bucket', name: 'example-audit-logs', region: 'af-south-1', status: 'active', detail: 'Private · 2.4 GB', alerts: 0 },
];

const AWS_CAPABILITIES = [
    { icon: '📋', title: 'CloudTrail', desc: 'API calls ingested as events' },
    { icon: '🛡️', title: 'GuardDuty', desc: 'Findings raised as alerts' },
    { icon: '📦', title: 'EC2 + S3', desc: 'Asset and exposure inventory' },
];

export function CloudAssets() {
    const [selected, setSelected] = useState<ProviderId>('selfhosted');
    const [agents, setAgents] = useState<Agent[] | null>(null);
    const [agentError, setAgentError] = useState(false);

    useEffect(() => {
        apiFetch(apiUrl('/api/wazuh/agents'), { cache: 'no-store', signal: AbortSignal.timeout(10000) })
            .then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
            .then((d) => setAgents(Array.isArray(d?.agents) ? d.agents : []))
            .catch(() => { setAgents([]); setAgentError(true); });
    }, []);

    return (
        <div className="space-y-5">
            <div className="flex items-start justify-between gap-4 flex-wrap">
                <div className="flex items-start gap-2.5">
                    <div className="w-8 h-8 rounded-lg bg-blue/10 flex items-center justify-center shrink-0">
                        <Cloud className="w-4 h-4 text-blue" />
                    </div>
                    <div>
                        <h1 className="text-lg font-black text-foreground">Cloud Assets</h1>
                        <p className="text-xs text-foreground-muted">Infrastructure &amp; Assets · Monitoring across hosting providers</p>
                    </div>
                </div>
                <div className="bg-amber-500/5 border border-amber-500/30 rounded-xl px-4 py-2">
                    <span className="text-[11px] font-bold text-amber-500">No cloud account connected — AWS/Azure/GCP views are examples</span>
                </div>
            </div>

            {/* Provider selector */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {PROVIDERS.map((p) => (
                    <button key={p.id} onClick={() => setSelected(p.id)}
                        className={`p-4 rounded-2xl border text-left transition-colors ${
                            selected === p.id ? 'border-purple bg-purple/5' : 'border-border bg-card hover:border-purple/40'
                        }`}>
                        <div className="text-2xl mb-2">{p.icon}</div>
                        <div className="text-xs font-black text-foreground mb-1">{p.name}</div>
                        <div className="flex items-center gap-1.5">
                            <div className={`w-1.5 h-1.5 rounded-full ${p.connected ? 'bg-green' : 'bg-card-muted'}`} />
                            <span className={`text-[9px] font-bold ${p.connected ? 'text-green' : 'text-foreground-muted'}`}>
                                {p.connected ? 'Monitored' : 'Not connected'}
                            </span>
                        </div>
                    </button>
                ))}
            </div>

            {/* Self-hosted — real agents */}
            {selected === 'selfhosted' && (
                <div className="bg-card border border-border rounded-xl overflow-hidden">
                    <div className="px-5 py-4 border-b border-border flex items-center gap-2 flex-wrap">
                        <div className="w-2 h-2 rounded-full bg-green" />
                        <h3 className="text-sm font-black text-foreground">Self-hosted infrastructure</h3>
                        <span className="text-[10px] text-foreground-muted">Live from the Wazuh manager</span>
                        <Link href="/admin/infra/assets" className="ml-auto text-[11px] font-bold text-purple hover:underline">
                            Full asset inventory →
                        </Link>
                    </div>

                    {agents === null ? (
                        <div className="p-5 space-y-2">{Array.from({ length: 3 }).map((_, i) => <div key={i} className="h-12 bg-card-muted rounded animate-pulse" />)}</div>
                    ) : agents.length === 0 ? (
                        <p className="px-5 py-8 text-center text-xs text-foreground-muted">
                            {agentError
                                ? 'Could not reach the Wazuh manager. This is a connectivity problem, not an empty inventory.'
                                : 'No agents are enrolled yet.'}
                        </p>
                    ) : (
                        <div className="divide-y divide-border">
                            {agents.map((a) => (
                                <Link key={a.id} href={`/admin/infra/assets/${encodeURIComponent(a.id)}`}
                                    className="flex items-center gap-4 px-5 py-4 hover:bg-card-muted/40 transition-colors">
                                    <div className="w-10 h-10 rounded-xl bg-purple/10 flex items-center justify-center shrink-0">
                                        <span className="text-lg">🖥️</span>
                                    </div>
                                    <div className="flex-1 min-w-0">
                                        <div className="text-sm font-bold text-foreground">{a.name}</div>
                                        <div className="text-xs text-foreground-muted truncate">{a.ip ?? 'no IP'} · {a.os ?? 'unknown OS'}</div>
                                    </div>
                                    <div className="text-right shrink-0">
                                        <div className={`text-[9px] font-bold px-2 py-0.5 rounded-full uppercase ${
                                            a.status === 'active' ? 'bg-green/10 text-green' : 'bg-card-muted text-foreground-muted'
                                        }`}>
                                            {a.status === 'active' ? 'Monitored' : a.status}
                                        </div>
                                        <div className="text-[10px] text-foreground-muted mt-0.5">agent {a.id}</div>
                                    </div>
                                </Link>
                            ))}
                        </div>
                    )}
                </div>
            )}

            {/* AWS — connection prompt plus a clearly-labelled example */}
            {selected === 'aws' && (
                <div className="space-y-4">
                    <div className="bg-card border border-border rounded-2xl p-5">
                        <div className="flex items-start gap-4 flex-wrap">
                            <span className="text-3xl">☁️</span>
                            <div className="flex-1 min-w-[260px]">
                                <h3 className="font-bold text-sm text-foreground mb-1">Connect AWS to NovrSOC</h3>
                                <p className="text-xs text-foreground-muted mb-4 leading-relaxed">
                                    NovrSOC would read CloudTrail events, GuardDuty findings and EC2/S3 inventory
                                    through a read-only IAM role. No agents required.
                                </p>
                                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-4">
                                    {AWS_CAPABILITIES.map((f) => (
                                        <div key={f.title} className="bg-card-muted/50 border border-border rounded-xl p-3 text-center">
                                            <div className="text-xl mb-1">{f.icon}</div>
                                            <div className="text-xs font-bold text-foreground">{f.title}</div>
                                            <div className="text-[10px] text-foreground-muted">{f.desc}</div>
                                        </div>
                                    ))}
                                </div>
                                <div className="flex items-center gap-3 flex-wrap">
                                    <button disabled title="AWS integration is not available yet"
                                        className="bg-card-muted text-foreground-muted border border-border font-bold px-4 py-2.5 rounded-xl text-xs cursor-not-allowed">
                                        Connect AWS — not yet available
                                    </button>
                                    <span className="text-[10px] text-foreground-muted">Will require a read-only IAM role, not access keys</span>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div className="relative">
                        {/* The blur and this overlay are what keep the list below from reading as a
                            real inventory. Do not remove them while the data is illustrative. */}
                        <div className="absolute inset-0 bg-card/70 backdrop-blur-[2px] rounded-2xl z-10 flex items-center justify-center">
                            <div className="text-center px-6">
                                <div className="text-2xl mb-2">🔒</div>
                                <div className="text-sm font-bold text-foreground">Connect AWS to see your real assets</div>
                                <div className="text-xs text-foreground-muted mt-1">Everything below is example data, not your account</div>
                            </div>
                        </div>
                        <div className="bg-card border border-border rounded-2xl overflow-hidden" aria-hidden="true">
                            <div className="px-5 py-4 border-b border-border">
                                <h3 className="text-sm font-black text-foreground">Assets — example only</h3>
                            </div>
                            <div className="divide-y divide-border">
                                {EXAMPLE_AWS_ASSETS.map((asset) => (
                                    <div key={asset.id} className="flex items-center gap-4 px-5 py-4">
                                        <div className="w-10 h-10 rounded-xl bg-orange/10 flex items-center justify-center shrink-0">
                                            <span className="text-lg">{asset.kind === 'EC2 Instance' ? '🖥️' : '🪣'}</span>
                                        </div>
                                        <div className="flex-1 min-w-0">
                                            <div className="text-sm font-bold text-foreground">{asset.name}</div>
                                            <div className="text-xs text-foreground-muted truncate">{asset.id} · {asset.region} · {asset.detail}</div>
                                        </div>
                                        <div className="text-right shrink-0">
                                            <div className="text-[9px] font-bold px-2 py-0.5 rounded-full uppercase bg-green/10 text-green">{asset.status}</div>
                                            {asset.alerts > 0 && <div className="text-[9px] text-red-500 font-bold mt-0.5">{asset.alerts} alerts</div>}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {(selected === 'azure' || selected === 'gcp') && (
                <div className="bg-card border border-border rounded-2xl p-8 text-center">
                    <div className="text-4xl mb-3">{selected === 'azure' ? '🔷' : '🌐'}</div>
                    <h3 className="font-bold text-foreground mb-2">
                        {selected === 'azure' ? 'Microsoft Azure' : 'Google Cloud Platform'}
                    </h3>
                    <p className="text-xs text-foreground-muted mb-4 max-w-md mx-auto leading-relaxed">
                        {selected === 'azure'
                            ? 'Would monitor Azure VMs, storage accounts, Entra ID sign-ins and Microsoft Defender alerts.'
                            : 'Would monitor Compute Engine instances, Cloud Storage buckets, Cloud Audit Logs and Security Command Center findings.'}
                    </p>
                    <span className="inline-flex items-center gap-2 bg-card-muted border border-border rounded-xl px-4 py-2 text-xs text-foreground-muted font-medium">
                        Planned — no integration built yet
                    </span>
                </div>
            )}

            {/* How it works */}
            <div className="bg-card border border-border rounded-xl p-5">
                <h3 className="text-sm font-black text-foreground mb-3">How cloud monitoring works</h3>
                <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
                    {[
                        { step: '01', text: 'Connect the cloud account with a read-only role.' },
                        { step: '02', text: 'NovrSOC ingests the provider’s audit log (CloudTrail, Activity Log, Cloud Audit Logs).' },
                        { step: '03', text: 'Findings surface in Alerts and Incidents alongside endpoint detections.' },
                        { step: '04', text: 'Cloud resources appear in Digital Assets next to your agents.' },
                    ].map((s) => (
                        <div key={s.step} className="bg-card-muted/40 border border-border rounded-xl p-3">
                            <div className="text-[10px] font-black text-purple mb-1">{s.step}</div>
                            <p className="text-[11px] text-foreground-muted leading-relaxed">{s.text}</p>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
}
