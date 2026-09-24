'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { CheckCircle2, Circle, Copy, Check, AlertTriangle } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { GUIDES, type GuideId } from '@/lib/setupGuides';
import type { WazuhAgentSummary } from '@/lib/firewallAgent';

// Setup guide shell for the sensor pages. Live status comes from GET /api/wazuh/agents; the
// manager address in the commands from GET /api/wazuh/enrollment. When the address isn't
// available the commands show a visible placeholder rather than a guessed IP.

const PLACEHOLDER = '<manager-address>';

function CodeBlock({ code }: { code: string }) {
    const [copied, setCopied] = useState(false);
    const copy = () => {
        void navigator.clipboard?.writeText(code).then(() => {
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
        }).catch(() => {});
    };
    return (
        <div className="relative mt-2">
            <pre className="bg-grey-900 text-grey-100 text-[11px] leading-relaxed rounded-lg p-3 pr-12 overflow-x-auto whitespace-pre font-mono" style={{ backgroundColor: '#1C1F2E', color: '#E6E8F0' }}>{code}</pre>
            <button
                onClick={copy}
                aria-label={copied ? 'Copied' : 'Copy to clipboard'}
                className="absolute top-2 right-2 p-1.5 rounded-md bg-white/10 hover:bg-white/20 text-white transition-colors"
            >
                {copied ? <Check size={13} /> : <Copy size={13} />}
            </button>
        </div>
    );
}

export function SetupGuide({ guide: id }: { guide: GuideId }) {
    const guide = GUIDES[id];
    const [agents, setAgents] = useState<{ list: WazuhAgentSummary[] } | { error: string } | null>(null);
    const [manager, setManager] = useState<string | null>(null);

    useEffect(() => {
        apiFetch(apiUrl('/api/wazuh/agents'), { cache: 'no-store' })
            .then(async (r) => {
                const d = await r.json().catch(() => null);
                if (!r.ok || !d) throw new Error(`HTTP ${r.status}`);
                setAgents({ list: Array.isArray(d.agents) ? d.agents : [] });
            })
            .catch((e: unknown) => setAgents({ error: e instanceof Error ? e.message : 'unavailable' }));
        apiFetch(apiUrl('/api/wazuh/enrollment'), { cache: 'no-store' })
            .then((r) => (r.ok ? r.json() : null))
            .then((d) => { if (d?.manager) setManager(String(d.manager)); })
            .catch(() => {});
    }, []);

    const matched = agents && 'list' in agents ? guide.matchAgents(agents.list) : [];
    const active = matched.filter((a) => a.status === 'active');
    const fill = (code: string) => code.replaceAll('{{MANAGER}}', manager ?? PLACEHOLDER);

    return (
        <div className="space-y-5 max-w-4xl">
            <div>
                <h1 className="text-lg font-black text-foreground">{guide.title}</h1>
                <p className="text-xs text-foreground-muted">{guide.subtitle}</p>
            </div>

            <p className="text-sm text-foreground-muted">{guide.intro}</p>

            {/* Live status */}
            <div className={`rounded-xl border p-4 ${active.length > 0 ? 'bg-green/5 border-green/30' : 'bg-card border-border'}`}>
                <div className="flex items-center gap-2">
                    {agents === null ? (
                        <span className="text-xs text-foreground-muted">Checking the Wazuh manager…</span>
                    ) : 'error' in agents ? (
                        <>
                            <AlertTriangle size={15} className="text-amber-500" />
                            <span className="text-xs text-foreground">Could not read the agent list ({agents.error}) — status unknown.</span>
                        </>
                    ) : active.length > 0 ? (
                        <>
                            <CheckCircle2 size={15} className="text-green" />
                            <span className="text-xs font-bold text-foreground">{active.length} {guide.matchLabel} reporting</span>
                        </>
                    ) : (
                        <>
                            <Circle size={15} className="text-foreground-muted" />
                            <span className="text-xs font-bold text-foreground">
                                {matched.length > 0 ? `${matched.length} ${guide.matchLabel} registered, none online` : `No ${guide.matchLabel} yet`}
                            </span>
                        </>
                    )}
                </div>
                {matched.length > 0 && (
                    <div className="flex flex-wrap gap-2 mt-3">
                        {matched.map((a) => (
                            <Link key={a.id} href={`/admin/infra/assets/${a.id}`} className="flex items-center gap-1.5 text-[11px] px-2.5 py-1 rounded-full border border-border hover:border-purple/40">
                                <span className={`w-1.5 h-1.5 rounded-full ${a.status === 'active' ? 'bg-green' : 'bg-foreground-muted'}`} />
                                <span className="font-bold text-foreground">{a.name}</span>
                                <span className="text-foreground-muted">{a.status.replace('_', ' ')}</span>
                            </Link>
                        ))}
                    </div>
                )}
                <p className="text-[10px] text-foreground-muted mt-2">{guide.statusNote}</p>
            </div>

            {!manager && (
                <p className="text-[11px] text-amber-600">
                    The manager address isn&apos;t configured on the backend (WAZUH_AGENT_MANAGER or WAZUH_HOST), so commands show {PLACEHOLDER} — replace it with your manager&apos;s address.
                </p>
            )}

            <ol className="space-y-3">
                {guide.steps.map((step, i) => (
                    <li key={step.title} className="bg-card border border-border rounded-xl p-4 sm:p-5">
                        <div className="flex items-start gap-3">
                            <span className="w-6 h-6 rounded-full bg-purple/10 text-purple text-xs font-black flex items-center justify-center shrink-0">{i + 1}</span>
                            <div className="min-w-0 flex-1">
                                <h2 className="text-sm font-bold text-foreground">{step.title}</h2>
                                <p className="text-xs text-foreground-muted mt-1 leading-relaxed">{step.body}</p>
                                {step.code && <CodeBlock code={fill(step.code)} />}
                            </div>
                        </div>
                    </li>
                ))}
            </ol>
        </div>
    );
}
