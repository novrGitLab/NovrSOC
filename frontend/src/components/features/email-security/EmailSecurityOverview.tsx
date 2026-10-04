'use client';

import Link from 'next/link';
import { Settings2, ShieldCheck, Inbox, Fingerprint } from 'lucide-react';
import { useEmailApi, PageHeader, Panel, Gate, Empty, SevBadge, StatusBadge, Badge, SetupNotice, wat, label, th, td } from './shared';
import { useEmailSecurity, domainReadiness, isVerified } from './context';
import { providerName } from './providers';

// Email Security command centre: "How secure is our email right now?"
// Posture, setup status, domain health and recent activity — all from the backend. Where a
// source isn't connected the figure says so; nothing is estimated or filled in.

interface Overview {
    kpis: { dmarc_compliance: number | null; critical_alerts: number };
    recent_alerts: { id: string; severity: string; detection_type: string; source_module: string; modules: string[]; entity: string; title: string; status: string; last_seen: string; occurrences: number }[];
}
const MODULE: Record<string, string> = { dmarc: 'DMARC', phishid: 'Phish ID', messaging: 'Messaging' };
const READINESS: Record<string, string> = { ready: 'protected', attention: 'warning', incomplete: 'pending' };

function Metric({ label: l, value, note }: { label: string; value: string | number; note?: string }) {
    return (
        <div className="bg-card border border-border rounded-xl p-4 min-w-0">
            <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">{l}</p>
            <p className="text-2xl font-black text-foreground mt-1 truncate">{value}</p>
            {note && <p className="text-[10px] text-foreground-muted mt-0.5">{note}</p>}
        </div>
    );
}

function AuthCell({ s }: { s: string | null }) {
    if (!s) return <span className="text-foreground-muted">—</span>;
    const sym = s === 'pass' ? '✓' : s === 'warn' ? '⚠' : s === 'not_found' ? '○' : '✕';
    const tone = s === 'pass' ? 'text-green' : s === 'warn' ? 'text-amber-600' : s === 'not_found' ? 'text-foreground-muted' : 'text-red-500';
    return <span className={`font-bold ${tone}`} title={label(s)}>{sym} <span className="sr-only">{label(s)}</span></span>;
}

export function EmailSecurityOverview() {
    const { domains, providers, setup, loading, notSetUp, error } = useEmailSecurity();
    const ov = useEmailApi<Overview>('/overview');
    const open = useEmailApi<{ alerts: { id: string }[] }>('/alerts?status=open');
    const connected = providers.filter((p) => p.status === 'connected');
    const scores = domains.map((d) => d.health_score).filter((x): x is number => typeof x === 'number');
    const health = scores.length ? `${Math.round(scores.reduce((a, b) => a + b, 0) / scores.length)}/100` : 'Not configured';

    return (
        <div className="space-y-5">
            <PageHeader
                title="Email Security"
                subtitle="Protect your domains, email infrastructure and organisation from spoofing, phishing and malicious email."
                actions={<Link href="/admin/email/setup" className="inline-flex items-center gap-1.5 text-[11px] font-bold rounded-lg px-3 py-1.5 border bg-purple text-white border-purple hover:opacity-90"><Settings2 size={12} /> Configure Email Security</Link>}
            />
            {notSetUp ? <SetupNotice message={notSetUp} /> : (
                <Gate state={{ loading, error, setup: null }} rows={5}>
                    <section aria-label="Security posture" className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                        <Metric label="Domains" value={domains.length} note={domains.length ? `${domains.filter(isVerified).length} verified · ${domains.filter((d) => domainReadiness(d).state === 'ready').length} fully protected` : 'Add a domain to begin'} />
                        <Metric label="Connected providers" value={connected.length} note={connected.length ? connected.map((p) => providerName(p.provider)).join(', ') : 'None connected yet'} />
                        <Metric label="Active threats" value={open.data ? open.data.alerts.length : '—'} note={open.data ? 'Open Email Security alerts' : open.error ? 'Unavailable' : undefined} />
                        <Metric label="Authentication health" value={health} note={scores.length ? `Average across ${scores.length} domain${scores.length === 1 ? '' : 's'}${ov.data?.kpis.dmarc_compliance != null ? ` · DMARC pass rate ${ov.data.kpis.dmarc_compliance}%` : ''}` : 'Inspect a domain to measure'} />
                    </section>

                    {setup.status === 'active' ? (
                        <Panel title="Email Security is active">
                            <ul className="flex flex-wrap gap-x-6 gap-y-1 text-xs text-foreground">
                                <li>✓ Domain protection</li><li>✓ DMARC monitoring</li><li>✓ Email monitoring</li>
                            </ul>
                        </Panel>
                    ) : (
                        <section className="bg-card border border-purple/30 rounded-xl p-4 flex flex-col md:flex-row md:items-center gap-4 justify-between">
                            <div className="min-w-0">
                                <h2 className="text-sm font-black text-foreground">Email Security setup</h2>
                                <p className="text-xs text-foreground-muted mt-0.5">Your organisation is not fully configured — {setup.completed} of {setup.total} steps complete.</p>
                                <ul className="mt-2 grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-0.5 text-xs">
                                    {setup.steps.slice(0, 4).map((s) => <li key={s.id} className={s.done ? 'text-foreground' : 'text-foreground-muted'}><span aria-hidden className="inline-block w-4">{s.done ? '✓' : '○'}</span>{s.title}<span className="sr-only">{s.done ? ' — done' : ' — not done'}</span></li>)}
                                </ul>
                            </div>
                            <Link href="/admin/email/setup" className="shrink-0 inline-flex items-center justify-center text-xs font-bold rounded-lg px-4 py-2 bg-purple text-white hover:opacity-90">{setup.completed ? 'Continue setup' : 'Start setup'}</Link>
                        </section>
                    )}

                    <Panel title={<span className="flex items-center gap-1.5"><ShieldCheck size={13} /> Domain health</span>} action={<Link href="/admin/email/dmarc" className="text-[10px] font-bold text-purple hover:underline">DMARC SaaS →</Link>}>
                        {domains.length === 0 ? (
                            <Empty title="No domains configured yet" body="Add your first domain to begin protecting your email identity." action={<Link href="/admin/email/setup" className="text-xs font-bold text-purple hover:underline">Add domain →</Link>} />
                        ) : (
                            <div className="overflow-x-auto -m-4">
                                <table className="w-full text-xs min-w-[640px]">
                                    <thead><tr className="border-b border-border">{['Domain', 'Verification', 'SPF', 'DKIM', 'DMARC', 'Status'].map((h) => <th key={h} className={th}>{h}</th>)}</tr></thead>
                                    <tbody>
                                        {domains.map((d) => {
                                            const r = domainReadiness(d);
                                            return (
                                                <tr key={d.id} className="border-b border-border/60 last:border-0 hover:bg-card-muted/40">
                                                    <td className={td}><Link href={`/admin/email/dmarc/${encodeURIComponent(d.domain)}`} className="font-bold text-foreground hover:text-purple wrap-anywhere">{d.domain}</Link></td>
                                                    <td className={td}><StatusBadge s={d.verification?.state === 'verified' ? 'verified' : d.verification?.state ?? 'not_verified'} /></td>
                                                    <td className={td}><AuthCell s={d.spf_status} /></td>
                                                    <td className={td}><AuthCell s={d.dkim_status} /></td>
                                                    <td className={td}><AuthCell s={d.dmarc_status} /></td>
                                                    <td className={td}><StatusBadge s={READINESS[r.state]} /><p className="text-[10px] text-foreground-muted mt-0.5">{r.reason}</p></td>
                                                </tr>
                                            );
                                        })}
                                    </tbody>
                                </table>
                            </div>
                        )}
                    </Panel>

                    <Panel title="Recent security activity" action={<span className="text-[10px] text-foreground-muted hidden sm:inline">Observations of one incident are grouped into one alert</span>}>
                        <Gate state={ov}>
                            {!ov.data?.recent_alerts.length ? (
                                <Empty title="No security activity yet" body={domains.length || connected.length ? 'Nothing has crossed an alert threshold.' : 'Activity appears once a domain is monitored or a mail provider is connected.'} />
                            ) : (
                                <ul className="divide-y divide-border -my-2">
                                    {ov.data.recent_alerts.map((a) => (
                                        <li key={a.id} className="py-2.5 flex items-start gap-3 min-w-0">
                                            <SevBadge s={a.severity} />
                                            <div className="min-w-0 flex-1">
                                                <Link href={`/admin/email/alerts/${a.id}`} className="text-xs font-bold text-foreground hover:text-purple">{label(a.detection_type)}</Link>
                                                <p className="text-[11px] text-foreground-muted wrap-anywhere">{a.title}</p>
                                            </div>
                                            <div className="text-right shrink-0">
                                                <div className="flex gap-1 justify-end flex-wrap">{a.modules.map((m) => <Badge key={m} tone="purple">{MODULE[m] ?? m}</Badge>)}</div>
                                                <p className="text-[10px] text-foreground-muted mt-1 whitespace-nowrap">{wat(a.last_seen)}</p>
                                            </div>
                                        </li>
                                    ))}
                                </ul>
                            )}
                        </Gate>
                    </Panel>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                        {[
                            { href: '/admin/email/dmarc', icon: ShieldCheck, title: 'DMARC SaaS', body: 'Domain authentication, sending sources and spoofing.' },
                            { href: '/admin/email/phishid', icon: Fingerprint, title: 'Intellicode Phish ID', body: 'Look-alike domains and brand impersonation.' },
                            { href: '/admin/email/messaging', icon: Inbox, title: 'Messaging Suite', body: 'Threats in your mail from connected providers.' },
                        ].map((c) => (
                            <Link key={c.href} href={c.href} className="bg-card border border-border rounded-xl p-3 hover:border-purple/40 flex gap-3">
                                <c.icon size={16} className="text-purple shrink-0 mt-0.5" aria-hidden />
                                <span><span className="font-bold text-foreground block">{c.title}</span><span className="text-foreground-muted">{c.body}</span></span>
                            </Link>
                        ))}
                    </div>
                </Gate>
            )}
        </div>
    );
}
