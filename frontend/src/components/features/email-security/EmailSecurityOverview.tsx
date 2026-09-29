'use client';

import { useState } from 'react';
import Link from 'next/link';
import { RefreshCw, ShieldCheck, Fingerprint, Inbox } from 'lucide-react';
import { useEmailApi, PageHeader, Panel, Kpi, Gate, Empty, SevBadge, StatusBadge, Button, Badge, wat, label, n, th, td } from './shared';

// Email Security command center: one view over the three modules. Every figure is computed by
// GET /api/email-security/overview from stored telemetry; a figure whose source isn't connected
// is null and shown as "Not available" with what to connect — never as 0.

interface Overview {
    setup: { domains: boolean; reports: boolean; brand: boolean; providers: boolean };
    kpis: {
        protected_domains: number; dmarc_compliance: number | null; spoofing_attempts: number | null; phishing_domains: number | null;
        active_phishing_threats: number | null; malicious_emails: number | null; quarantined_emails: number | null; critical_alerts: number;
    };
    dmarc: { passing: number; failing: number; unknown_senders: number; sending_sources: number; reports: number };
    phishing: { new_7d: number; high_risk: number; active_sites: number; suspicious_urls: number };
    messaging: { threats: number; quarantined: number; malicious_urls: number; malicious_attachments: number; providers: string[] };
    recent_alerts: { id: string; severity: string; detection_type: string; source_module: string; modules: string[]; entity: string; title: string; status: string; last_seen: string; occurrences: number }[];
    generated_at: string;
}
interface Integrations { integrations: { id: string; label: string; state: 'configured' | 'not_configured'; detail: string; used_by: string[] }[]; opencti: { ok: boolean; detail: string } }

const MODULE: Record<string, string> = { dmarc: 'DMARC', phishid: 'Phish ID', messaging: 'Messaging' };
const PROVIDER: Record<string, string> = { microsoft365: 'Microsoft 365', google_workspace: 'Google Workspace', gateway: 'Mail gateway' };

function Stat({ label: l, value, available = true }: { label: string; value: number; available?: boolean }) {
    return (
        <div className="flex items-baseline justify-between gap-3 py-1.5 border-b border-border/60 last:border-0">
            <span className="text-xs text-foreground-muted">{l}</span>
            <span className="text-sm font-black text-foreground">{available ? n(value) : '—'}</span>
        </div>
    );
}

export function EmailSecurityOverview() {
    const [nonce, setNonce] = useState(0);
    const ov = useEmailApi<Overview>('/overview', nonce);
    const integ = useEmailApi<Integrations>('/integrations', nonce);
    const d = ov.data;
    const k = d?.kpis;

    return (
        <div className="space-y-5">
            <PageHeader
                title="Email Security"
                subtitle={<>Domain authentication, brand impersonation and mail threats in one view.{d ? ` Updated ${wat(d.generated_at)}.` : ''}</>}
                actions={<Button onClick={() => setNonce((x) => x + 1)} busy={ov.loading}><RefreshCw size={12} /> Refresh</Button>}
            />

            <Gate state={ov} rows={6}>
                {d && k && (
                    <>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                            <Kpi label="Protected Domains" value={d.setup.domains ? k.protected_domains : null} hint="Add a domain in DMARC SaaS" />
                            <Kpi label="DMARC Compliance (30d)" value={k.dmarc_compliance} suffix="%" hint={d.setup.domains ? 'No DMARC reports received yet' : 'Connect a domain'}
                                tone={k.dmarc_compliance === null ? undefined : k.dmarc_compliance >= 98 ? 'good' : k.dmarc_compliance >= 90 ? 'warn' : 'danger'} />
                            <Kpi label="Spoofing Attempts (30d)" value={k.spoofing_attempts} hint="Needs DMARC aggregate reports" tone={k.spoofing_attempts ? 'danger' : undefined} />
                            <Kpi label="Phishing Domains" value={k.phishing_domains} hint="Configure your brand in Phish ID" tone={k.phishing_domains ? 'warn' : undefined} />
                            <Kpi label="Active Phishing Threats" value={k.active_phishing_threats} hint="Configure your brand in Phish ID" tone={k.active_phishing_threats ? 'danger' : undefined} />
                            <Kpi label="Malicious Emails (30d)" value={k.malicious_emails} hint="Connect a mail provider" tone={k.malicious_emails ? 'danger' : undefined} />
                            <Kpi label="Quarantined (30d)" value={k.quarantined_emails} hint="Connect a mail provider" />
                            <Kpi label="Critical Email Alerts" value={k.critical_alerts} tone={k.critical_alerts ? 'danger' : 'good'} />
                        </div>

                        <Panel title="Recent Email Security Alerts" action={<span className="text-[10px] text-foreground-muted">Observations of the same incident are grouped into one alert</span>}>
                            {d.recent_alerts.length === 0 ? (
                                <Empty title="No email security alerts" body={d.setup.domains || d.setup.brand || d.setup.providers ? 'Nothing has crossed an alert threshold yet.' : 'Alerts appear once a domain, your brand or a mail provider is connected.'} />
                            ) : (
                                <div className="overflow-x-auto -m-4">
                                    <table className="w-full text-xs min-w-[760px]">
                                        <thead><tr className="border-b border-border">{['Severity', 'Detection', 'Source', 'Target', 'Module', 'Status', 'Time'].map((h) => <th key={h} className={th}>{h}</th>)}</tr></thead>
                                        <tbody>
                                            {d.recent_alerts.map((a) => (
                                                <tr key={a.id} className="border-b border-border/60 last:border-0 hover:bg-card-muted/40">
                                                    <td className={td}><SevBadge s={a.severity} /></td>
                                                    <td className={td}><Link href={`/admin/email/alerts/${a.id}`} className="font-bold text-foreground hover:text-purple">{label(a.detection_type)}</Link><p className="text-[10px] text-foreground-muted line-clamp-1 max-w-[260px]">{a.title}</p></td>
                                                    <td className={`${td} text-foreground-muted whitespace-nowrap`}>{a.modules.map((m) => MODULE[m] ?? m).join(' + ')}</td>
                                                    <td className={`${td} font-mono text-[11px] text-foreground break-all max-w-[200px]`}>{a.entity}</td>
                                                    <td className={td}><Badge tone="purple">{MODULE[a.source_module] ?? a.source_module}</Badge></td>
                                                    <td className={td}><StatusBadge s={a.status} /></td>
                                                    <td className={`${td} text-foreground-muted whitespace-nowrap`}>{wat(a.last_seen)}{a.occurrences > 1 && <span className="block text-[10px]">{a.occurrences} observations</span>}</td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            )}
                        </Panel>

                        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                            <Panel title={<span className="flex items-center gap-1.5"><ShieldCheck size={13} /> DMARC Activity (30d)</span>} action={<Link href="/admin/email/dmarc" className="text-[10px] font-bold text-purple hover:underline">Open →</Link>}>
                                {!d.setup.domains ? <Empty title="No domains connected" body="Add your first protected domain to begin monitoring SPF, DKIM and DMARC." />
                                    : !d.setup.reports ? <Empty title="No DMARC reports yet" body="Point your DMARC rua= address at the NovrSOC report inbox, or upload a report." />
                                    : <><Stat label="Passing messages" value={d.dmarc.passing} /><Stat label="Failed messages" value={d.dmarc.failing} /><Stat label="Unknown / suspicious senders" value={d.dmarc.unknown_senders} /><Stat label="Sending sources" value={d.dmarc.sending_sources} /></>}
                            </Panel>
                            <Panel title={<span className="flex items-center gap-1.5"><Fingerprint size={13} /> Phishing Activity</span>} action={<Link href="/admin/email/phishid" className="text-[10px] font-bold text-purple hover:underline">Open →</Link>}>
                                {!d.setup.brand ? <Empty title="No brand configured" body="Add your organisation's domains and brand assets to begin monitoring for impersonation." />
                                    : <><Stat label="Newly discovered domains (7d)" value={d.phishing.new_7d} /><Stat label="High-risk domains" value={d.phishing.high_risk} /><Stat label="Active phishing sites" value={d.phishing.active_sites} /><Stat label="Suspicious URLs in email (30d)" value={d.phishing.suspicious_urls} available={d.setup.providers} /></>}
                            </Panel>
                            <Panel title={<span className="flex items-center gap-1.5"><Inbox size={13} /> Messaging Activity (30d)</span>} action={<Link href="/admin/email/messaging" className="text-[10px] font-bold text-purple hover:underline">Open →</Link>}>
                                {!d.setup.providers ? <Empty title="No mail provider connected" body="Connect Microsoft 365, Google Workspace or the NovrSOC mail gateway to collect authorised email-security telemetry." />
                                    : <><Stat label="Threats detected" value={d.messaging.threats} /><Stat label="Quarantined" value={d.messaging.quarantined} /><Stat label="Malicious URLs" value={d.messaging.malicious_urls} /><Stat label="Malicious attachments" value={d.messaging.malicious_attachments} />
                                        <p className="text-[10px] text-foreground-muted mt-2">From {d.messaging.providers.map((p) => PROVIDER[p] ?? p).join(', ')}.</p></>}
                            </Panel>
                        </div>
                    </>
                )}
            </Gate>

            <Panel title="Integration health" action={<span className="text-[10px] text-foreground-muted">Configured means credentials are present — connections are verified on their own pages</span>}>
                <Gate state={integ}>
                    {integ.data && (
                        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-2">
                            {integ.data.integrations.map((i) => (
                                <div key={i.id} className="flex items-start gap-2 border border-border rounded-lg px-3 py-2">
                                    <span className={`mt-1 w-2 h-2 rounded-full shrink-0 ${i.state === 'configured' ? 'bg-green' : 'bg-grey-300'}`} aria-hidden />
                                    <div className="min-w-0">
                                        <p className="text-xs font-bold text-foreground">{i.label} <span className="font-normal text-foreground-muted">· {i.state === 'configured' ? 'Configured' : 'Not connected'}</span></p>
                                        <p className="text-[10px] text-foreground-muted break-words">{i.id === 'opencti' && i.state === 'configured' ? `${integ.data!.opencti.ok ? 'Reachable' : 'Unreachable'}: ${integ.data!.opencti.detail}` : i.detail}</p>
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </Gate>
            </Panel>
        </div>
    );
}
