'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import { Inbox, Search } from 'lucide-react';
import { useEmailApi, PageHeader, Panel, Gate, Empty, SevBadge, Badge, ErrorNote, SetupNotice, inputCls, wat, label, th, td } from './shared';
import { useEmailSecurity } from './context';
import { ProviderCards, providerName } from './providers';

// Messaging Suite — are dangerous emails reaching your users?
// Email sources (Microsoft 365, Google Workspace, NovrSOC Mail Gateway) with their verified state,
// then email activity from those sources. NovrSOC reads provider telemetry; the action shown on a
// message is what the PROVIDER did — NovrSOC never claims to have blocked anything itself.

export interface EventRow {
    id: string; provider: string; message_id: string | null; sender: string | null; sender_domain: string | null; recipient: string | null; subject: string | null; received_at: string;
    source_ip: string | null; spf: string | null; dkim: string | null; dmarc: string | null; detection: string; categories: string[]; severity: string; action: string; action_by: string; alert_id: string | null;
}

type Filter = 'all' | 'threat' | 'suspicious' | 'clean' | 'quarantine';
const FILTERS: { id: Filter; label: string; qs: string }[] = [
    { id: 'all', label: 'All', qs: '' }, { id: 'threat', label: 'Threats', qs: 'risk=threat' }, { id: 'suspicious', label: 'Suspicious', qs: 'risk=suspicious' },
    { id: 'clean', label: 'Clean', qs: 'risk=clean' }, { id: 'quarantine', label: 'Quarantined', qs: 'view=quarantine' },
];

/** Provider action shown as status: what happened to the message, and who did it. */
function MessageStatus({ e }: { e: EventRow }) {
    const delivered = e.action === 'allow' || e.action === 'flag';
    const text = e.action === 'quarantine' ? 'Quarantined' : e.action === 'block' ? 'Blocked' : e.action === 'flag' ? 'Delivered · flagged' : 'Delivered';
    return (
        <span>
            <Badge tone={delivered ? (e.action === 'flag' ? 'amber' : 'grey') : 'green'}><span aria-hidden className="mr-1">{delivered ? (e.action === 'flag' ? '⚠' : '○') : '✓'}</span>{text}</Badge>
            {!delivered && e.action_by !== 'none' && <span className="block text-[10px] text-foreground-muted mt-0.5">by {e.action_by}</span>}
        </span>
    );
}

export function EventsTable({ events }: { events: EventRow[] }) {
    return (
        <div className="overflow-x-auto -m-4">
            <table className="w-full text-xs min-w-[860px]">
                <thead><tr className="border-b border-border">{['Time', 'Sender', 'Recipient', 'Subject', 'Provider', 'Risk', 'Status'].map((h) => <th key={h} className={th}>{h}</th>)}</tr></thead>
                <tbody>
                    {events.map((e) => (
                        <tr key={e.id} className="border-b border-border/60 last:border-0 hover:bg-card-muted/40 align-top">
                            <td className={`${td} whitespace-nowrap text-foreground-muted`}><Link href={`/admin/email/messaging/${e.id}`} className="hover:text-purple">{wat(e.received_at)}</Link></td>
                            <td className={`${td} max-w-[200px] wrap-anywhere`}>{e.sender ?? '—'}</td>
                            <td className={`${td} max-w-[180px] wrap-anywhere`}>{e.recipient ?? '—'}</td>
                            <td className={`${td} max-w-[240px]`}>
                                <Link href={`/admin/email/messaging/${e.id}`} className="line-clamp-2 font-bold text-foreground hover:text-purple wrap-anywhere">{e.subject ?? <span className="font-normal text-foreground-muted">(subject not provided)</span>}</Link>
                                {e.detection !== 'clean' && <span className="text-[10px] text-foreground-muted">{label(e.detection)}{e.alert_id ? ' · alert open' : ''}</span>}
                            </td>
                            <td className={`${td} text-foreground-muted whitespace-nowrap`}>{providerName(e.provider)}</td>
                            <td className={td}>{e.detection === 'clean' ? <Badge tone="grey"><span aria-hidden className="mr-1">✓</span>Clean</Badge> : <SevBadge s={e.severity} />}</td>
                            <td className={td}><MessageStatus e={e} /></td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}

export function MessagingSuite() {
    const { providers, notSetUp } = useEmailSecurity();
    const params = useSearchParams();
    const callback = params.get('provider') ? { provider: params.get('provider')!, result: params.get('result') ?? '', detail: params.get('detail') ?? '' } : null;
    const [filter, setFilter] = useState<Filter>('all');
    const [q, setQ] = useState('');
    const [search, setSearch] = useState('');
    const qs = [FILTERS.find((f) => f.id === filter)!.qs, search ? `q=${encodeURIComponent(search)}` : ''].filter(Boolean).join('&');
    const events = useEmailApi<{ events: EventRow[] }>(notSetUp ? null : `/messaging/events${qs ? `?${qs}` : ''}`);
    const anyConnected = providers.some((p) => p.status === 'connected');

    return (
        <div className="space-y-5">
            <PageHeader title="Messaging Suite" subtitle="Monitor email threats across Microsoft 365, Google Workspace and the NovrSOC Mail Gateway." />
            {callback && (callback.result === 'connected'
                ? <p role="status" className="text-xs font-bold text-green bg-green/5 border border-green/30 rounded-lg px-3 py-2">{providerName(callback.provider)} connected and verified.</p>
                : <ErrorNote message={`${providerName(callback.provider)}: ${label(callback.result)} — ${callback.detail}`} />)}
            {notSetUp ? <SetupNotice message={notSetUp} /> : (
                <>
                    <section aria-labelledby="sources-h" className="space-y-2">
                        <h2 id="sources-h" className="text-xs font-black text-foreground uppercase tracking-wider">Email sources</h2>
                        <ProviderCards />
                        <p className="text-[10px] text-foreground-muted">Connected sources sync every 10 minutes. NovrSOC reads security telemetry and message metadata only — never mailbox contents.</p>
                    </section>

                    <Panel title="Email activity" action={
                        <form onSubmit={(e) => { e.preventDefault(); setSearch(q.trim()); }} className="flex items-center gap-1.5 min-w-0">
                            <label className="relative min-w-0">
                                <span className="sr-only">Search email activity</span>
                                <Search size={12} className="absolute left-2 top-1/2 -translate-y-1/2 text-foreground-muted" aria-hidden />
                                <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Sender, recipient, subject or message ID" className={`${inputCls} pl-7 w-64 max-w-full`} />
                            </label>
                        </form>
                    }>
                        <div role="tablist" aria-label="Filter email activity" className="flex flex-wrap gap-1.5 mb-3">
                            {FILTERS.map((f) => (
                                <button key={f.id} role="tab" aria-selected={filter === f.id} onClick={() => setFilter(f.id)}
                                    className={`text-[11px] font-bold px-2.5 py-1 rounded-full border ${filter === f.id ? 'bg-purple text-white border-purple' : 'border-border text-foreground-muted hover:text-foreground'}`}>{f.label}</button>
                            ))}
                            {search && <button onClick={() => { setSearch(''); setQ(''); }} className="text-[11px] font-bold text-purple hover:underline ml-1">Clear search “{search}”</button>}
                        </div>
                        <Gate state={events}>
                            {(events.data?.events ?? []).length === 0 ? (
                                <Empty icon={<Inbox size={18} />}
                                    title={filter !== 'all' || search ? 'No email events match' : 'No email events received yet'}
                                    body={filter !== 'all' || search ? 'Try another filter or search.' : anyConnected ? 'Connected sources have not reported any messages yet.' : 'Connect an email source above to start receiving email security telemetry.'} />
                            ) : <EventsTable events={events.data!.events} />}
                        </Gate>
                        <p className="text-[10px] text-foreground-muted mt-3">Newest 200 shown. Status is the action taken by the mail provider.</p>
                    </Panel>
                </>
            )}
        </div>
    );
}
