'use client';

import { Fragment, useMemo, useState } from 'react';
import Link from 'next/link';
import { useTheme } from 'next-themes';
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { Plus, Upload, RefreshCw, ShieldCheck, ChevronDown, ChevronRight } from 'lucide-react';
import {
    useEmailApi, send, useRole, isManager, PageHeader, Panel, Kpi, Tabs, Gate, Empty, StatusBadge, Badge, Button, Feedback,
    inputCls, selectCls, wat, day, n, th, td,
} from './shared';

// DMARC SaaS — who is sending mail as your domains, and are they authorised?
// Domains (with live SPF / DKIM / DMARC inspection), sending sources and aggregate reports.

export interface EmailDomain {
    id: string; domain: string; status: string; dmarc_policy: string | null; spf_status: string | null; dkim_status: string | null; dmarc_status: string | null;
    health_score: number | null; sending_sources: number; last_checked: string | null; last_error: string | null; dkim_selectors: string[];
}
export interface SendingSource {
    id: string; domain: string; source_ip: string; provider: string | null; ptr: string | null; classification: string; classification_reason: string | null; classified_by: string;
    message_count: number; spf_pass: number; dkim_pass: number; dmarc_pass: number; first_seen: string; last_seen: string;
}
export interface DmarcReportRow { id: string; domain: string; reporter: string; report_id: string; date_begin: string; date_end: string; record_count: number; message_count: number; pass_count: number; received_via: string; created_at: string }
interface Analytics {
    days: number; reports: number; totals: { messages: number; pass: number; fail: number; spf_fail: number; dkim_fail: number; pass_rate: number | null };
    sources: { known: number; unknown: number; suspicious: number }; series: { day: string; pass: number; fail: number }[]; top_failing: { source_ip: string; messages: number }[];
}

type Tab = 'domains' | 'sources' | 'reports' | 'analytics';
const pct = (a: number, b: number) => (b ? `${Math.round((a / b) * 100)}%` : '—');

export function DmarcSaas() {
    const [tab, setTab] = useState<Tab>('domains');
    const [nonce, setNonce] = useState(0);
    const domains = useEmailApi<{ domains: EmailDomain[] }>('/dmarc/domains', nonce);
    const reload = () => setNonce((x) => x + 1);
    const list = domains.data?.domains ?? [];

    return (
        <div className="space-y-4">
            <PageHeader
                title="DMARC SaaS"
                subtitle="Who is sending email as your domains, and are they authorised? SPF, DKIM and DMARC posture, aggregate reports and sending sources."
                actions={<Button onClick={reload}><RefreshCw size={12} /> Refresh</Button>}
            />
            <Tabs<Tab> value={tab} onChange={setTab} tabs={[
                { id: 'domains', label: 'Domains', count: domains.data ? list.length : null },
                { id: 'sources', label: 'Sending Sources' },
                { id: 'reports', label: 'Reports' },
                { id: 'analytics', label: 'Analytics' },
            ]} />
            {tab === 'domains' && <DomainsTab state={domains} list={list} reload={reload} />}
            {tab === 'sources' && <SourcesTab domains={list} nonce={nonce} reload={reload} />}
            {tab === 'reports' && <ReportsTab domains={list} nonce={nonce} reload={reload} />}
            {tab === 'analytics' && <AnalyticsTab domains={list} />}
        </div>
    );
}

// ── Domains ──

function DomainsTab({ state, list, reload }: { state: { loading: boolean; error: string | null; setup: string | null }; list: EmailDomain[]; reload: () => void }) {
    const role = useRole();
    const [domain, setDomain] = useState('');
    const [busy, setBusy] = useState(false);
    const [fb, setFb] = useState<{ ok: boolean; text: string } | null>(null);

    async function add(e: React.FormEvent) {
        e.preventDefault();
        setBusy(true); setFb(null);
        const r = await send<{ domain: EmailDomain }>('POST', '/dmarc/domains', { domain });
        setBusy(false);
        setFb({ ok: r.ok, text: r.ok ? `${r.data?.domain.domain} added and inspected.` : r.error ?? 'Failed' });
        if (r.ok) { setDomain(''); reload(); }
    }

    const form = isManager(role) && (
        <form onSubmit={add} className="flex flex-wrap items-center gap-2">
            <input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="company.com" aria-label="Domain to protect" className={`${inputCls} w-56`} required />
            <Button type="submit" variant="primary" busy={busy}><Plus size={12} /> Add domain</Button>
            <Feedback result={fb} />
        </form>
    );

    return (
        <Panel title="Protected domains" action={list.length > 0 ? form : undefined}>
            <Gate state={state}>
                {list.length === 0 ? (
                    <Empty icon={<ShieldCheck size={18} />} title="No domains connected"
                        body="Add your first protected domain to begin monitoring SPF, DKIM and DMARC. NovrSOC inspects the published records immediately and re-checks them every few hours."
                        action={form || <p className="text-[11px] text-foreground-muted">A SOC manager can add domains.</p>} />
                ) : (
                    <div className="overflow-x-auto -m-4">
                        <table className="w-full text-xs min-w-[860px]">
                            <thead><tr className="border-b border-border">{['Domain', 'Status', 'DMARC policy', 'SPF', 'DKIM', 'DMARC', 'Health', 'Sources', 'Last checked'].map((h) => <th key={h} className={th}>{h}</th>)}</tr></thead>
                            <tbody>
                                {list.map((d) => (
                                    <tr key={d.id} className="border-b border-border/60 last:border-0 hover:bg-card-muted/40">
                                        <td className={td}><Link href={`/admin/email/dmarc/${d.id}`} className="font-bold text-foreground hover:text-purple">{d.domain}</Link>{d.last_error && <p className="text-[10px] text-red-500 max-w-[220px] line-clamp-2">{d.last_error}</p>}</td>
                                        <td className={td}><StatusBadge s={d.status} /></td>
                                        <td className={`${td} font-mono`}>{d.dmarc_policy ? `p=${d.dmarc_policy}` : d.dmarc_status === 'fail' ? <span className="text-red-500">invalid — none applied</span> : <span className="text-foreground-muted">not published</span>}</td>
                                        <td className={td}><StatusBadge s={d.spf_status} /></td>
                                        <td className={td}><StatusBadge s={d.dkim_status} /></td>
                                        <td className={td}><StatusBadge s={d.dmarc_status} /></td>
                                        <td className={`${td} font-black`}>{d.health_score ?? '—'}{d.health_score !== null && <span className="text-foreground-muted font-normal">/100</span>}</td>
                                        <td className={td}>{n(d.sending_sources)}</td>
                                        <td className={`${td} text-foreground-muted whitespace-nowrap`}>{wat(d.last_checked)}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </Gate>
        </Panel>
    );
}

// ── Sending sources ──

export function SourcesTable({ sources, canEdit, onChanged }: { sources: SendingSource[]; canEdit: boolean; onChanged: () => void }) {
    const [busy, setBusy] = useState<string | null>(null);
    const [err, setErr] = useState<string | null>(null);
    async function classify(s: SendingSource, classification: string) {
        setBusy(s.id); setErr(null);
        const r = await send('PATCH', `/dmarc/sources/${s.id}`, { classification });
        setBusy(null);
        if (!r.ok) setErr(r.error); else onChanged();
    }
    return (
        <>
            {err && <p role="alert" className="text-[11px] text-red-500 mb-2">{err}</p>}
            <div className="overflow-x-auto -m-4">
                <table className="w-full text-xs min-w-[980px]">
                    <thead><tr className="border-b border-border">{['IP', 'Provider / organisation', 'Domain', 'Messages', 'SPF', 'DKIM', 'DMARC', 'Status', 'First seen', 'Last seen'].map((h) => <th key={h} className={th}>{h}</th>)}</tr></thead>
                    <tbody>
                        {sources.map((s) => (
                            <tr key={s.id} className="border-b border-border/60 last:border-0 align-top">
                                <td className={`${td} font-mono`}>{s.source_ip}</td>
                                <td className={td}><p className="font-bold text-foreground">{s.provider ?? 'Unrecognised'}</p>{s.ptr && <p className="text-[10px] font-mono text-foreground-muted break-all">{s.ptr}</p>}</td>
                                <td className={td}>{s.domain}</td>
                                <td className={`${td} font-bold`}>{n(s.message_count)}</td>
                                <td className={td}>{pct(s.spf_pass, s.message_count)}</td>
                                <td className={td}>{pct(s.dkim_pass, s.message_count)}</td>
                                <td className={`${td} font-bold`}>{pct(s.dmarc_pass, s.message_count)}</td>
                                <td className={`${td} max-w-[260px]`}>
                                    {canEdit ? (
                                        <select value={s.classification} disabled={busy === s.id} onChange={(e) => classify(s, e.target.value)} aria-label={`Classification for ${s.source_ip}`} className={selectCls}>
                                            <option value="known">Known</option><option value="unknown">Unknown</option><option value="suspicious">Suspicious</option>
                                        </select>
                                    ) : <StatusBadge s={s.classification} />}
                                    <p className="text-[10px] text-foreground-muted mt-1">{s.classification_reason}{s.classified_by !== 'system' && ` — set by ${s.classified_by}`}</p>
                                </td>
                                <td className={`${td} text-foreground-muted whitespace-nowrap`}>{day(s.first_seen)}</td>
                                <td className={`${td} text-foreground-muted whitespace-nowrap`}>{day(s.last_seen)}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </>
    );
}

function SourcesTab({ domains, nonce, reload }: { domains: EmailDomain[]; nonce: number; reload: () => void }) {
    const role = useRole();
    const [domain, setDomain] = useState('');
    const [cls, setCls] = useState('');
    const [q, setQ] = useState('');
    const qs = new URLSearchParams({ ...(domain ? { domain } : {}), ...(cls ? { classification: cls } : {}) }).toString();
    const state = useEmailApi<{ sources: SendingSource[] }>(`/dmarc/sources${qs ? `?${qs}` : ''}`, nonce);
    const sources = (state.data?.sources ?? []).filter((s) => !q || s.source_ip.includes(q) || (s.provider ?? '').toLowerCase().includes(q.toLowerCase()) || (s.ptr ?? '').includes(q.toLowerCase()));
    return (
        <Panel title="Sending sources" action={
            <div className="flex flex-wrap gap-2">
                <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search IP or provider" aria-label="Search sources" className={`${inputCls} w-44`} />
                <select value={domain} onChange={(e) => setDomain(e.target.value)} aria-label="Domain" className={selectCls}><option value="">All domains</option>{domains.map((d) => <option key={d.id} value={d.domain}>{d.domain}</option>)}</select>
                <select value={cls} onChange={(e) => setCls(e.target.value)} aria-label="Classification" className={selectCls}><option value="">All statuses</option><option value="known">Known</option><option value="unknown">Unknown</option><option value="suspicious">Suspicious</option></select>
            </div>
        }>
            <p className="text-[11px] text-foreground-muted mb-3">
                Known = passes DMARC with alignment. Unknown is the default for anything else and is not an accusation — forwarders and mailing lists often fail. Suspicious = every message fails, from a server that isn&apos;t a recognised mail provider.
            </p>
            <Gate state={state}>
                {sources.length === 0
                    ? <Empty title={state.data?.sources.length ? 'No sources match these filters' : 'No sending sources yet'} body="Sources come from DMARC aggregate reports. Once receivers start sending reports for your domains, every server that sent mail as them appears here." />
                    : <SourcesTable sources={sources} canEdit={isManager(role)} onChanged={reload} />}
            </Gate>
        </Panel>
    );
}

// ── Reports ──

function ReportsTab({ domains, nonce, reload }: { domains: EmailDomain[]; nonce: number; reload: () => void }) {
    const role = useRole();
    const [domain, setDomain] = useState('');
    const state = useEmailApi<{ reports: DmarcReportRow[] }>(`/dmarc/reports${domain ? `?domain=${encodeURIComponent(domain)}` : ''}`, nonce);
    const [file, setFile] = useState<File | null>(null);
    const [busy, setBusy] = useState(false);
    const [fb, setFb] = useState<{ ok: boolean; text: string } | null>(null);
    const [open, setOpen] = useState<string | null>(null);

    async function upload(e: React.FormEvent) {
        e.preventDefault();
        if (!file) return;
        const fd = new FormData();
        fd.append('report', file);
        setBusy(true); setFb(null);
        const r = await send<{ duplicate: boolean; records: number; messages: number; suspicious_sources: number; domain: string }>('POST', '/dmarc/reports/upload', fd);
        setBusy(false);
        if (!r.ok || !r.data) { setFb({ ok: false, text: r.error ?? 'Upload failed' }); return; }
        setFb({ ok: true, text: r.data.duplicate ? 'This report was already stored — nothing changed.' : `${r.data.domain}: ${r.data.records} records, ${n(r.data.messages)} messages${r.data.suspicious_sources ? `, ${r.data.suspicious_sources} suspicious source(s)` : ''}.` });
        setFile(null);
        reload();
    }

    const reports = state.data?.reports ?? [];
    return (
        <div className="space-y-4">
            <Panel title="Report ingestion">
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 text-xs text-foreground-muted">
                    <div>
                        <p className="font-bold text-foreground mb-1">Automatic (recommended)</p>
                        <p>Add the NovrSOC report mailbox to each domain&apos;s DMARC record (<span className="font-mono">rua=mailto:…</span>). Reports arrive through a signed Mailgun inbound route, are parsed and stored, and sending sources and spoofing alerts update on arrival. The status of that inbox is on the Email Security overview.</p>
                    </div>
                    {isManager(role) ? (
                        <form onSubmit={upload} className="space-y-2">
                            <p className="font-bold text-foreground">Upload a report</p>
                            <p>Aggregate reports as received: .xml, .xml.gz or .zip (max 10 MB).</p>
                            <div className="flex flex-wrap items-center gap-2">
                                <input type="file" accept=".xml,.gz,.zip,application/xml,application/gzip,application/zip" onChange={(e) => setFile(e.target.files?.[0] ?? null)} aria-label="DMARC report file" className="text-xs" />
                                <Button type="submit" variant="primary" busy={busy} disabled={!file}><Upload size={12} /> Upload</Button>
                            </div>
                            <Feedback result={fb} />
                        </form>
                    ) : <p>A SOC manager can upload reports by hand.</p>}
                </div>
            </Panel>
            <Panel title="Received reports" action={<select value={domain} onChange={(e) => setDomain(e.target.value)} aria-label="Domain" className={selectCls}><option value="">All domains</option>{domains.map((d) => <option key={d.id} value={d.domain}>{d.domain}</option>)}</select>}>
                <Gate state={state}>
                    {reports.length === 0 ? <Empty title="No DMARC reports yet" body="Receivers such as Google and Microsoft send aggregate reports daily once your DMARC record has an rua= address." /> : (
                        <div className="overflow-x-auto -m-4">
                            <table className="w-full text-xs min-w-[820px]">
                                <thead><tr className="border-b border-border">{['', 'Reporter', 'Domain', 'Period', 'Records', 'Messages', 'DMARC pass', 'Received via'].map((h, i) => <th key={i} className={th}>{h}</th>)}</tr></thead>
                                <tbody>
                                    {reports.map((r) => (
                                        <Fragment key={r.id}>
                                            <tr className="border-b border-border/60 hover:bg-card-muted/40 cursor-pointer" onClick={() => setOpen(open === r.id ? null : r.id)}>
                                                <td className={td}>{open === r.id ? <ChevronDown size={13} /> : <ChevronRight size={13} />}</td>
                                                <td className={td}><p className="font-bold text-foreground">{r.reporter}</p><p className="text-[10px] font-mono text-foreground-muted">{r.report_id}</p></td>
                                                <td className={td}>{r.domain}</td>
                                                <td className={`${td} whitespace-nowrap text-foreground-muted`}>{day(r.date_begin)} – {day(r.date_end)}</td>
                                                <td className={td}>{n(r.record_count)}</td>
                                                <td className={`${td} font-bold`}>{n(r.message_count)}</td>
                                                <td className={td}>{pct(r.pass_count, r.message_count)}</td>
                                                <td className={td}><Badge tone="grey">{r.received_via}</Badge></td>
                                            </tr>
                                            {open === r.id && <tr className="border-b border-border/60"><td colSpan={8} className="bg-card-muted/30 p-4"><ReportRecords id={r.id} /></td></tr>}
                                        </Fragment>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </Gate>
            </Panel>
        </div>
    );
}

function ReportRecords({ id }: { id: string }) {
    const state = useEmailApi<{ records: { id: string; source_ip: string; message_count: number; disposition: string | null; header_from: string | null; spf_result: string | null; spf_domain: string | null; dkim_result: string | null; dkim_domain: string | null; spf_aligned: boolean; dkim_aligned: boolean; dmarc_pass: boolean }[] }>(`/dmarc/reports/${id}`);
    return (
        <Gate state={state}>
            <table className="w-full text-[11px]">
                <thead><tr>{['Source IP', 'Messages', 'Header from', 'SPF (domain)', 'DKIM (domain)', 'Aligned', 'DMARC', 'Disposition'].map((h) => <th key={h} className={th}>{h}</th>)}</tr></thead>
                <tbody>
                    {(state.data?.records ?? []).map((r) => (
                        <tr key={r.id} className="border-t border-border/60">
                            <td className={`${td} font-mono`}>{r.source_ip}</td>
                            <td className={td}>{n(r.message_count)}</td>
                            <td className={td}>{r.header_from ?? '—'}</td>
                            <td className={td}>{r.spf_result ?? '—'} <span className="text-foreground-muted">{r.spf_domain ? `(${r.spf_domain})` : ''}</span></td>
                            <td className={td}>{r.dkim_result ?? '—'} <span className="text-foreground-muted">{r.dkim_domain ? `(${r.dkim_domain})` : ''}</span></td>
                            <td className={td}>{[r.spf_aligned && 'SPF', r.dkim_aligned && 'DKIM'].filter(Boolean).join(' + ') || 'none'}</td>
                            <td className={td}><StatusBadge s={r.dmarc_pass ? 'pass' : 'fail'} /></td>
                            <td className={td}>{r.disposition ?? '—'}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </Gate>
    );
}

// ── Analytics ──

// Validated with the dataviz palette checker against the app's card surfaces (#ffffff light,
// #14172a dark): distinct under all colour-vision deficiencies. Red/green was rejected — it
// fails deuteranopia.
const SERIES = { light: { pass: '#2B3BCC', fail: '#E8590C', surface: '#ffffff' }, dark: { pass: '#6B7BFF', fail: '#E8590C', surface: '#14172a' } };

function AnalyticsTab({ domains }: { domains: EmailDomain[] }) {
    const [domain, setDomain] = useState('');
    const [days, setDays] = useState(30);
    const [showTable, setShowTable] = useState(false);
    const state = useEmailApi<Analytics>(`/dmarc/analytics?days=${days}${domain ? `&domain=${encodeURIComponent(domain)}` : ''}`);
    const { resolvedTheme } = useTheme();
    const c = SERIES[resolvedTheme === 'dark' ? 'dark' : 'light'];
    const a = state.data;
    const series = useMemo(() => (a?.series ?? []).map((s) => ({ ...s, label: new Intl.DateTimeFormat('en-GB', { day: '2-digit', month: 'short', timeZone: 'UTC' }).format(new Date(`${s.day}T00:00:00Z`)) })), [a]);

    return (
        <div className="space-y-4">
            <div className="flex flex-wrap gap-2">
                <select value={domain} onChange={(e) => setDomain(e.target.value)} aria-label="Domain" className={selectCls}><option value="">All domains</option>{domains.map((d) => <option key={d.id} value={d.domain}>{d.domain}</option>)}</select>
                <select value={days} onChange={(e) => setDays(Number(e.target.value))} aria-label="Date range" className={selectCls}>
                    <option value={7}>Last 7 days</option><option value={30}>Last 30 days</option><option value={90}>Last 90 days</option>
                </select>
            </div>
            <Gate state={state} rows={5}>
                {a && (a.reports === 0 ? (
                    <Panel><Empty title="No DMARC reports in this period" body="Analytics are computed from aggregate reports. None have been received for this range yet." /></Panel>
                ) : (
                    <>
                        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                            <Kpi label="Authentication pass rate" value={a.totals.pass_rate} suffix="%" tone={a.totals.pass_rate !== null && a.totals.pass_rate >= 98 ? 'good' : 'warn'} />
                            <Kpi label="DMARC failures" value={a.totals.fail} tone={a.totals.fail ? 'danger' : undefined} />
                            <Kpi label="SPF failures (unaligned)" value={a.totals.spf_fail} />
                            <Kpi label="DKIM failures (unaligned)" value={a.totals.dkim_fail} />
                            <Kpi label="Unknown / suspicious sources" value={a.sources.unknown + a.sources.suspicious} tone={a.sources.suspicious ? 'danger' : undefined} />
                        </div>
                        <Panel title="Messages per day by DMARC result" action={<button onClick={() => setShowTable((v) => !v)} className="text-[10px] font-bold text-purple hover:underline">{showTable ? 'Hide' : 'Show'} data table</button>}>
                            <div className="h-64" role="img" aria-label={`Messages per day: ${n(a.totals.pass)} passed and ${n(a.totals.fail)} failed DMARC over ${a.days} days`}>
                                <ResponsiveContainer width="100%" height="100%">
                                    <BarChart data={series} margin={{ top: 8, right: 8, bottom: 0, left: 0 }} barCategoryGap="20%">
                                        <CartesianGrid vertical={false} stroke="currentColor" strokeOpacity={0.08} />
                                        <XAxis dataKey="label" tick={{ fontSize: 10, fill: 'currentColor' }} tickLine={false} axisLine={false} className="text-foreground-muted" />
                                        <YAxis tick={{ fontSize: 10, fill: 'currentColor' }} tickLine={false} axisLine={false} width={48} className="text-foreground-muted" allowDecimals={false} />
                                        <Tooltip cursor={{ fill: 'currentColor', fillOpacity: 0.05 }} contentStyle={{ fontSize: 11, borderRadius: 8 }} formatter={(v, name) => [Number(v).toLocaleString(), name]} />
                                        <Legend iconType="square" wrapperStyle={{ fontSize: 11 }} />
                                        <Bar dataKey="pass" name="Passed DMARC" stackId="m" fill={c.pass} stroke={c.surface} strokeWidth={2} />
                                        <Bar dataKey="fail" name="Failed DMARC" stackId="m" fill={c.fail} stroke={c.surface} strokeWidth={2} radius={[4, 4, 0, 0]} />
                                    </BarChart>
                                </ResponsiveContainer>
                            </div>
                            {showTable && (
                                <table className="w-full text-[11px] mt-3">
                                    <thead><tr>{['Day', 'Passed', 'Failed', 'Pass rate'].map((h) => <th key={h} className={th}>{h}</th>)}</tr></thead>
                                    <tbody>{a.series.map((s) => <tr key={s.day} className="border-t border-border/60"><td className={td}>{s.day}</td><td className={td}>{n(s.pass)}</td><td className={td}>{n(s.fail)}</td><td className={td}>{pct(s.pass, s.pass + s.fail)}</td></tr>)}</tbody>
                                </table>
                            )}
                        </Panel>
                        <Panel title="Top failing sources">
                            {a.top_failing.length === 0 ? <p className="text-xs text-foreground-muted">No failing messages in this period.</p> : (
                                <table className="w-full text-xs">
                                    <thead><tr><th className={th}>Source IP</th><th className={th}>Failed messages</th></tr></thead>
                                    <tbody>{a.top_failing.map((t) => <tr key={t.source_ip} className="border-t border-border/60"><td className={`${td} font-mono`}>{t.source_ip}</td><td className={`${td} font-bold`}>{n(t.messages)}</td></tr>)}</tbody>
                                </table>
                            )}
                        </Panel>
                    </>
                ))}
            </Gate>
        </div>
    );
}
