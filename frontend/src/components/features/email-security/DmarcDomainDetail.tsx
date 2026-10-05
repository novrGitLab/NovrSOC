'use client';

import { useState } from 'react';
import { RefreshCw, Trash2, Copy, BadgeCheck } from 'lucide-react';
import { useRouter } from 'next/navigation';
import {
    useEmailApi, send, useRole, isManager, isAnalyst, PageHeader, Panel, Gate, Empty, StatusBadge, Button, Feedback, KeyValue, DnsRecordCard,
    inputCls, wat, day, n, th, td,
} from './shared';
import { useEmailSecurity } from './context';
import { SourcesTable, type EmailDomain, type SendingSource, type DmarcReportRow } from './DmarcSaas';

// One protected domain: the latest DNS inspection with every finding explained, the three
// DMARC policies, a policy-change plan (the record to publish — NovrSOC never edits DNS),
// DKIM selectors, sending sources and reports.

interface Findings { errors: string[]; warnings: string[]; recommendations: string[] }
interface Inspection {
    checked_at: string; mx: { exchange: string; priority: number }[];
    spf: Findings & { exists: boolean; raw: string | null; all: string | null; lookups: number; total_lookups: number | null };
    dmarc: Findings & { exists: boolean; raw: string | null; records?: string[]; policy: string | null; subdomainPolicy: string | null; pct: number; rua: string[]; ruf: string[]; adkim: string; aspf: string };
    dkim: { selectors_checked: string[]; found: (Findings & { selector: string; raw: string | null; keyType: string; keyBits: number | null; revoked: boolean })[] };
    statuses: { spf: string; dkim: string; dmarc: string };
    health: { score: number; status: string; parts: { label: string; points: number; max: number }[] };
    lookup_errors: string[];
    verification?: { state: string; checked_at: string; detail: string };
}
interface Detail {
    verification_record: { type: string; host: string; name: string; value: string } | null;
    domain: EmailDomain; latest: Inspection | null; history: { at: string }[]; sources: SendingSource[]; reports: DmarcReportRow[];
    policies: Record<'none' | 'quarantine' | 'reject', { title: string; effect: string; when: string }>;
}

function FindingList({ f }: { f: Findings }) {
    if (!f.errors.length && !f.warnings.length && !f.recommendations.length) return <p className="text-[11px] text-green font-bold">No issues found.</p>;
    return (
        <ul className="space-y-1 text-[11px]">
            {f.errors.map((e) => <li key={e} className="text-red-500"><span className="font-bold">Error:</span> {e}</li>)}
            {f.warnings.map((e) => <li key={e} className="text-amber-600"><span className="font-bold">Warning:</span> {e}</li>)}
            {f.recommendations.map((e) => <li key={e} className="text-foreground-muted"><span className="font-bold text-foreground">Recommendation:</span> {e}</li>)}
        </ul>
    );
}

const Record = ({ value }: { value: string | null }) => value
    ? <code className="block text-[11px] font-mono bg-card-muted border border-border rounded-lg p-2 break-all text-foreground">{value}</code>
    : <p className="text-[11px] text-red-500 font-bold">Not published</p>;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Route: /admin/email/dmarc/[domain] — a domain name, or an id from older links. */
export function DmarcDomainRoute({ param }: { param: string }) {
    const { domains, loading, notSetUp } = useEmailSecurity();
    const value = decodeURIComponent(param).toLowerCase();
    if (UUID.test(value)) return <DmarcDomainDetail id={value} />;
    if (loading) return <div className="h-40 bg-card-muted rounded-xl animate-pulse" aria-busy="true" />;
    const match = domains.find((d) => d.domain.toLowerCase() === value);
    if (!match) {
        return (
            <div className="space-y-4">
                <PageHeader back={{ href: '/admin/email/dmarc', label: 'DMARC SaaS' }} title={value} />
                <Panel><Empty title={notSetUp ? 'Email Security is not set up yet' : 'This domain is not monitored'} body={notSetUp ?? `${value} is not one of your organisation's domains. Add it in Setup to start monitoring it.`} /></Panel>
            </div>
        );
    }
    return <DmarcDomainDetail id={match.id} />;
}

export function DmarcDomainDetail({ id }: { id: string }) {
    const { reload } = useEmailSecurity();
    const role = useRole();
    const router = useRouter();
    const [nonce, setNonce] = useState(0);
    const state = useEmailApi<Detail>(`/dmarc/domains/${id}`, nonce);
    const [busy, setBusy] = useState<string | null>(null);
    const [fb, setFb] = useState<{ ok: boolean; text: string } | null>(null);
    const [plan, setPlan] = useState<{ host: string; value: string; current: string | null; note: string } | null>(null);
    const [selectors, setSelectors] = useState<string | null>(null);
    const d = state.data;
    const i = d?.latest ?? null;

    async function act(key: string, fn: () => Promise<{ ok: boolean; text: string }>) {
        setBusy(key); setFb(null);
        const r = await fn();
        setBusy(null); setFb(r);
    }
    const inspect = () => act('inspect', async () => {
        const r = await send('POST', `/dmarc/domains/${id}/inspect`);
        if (r.ok) { setNonce((x) => x + 1); reload(); }
        return { ok: r.ok, text: r.ok ? 'Inspection complete.' : r.error ?? 'Failed' };
    });
    const verify = () => act('verify', async () => {
        const r = await send<{ verification: { state: string; detail: string } }>('POST', `/dmarc/domains/${id}/verify`);
        if (r.ok) { setNonce((x) => x + 1); reload(); }
        return { ok: r.ok && r.data?.verification.state === 'verified', text: r.ok ? r.data?.verification.detail ?? '' : r.error ?? 'Failed' };
    });
    const planFor = (policy: string) => act(`plan-${policy}`, async () => {
        const r = await send<{ host: string; value: string; current: string | null; note: string }>('POST', `/dmarc/domains/${id}/policy-plan`, { policy });
        if (r.ok && r.data) setPlan(r.data);
        return { ok: r.ok, text: r.ok ? `Record for p=${policy} generated below.` : r.error ?? 'Failed' };
    });
    const remove = () => act('remove', async () => {
        if (!window.confirm(`Stop monitoring ${d?.domain.domain}? Its inspection history, reports and sources are deleted.`)) return { ok: false, text: 'Cancelled.' };
        const r = await send('DELETE', `/dmarc/domains/${id}`);
        if (r.ok) router.push('/admin/email/dmarc');
        return { ok: r.ok, text: r.ok ? 'Removed.' : r.error ?? 'Failed' };
    });
    const saveSelectors = () => act('selectors', async () => {
        const list = (selectors ?? '').split(/[\s,]+/).filter(Boolean);
        const r = await send('PATCH', `/dmarc/domains/${id}`, { dkim_selectors: list });
        if (r.ok) { setSelectors(null); setNonce((x) => x + 1); }
        return { ok: r.ok, text: r.ok ? 'Selectors saved — run an inspection to check them.' : r.error ?? 'Failed' };
    });

    return (
        <div className="space-y-4">
            <PageHeader
                back={{ href: '/admin/email/dmarc', label: 'DMARC SaaS' }}
                title={d?.domain.domain ?? 'Domain'}
                subtitle={d ? <>Last inspected {wat(d.domain.last_checked)} · {n(d.domain.sending_sources)} sending sources</> : undefined}
                actions={d && <>
                    {isAnalyst(role) && <Button onClick={inspect} busy={busy === 'inspect'}><RefreshCw size={12} /> Inspect now</Button>}
                    {isManager(role) && <Button variant="danger" onClick={remove} busy={busy === 'remove'}><Trash2 size={12} /> Remove</Button>}
                </>}
            />
            <Feedback result={fb} />
            <Gate state={state} rows={8}>
                {d && (
                    <Panel title={<span className="flex items-center gap-1.5"><BadgeCheck size={13} /> Domain ownership</span>} action={<StatusBadge s={i?.verification?.state === 'verified' ? 'verified' : i?.verification?.state ?? 'not_verified'} />} className="mb-4">
                        {i?.verification?.state === 'verified' ? (
                            <p className="text-xs text-foreground">Ownership verified — last checked {wat(i.verification.checked_at)}. Keep the record published; verification is re-checked with every inspection.</p>
                        ) : d.verification_record ? (
                            <div className="space-y-3">
                                <p className="text-xs text-foreground-muted">Prove your organisation controls {d.domain.domain} by publishing this TXT record at your DNS provider. NovrSOC never changes DNS. Reports from NovrSOC&apos;s DMARC inbox are delivered only after verification. {i?.verification ? <span className="block mt-1 text-foreground">{i.verification.detail}</span> : null}</p>
                                <DnsRecordCard type={d.verification_record.type} host={d.verification_record.name} value={d.verification_record.value} note="Some DNS providers want only the host part (_novrsoc-verification) in the name field." />
                                {isAnalyst(role) && <Button variant="primary" onClick={verify} busy={busy === 'verify'}>Verify now</Button>}
                            </div>
                        ) : <p className="text-xs text-foreground-muted">Domain verification is not configured on this NovrSOC deployment.</p>}
                    </Panel>
                )}
                {d && (!i ? (
                    <Panel><Empty title="Not inspected yet" body={d.domain.last_error ?? 'Run an inspection to read the published SPF, DKIM and DMARC records.'} /></Panel>
                ) : (
                    <>
                        <div className="grid grid-cols-1 xl:grid-cols-[280px_minmax(0,1fr)] gap-4 [&>*]:min-w-0">
                            <Panel title="Authentication health">
                                <p className="text-4xl font-black text-foreground">{i.health.score}<span className="text-base text-foreground-muted">/100</span></p>
                                <div className="mt-1"><StatusBadge s={i.health.status} /></div>
                                <ul className="mt-3 space-y-1">
                                    {i.health.parts.map((p) => (
                                        <li key={p.label} className="flex justify-between gap-2 text-[11px]">
                                            <span className="text-foreground-muted">{p.label}</span>
                                            <span className={`font-bold ${p.points === p.max ? 'text-green' : p.points === 0 ? 'text-red-500' : 'text-amber-600'}`}>{p.points}/{p.max}</span>
                                        </li>
                                    ))}
                                </ul>
                                {i.lookup_errors.length > 0 && <p className="text-[10px] text-red-500 mt-2">DNS errors: {i.lookup_errors.join('; ')}</p>}
                            </Panel>
                            <div className="grid grid-cols-1 2xl:grid-cols-3 gap-4 [&>*]:min-w-0">
                                <Panel title={<span className="flex items-center gap-2">SPF <StatusBadge s={i.statuses.spf} /></span>}>
                                    <Record value={i.spf.raw} />
                                    {i.spf.exists && <p className="text-[10px] text-foreground-muted my-2">DNS lookups: {i.spf.total_lookups ?? i.spf.lookups} of 10 (incl. nested includes) · all: {i.spf.all ? `${i.spf.all}all` : 'none'}</p>}
                                    <div className="mt-2"><FindingList f={i.spf} /></div>
                                </Panel>
                                <Panel title={<span className="flex items-center gap-2">DKIM <StatusBadge s={i.statuses.dkim} /></span>}>
                                    {i.dkim.found.length === 0 ? (
                                        <p className="text-[11px] text-foreground-muted">No key found under the {i.dkim.selectors_checked.length} selectors checked. DKIM keys can only be found by selector name — if your provider uses a different one, add it below. This is not the same as DKIM being missing.</p>
                                    ) : i.dkim.found.map((k) => (
                                        <div key={k.selector} className="mb-3 last:mb-0">
                                            <p className="text-[11px] font-bold text-foreground">Selector <span className="font-mono">{k.selector}</span> · {k.keyType.toUpperCase()}{k.keyBits ? ` ${k.keyBits}-bit` : ''}{k.revoked ? ' · revoked' : ''}</p>
                                            <FindingList f={k} />
                                        </div>
                                    ))}
                                    {isManager(role) && (
                                        <div className="mt-3 pt-3 border-t border-border space-y-1.5">
                                            <p className="text-[10px] text-foreground-muted">Extra selectors: {d.domain.dkim_selectors.length ? d.domain.dkim_selectors.join(', ') : 'none'}</p>
                                            {selectors === null ? <Button onClick={() => setSelectors(d.domain.dkim_selectors.join(', '))}>Edit selectors</Button> : (
                                                <div className="flex gap-2"><input value={selectors} onChange={(e) => setSelectors(e.target.value)} placeholder="s1, mailgun" aria-label="DKIM selectors" className={`${inputCls} flex-1`} /><Button variant="primary" onClick={saveSelectors} busy={busy === 'selectors'}>Save</Button></div>
                                            )}
                                        </div>
                                    )}
                                </Panel>
                                <Panel title={<span className="flex items-center gap-2">DMARC <StatusBadge s={i.statuses.dmarc} /></span>}>
                                    {(i.dmarc.records ?? []).length > 1
                                        ? <div className="space-y-1">{i.dmarc.records!.map((r) => <Record key={r} value={r} />)}<p className="text-[11px] text-red-500 font-bold">{i.dmarc.records!.length} records published — receivers ignore all of them. Keep exactly one.</p></div>
                                        : <Record value={i.dmarc.raw} />}
                                    {i.dmarc.exists && (i.dmarc.records ?? []).length <= 1 && (
                                        <div className="my-2"><KeyValue rows={[
                                            ['Policy', i.dmarc.policy ? `p=${i.dmarc.policy}` : '—'], ['Subdomains', i.dmarc.subdomainPolicy ? `sp=${i.dmarc.subdomainPolicy}` : '—'],
                                            ['Applies to', `${i.dmarc.pct}% of failing mail`], ['Alignment', `DKIM ${i.dmarc.adkim === 's' ? 'strict' : 'relaxed'}, SPF ${i.dmarc.aspf === 's' ? 'strict' : 'relaxed'}`],
                                            ['Aggregate reports', i.dmarc.rua.join(', ') || 'none'],
                                        ]} /></div>
                                    )}
                                    <FindingList f={i.dmarc} />
                                </Panel>
                            </div>
                        </div>

                        <Panel title="DMARC policy">
                            <p className="text-[11px] text-foreground-muted mb-3">The policy tells receiving mail servers what to do with messages that fail DMARC. NovrSOC never changes your DNS — moving to a stricter policy is an administrative action you publish at your DNS provider.</p>
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                                {(['none', 'quarantine', 'reject'] as const).map((p) => {
                                    // An invalid record set is applied as no policy at all.
                                    const current = !i.dmarc.errors.length && i.dmarc.policy === p;
                                    return (
                                        <div key={p} className={`rounded-xl border p-3 ${current ? 'border-purple bg-purple/5' : 'border-border'}`}>
                                            <p className="text-xs font-black text-foreground">{d.policies[p].title}{current && <span className="ml-2 text-[9px] font-bold text-purple uppercase">Current</span>}</p>
                                            <p className="text-[11px] text-foreground mt-1">{d.policies[p].effect}</p>
                                            <p className="text-[11px] text-foreground-muted mt-1">{d.policies[p].when}</p>
                                            {isManager(role) && !current && <div className="mt-2"><Button onClick={() => planFor(p)} busy={busy === `plan-${p}`}>Prepare record for p={p}</Button></div>}
                                        </div>
                                    );
                                })}
                            </div>
                            {plan && (
                                <div className="mt-4 border border-border rounded-xl p-3 space-y-2">
                                    <KeyValue rows={[['Host', <span key="h" className="font-mono">{plan.host}</span>], ['Type', 'TXT'], ['Currently published', plan.current ?? 'nothing']]} />
                                    <div className="flex items-start gap-2"><div className="flex-1"><Record value={plan.value} /></div><Button onClick={() => void navigator.clipboard?.writeText(plan.value)} title="Copy record"><Copy size={12} /></Button></div>
                                    <p className="text-[10px] text-foreground-muted">{plan.note}</p>
                                </div>
                            )}
                        </Panel>

                        <Panel title={`Sending sources (${d.sources.length})`}>
                            {d.sources.length === 0 ? <Empty title="No sending sources yet" body="They appear once DMARC aggregate reports for this domain arrive." />
                                : <SourcesTable sources={d.sources} canEdit={isManager(role)} onChanged={() => setNonce((x) => x + 1)} />}
                        </Panel>

                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                            <Panel title="Recent reports">
                                {d.reports.length === 0 ? <p className="text-xs text-foreground-muted">No reports received for this domain.</p> : (
                                    <table className="w-full text-xs">
                                        <thead><tr>{['Reporter', 'Period', 'Messages'].map((h) => <th key={h} className={th}>{h}</th>)}</tr></thead>
                                        <tbody>{d.reports.map((r) => <tr key={r.id} className="border-t border-border/60"><td className={td}>{r.reporter}</td><td className={`${td} text-foreground-muted`}>{day(r.date_begin)}</td><td className={td}>{n(r.message_count)}</td></tr>)}</tbody>
                                    </table>
                                )}
                            </Panel>
                            <Panel title="Mail servers (MX)">
                                {i.mx.length === 0 ? <p className="text-xs text-foreground-muted">No MX records — this domain does not receive mail.</p>
                                    : <ul className="text-xs space-y-1">{[...i.mx].sort((a, b) => a.priority - b.priority).map((m) => <li key={m.exchange} className="font-mono">{m.priority} {m.exchange}</li>)}</ul>}
                                <p className="text-[10px] text-foreground-muted mt-3">Inspection history: {d.history.length} check{d.history.length === 1 ? '' : 's'} on record.</p>
                            </Panel>
                        </div>
                    </>
                ))}
            </Gate>
        </div>
    );
}
