'use client';

import { useState } from 'react';
import Link from 'next/link';
import { RefreshCw, Share2 } from 'lucide-react';
import {
    useEmailApi, send, useRole, isManager, isAnalyst, PageHeader, Panel, Gate, Empty, SevBadge, StatusBadge, Badge, Button, Feedback, KeyValue,
    inputCls, selectCls, wat, day, label, th, td,
} from './shared';

// Investigation of one discovered domain: why it is rated what it is (every signal), what it
// is (registration, DNS, hosting, certificates), what the site shows (one safe GET — never
// submitted to), where else it has been seen (indicators, SOC alerts), and the analyst record.

interface Signal { id: string; label: string; detail: string; points: number }
interface Detail {
    domain: {
        id: string; domain: string; brand_domain: string | null; techniques: string[]; similarity: number | null; discovered_via: string; status: string; risk: string;
        risk_score: number; risk_signals: Signal[]; resolves: boolean | null; assigned_to: string | null; alert_id: string | null; opencti_id: string | null;
        first_observed: string; last_observed: string; last_enriched: string | null;
        intel: null | {
            registrar: string | null; created: string | null; expires: string | null; age_days: number | null; nameservers: string[];
            dns: { a: string[]; aaaa: string[]; mx: string[]; ns: string[] }; hosting: { ip: string; asn: string | null; holder: string | null; prefix: string | null }[];
            certificates: { issuer: string; not_before: string; not_after: string; names: string }[]; ti: { source: string; detail: string }[]; collected_at: string;
        };
        website: null | {
            inspected_at: string; url: string; reachable: boolean; error: string | null; blocked: boolean; final_url: string | null; status: number | null;
            redirects: { url: string; status: number; location: string | null }[]; cross_domain_redirect: boolean;
            tls: { authorized: boolean; authorization_error: string | null; subject: string | null; issuer: string | null; valid_from: string | null; valid_to: string | null; san: string[] } | null;
            title: string | null; meta: Record<string, string>; forms: { action: string | null; method: string; external: boolean; password_fields: number; email_fields: number }[];
            login_indicators: string[]; brand_mentions: string[]; external_scripts: number; iframes: number;
        };
    };
    timeline: { id: string; kind: string; summary: string; actor: string; created_at: string }[];
    related_indicators: { type: string; value: string; refs: { module: string; kind: string; id: string }[]; first_seen: string; last_seen: string }[];
    alert: { id: string; title: string; severity: string; status: string; case_number: string | null } | null;
    soc_alerts: { available: boolean; error?: string; alerts: { id: string; timestamp: string; rule: string; level: number; agent: string | null; match: string }[] };
}

const STATUSES = ['discovered', 'under_investigation', 'suspicious', 'confirmed_phishing', 'false_positive', 'resolved'];
const REF_LABEL: Record<string, string> = { alert: 'Alert', email_event: 'Email', phishing_domain: 'Phish ID', sending_source: 'DMARC source' };

export function PhishInvestigation({ id }: { id: string }) {
    const role = useRole();
    const [nonce, setNonce] = useState(0);
    const state = useEmailApi<Detail>(`/phishid/domains/${id}`, nonce);
    const [busy, setBusy] = useState<string | null>(null);
    const [fb, setFb] = useState<{ ok: boolean; text: string } | null>(null);
    const [note, setNote] = useState('');
    const [assignee, setAssignee] = useState<string | null>(null);
    const d = state.data?.domain;
    const reload = () => setNonce((x) => x + 1);

    async function run(key: string, method: string, path: string, body: unknown, ok: string) {
        setBusy(key); setFb(null);
        const r = await send(method, path, body);
        setBusy(null);
        setFb({ ok: r.ok, text: r.ok ? ok : r.error ?? 'Failed' });
        if (r.ok) reload();
        return r.ok;
    }

    const w = d?.website;
    const i = d?.intel;
    return (
        <div className="space-y-4">
            <PageHeader
                back={{ href: '/admin/email/phishid', label: 'Phish ID' }}
                title={d?.domain ?? 'Domain'}
                subtitle={d && <>Resembles {d.brand_domain ?? 'your brand'} · first observed {wat(d.first_observed)} · last assessed {wat(d.last_enriched)}</>}
                actions={d && <>
                    {isAnalyst(role) && <Button onClick={() => run('refresh', 'POST', `/phishid/domains/${id}/refresh`, undefined, 'Re-assessed with fresh intelligence and a new website inspection.')} busy={busy === 'refresh'}><RefreshCw size={12} /> Re-assess</Button>}
                    {isManager(role) && d.status === 'confirmed_phishing' && !d.opencti_id && <Button onClick={() => run('octi', 'POST', `/phishid/domains/${id}/opencti`, undefined, 'Shared to OpenCTI.')} busy={busy === 'octi'}><Share2 size={12} /> Share to OpenCTI</Button>}
                </>}
            />
            <Feedback result={fb} />
            <Gate state={state} rows={8}>
                {d && state.data && (
                    <>
                        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                            <Panel title="Overview">
                                <KeyValue rows={[
                                    ['Risk', d.last_enriched ? <span key="r" className="flex items-center gap-2"><SevBadge s={d.risk} /> <span className="text-foreground-muted">score {d.risk_score}</span></span> : 'Not assessed yet'],
                                    ['Status', <StatusBadge key="s" s={d.status} />],
                                    ['Techniques', d.techniques.length ? d.techniques.map(label).join(', ') : '—'],
                                    ['Similarity', d.similarity !== null ? `${Math.round(d.similarity * 100)}%` : '—'],
                                    ['Found via', label(d.discovered_via)],
                                    ['Resolves', d.resolves === null ? 'Unknown' : d.resolves ? 'Yes' : 'No'],
                                    ['Assigned to', d.assigned_to ?? 'Unassigned'],
                                    ['Alert', state.data.alert ? <Link key="a" href={`/admin/email/alerts/${state.data.alert.id}`} className="text-purple hover:underline">{label(state.data.alert.status)}{state.data.alert.case_number ? ` · ${state.data.alert.case_number}` : ''}</Link> : 'None'],
                                    ['OpenCTI', d.opencti_id ? `Shared (${d.opencti_id})` : 'Not shared'],
                                ]} />
                                {isAnalyst(role) && (
                                    <div className="mt-4 pt-3 border-t border-border space-y-2">
                                        <label className="block text-[10px] font-bold text-foreground-muted uppercase">Investigation status</label>
                                        <select value={d.status} disabled={busy === 'status'} aria-label="Investigation status" className={`${selectCls} w-full`}
                                            onChange={(e) => void run('status', 'PATCH', `/phishid/domains/${id}`, { status: e.target.value }, `Status set to ${label(e.target.value)}.`)}>
                                            {STATUSES.map((s) => <option key={s} value={s}>{label(s)}</option>)}
                                        </select>
                                        <div className="flex gap-2">
                                            <input value={assignee ?? d.assigned_to ?? ''} onChange={(e) => setAssignee(e.target.value)} placeholder="Assign to (email)" aria-label="Assignee" className={`${inputCls} flex-1`} />
                                            <Button onClick={() => void run('assign', 'PATCH', `/phishid/domains/${id}`, { assigned_to: assignee ?? '' }, 'Assignment saved.').then((ok) => ok && setAssignee(null))} busy={busy === 'assign'}>Assign</Button>
                                        </div>
                                    </div>
                                )}
                            </Panel>
                            <Panel title="Why this rating" className="lg:col-span-2">
                                {!d.last_enriched ? <p className="text-xs text-foreground-muted">This domain has not been assessed yet. Assessment runs in the background, or re-assess it now.</p>
                                    : d.risk_signals.length === 0 ? <p className="text-xs text-foreground-muted">No risk signals were found. The domain resembles your brand but shows no phishing behaviour or intelligence matches.</p> : (
                                        <table className="w-full text-xs">
                                            <thead><tr><th className={th}>Signal</th><th className={th}>Evidence</th><th className={`${th} text-right`}>Points</th></tr></thead>
                                            <tbody>
                                                {d.risk_signals.map((s, k) => (
                                                    <tr key={k} className="border-t border-border/60">
                                                        <td className={`${td} font-bold text-foreground whitespace-nowrap`}>{s.label}</td>
                                                        <td className={`${td} text-foreground-muted`}>{s.detail}</td>
                                                        <td className={`${td} text-right font-black`}>+{s.points}</td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    )}
                                <p className="text-[10px] text-foreground-muted mt-3">Resemblance alone never rates above low. Risk rises only with evidence of phishing behaviour — a login form, your brand on the page, data sent to another site, a fresh registration — or a threat-intelligence listing, which is always at least high.</p>
                            </Panel>
                        </div>

                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                            <Panel title="Domain intelligence">
                                {!i ? <p className="text-xs text-foreground-muted">Not collected yet.</p> : (
                                    <KeyValue rows={[
                                        ['Registrar', i.registrar ?? 'Not published (RDAP)'], ['Registered', i.created ? `${day(i.created)}${i.age_days !== null ? ` (${i.age_days} days ago)` : ''}` : '—'],
                                        ['Expires', day(i.expires)], ['Nameservers', i.nameservers.join(', ') || '—'],
                                        ['Threat intelligence', i.ti.length ? i.ti.map((t) => `${t.source}: ${t.detail}`).join('; ') : 'No listings'],
                                        ['Collected', wat(i.collected_at)],
                                    ]} />
                                )}
                            </Panel>
                            <Panel title="DNS & hosting">
                                {!i ? <p className="text-xs text-foreground-muted">Not collected yet.</p> : (
                                    <>
                                        <KeyValue rows={[['A', i.dns.a.join(', ') || '—'], ['AAAA', i.dns.aaaa.join(', ') || '—'], ['MX', i.dns.mx.join(', ') || '—'], ['NS', i.dns.ns.join(', ') || '—']]} />
                                        {i.hosting.length > 0 && (
                                            <table className="w-full text-[11px] mt-3">
                                                <thead><tr>{['IP', 'ASN', 'Provider', 'Prefix'].map((h) => <th key={h} className={th}>{h}</th>)}</tr></thead>
                                                <tbody>{i.hosting.map((h) => <tr key={h.ip} className="border-t border-border/60"><td className={`${td} font-mono`}>{h.ip}</td><td className={td}>{h.asn ?? '—'}</td><td className={td}>{h.holder ?? '—'}</td><td className={`${td} font-mono`}>{h.prefix ?? '—'}</td></tr>)}</tbody>
                                            </table>
                                        )}
                                    </>
                                )}
                            </Panel>
                        </div>

                        <Panel title="Website evidence" action={w && <span className="text-[10px] text-foreground-muted">Inspected {wat(w.inspected_at)} · one GET, nothing submitted</span>}>
                            {!w ? <p className="text-xs text-foreground-muted">{d.resolves === false ? 'The domain does not resolve, so there is no website to inspect.' : 'Not inspected yet.'}</p>
                                : !w.reachable ? <p className="text-xs text-foreground-muted">{w.blocked ? 'Inspection refused by the safety policy: ' : 'Unreachable: '}{w.error}</p> : (
                                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                                        <KeyValue rows={[
                                            ['Final URL', <span key="u" className="font-mono break-all">{w.final_url}</span>], ['HTTP status', String(w.status)], ['Page title', w.title ?? '—'],
                                            ['Redirects', w.redirects.length ? w.redirects.map((r) => `${r.status} ${r.url}`).join(' → ') : 'None'],
                                            ['Cross-domain redirect', w.cross_domain_redirect ? 'Yes' : 'No'],
                                            ['TLS', w.tls ? `${w.tls.authorized ? 'Trusted' : `Not trusted (${w.tls.authorization_error})`} · ${w.tls.issuer ?? '?'} · valid ${day(w.tls.valid_from)}–${day(w.tls.valid_to)}` : 'Plain HTTP'],
                                            ...Object.entries(w.meta).map(([k, v]) => [`Meta ${k}`, v] as [string, string]),
                                        ]} />
                                        <div className="space-y-3 text-xs">
                                            <div><p className="font-bold text-foreground">Forms ({w.forms.length})</p>
                                                {w.forms.length === 0 ? <p className="text-foreground-muted">None</p> : w.forms.map((f, k) => (
                                                    <p key={k} className="text-foreground-muted">{f.method.toUpperCase()} → <span className="font-mono break-all">{f.action ?? '(same page)'}</span>{f.external && <Badge tone="red">off-site</Badge>} · {f.password_fields} password, {f.email_fields} email field(s)</p>
                                                ))}</div>
                                            <div><p className="font-bold text-foreground">Login indicators</p><p className="text-foreground-muted">{w.login_indicators.join(', ') || 'None'}</p></div>
                                            <div><p className="font-bold text-foreground">Brand mentions</p><p className="text-foreground-muted">{w.brand_mentions.join(', ') || 'None'}</p></div>
                                            <p className="text-foreground-muted">{w.external_scripts} external script(s) · {w.iframes} iframe(s)</p>
                                        </div>
                                    </div>
                                )}
                        </Panel>

                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                            <Panel title="Certificates (Certificate Transparency)">
                                {!i?.certificates.length ? <p className="text-xs text-foreground-muted">No certificates found in CT logs.</p> : (
                                    <table className="w-full text-[11px]">
                                        <thead><tr>{['Issued', 'Expires', 'Issuer', 'Names'].map((h) => <th key={h} className={th}>{h}</th>)}</tr></thead>
                                        <tbody>{i.certificates.map((c, k) => <tr key={k} className="border-t border-border/60"><td className={td}>{day(c.not_before)}</td><td className={td}>{day(c.not_after)}</td><td className={`${td} break-all`}>{c.issuer.replace(/^.*O=([^,]+).*$/, '$1')}</td><td className={`${td} font-mono break-all`}>{c.names}</td></tr>)}</tbody>
                                    </table>
                                )}
                            </Panel>
                            <Panel title="Related indicators & SOC alerts">
                                {state.data.related_indicators.length === 0 ? <p className="text-xs text-foreground-muted">Not seen anywhere else yet.</p> : (
                                    <ul className="text-[11px] space-y-1.5">
                                        {state.data.related_indicators.map((s) => (
                                            <li key={`${s.type}|${s.value}`}><span className="font-mono text-foreground">{s.value}</span> <span className="text-foreground-muted">({s.type}) — seen in {[...new Set(s.refs.map((r) => REF_LABEL[r.kind] ?? r.kind))].join(', ')} · last {wat(s.last_seen)}</span></li>
                                        ))}
                                    </ul>
                                )}
                                <div className="mt-3 pt-3 border-t border-border">
                                    <p className="text-[11px] font-bold text-foreground mb-1">Wazuh alerts mentioning this domain or its IPs (30 days)</p>
                                    {!state.data.soc_alerts.available ? <p className="text-[11px] text-foreground-muted">Not available: {state.data.soc_alerts.error}</p>
                                        : state.data.soc_alerts.alerts.length === 0 ? <p className="text-[11px] text-foreground-muted">None.</p>
                                        : <ul className="text-[11px] space-y-1">{state.data.soc_alerts.alerts.map((a) => <li key={a.id}>{wat(a.timestamp)} · level {a.level} · {a.rule}{a.agent ? ` · ${a.agent}` : ''} <span className="text-foreground-muted">({a.match})</span></li>)}</ul>}
                                </div>
                            </Panel>
                        </div>

                        <Panel title="Timeline & analyst notes">
                            {isAnalyst(role) && (
                                <form className="flex gap-2 mb-4" onSubmit={(e) => { e.preventDefault(); void run('note', 'POST', `/phishid/domains/${id}/notes`, { body: note }, 'Note added.').then((ok) => ok && setNote('')); }}>
                                    <input value={note} onChange={(e) => setNote(e.target.value)} placeholder="Add an analyst note" aria-label="Analyst note" className={`${inputCls} flex-1`} required />
                                    <Button type="submit" variant="primary" busy={busy === 'note'}>Add note</Button>
                                </form>
                            )}
                            {state.data.timeline.length === 0 ? <Empty title="No activity yet" /> : (
                                <ol className="space-y-2">
                                    {state.data.timeline.map((t) => (
                                        <li key={t.id} className="flex gap-3 text-xs">
                                            <span className="text-foreground-muted whitespace-nowrap w-40 shrink-0">{wat(t.created_at)}</span>
                                            <span className="shrink-0"><Badge tone={t.kind === 'note' ? 'purple' : t.kind === 'email' ? 'orange' : 'grey'}>{t.kind}</Badge></span>
                                            <span className="text-foreground min-w-0 break-words">{t.summary} <span className="text-foreground-muted">— {t.actor}</span></span>
                                        </li>
                                    ))}
                                </ol>
                            )}
                        </Panel>
                    </>
                )}
            </Gate>
        </div>
    );
}
