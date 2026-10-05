'use client';

import { useState } from 'react';
import Link from 'next/link';
import { Radar, Plus, RefreshCw, Fingerprint, ShieldPlus } from 'lucide-react';
import {
    useEmailApi, send, useRole, isManager, isAnalyst, PageHeader, Panel, Tabs, Gate, Empty, SevBadge, StatusBadge, Badge, Button, Feedback,
    inputCls, selectCls, wat, label, th, td,
} from './shared';

export const investigateHref = (domain: string) => `/admin/email/phishid/investigate/${encodeURIComponent(domain)}`;

// Intellicode Phish ID — is someone pretending to be your organisation on the internet?
// Brand configuration drives look-alike discovery (typosquats, homoglyphs, keyword domains,
// Certificate Transparency). Discovery only records domains that exist; each is scored from
// evidence and every score shows its reasons on the investigation page.

export interface Brand {
    organization_name: string; primary_domains: string[]; additional_domains: string[]; keywords: string[];
    legitimate_domains: string[]; legitimate_urls: string[]; logo_url: string | null; last_discovery: string | null; updated_by: string | null; updated_at: string;
}
interface DomainRow {
    id: string; domain: string; brand_domain: string | null; techniques: string[]; similarity: number | null; discovered_via: string; status: string; risk: string;
    risk_score: number; resolves: boolean | null; assigned_to: string | null; alert_id: string | null; first_observed: string; last_observed: string; last_enriched: string | null;
    risk_signals?: { id: string; label: string; points: number }[];
}
const OPEN = (d: DomainRow) => !['false_positive', 'resolved'].includes(d.status);
const WEBSITE_SIGNALS = new Set(['login_form', 'login_language', 'brand_on_page', 'external_form', 'credential_harvest', 'redirect']);
/** Why it was flagged, in a few words: the strongest evidence first, else how it imitates the brand. */
function reason(d: DomainRow): string {
    const sig = [...(d.risk_signals ?? [])].sort((a, b) => b.points - a.points).map((x) => x.label);
    if (sig.length) return sig.slice(0, 2).join(' + ');
    return d.techniques.length ? `Look-alike (${d.techniques.map(label).join(', ').toLowerCase()})` : 'Reported for investigation';
}

const STATUSES = ['discovered', 'under_investigation', 'suspicious', 'confirmed_phishing', 'false_positive', 'resolved'];
const RISKS = ['critical', 'high', 'medium', 'low', 'informational'];
const VIA: Record<string, string> = { permutation: 'Permutation', certificate_transparency: 'Cert. Transparency', manual: 'Manual', email: 'Email' };
type Tab = 'discoveries' | 'brand';

export function PhishId() {
    const [nonce, setNonce] = useState(0);
    const brand = useEmailApi<{ brand: Brand | null }>('/phishid/brand', nonce);
    const hasBrand = !!brand.data?.brand;
    const [tabChoice, setTab] = useState<Tab | null>(null);
    const tab: Tab = tabChoice ?? (brand.data && !hasBrand ? 'brand' : 'discoveries');
    const manager = isManager(useRole());
    return (
        <div className="space-y-4">
            <PageHeader
                title="Intellicode Phish ID"
                subtitle="Detect domains and infrastructure attempting to impersonate your organisation."
                actions={manager ? <Button variant="primary" onClick={() => setTab('brand')}><ShieldPlus size={12} /> {hasBrand ? 'Edit protected brand' : 'Protect a brand'}</Button>
                    : hasBrand ? <Button onClick={() => setTab('brand')}>View protected brand</Button> : undefined}
            />
            <Tabs<Tab> value={tab} onChange={setTab} tabs={[{ id: 'discoveries', label: 'Threats' }, { id: 'brand', label: 'Protected brand' }]} />
            <Gate state={brand}>
                {tab === 'discoveries'
                    ? (hasBrand ? <Discoveries brand={brand.data!.brand!} /> : (
                        <Panel><Empty icon={<Fingerprint size={18} />} title="No brand protected yet" body="Add your organisation's name, domains and brand keywords. Phish ID then searches daily for look-alike domains and impersonating websites." action={manager ? <Button variant="primary" onClick={() => setTab('brand')}>Protect a brand</Button> : <span className="text-xs text-foreground-muted">A SOC manager can set this up.</span>} /></Panel>
                    ))
                    : <BrandForm brand={brand.data?.brand ?? null} onSaved={() => { setNonce((x) => x + 1); setTab('discoveries'); }} />}
            </Gate>
        </div>
    );
}

function Discoveries({ brand }: { brand: Brand }) {
    const role = useRole();
    const [nonce, setNonce] = useState(0);
    const [status, setStatus] = useState('open');
    const [risk, setRisk] = useState('');
    const [q, setQ] = useState('');
    const qs = new URLSearchParams({ ...(status && status !== 'open' ? { status } : {}), ...(risk ? { risk } : {}), ...(q.trim() ? { q: q.trim() } : {}) }).toString();
    const state = useEmailApi<{ domains: DomainRow[] }>(`/phishid/domains${qs ? `?${qs}` : ''}`, nonce);
    const rows = (state.data?.domains ?? []).filter((d) => status !== 'open' || !['false_positive', 'resolved'].includes(d.status));
    const [busy, setBusy] = useState<string | null>(null);
    const [fb, setFb] = useState<{ ok: boolean; text: string } | null>(null);
    const [manual, setManual] = useState('');

    async function discover() {
        setBusy('discover'); setFb(null);
        const r = await send<{ candidates_checked: number; registered: number; new_domains: string[]; ct_error: string | null; errors: number }>('POST', '/phishid/discover');
        setBusy(null);
        if (!r.ok || !r.data) { setFb({ ok: false, text: r.error ?? 'Discovery failed' }); return; }
        const d = r.data;
        setFb({ ok: true, text: `Checked ${d.candidates_checked.toLocaleString()} look-alike candidates: ${d.registered} registered, ${d.new_domains.length} new.${d.ct_error ? ` Certificate Transparency: ${d.ct_error}.` : ''}${d.errors ? ` ${d.errors} DNS lookups failed and will be retried next run.` : ''} New domains are enriched in the background.` });
        setNonce((x) => x + 1);
    }
    async function addManual(e: React.FormEvent) {
        e.preventDefault();
        setBusy('manual'); setFb(null);
        const r = await send<{ domain: DomainRow; created: boolean }>('POST', '/phishid/domains', { domain: manual });
        setBusy(null);
        setFb({ ok: r.ok, text: r.ok ? (r.data?.created ? `${r.data.domain.domain} added for investigation.` : 'Already tracked.') : r.error ?? 'Failed' });
        if (r.ok) { setManual(''); setNonce((x) => x + 1); }
    }

    const all = useEmailApi<{ domains: DomainRow[] }>('/phishid/domains', nonce);
    const findings = all.data?.domains ?? [];
    const summary = [
        { label: 'Look-alike domains', value: findings.filter(OPEN).length, note: 'Open findings' },
        { label: 'Suspicious websites', value: findings.filter((d) => OPEN(d) && (d.risk_signals ?? []).some((x) => WEBSITE_SIGNALS.has(x.id))).length, note: 'Login forms, brand use or off-site forms' },
        { label: 'Phishing infrastructure', value: findings.filter((d) => d.status === 'confirmed_phishing').length, note: 'Confirmed by an analyst' },
        { label: 'High-risk findings', value: findings.filter((d) => OPEN(d) && (d.risk === 'high' || d.risk === 'critical')).length, note: 'High or critical risk' },
    ];
    return (
        <div className="space-y-4">
            <section className="bg-card border border-border rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-3">
                <div className="min-w-0">
                    <p className="text-[10px] font-bold uppercase tracking-wider text-foreground-muted">Protected brand</p>
                    <p className="text-sm font-black text-foreground mt-0.5">{brand.organization_name}</p>
                    <p className="text-xs text-foreground-muted wrap-anywhere">{[...brand.primary_domains, ...brand.additional_domains].join(' · ')}{brand.keywords.length ? <> · keywords: {brand.keywords.join(', ')}</> : null}</p>
                </div>
                <div className="text-xs md:text-right shrink-0">
                    <StatusBadge s="monitoring" />
                    <p className="text-[10px] text-foreground-muted mt-1">Last discovery: {brand.last_discovery ? wat(brand.last_discovery) : 'pending (runs within the hour, then daily)'}</p>
                </div>
            </section>
            <Gate state={all}>
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                    {summary.map((m) => (
                        <div key={m.label} className="bg-card border border-border rounded-xl p-4 min-w-0">
                            <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">{m.label}</p>
                            <p className="text-2xl font-black text-foreground mt-1">{m.value}</p>
                            <p className="text-[10px] text-foreground-muted">{m.note}</p>
                        </div>
                    ))}
                </div>
            </Gate>
            <Panel title="Discovery" action={<span className="text-[10px] text-foreground-muted hidden sm:inline">Typosquats, homoglyphs, keyword domains and Certificate Transparency</span>}>
                <div className="flex flex-wrap items-center gap-3 justify-between">
                    <p className="text-xs text-foreground-muted">Found something suspicious yourself? Add it for investigation.</p>
                    <div className="flex flex-wrap gap-2">
                        {isAnalyst(role) && (
                            <form onSubmit={addManual} className="flex gap-2 min-w-0">
                                <input value={manual} onChange={(e) => setManual(e.target.value)} placeholder="Report a suspicious domain" aria-label="Suspicious domain" className={`${inputCls} w-52 min-w-0`} required />
                                <Button type="submit" busy={busy === 'manual'}><Plus size={12} /> Add</Button>
                            </form>
                        )}
                        {isManager(role) && <Button variant="primary" onClick={discover} busy={busy === 'discover'}><Radar size={12} /> Run discovery now</Button>}
                    </div>
                </div>
                <div className="mt-2"><Feedback result={fb} /></div>
            </Panel>

            <div className="flex flex-wrap gap-2 items-center">
                <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search domains" aria-label="Search domains" className={`${inputCls} w-52`} />
                <select value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Status" className={selectCls}>
                    <option value="open">Open (not resolved / false positive)</option><option value="">All statuses</option>
                    {STATUSES.map((s) => <option key={s} value={s}>{label(s)}</option>)}
                </select>
                <select value={risk} onChange={(e) => setRisk(e.target.value)} aria-label="Risk" className={selectCls}>
                    <option value="">All risk levels</option>{RISKS.map((r) => <option key={r} value={r}>{label(r)}</option>)}
                </select>
                <Button onClick={() => setNonce((x) => x + 1)}><RefreshCw size={12} /> Refresh</Button>
            </div>

            <Panel>
                <Gate state={state}>
                    {rows.length === 0 ? (
                        <Empty title={state.data?.domains.length ? 'Nothing matches these filters' : 'No phishing threats detected'}
                            body={state.data?.domains.length ? undefined : brand.last_discovery ? 'The last discovery run found no registered look-alikes. Discovery repeats daily.' : 'The first discovery run starts within the hour after the brand is saved, or a manager can run it now.'} />
                    ) : (
                        <div className="overflow-x-auto -m-4">
                            <table className="w-full text-xs min-w-[760px]">
                                <thead><tr className="border-b border-border">{['Domain', 'Risk', 'Detection reason', 'First seen', 'Status'].map((h) => <th key={h} className={th}>{h}</th>)}</tr></thead>
                                <tbody>
                                    {rows.map((d) => (
                                        <tr key={d.id} className="border-b border-border/60 last:border-0 hover:bg-card-muted/40 align-top">
                                            <td className={`${td} max-w-[260px]`}>
                                                <Link href={investigateHref(d.domain)} className="font-mono font-bold text-foreground hover:text-purple wrap-anywhere">{d.domain}</Link>
                                                <p className="text-[10px] text-foreground-muted">{d.brand_domain ? `Resembles ${d.brand_domain}` : 'Reported'}{d.resolves === false ? ' · not resolving' : ''} · {VIA[d.discovered_via] ?? d.discovered_via}</p>
                                            </td>
                                            <td className={td}>{d.last_enriched ? <SevBadge s={d.risk} /> : <span className="text-[10px] text-foreground-muted">Not assessed yet</span>}</td>
                                            <td className={`${td} text-foreground max-w-[320px]`}>{reason(d)}<div className="flex flex-wrap gap-1 mt-1">{d.techniques.slice(0, 3).map((t) => <Badge key={t} tone="grey">{label(t)}</Badge>)}</div></td>
                                            <td className={`${td} text-foreground-muted whitespace-nowrap`}>{wat(d.first_observed)}</td>
                                            <td className={td}><StatusBadge s={d.status} />{d.assigned_to && <p className="text-[10px] text-foreground-muted mt-0.5 wrap-anywhere">{d.assigned_to}</p>}</td>
                                        </tr>
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

function BrandForm({ brand, onSaved }: { brand: Brand | null; onSaved: () => void }) {
    const role = useRole();
    const canEdit = isManager(role);
    const join = (a?: string[]) => (a ?? []).join('\n');
    const [f, setF] = useState({
        organization_name: brand?.organization_name ?? '', primary_domains: join(brand?.primary_domains), additional_domains: join(brand?.additional_domains),
        keywords: join(brand?.keywords), legitimate_domains: join(brand?.legitimate_domains), legitimate_urls: join(brand?.legitimate_urls), logo_url: brand?.logo_url ?? '',
    });
    const [busy, setBusy] = useState(false);
    const [fb, setFb] = useState<{ ok: boolean; text: string } | null>(null);
    const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => setF((x) => ({ ...x, [k]: e.target.value }));

    async function save(e: React.FormEvent) {
        e.preventDefault();
        setBusy(true); setFb(null);
        const r = await send('PUT', '/phishid/brand', { ...f, logo_url: f.logo_url || null });
        setBusy(false);
        setFb({ ok: r.ok, text: r.ok ? 'Brand saved. Discovery runs automatically.' : r.error ?? 'Failed' });
        if (r.ok) onSaved();
    }

    const field = (k: keyof typeof f, title: string, hint: string, multi = true) => (
        <label className="block">
            <span className="block text-[11px] font-bold text-foreground">{title}</span>
            <span className="block text-[10px] text-foreground-muted mb-1">{hint}</span>
            {multi ? <textarea value={f[k]} onChange={set(k)} rows={3} disabled={!canEdit} className={`${inputCls} w-full font-mono`} />
                : <input value={f[k]} onChange={set(k)} disabled={!canEdit} className={`${inputCls} w-full`} />}
        </label>
    );

    return (
        <Panel title="Brand configuration" action={brand && <span className="text-[10px] text-foreground-muted">Updated {wat(brand.updated_at)}{brand.updated_by ? ` by ${brand.updated_by}` : ''}</span>}>
            <form onSubmit={save} className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {field('organization_name', 'Organisation name', 'Also used to recognise your brand on suspicious pages.', false)}
                {field('logo_url', 'Logo URL (optional)', 'https:// address of your logo, kept for reference.', false)}
                {field('primary_domains', 'Primary domains', 'One per line. Look-alikes of these are searched for.')}
                {field('additional_domains', 'Additional domains', 'Other domains you own that should also be protected.')}
                {field('keywords', 'Brand keywords', 'Product or brand names (min. 3 characters) to look for in domains and pages.')}
                {field('legitimate_domains', 'Known legitimate domains', 'Domains you own or trust that resemble your brand — never flagged.')}
                {field('legitimate_urls', 'Known legitimate URLs', 'Official login / portal URLs, one per line.')}
                <div className="md:col-span-2 flex items-center gap-3">
                    {canEdit ? <Button type="submit" variant="primary" busy={busy}>Save brand</Button> : <p className="text-[11px] text-foreground-muted">A SOC manager can change the brand configuration.</p>}
                    <Feedback result={fb} />
                </div>
            </form>
        </Panel>
    );
}
