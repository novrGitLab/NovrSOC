'use client';

import { useState } from 'react';
import { Globe, Search, ShieldAlert, FileText, Network, Award, Copy } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';

// Domain Intelligence — one domain in, every domain-facing check out.
//
// Replaces the old Domain & DNS Suite, which was two independent tools behind a tab switch:
// each had its own input, so investigating one domain meant typing it twice and reading two
// unrelated result panes. Here a single query fans out across three backends in parallel and
// the tabs below are views onto one investigation.
//
// The three calls, and why they're separate:
//   POST /api/brand/domains/investigate  → RDAP/WHOIS + typosquat candidates for any domain.
//   POST /api/dns/lookup                 → DNS records AND crt.sh certificates in one call.
//   POST /api/cti/lookup                 → multi-source reputation.
// Everything else in routes/domainSuite.ts is keyed on a *monitored domain's* id and 404s for
// a domain that was merely typed in, which is why /investigate exists.
//
// Promise.allSettled, not Promise.all: RDAP is unavailable for plenty of TLDs and crt.sh
// rate-limits. One upstream failing must degrade its own tab, not blank the whole report.

interface Whois {
    domain: string;
    registrar: string;
    created: string | null;
    updated: string | null;
    expires: string | null;
    nameservers: string[];
    status: string[];
    dnssec: boolean;
    daysUntilExpiry: number | null;
}

interface Lookalike { domain: string; similarity: number; risk: string }

interface InvestigateResponse {
    domain: string;
    whois: Whois | null;
    lookalikes: Lookalike[];
    lookalikes_note?: string;
}

interface SimpleRecord { name: string; ttl: number; data: string }
interface MxRecord { name: string; ttl: number; priority: number; exchange: string }
interface TxtRecord { name: string; ttl: number; value: string }

interface DnsResponse {
    domain: string;
    records: {
        A: SimpleRecord[]; AAAA: SimpleRecord[]; MX: MxRecord[];
        TXT: TxtRecord[]; NS: SimpleRecord[]; CNAME: SimpleRecord[]; SOA: unknown[];
    };
    certificates: Array<{ issuer: string; common_name: string; san: string[]; not_before: string; not_after: string; expired: boolean }>;
    summary: { total_records: number; total_certs: number; expired_certs: number; expiring_soon: number };
}

interface CtiResponse {
    value: string;
    risk_score: number;
    verdict: 'clean' | 'suspicious' | 'malicious';
    sources: Record<string, unknown>;
    tags: string[];
}

type TabId = 'overview' | 'whois' | 'dns' | 'certs' | 'reputation' | 'lookalikes';

const TABS: { id: TabId; label: string; icon: typeof Globe }[] = [
    { id: 'overview', label: 'Overview', icon: Globe },
    { id: 'whois', label: 'WHOIS', icon: FileText },
    { id: 'dns', label: 'DNS Records', icon: Network },
    { id: 'certs', label: 'Certificates', icon: Award },
    { id: 'reputation', label: 'Reputation', icon: ShieldAlert },
    { id: 'lookalikes', label: 'Lookalikes', icon: Copy },
];

const VERDICT_STYLE: Record<string, string> = {
    malicious: 'bg-red/10 text-red border-red/30',
    suspicious: 'bg-amber/10 text-amber border-amber/30',
    clean: 'bg-green/10 text-green border-green/30',
};

const RISK_STYLE: Record<string, string> = {
    HIGH: 'text-red',
    MEDIUM: 'text-amber',
    LOW: 'text-foreground-muted',
};

function fmtDate(value: string | null | undefined): string {
    if (!value) return '—';
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? value : d.toISOString().split('T')[0];
}

export function DomainIntelligence() {
    const [domain, setDomain] = useState('');
    const [investigating, setInvestigating] = useState(false);
    const [queried, setQueried] = useState<string | null>(null);
    const [tab, setTab] = useState<TabId>('overview');

    const [whoisData, setWhoisData] = useState<InvestigateResponse | null>(null);
    const [dnsData, setDnsData] = useState<DnsResponse | null>(null);
    const [ctiData, setCtiData] = useState<CtiResponse | null>(null);
    // Per-source failure notes, so a tab can say which upstream let it down rather than just
    // rendering empty.
    const [errors, setErrors] = useState<Record<string, string>>({});

    const investigate = async (raw?: string) => {
        const target = (raw ?? domain).trim().toLowerCase()
            .replace(/^https?:\/\//, '').replace(/\/.*$/, '');
        if (!target || investigating) return;

        setInvestigating(true);
        setWhoisData(null); setDnsData(null); setCtiData(null);
        setErrors({});
        setQueried(target);
        setTab('overview');

        const post = (path: string, body: unknown) =>
            apiFetch(apiUrl(path), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
            }).then(async (r) => {
                const data = await r.json();
                if (!r.ok) throw new Error(data?.error ?? `HTTP ${r.status}`);
                return data;
            });

        const [investigation, dns, cti] = await Promise.allSettled([
            post('/api/brand/domains/investigate', { domain: target }),
            post('/api/dns/lookup', { domain: target }),
            post('/api/cti/lookup', { value: target, type: 'domain' }),
        ]);

        const nextErrors: Record<string, string> = {};
        if (investigation.status === 'fulfilled') setWhoisData(investigation.value as InvestigateResponse);
        else nextErrors.whois = investigation.reason?.message ?? 'WHOIS lookup failed';

        if (dns.status === 'fulfilled') setDnsData(dns.value as DnsResponse);
        else nextErrors.dns = dns.reason?.message ?? 'DNS lookup failed';

        if (cti.status === 'fulfilled') setCtiData(cti.value as CtiResponse);
        else nextErrors.reputation = cti.reason?.message ?? 'Reputation lookup failed';

        setErrors(nextErrors);
        setInvestigating(false);
    };

    const hasResults = Boolean(whoisData || dnsData || ctiData);
    const records = dnsData?.records;
    const certs = dnsData?.certificates ?? [];

    return (
        <div id="report-content" className="space-y-4">
            <div className="flex items-start gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-purple/10 flex items-center justify-center flex-shrink-0">
                    <Globe className="w-4 h-4 text-purple" />
                </div>
                <div>
                    <h1 className="text-lg font-black text-foreground">Domain Intelligence</h1>
                    <p className="text-xs text-foreground-muted">
                        Brand Protection · WHOIS, DNS, certificates, reputation and lookalikes for any domain, in one pass
                    </p>
                </div>
            </div>

            {/* Single input */}
            <div className="bg-card border border-border rounded-xl p-4">
                <div className="flex flex-col sm:flex-row gap-3">
                    <input
                        type="text"
                        value={domain}
                        onChange={(e) => setDomain(e.target.value)}
                        onKeyDown={(e) => { if (e.key === 'Enter') void investigate(); }}
                        placeholder="Enter domain to investigate — e.g. cybernovr.com"
                        aria-label="Domain to investigate"
                        className="flex-1 bg-card border border-border rounded-xl px-4 py-3 text-sm text-foreground focus:outline-none focus:border-purple"
                    />
                    <button
                        onClick={() => void investigate()}
                        disabled={investigating || !domain.trim()}
                        className="flex items-center justify-center gap-2 bg-purple hover:opacity-90 disabled:opacity-50 disabled:cursor-not-allowed text-white text-xs font-black px-6 py-3 rounded-xl transition-opacity whitespace-nowrap"
                    >
                        <Search size={14} />
                        {investigating ? 'Investigating…' : 'Investigate'}
                    </button>
                </div>
                <div className="flex gap-2 flex-wrap items-center mt-3">
                    <span className="text-[10px] text-foreground-muted">Try:</span>
                    {['cybernovr.com', 'google.com'].map((ex) => (
                        <button key={ex} onClick={() => { setDomain(ex); void investigate(ex); }} disabled={investigating}
                            className="text-[10px] bg-card-muted text-foreground-muted px-2 py-1 rounded-full hover:text-purple disabled:opacity-40 transition-colors">
                            {ex}
                        </button>
                    ))}
                </div>
                {investigating && (
                    <p className="text-[11px] text-foreground-muted mt-3">
                        Running RDAP, DNS, certificate transparency and reputation checks in parallel…
                    </p>
                )}
            </div>

            {!hasResults && !investigating && (
                <div className="bg-card border border-border rounded-xl p-10 text-center">
                    <Globe className="w-8 h-8 text-foreground-muted mx-auto mb-3 opacity-40" />
                    <p className="text-sm font-bold text-foreground mb-1">No investigation yet</p>
                    <p className="text-xs text-foreground-muted max-w-sm mx-auto">
                        Enter a domain above to run WHOIS, DNS records, certificate transparency,
                        reputation and lookalike checks together.
                    </p>
                </div>
            )}

            {hasResults && (
                <>
                    <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-xs text-foreground-muted">Results for</span>
                        <span className="font-mono text-sm font-bold text-foreground">{queried}</span>
                        {ctiData && (
                            <span className={`text-[10px] font-black uppercase px-2.5 py-1 rounded-full border ${VERDICT_STYLE[ctiData.verdict] ?? 'bg-card-muted text-foreground-muted border-border'}`}>
                                {ctiData.verdict}
                            </span>
                        )}
                    </div>

                    <div className="flex gap-1 bg-card-muted rounded-lg p-1 w-fit overflow-x-auto max-w-full">
                        {TABS.map((t) => {
                            const Icon = t.icon;
                            return (
                                <button
                                    key={t.id}
                                    onClick={() => setTab(t.id)}
                                    className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-bold transition-colors whitespace-nowrap ${
                                        tab === t.id ? 'bg-card text-purple shadow-sm' : 'text-foreground-muted hover:text-foreground'
                                    }`}
                                >
                                    <Icon size={13} />
                                    {t.label}
                                </button>
                            );
                        })}
                    </div>

                    <div className="bg-card border border-border rounded-xl p-5">
                        {tab === 'overview' && (
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                                {[
                                    { label: 'Registrar', value: whoisData?.whois?.registrar ?? '—' },
                                    { label: 'Expires', value: fmtDate(whoisData?.whois?.expires) },
                                    { label: 'DNS Records', value: dnsData ? String(dnsData.summary.total_records) : '—' },
                                    { label: 'Certificates', value: dnsData ? String(dnsData.summary.total_certs) : '—' },
                                    { label: 'Risk Score', value: ctiData ? `${ctiData.risk_score}/100` : '—' },
                                    { label: 'Nameservers', value: whoisData?.whois ? String(whoisData.whois.nameservers.length) : '—' },
                                    { label: 'Expiring Certs (30d)', value: dnsData ? String(dnsData.summary.expiring_soon) : '—' },
                                    { label: 'Lookalike Candidates', value: whoisData ? String(whoisData.lookalikes.length) : '—' },
                                ].map((s) => (
                                    <div key={s.label} className="bg-card-muted/50 border border-border rounded-xl p-3">
                                        <div className="text-sm font-black text-foreground truncate" title={s.value}>{s.value}</div>
                                        <div className="text-[10px] text-foreground-muted mt-0.5">{s.label}</div>
                                    </div>
                                ))}
                                {Object.entries(errors).map(([k, v]) => (
                                    <div key={k} className="col-span-2 md:col-span-4 text-[11px] text-amber">
                                        {k}: {v}
                                    </div>
                                ))}
                            </div>
                        )}

                        {tab === 'whois' && (
                            errors.whois ? <p className="text-xs text-amber">{errors.whois}</p>
                                : !whoisData?.whois ? <p className="text-xs text-foreground-muted">No RDAP/WHOIS record returned for this domain. Many ccTLDs do not publish RDAP.</p>
                                    : (
                                        <div className="space-y-2 text-xs">
                                            {[
                                                ['Domain', whoisData.whois.domain],
                                                ['Registrar', whoisData.whois.registrar],
                                                ['Created', fmtDate(whoisData.whois.created)],
                                                ['Updated', fmtDate(whoisData.whois.updated)],
                                                ['Expires', fmtDate(whoisData.whois.expires)],
                                                ['Days until expiry', whoisData.whois.daysUntilExpiry === null ? '—' : String(whoisData.whois.daysUntilExpiry)],
                                                ['DNSSEC', whoisData.whois.dnssec ? 'Enabled' : 'Not enabled'],
                                                ['Nameservers', whoisData.whois.nameservers.join(', ') || '—'],
                                                ['Status', whoisData.whois.status.join(', ') || '—'],
                                            ].map(([k, v]) => (
                                                <div key={k} className="flex gap-4 border-b border-border pb-2 last:border-0">
                                                    <span className="text-foreground-muted w-40 flex-shrink-0">{k}</span>
                                                    <span className="text-foreground font-medium break-all">{v}</span>
                                                </div>
                                            ))}
                                        </div>
                                    )
                        )}

                        {tab === 'dns' && (
                            errors.dns ? <p className="text-xs text-amber">{errors.dns}</p>
                                : !records ? <p className="text-xs text-foreground-muted">No DNS data returned.</p>
                                    : (
                                        <div className="space-y-5">
                                            {([
                                                ['A', records.A.map((r) => r.data)],
                                                ['AAAA', records.AAAA.map((r) => r.data)],
                                                ['CNAME', records.CNAME.map((r) => r.data)],
                                                ['NS', records.NS.map((r) => r.data)],
                                                ['MX', records.MX.map((r) => `${r.priority} ${r.exchange}`)],
                                                ['TXT', records.TXT.map((r) => r.value)],
                                            ] as [string, string[]][]).map(([type, values]) => (
                                                <div key={type}>
                                                    <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider mb-1.5">
                                                        {type} <span className="text-foreground-muted/60">({values.length})</span>
                                                    </p>
                                                    {values.length === 0 ? (
                                                        <p className="text-[11px] text-foreground-muted">No {type} records.</p>
                                                    ) : (
                                                        <div className="space-y-1">
                                                            {values.map((v, i) => (
                                                                <p key={i} className="font-mono text-[11px] text-foreground break-all bg-card-muted/50 rounded px-2 py-1">{v}</p>
                                                            ))}
                                                        </div>
                                                    )}
                                                </div>
                                            ))}
                                            {/* SPF/DMARC are TXT records — surfaced explicitly because their
                                                absence is the finding, and a missing row is easy to miss. */}
                                            <div className="flex gap-3 flex-wrap pt-2 border-t border-border">
                                                {[
                                                    ['SPF', records.TXT.some((r) => r.value.includes('v=spf1'))],
                                                    ['DMARC', records.TXT.some((r) => r.value.includes('v=DMARC1'))],
                                                ].map(([label, present]) => (
                                                    <span key={String(label)} className={`text-[10px] font-bold px-2.5 py-1 rounded-full ${present ? 'bg-green/10 text-green' : 'bg-amber/10 text-amber'}`}>
                                                        {String(label)}: {present ? 'present' : 'not found at this name'}
                                                    </span>
                                                ))}
                                            </div>
                                        </div>
                                    )
                        )}

                        {tab === 'certs' && (
                            errors.dns ? <p className="text-xs text-amber">{errors.dns}</p>
                                : certs.length === 0 ? <p className="text-xs text-foreground-muted">No certificates found in Certificate Transparency logs for this domain.</p>
                                    : (
                                        <div className="overflow-x-auto scrollbar-thin">
                                            <table className="w-full text-left text-xs">
                                                <thead>
                                                    <tr className="border-b border-border">
                                                        {['Common Name', 'Issuer', 'Valid From', 'Valid To', 'Status'].map((c) => (
                                                            <th key={c} className="py-2 pr-4 text-[10px] font-semibold text-foreground-muted uppercase tracking-widest whitespace-nowrap">{c}</th>
                                                        ))}
                                                    </tr>
                                                </thead>
                                                <tbody className="divide-y divide-border">
                                                    {certs.slice(0, 40).map((c, i) => (
                                                        <tr key={i}>
                                                            <td className="py-2 pr-4 font-mono text-foreground break-all">{c.common_name}</td>
                                                            <td className="py-2 pr-4 text-foreground-muted">{c.issuer}</td>
                                                            <td className="py-2 pr-4 text-foreground-muted whitespace-nowrap">{fmtDate(c.not_before)}</td>
                                                            <td className="py-2 pr-4 text-foreground-muted whitespace-nowrap">{fmtDate(c.not_after)}</td>
                                                            <td className={`py-2 font-bold uppercase text-[10px] ${c.expired ? 'text-foreground-muted' : 'text-green'}`}>
                                                                {c.expired ? 'Expired' : 'Valid'}
                                                            </td>
                                                        </tr>
                                                    ))}
                                                </tbody>
                                            </table>
                                            {certs.length > 40 && (
                                                <p className="text-[10px] text-foreground-muted mt-2">Showing the first 40 of {certs.length} certificates.</p>
                                            )}
                                        </div>
                                    )
                        )}

                        {tab === 'reputation' && (
                            errors.reputation ? <p className="text-xs text-amber">{errors.reputation}</p>
                                : !ctiData ? <p className="text-xs text-foreground-muted">No reputation data returned.</p>
                                    : (
                                        <div className="space-y-4">
                                            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                                                <div className="bg-card-muted/50 border border-border rounded-xl p-3">
                                                    <div className="text-xl font-black text-foreground">{ctiData.risk_score}/100</div>
                                                    <div className="text-[10px] text-foreground-muted">Risk Score</div>
                                                </div>
                                                <div className="bg-card-muted/50 border border-border rounded-xl p-3">
                                                    <div className="text-xl font-black text-foreground capitalize">{ctiData.verdict}</div>
                                                    <div className="text-[10px] text-foreground-muted">Verdict</div>
                                                </div>
                                                <div className="bg-card-muted/50 border border-border rounded-xl p-3">
                                                    <div className="text-xl font-black text-foreground">
                                                        {Object.values(ctiData.sources ?? {}).filter((v) => v !== null).length}
                                                    </div>
                                                    <div className="text-[10px] text-foreground-muted">Sources Responded</div>
                                                </div>
                                            </div>
                                            {ctiData.tags?.length > 0 && (
                                                <div className="flex gap-1.5 flex-wrap">
                                                    {ctiData.tags.map((t) => (
                                                        <span key={t} className="text-[10px] bg-card-muted text-foreground-muted px-2 py-0.5 rounded-full">{t}</span>
                                                    ))}
                                                </div>
                                            )}
                                            <div className="space-y-1.5">
                                                {Object.entries(ctiData.sources ?? {}).map(([name, value]) => (
                                                    <div key={name} className="flex items-center justify-between text-xs border-b border-border pb-1.5 last:border-0">
                                                        <span className="text-foreground-muted capitalize">{name}</span>
                                                        <span className={value === null ? 'text-foreground-muted' : 'text-foreground font-medium'}>
                                                            {value === null ? 'no response' : 'responded'}
                                                        </span>
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    )
                        )}

                        {tab === 'lookalikes' && (
                            errors.whois ? <p className="text-xs text-amber">{errors.whois}</p>
                                : !whoisData || whoisData.lookalikes.length === 0 ? <p className="text-xs text-foreground-muted">No lookalike candidates generated.</p>
                                    : (
                                        <div className="space-y-3">
                                            {/* The backend generates these by pattern and does NOT check whether
                                                they are registered or resolving. Saying so here matters: an
                                                unlabelled list reads as confirmed hostile registrations. */}
                                            <p className="text-[11px] text-amber bg-amber/10 border border-amber/20 rounded-lg p-2.5">
                                                {whoisData.lookalikes_note ?? 'Pattern-generated candidates — registration and resolution are not verified.'}
                                            </p>
                                            {whoisData.lookalikes.map((l) => (
                                                <div key={l.domain} className="flex items-center justify-between gap-3 border-b border-border pb-2 last:border-0">
                                                    <span className="font-mono text-xs text-foreground break-all">{l.domain}</span>
                                                    <div className="flex items-center gap-4 flex-shrink-0">
                                                        <span className="text-[11px] text-foreground-muted">{l.similarity}% similar</span>
                                                        <span className={`text-[10px] font-black uppercase ${RISK_STYLE[l.risk] ?? 'text-foreground-muted'}`}>{l.risk}</span>
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    )
                        )}
                    </div>
                </>
            )}
        </div>
    );
}
