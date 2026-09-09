'use client';

import { useCallback, useEffect, useState } from 'react';
import { ExternalLink, Newspaper, RefreshCw, Radar } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';

// NCC-CSIRT/NGCERT advisories below are still mock data — neither agency exposes a scrapable
// feed. Real advisory format so this stays useful as a template once a live scraper is wired in.
// The "Live Cyber News" section underneath IS live: GET /api/dashboard/nigeria-threats'
// `supplemental` field, sourced from services/serper.ts (Google News search, degrades to an
// empty array if SERPER_API_KEY isn't set).

interface Advisory {
    id: string;
    source: 'NCC-CSIRT' | 'NGCERT';
    title: string;
    severity: 'critical' | 'high' | 'medium';
    date: string;
    affected: string;
    description: string;
    tags: string[];
    link: string;
}

const MOCK_NIGERIA_ADVISORIES: Advisory[] = [
    { id: 'NCC-2026-001', source: 'NCC-CSIRT', title: 'Critical Vulnerability in Nigerian Banking Applications', severity: 'critical', date: '2026-08-20', affected: 'Financial sector', description: 'Multiple Nigerian banking apps found vulnerable to authentication bypass. Immediate patching required.', tags: ['banking', 'authentication', 'CVE'], link: 'https://csirt.ncc.gov.ng' },
    { id: 'NGCERT-2026-047', source: 'NGCERT', title: 'Phishing Campaign Targeting Nigerian Telcos', severity: 'high', date: '2026-08-18', affected: 'Telecommunications', description: 'Coordinated phishing campaign targeting employees of major Nigerian telecom operators.', tags: ['phishing', 'telecom', 'social-engineering'], link: 'https://ngcert.gov.ng' },
    { id: 'NCC-2026-002', source: 'NCC-CSIRT', title: 'Ransomware Wave Targeting West African Organizations', severity: 'critical', date: '2026-08-15', affected: 'All sectors', description: "New ransomware variant specifically targeting organizations in Nigeria, Ghana, and Côte d'Ivoire.", tags: ['ransomware', 'west-africa', 'malware'], link: 'https://csirt.ncc.gov.ng' },
    { id: 'NGCERT-2026-046', source: 'NGCERT', title: 'CBN Issues Warning on Fraudulent USSD Transactions', severity: 'high', date: '2026-08-12', affected: 'Banking, Fintech', description: 'Central Bank of Nigeria warns of increase in fraudulent USSD-based mobile banking transactions.', tags: ['fraud', 'ussd', 'mobile-banking', 'cbn'], link: 'https://ngcert.gov.ng' },
];

const SEV_STYLE: Record<Advisory['severity'], string> = {
    critical: 'bg-red/10 text-red border-red/30', high: 'bg-orange/10 text-orange border-orange/30', medium: 'bg-amber/10 text-amber border-amber/30',
};
const SOURCES = ['All', 'NCC-CSIRT', 'NGCERT'] as const;

// Sector filtering works off the advisory's own tags. Collected advisories carry an explicit
// `sector:<slug>` tag (see backend services/nigeriaDemoSeed.ts, which sets sector:banking,
// sector:telecommunications and so on); older or externally-sourced rows may not, so the
// matcher also falls back to the sector's keywords appearing in any tag or in the title.
const SECTORS = [
    'All Sectors', 'Banking & Finance', 'Telecommunications', 'Fintech',
    'Government', 'Healthcare', 'Energy', 'Education',
] as const;

const SECTOR_KEYWORDS: Record<string, string[]> = {
    'Banking & Finance': ['banking', 'bank', 'finance', 'financial', 'cbn', 'ussd', 'swift'],
    'Telecommunications': ['telecom', 'telco', 'ncc', 'sim', 'ss7', 'mobile'],
    'Fintech': ['fintech', 'payment', 'api', 'mobile-money'],
    'Government': ['government', 'govt', 'public-sector', 'nimc'],
    'Healthcare': ['health', 'healthcare', 'hospital', 'medical'],
    'Energy': ['energy', 'power', 'oil', 'gas', 'utility'],
    'Education': ['education', 'university', 'school', 'academic'],
};

function matchesSector(sector: string, tags: string[] | undefined, title: string): boolean {
    if (sector === 'All Sectors') return true;
    const slug = sector.toLowerCase().split(' ')[0].replace(/[^a-z]/g, '');
    const lowerTags = (tags ?? []).map((t) => t.toLowerCase());

    // Explicit tag wins: `sector:banking`, `sector:telecommunications`, or a blanket `sector:all`.
    if (lowerTags.includes('sector:all')) return true;
    if (lowerTags.some((t) => t.startsWith('sector:') && t.slice(7).startsWith(slug))) return true;

    const keywords = SECTOR_KEYWORDS[sector] ?? [slug];
    const haystack = `${lowerTags.join(' ')} ${title.toLowerCase()}`;
    return keywords.some((k) => haystack.includes(k));
}

interface NewsItem {
    title: string;
    url: string;
    snippet: string;
    source: string;
    date: string | null;
}

// Collected by services/nigerianIntelCollector.ts (ngCERT + OTX), surfaced through
// GET /api/dashboard/nigeria-threats' `supplemental.advisories`.
interface CollectedAdvisory {
    source: string;
    advisory_id: string;
    title: string;
    description: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    threat_type: string;
    tags: string[];
    source_url: string;
    published_at: string;
}

interface CollectorRun {
    ran_at: string;
    advisories: number;
    ips_found: number;
    states_updated: string[];
    advisories_persisted: boolean;
    sources: Array<{ name: string; ok: boolean; items: number; note?: string }>;
}

const COLLECTED_SEV_STYLE: Record<CollectedAdvisory['severity'], string> = {
    critical: 'bg-red/10 text-red border-red/30',
    high: 'bg-orange/10 text-orange border-orange/30',
    medium: 'bg-amber/10 text-amber border-amber/30',
    low: 'bg-blue/10 text-blue border-blue/30',
};

export function NigerianThreatFeed() {
    const [sourceFilter, setSourceFilter] = useState<(typeof SOURCES)[number]>('All');
    const [sectorFilter, setSectorFilter] = useState<string>('All Sectors');
    const filtered = MOCK_NIGERIA_ADVISORIES.filter(
        (a) => (sourceFilter === 'All' || a.source === sourceFilter) && matchesSector(sectorFilter, a.tags, a.title)
    );

    const [news, setNews] = useState<NewsItem[]>([]);
    const [newsLoading, setNewsLoading] = useState(true);
    const [advisories, setAdvisories] = useState<CollectedAdvisory[]>([]);
    const [totalThreats, setTotalThreats] = useState(0);
    const [statesAffected, setStatesAffected] = useState(0);
    const [lastRun, setLastRun] = useState<CollectorRun | null>(null);
    const [refreshing, setRefreshing] = useState(false);

    // Collected (live) advisories get the same sector filter as the reference list above.
    const visibleAdvisories = advisories.filter((a) => matchesSector(sectorFilter, a.tags, a.title));

    const load = useCallback(async () => {
        try {
            const res = await apiFetch(apiUrl('/api/dashboard/nigeria-threats?range=24h'), { cache: 'no-store' });
            if (!res.ok) return;
            const data = await res.json();
            setNews(data?.supplemental?.cyber_news ?? []);
            setAdvisories(data?.supplemental?.advisories ?? []);
            setTotalThreats(data?.summary?.total_threats ?? 0);
            setStatesAffected(data?.summary?.states_affected ?? 0);
        } catch {
            // leave sections empty — each renders its own empty state
        } finally {
            setNewsLoading(false);
        }
    }, []);

    useEffect(() => {
        void load();
        // Last collector run, so the banner can show when intelligence was last refreshed
        // without kicking off a new (slow, externally-rate-limited) collection.
        apiFetch(apiUrl('/api/dashboard/nigeria-threats/status'), { cache: 'no-store' })
            .then((r) => r.json())
            .then((d) => setLastRun(d?.last_run ?? null))
            .catch(() => {});
    }, [load]);

    const triggerCollection = async () => {
        setRefreshing(true);
        try {
            const res = await apiFetch(apiUrl('/api/dashboard/nigeria-threats/collect'), { method: 'POST' });
            const data = await res.json();
            if (data?.result) setLastRun(data.result);
            await load();
        } catch {
            // surfaced by the banner still showing the previous run
        } finally {
            setRefreshing(false);
        }
    };

    return (
        <div className="space-y-4">
            <div>
                <h1 className="text-lg font-black text-foreground">Nigerian Threat Intelligence Feed</h1>
                <p className="text-xs text-foreground-muted">NCC-CSIRT and NGCERT advisories (mock — no live scraper wired yet), plus live cyber news and exposure stats below.</p>
            </div>

            {/* Collector status — real counts from the live intel run, plus a manual trigger */}
            <div className="bg-green/5 border border-green/20 rounded-xl p-4">
                <div className="flex items-center justify-between gap-3 flex-wrap">
                    <div className="min-w-0">
                        <div className="flex items-center gap-2">
                            <Radar size={14} className="text-green" />
                            <span className="text-sm font-bold text-foreground">Nigerian Threat Intelligence</span>
                        </div>
                        <div className="text-xs text-foreground-muted mt-1">
                            {totalThreats.toLocaleString()} threats tracked across {statesAffected} state{statesAffected === 1 ? '' : 's'}
                            {lastRun ? ` · last collection ${new Date(lastRun.ran_at).toLocaleString()}` : ' · no collection run yet this session'}
                        </div>
                        {lastRun && (
                            <div className="text-[10px] text-foreground-muted mt-1.5 flex flex-wrap gap-x-3 gap-y-0.5">
                                {lastRun.sources.map((s) => (
                                    <span key={s.name} className={s.ok ? 'text-foreground-muted' : 'text-amber'}>
                                        {s.name}: {s.ok ? `${s.items} item${s.items === 1 ? '' : 's'}` : (s.note ?? 'unavailable')}
                                    </span>
                                ))}
                            </div>
                        )}
                    </div>
                    <button
                        onClick={triggerCollection}
                        disabled={refreshing}
                        className="flex items-center gap-1.5 bg-green text-white text-xs font-bold px-3 py-1.5 rounded-lg hover:opacity-90 disabled:opacity-50 transition-opacity flex-shrink-0"
                    >
                        <RefreshCw size={12} className={refreshing ? 'animate-spin' : ''} />
                        {refreshing ? 'Collecting…' : 'Refresh Now'}
                    </button>
                </div>
            </div>

            {/* Sector filter — applies to both the collected advisories below and the reference
                list further down. Matches on the advisory's `sector:` tag, falling back to
                keyword matching for rows that don't carry one. */}
            <div>
                <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider mb-2">Sector</p>
                <div className="flex gap-2 flex-wrap">
                    {SECTORS.map((s) => (
                        <button
                            key={s}
                            onClick={() => setSectorFilter(s)}
                            className={`text-xs px-3 py-1.5 rounded-full font-medium transition-colors ${
                                sectorFilter === s ? 'bg-purple text-white' : 'bg-card-muted text-foreground-muted hover:text-purple'
                            }`}
                        >
                            {s}
                        </button>
                    ))}
                </div>
            </div>

            {/* Live advisories collected from ngCERT + CIRCL */}
            {visibleAdvisories.length > 0 && (
                <div>
                    <div className="flex items-center gap-2 mb-2">
                        <h2 className="text-sm font-black text-foreground">Collected Advisories</h2>
                        <span className="text-[9px] font-bold px-1.5 py-0.5 bg-green/10 text-green rounded-full uppercase">Live</span>
                        {sectorFilter !== 'All Sectors' && (
                            <span className="text-[10px] text-foreground-muted">
                                {visibleAdvisories.length} of {advisories.length} in {sectorFilter}
                            </span>
                        )}
                    </div>
                    <div className="space-y-2">
                        {visibleAdvisories.map((a) => (
                            <div key={a.advisory_id} className="bg-card border border-border rounded-xl p-4">
                                <div className="flex items-start justify-between gap-3 mb-1.5">
                                    <div className="flex items-center gap-2 flex-wrap">
                                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border uppercase ${COLLECTED_SEV_STYLE[a.severity] ?? COLLECTED_SEV_STYLE.medium}`}>{a.severity}</span>
                                        <span className="text-[10px] font-bold px-2 py-0.5 bg-purple/10 text-purple rounded-full">{a.source}</span>
                                        {a.threat_type && a.threat_type !== 'unknown' && (
                                            <span className="text-[10px] text-foreground-muted font-mono">{a.threat_type}</span>
                                        )}
                                    </div>
                                    <span className="text-[10px] text-foreground-muted flex-shrink-0">{a.published_at ? new Date(a.published_at).toLocaleDateString() : ''}</span>
                                </div>
                                <p className="text-sm font-bold text-foreground mb-1">{a.title}</p>
                                {a.description && <p className="text-xs text-foreground-muted mb-2 line-clamp-3">{a.description}</p>}
                                <div className="flex items-center justify-between gap-2">
                                    <div className="flex flex-wrap gap-1">
                                        {a.tags?.slice(0, 6).map((t) => (
                                            <span key={t} className="text-[9px] font-medium px-1.5 py-0.5 bg-card-muted text-foreground-muted rounded-full">{t}</span>
                                        ))}
                                    </div>
                                    {a.source_url && (
                                        <a href={a.source_url} target="_blank" rel="noreferrer" className="flex items-center gap-1 text-[10px] font-bold text-blue hover:text-purple transition-colors flex-shrink-0">
                                            View Source <ExternalLink size={10} />
                                        </a>
                                    )}
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            <div className="flex gap-1 bg-card-muted rounded-lg p-1 w-fit">
                {SOURCES.map((s) => (
                    <button key={s} onClick={() => setSourceFilter(s)}
                        className={`px-3 py-1.5 rounded-md text-xs font-bold transition-colors ${sourceFilter === s ? 'bg-card text-blue shadow-sm' : 'text-foreground-muted hover:text-foreground'}`}>
                        {s}
                    </button>
                ))}
            </div>

            <div className="space-y-3">
                {filtered.map((a) => (
                    <div key={a.id} className="bg-card border border-border rounded-xl p-4">
                        <div className="flex items-start justify-between gap-3 mb-2">
                            <div className="flex items-center gap-2 flex-wrap">
                                <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border uppercase ${SEV_STYLE[a.severity]}`}>{a.severity}</span>
                                <span className="text-[10px] font-bold px-2 py-0.5 bg-purple/10 text-purple rounded-full">{a.source}</span>
                                <span className="text-[10px] text-foreground-muted font-mono">{a.id}</span>
                            </div>
                            <span className="text-[10px] text-foreground-muted flex-shrink-0">{a.date}</span>
                        </div>
                        <p className="text-sm font-bold text-foreground mb-1">{a.title}</p>
                        <p className="text-xs text-foreground-muted mb-2">{a.description}</p>
                        <p className="text-[10px] text-foreground-muted mb-3">Affected: <span className="font-bold text-foreground">{a.affected}</span></p>
                        <div className="flex items-center justify-between">
                            <div className="flex flex-wrap gap-1">
                                {a.tags.map((t) => <span key={t} className="text-[9px] font-medium px-1.5 py-0.5 bg-card-muted text-foreground-muted rounded-full">{t}</span>)}
                            </div>
                            <a href={a.link} target="_blank" rel="noreferrer" className="flex items-center gap-1 text-[10px] font-bold text-blue hover:text-purple transition-colors flex-shrink-0">
                                View Original Advisory <ExternalLink size={10} />
                            </a>
                        </div>
                    </div>
                ))}
            </div>

            {/* Live Nigerian Cyber News — Serper Google News search, no mock fallback */}
            <div className="pt-2">
                <div className="flex items-center gap-2 mb-2">
                    <Newspaper size={14} className="text-blue" />
                    <h2 className="text-sm font-black text-foreground">Live Cyber News</h2>
                    <span className="text-[9px] font-bold px-1.5 py-0.5 bg-blue/10 text-blue rounded-full uppercase">Serper</span>
                </div>
                {newsLoading ? (
                    <p className="text-xs text-foreground-muted">Loading live news…</p>
                ) : news.length === 0 ? (
                    <p className="text-xs text-foreground-muted">No live news available — SERPER_API_KEY not configured, or no recent results.</p>
                ) : (
                    <div className="space-y-2">
                        {news.slice(0, 8).map((n) => (
                            <a key={n.url} href={n.url} target="_blank" rel="noreferrer"
                                className="block bg-card border border-border rounded-xl p-3 hover:border-blue/40 transition-colors">
                                <div className="flex items-start justify-between gap-3">
                                    <p className="text-xs font-bold text-foreground">{n.title}</p>
                                    <ExternalLink size={10} className="text-foreground-muted flex-shrink-0 mt-0.5" />
                                </div>
                                {n.snippet && <p className="text-[11px] text-foreground-muted mt-1">{n.snippet}</p>}
                                <p className="text-[9px] text-foreground-muted mt-1">{n.source}{n.date ? ` · ${n.date}` : ''}</p>
                            </a>
                        ))}
                    </div>
                )}
            </div>

        </div>
    );
}
