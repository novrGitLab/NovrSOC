'use client';

import { useCallback, useEffect, useState } from 'react';
import { Radio, Search, Plus, Check, ExternalLink } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';

// Live IOC feed — fresh indicators straight from the upstream threat feeds.
//
// Deliberately NOT backed by /api/cti/feed. That endpoint reads Supabase's `ioc_enrichments`
// table, which only ever contains IOCs an analyst has already looked up by hand, so it returns
// an empty list on a perfectly healthy deployment (confirmed live: {"iocs":[],"count":0}). That
// is why this page previously showed nothing. GET /api/threats/live-ioc pulls ThreatFox,
// URLhaus and Feodo Tracker directly instead.

const REFRESH_MS = 60000;

type IOCType = 'ip' | 'domain' | 'url' | 'hash';

interface LiveIOC {
    value: string;
    type: IOCType;
    threat: string;
    source: string;
    confidence: number;
    tags: string[];
    first_seen: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    reference: string | null;
}

interface SourceStatus { name: string; ok: boolean; count: number }

interface FeedResponse {
    iocs: LiveIOC[];
    total: number;
    returned: number;
    sources: SourceStatus[];
    last_updated: string;
}

const SEVERITY_STYLE: Record<string, string> = {
    critical: 'bg-red-500/10 text-red-500 border-red-500/30',
    high: 'bg-orange/10 text-orange border-orange/30',
    medium: 'bg-amber-500/10 text-amber-500 border-amber-500/30',
    low: 'bg-card-muted text-foreground-muted border-border',
};

const TYPE_STYLE: Record<IOCType, string> = {
    ip: 'bg-blue/10 text-blue',
    domain: 'bg-purple/10 text-purple',
    url: 'bg-amber-500/10 text-amber-500',
    hash: 'bg-card-muted text-foreground-muted',
};

const TYPES: (IOCType | 'all')[] = ['all', 'ip', 'domain', 'url', 'hash'];
const WATCHLIST_KEY = 'novrsoc.ioc-watchlist';

function secondsAgo(iso: string | null): number | null {
    if (!iso) return null;
    const t = new Date(iso).getTime();
    if (Number.isNaN(t)) return null;
    return Math.max(0, Math.round((Date.now() - t) / 1000));
}

export function LiveIOCFeed() {
    const [data, setData] = useState<FeedResponse | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [typeFilter, setTypeFilter] = useState<IOCType | 'all'>('all');
    const [sourceFilter, setSourceFilter] = useState<string>('all');
    const [search, setSearch] = useState('');
    const [watchlist, setWatchlist] = useState<Set<string>>(new Set());
    // Ticks once a second purely to re-render the "updated Xs ago" label.
    const [, setTick] = useState(0);

    const load = useCallback((type: string, source: string) => {
        const params = new URLSearchParams({ limit: '150' });
        if (type !== 'all') params.set('type', type);
        if (source !== 'all') params.set('source', source);

        return apiFetch(apiUrl(`/api/threats/live-ioc?${params}`), { cache: 'no-store' })
            .then(async (r) => {
                const json = await r.json();
                if (!r.ok) throw new Error(json?.error ?? `HTTP ${r.status}`);
                return json as FeedResponse;
            })
            .then((json) => {
                setData(json);
                setError(null);
            })
            .catch((e) => setError(e instanceof Error ? e.message : 'Feed unavailable'))
            .finally(() => setLoading(false));
    }, []);

    useEffect(() => {
        void load(typeFilter, sourceFilter);
        const refresh = setInterval(() => void load(typeFilter, sourceFilter), REFRESH_MS);
        const ticker = setInterval(() => setTick((t) => t + 1), 1000);
        return () => { clearInterval(refresh); clearInterval(ticker); };
    }, [load, typeFilter, sourceFilter]);

    // Watchlist is per-browser. There is no watchlist table in Supabase and no endpoint to POST
    // one to, so persisting it locally is the honest option — the note under the list says so
    // rather than implying it's shared with the team.
    useEffect(() => {
        try {
            const raw = localStorage.getItem(WATCHLIST_KEY);
            // eslint-disable-next-line react-hooks/set-state-in-effect -- one-shot hydrate from localStorage, an external store; see note above
            if (raw) setWatchlist(new Set(JSON.parse(raw) as string[]));
        } catch {
            // Blocked site data — watchlist just starts empty.
        }
    }, []);

    function toggleWatch(value: string) {
        setWatchlist((prev) => {
            const next = new Set(prev);
            if (next.has(value)) next.delete(value); else next.add(value);
            try { localStorage.setItem(WATCHLIST_KEY, JSON.stringify([...next])); } catch { /* best effort */ }
            return next;
        });
    }

    const ago = secondsAgo(data?.last_updated ?? null);
    const sources = data?.sources ?? [];
    // Client-side text search on top of the server's type/source filters — the server has no
    // free-text parameter, and filtering 150 rows in the browser is instant.
    const visible = (data?.iocs ?? []).filter((i) => {
        if (!search.trim()) return true;
        const q = search.trim().toLowerCase();
        return i.value.toLowerCase().includes(q) || i.threat.toLowerCase().includes(q) || i.tags.some((t) => t.toLowerCase().includes(q));
    });

    return (
        <div className="space-y-4">
            <div className="flex items-start justify-between gap-4 flex-wrap">
                <div className="flex items-start gap-2.5">
                    <div className="w-8 h-8 rounded-lg bg-red-500/10 flex items-center justify-center shrink-0">
                        <Radio className="w-4 h-4 text-red-500" />
                    </div>
                    <div>
                        <h1 className="text-lg font-black text-foreground">Live IOC Feed</h1>
                        <p className="text-xs text-foreground-muted">
                            Threat Intelligence · Fresh indicators from ThreatFox, URLhaus and Feodo Tracker
                        </p>
                    </div>
                </div>
                <div className="flex items-center gap-2">
                    <div className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />
                    <span className="text-[10px] text-foreground-muted">
                        {ago === null ? 'Loading…' : `Last updated ${ago}s ago · refreshes every 60s`}
                    </span>
                </div>
            </div>

            {/* Totals + per-source health. Reports what each feed actually returned rather than
                implying all three always contribute. */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div className="bg-card border border-border rounded-xl p-4">
                    <div className="text-2xl font-black text-foreground">{data ? data.total.toLocaleString() : '—'}</div>
                    <div className="text-[10px] text-foreground-muted mt-0.5">Active IOCs</div>
                </div>
                {sources.map((s) => (
                    <div key={s.name} className="bg-card border border-border rounded-xl p-4">
                        <div className={`text-2xl font-black ${s.ok ? 'text-foreground' : 'text-red-500'}`}>
                            {s.ok ? s.count.toLocaleString() : '—'}
                        </div>
                        <div className="text-[10px] text-foreground-muted mt-0.5">
                            {s.name} {s.ok ? '' : '· unreachable'}
                        </div>
                    </div>
                ))}
            </div>

            {/* Filters */}
            <div className="bg-card border border-border rounded-xl p-4 flex flex-wrap items-center gap-3">
                <div className="flex items-center gap-1.5 flex-1 min-w-[200px]">
                    <Search size={14} className="text-foreground-muted shrink-0" />
                    <input
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                        placeholder="Search value, threat or tag…"
                        aria-label="Search IOCs"
                        className="flex-1 bg-transparent text-sm text-foreground focus:outline-none placeholder:text-foreground-muted"
                    />
                </div>
                <div className="flex items-center gap-0.5 bg-card-muted border border-border rounded-lg p-0.5">
                    {TYPES.map((t) => (
                        <button key={t} onClick={() => setTypeFilter(t)}
                            className={`px-2.5 py-1 rounded-md text-[11px] font-semibold uppercase transition-colors ${typeFilter === t ? 'bg-purple text-white' : 'text-foreground-muted hover:text-foreground'}`}>
                            {t}
                        </button>
                    ))}
                </div>
                <select
                    value={sourceFilter}
                    onChange={(e) => setSourceFilter(e.target.value)}
                    aria-label="Filter by source"
                    className="bg-card border border-border rounded-lg px-2.5 py-1.5 text-xs font-bold text-foreground focus:outline-none"
                >
                    <option value="all">All sources</option>
                    {sources.map((s) => <option key={s.name} value={s.name}>{s.name}</option>)}
                </select>
            </div>

            {error && (
                <div className="bg-red-500/5 border border-red-500/30 rounded-xl p-4 text-xs text-red-500">
                    Feed unavailable: {error}
                </div>
            )}

            {/* Feed */}
            <div className="space-y-2">
                {loading && !data ? (
                    Array.from({ length: 6 }).map((_, i) => <div key={i} className="h-20 bg-card-muted rounded-xl animate-pulse" />)
                ) : visible.length === 0 ? (
                    <div className="bg-card border border-border rounded-xl p-10 text-center">
                        <p className="text-sm font-bold text-foreground mb-1">No indicators match</p>
                        <p className="text-xs text-foreground-muted">
                            {data && data.total === 0
                                ? 'No feed returned indicators — check the source health above.'
                                : 'Try a different type, source or search term.'}
                        </p>
                    </div>
                ) : (
                    visible.map((ioc, i) => {
                        const watched = watchlist.has(ioc.value);
                        return (
                            <div key={`${ioc.source}-${ioc.value}-${i}`} className="bg-card border border-border rounded-xl p-4 hover:border-purple/40 transition-colors">
                                <div className="flex items-start justify-between gap-3 flex-wrap">
                                    <div className="min-w-0 flex-1">
                                        <div className="flex items-center gap-2 flex-wrap mb-1.5">
                                            <span className={`text-[9px] font-black px-2 py-0.5 rounded-full uppercase ${TYPE_STYLE[ioc.type]}`}>{ioc.type}</span>
                                            <span className={`text-[9px] font-black px-2 py-0.5 rounded-full border uppercase ${SEVERITY_STYLE[ioc.severity]}`}>{ioc.severity}</span>
                                            <span className="text-[10px] text-foreground-muted">{ioc.source}</span>
                                            <span className="text-[10px] text-foreground-muted">· {ioc.confidence}% confidence</span>
                                        </div>
                                        <p className="font-mono text-sm text-foreground break-all">{ioc.value}</p>
                                        <p className="text-xs text-foreground-muted mt-0.5">{ioc.threat}</p>
                                        {ioc.tags.length > 0 && (
                                            <div className="flex gap-1.5 flex-wrap mt-1.5">
                                                {ioc.tags.slice(0, 5).map((t, ti) => (
                                                    <span key={`${t}-${ti}`} className="text-[9px] bg-card-muted text-foreground-muted px-1.5 py-0.5 rounded-full">{t}</span>
                                                ))}
                                            </div>
                                        )}
                                    </div>
                                    <div className="flex items-center gap-2 shrink-0">
                                        {ioc.first_seen && <span className="text-[10px] text-foreground-muted">{ioc.first_seen}</span>}
                                        {ioc.reference && (
                                            <a href={ioc.reference} target="_blank" rel="noopener noreferrer"
                                                className="text-foreground-muted hover:text-purple transition-colors" aria-label="View source">
                                                <ExternalLink size={14} />
                                            </a>
                                        )}
                                        <button
                                            onClick={() => toggleWatch(ioc.value)}
                                            className={`flex items-center gap-1 text-[10px] font-bold px-2.5 py-1.5 rounded-lg border transition-colors ${
                                                watched ? 'bg-emerald-500/10 text-emerald-500 border-emerald-500/30' : 'border-border text-foreground-muted hover:text-purple hover:border-purple/40'
                                            }`}
                                        >
                                            {watched ? <Check size={12} /> : <Plus size={12} />}
                                            {watched ? 'Watching' : 'Watchlist'}
                                        </button>
                                    </div>
                                </div>
                            </div>
                        );
                    })
                )}
            </div>

            {data && data.total > data.returned && (
                <p className="text-[10px] text-foreground-muted text-center">
                    Showing {visible.length.toLocaleString()} of {data.total.toLocaleString()} indicators.
                </p>
            )}
            <p className="text-[10px] text-foreground-muted">
                Watchlist is saved in this browser only — there is no watchlist table yet, so it
                isn&apos;t shared with your team. URLhaus publishes no confidence score; its entries
                carry a fixed editorial value rather than a figure from the API.
            </p>
        </div>
    );
}
