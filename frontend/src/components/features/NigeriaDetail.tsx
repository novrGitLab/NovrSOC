'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { Radio, ArrowLeft } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { NigeriaThreatMap } from '@/components/geo/NigeriaThreatMap';

// Nigeria deep-dive, reached by clicking Nigeria on the global threat map.
//
// Composed from existing live endpoints rather than a new backend surface: the state map is the
// same NigeriaThreatMap widget the dashboard embeds (so the two can never disagree), advisories
// come from /api/advisories, actors from /api/threats/actors, and Nigerian indicators are
// filtered out of /api/threats/live-ioc.
//
// Every panel states what it is showing and what it found. Counts render "—" when a source could
// not be read: on a threat page, an unreadable count shown as 0 reads as "no threats", which is
// the opposite of what an unreachable source means.

interface Advisory {
    id?: number;
    advisory_id?: string;
    title: string;
    description?: string;
    severity: string;
    source?: string;
    published_at: string;
}

interface Actor {
    id: string;
    name: string;
    origin: string;
    motivation: string;
    targeted_sectors: string[];
    last_active: string;
    description: string;
    damage: string;
    known_incidents: Array<{ year: string; title: string; description: string; source: string }>;
    reference: string;
    reference_url: string;
}

interface LiveIOC {
    value: string;
    type: string;
    threat: string;
    source: string;
    severity: string;
    tags: string[];
}

const SEVERITY_STYLE: Record<string, string> = {
    critical: 'bg-red-500/10 text-red-500 border-red-500/30',
    high: 'bg-orange/10 text-orange border-orange/30',
    medium: 'bg-amber-500/10 text-amber-500 border-amber-500/30',
    low: 'bg-card-muted text-foreground-muted border-border',
};

export function NigeriaDetail() {
    const [advisories, setAdvisories] = useState<Advisory[] | null>(null);
    const [advisoryFailed, setAdvisoryFailed] = useState(false);
    const [actors, setActors] = useState<Actor[] | null>(null);
    const [iocs, setIocs] = useState<LiveIOC[] | null>(null);
    const [severityFilter, setSeverityFilter] = useState<string>('all');

    useEffect(() => {
        apiFetch(apiUrl('/api/advisories'), { cache: 'no-store', signal: AbortSignal.timeout(15000) })
            .then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
            .then((d) => setAdvisories(Array.isArray(d?.advisories) ? d.advisories : []))
            .catch(() => { setAdvisories([]); setAdvisoryFailed(true); });

        apiFetch(apiUrl('/api/threats/actors'), { cache: 'no-store' })
            .then((r) => r.json())
            .then((d) => setActors(Array.isArray(d?.nigerian) ? d.nigerian : []))
            .catch(() => setActors([]));

        // Nigerian indicators: the feed has no country filter, so this narrows on the tags and
        // threat text the sources actually carry. It is a subset, not an exhaustive view, and
        // the panel says so rather than implying complete coverage.
        apiFetch(apiUrl('/api/threats/live-ioc?limit=200'), { cache: 'no-store', signal: AbortSignal.timeout(30000) })
            .then((r) => r.json())
            .then((d) => {
                const all: LiveIOC[] = Array.isArray(d?.iocs) ? d.iocs : [];
                setIocs(all.filter((i) =>
                    i.tags?.some((t) => /nigeria|^ng$/i.test(t)) || /nigeria/i.test(i.threat ?? '')
                ));
            })
            .catch(() => setIocs(null));
    }, []);

    const visibleAdvisories = (advisories ?? []).filter(
        (a) => severityFilter === 'all' || a.severity === severityFilter
    );

    const kpis = [
        { label: 'States & FCT monitored', value: '37', note: 'All 36 states plus the FCT' },
        { label: 'Active advisories', value: advisories === null ? '…' : advisoryFailed ? '—' : String(advisories.length), note: advisoryFailed ? 'Advisory service unreachable' : 'ngCERT · NCC · CBN · NITDA' },
        { label: 'Nigerian threat actors', value: actors === null ? '…' : String(actors.length), note: 'Documented, publicly attributed' },
        { label: 'Nigeria-tagged IOCs', value: iocs === null ? '—' : String(iocs.length), note: iocs === null ? 'Feed unreachable' : 'Subset of the live feed' },
    ];

    return (
        <div className="space-y-5">
            <Link href="/admin/dashboard" className="flex items-center gap-1.5 text-xs font-bold text-blue hover:text-purple transition-colors w-fit">
                <ArrowLeft size={14} /> Back to Dashboard
            </Link>

            <div className="flex items-center gap-4 flex-wrap">
                <span className="text-4xl">🇳🇬</span>
                <div>
                    <h1 className="text-xl font-black text-foreground">Nigeria Threat Landscape</h1>
                    <p className="text-xs text-foreground-muted">Threat intelligence across all 36 states and the FCT</p>
                </div>
                <div className="ml-auto flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
                    <span className="text-[10px] text-foreground-muted">Live data</span>
                </div>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {kpis.map((k) => (
                    <div key={k.label} className="bg-card border border-border rounded-xl p-4">
                        <div className="text-2xl font-black text-foreground">{k.value}</div>
                        <div className="text-[10px] text-foreground-muted mt-0.5">{k.label}</div>
                        <div className="text-[9px] text-foreground-muted/70 mt-1">{k.note}</div>
                    </div>
                ))}
            </div>

            {/* Same widget the dashboard embeds — state selection, fullscreen and time-range
                controls all come with it, so this page doesn't reimplement the map. */}
            <NigeriaThreatMap
                advisories={advisories?.map((a, i) => ({
                    id: a.id ?? i,
                    title: a.title,
                    severity: a.severity,
                    published_at: a.published_at,
                })) ?? null}
            />

            {/* Advisories */}
            <div>
                <div className="flex items-center justify-between gap-3 mb-2 flex-wrap">
                    <h2 className="text-sm font-black text-foreground">Active Advisories</h2>
                    <div className="flex items-center gap-0.5 bg-card-muted border border-border rounded-lg p-0.5">
                        {['all', 'critical', 'high', 'medium', 'low'].map((sv) => (
                            <button key={sv} onClick={() => setSeverityFilter(sv)}
                                className={`px-2.5 py-1 rounded-md text-[11px] font-semibold capitalize transition-colors ${severityFilter === sv ? 'bg-purple text-white' : 'text-foreground-muted hover:text-foreground'}`}>
                                {sv}
                            </button>
                        ))}
                    </div>
                </div>

                {advisories === null ? (
                    <div className="h-20 bg-card-muted rounded-xl animate-pulse" />
                ) : visibleAdvisories.length === 0 ? (
                    <div className="bg-card border border-border rounded-xl p-6 text-center">
                        <p className="text-xs text-foreground-muted">
                            {advisoryFailed
                                ? 'The advisory service could not be reached. This is a connectivity problem, not an absence of advisories.'
                                : advisories.length === 0
                                    ? 'No advisories collected yet from ngCERT, NCC-CSIRT, CBN or NITDA.'
                                    : `No advisories at ${severityFilter} severity.`}
                        </p>
                    </div>
                ) : (
                    <div className="space-y-2">
                        {visibleAdvisories.slice(0, 15).map((a) => (
                            <div key={a.advisory_id ?? a.id ?? a.title} className="bg-card border border-border rounded-xl p-4">
                                <div className="flex items-start justify-between gap-3 mb-1.5 flex-wrap">
                                    <div className="flex items-center gap-2 flex-wrap">
                                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border uppercase ${SEVERITY_STYLE[a.severity] ?? SEVERITY_STYLE.medium}`}>{a.severity}</span>
                                        <span className="text-[10px] font-bold px-2 py-0.5 bg-purple/10 text-purple rounded-full">{a.source}</span>
                                    </div>
                                    {a.published_at && (
                                        <span className="text-[10px] text-foreground-muted shrink-0">{new Date(a.published_at).toLocaleDateString('en-GB')}</span>
                                    )}
                                </div>
                                <p className="text-sm font-bold text-foreground">{a.title}</p>
                                {a.description && <p className="text-xs text-foreground-muted mt-0.5 leading-relaxed">{a.description}</p>}
                            </div>
                        ))}
                    </div>
                )}
            </div>

            {/* Nigerian threat actors */}
            <div className="bg-card border border-border rounded-xl p-5">
                <div className="flex items-start justify-between gap-3 mb-3 flex-wrap">
                    <div>
                        <h2 className="text-sm font-black text-foreground">🇳🇬 Nigerian Threat Actors</h2>
                        <p className="text-[11px] text-foreground-muted">Groups originating from or primarily targeting Nigeria and West Africa</p>
                    </div>
                    <Link href="/admin/threat/actors" className="text-[11px] font-bold text-purple hover:underline shrink-0">
                        View all threat actors →
                    </Link>
                </div>

                {actors === null ? (
                    <div className="h-24 bg-card-muted rounded-xl animate-pulse" />
                ) : actors.length === 0 ? (
                    <p className="text-xs text-foreground-muted">Threat actor library unavailable.</p>
                ) : (
                    <div className="space-y-3">
                        {actors.map((actor) => (
                            <div key={actor.id} className="border border-border rounded-xl p-4">
                                <div className="flex items-center gap-2 flex-wrap mb-1.5">
                                    <span className="text-sm font-black text-foreground">{actor.name}</span>
                                    <span className="text-[9px] font-bold px-2 py-0.5 rounded-full bg-card-muted text-foreground-muted uppercase">{actor.motivation}</span>
                                    <span className="text-[10px] text-foreground-muted">{actor.origin} · active {actor.last_active}</span>
                                </div>
                                <p className="text-xs text-foreground-muted leading-relaxed mb-2">{actor.damage}</p>
                                <div className="flex gap-1.5 flex-wrap mb-2">
                                    {actor.targeted_sectors.slice(0, 4).map((sec) => (
                                        <span key={sec} className="text-[9px] bg-card-muted text-foreground-muted px-1.5 py-0.5 rounded-full">{sec}</span>
                                    ))}
                                </div>
                                {actor.known_incidents?.length > 0 && (
                                    <details className="group">
                                        <summary className="cursor-pointer text-[10px] font-bold text-foreground-muted uppercase tracking-wider list-none flex items-center gap-1.5 hover:text-foreground">
                                            <span className="transition-transform group-open:rotate-90">▸</span>
                                            Documented incidents ({actor.known_incidents.length})
                                        </summary>
                                        <div className="mt-2 space-y-2">
                                            {actor.known_incidents.map((inc, i) => (
                                                <div key={`${inc.year}-${i}`} className="bg-card-muted/40 rounded-lg p-3">
                                                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                                                        <span className="text-[10px] font-black bg-card text-foreground-muted px-2 py-0.5 rounded-full">{inc.year}</span>
                                                        <span className="text-xs font-bold text-foreground">{inc.title}</span>
                                                    </div>
                                                    <p className="text-xs text-foreground-muted leading-relaxed mb-1">{inc.description}</p>
                                                    <p className="text-[10px] text-purple font-medium">Source: {inc.source}</p>
                                                </div>
                                            ))}
                                        </div>
                                    </details>
                                )}
                            </div>
                        ))}
                    </div>
                )}
            </div>

            {/* Nigeria-tagged indicators */}
            <div className="bg-card border border-border rounded-xl p-5">
                <div className="flex items-start justify-between gap-3 mb-3 flex-wrap">
                    <div className="flex items-start gap-2.5">
                        <div className="w-8 h-8 rounded-lg bg-red-500/10 flex items-center justify-center shrink-0">
                            <Radio className="w-4 h-4 text-red-500" />
                        </div>
                        <div>
                            <h2 className="text-sm font-black text-foreground">Nigeria-tagged Indicators</h2>
                            <p className="text-[11px] text-foreground-muted">
                                Indicators from the live feed whose tags or threat name reference Nigeria
                            </p>
                        </div>
                    </div>
                    <Link href="/admin/threat/live-ioc" className="text-[11px] font-bold text-purple hover:underline shrink-0">
                        Full IOC feed →
                    </Link>
                </div>

                {iocs === null ? (
                    <p className="text-xs text-foreground-muted">
                        The live IOC feed could not be reached, so no indicators can be shown. This is not the
                        same as there being none.
                    </p>
                ) : iocs.length === 0 ? (
                    <p className="text-xs text-foreground-muted">
                        No indicator in the current feed window carries a Nigeria tag. The upstream feeds
                        rarely tag by country, so this being empty is expected and does not mean Nigeria is
                        unaffected — use the full feed for the unfiltered view.
                    </p>
                ) : (
                    <div className="space-y-2">
                        {iocs.slice(0, 20).map((i, idx) => (
                            <div key={`${i.value}-${idx}`} className="flex items-start justify-between gap-3 border-b border-border pb-2 last:border-0 flex-wrap">
                                <div className="min-w-0">
                                    <p className="font-mono text-xs text-foreground break-all">{i.value}</p>
                                    <p className="text-[10px] text-foreground-muted">{i.threat} · {i.source}</p>
                                </div>
                                <span className={`text-[9px] font-black px-2 py-0.5 rounded-full border uppercase shrink-0 ${SEVERITY_STYLE[i.severity] ?? SEVERITY_STYLE.low}`}>
                                    {i.severity}
                                </span>
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
}
