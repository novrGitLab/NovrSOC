'use client';

import { useEffect, useState } from 'react';
import { ExternalLink, Crosshair, Info, Target } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';

// Reads GET /api/threats/actors. That endpoint serves a curated reference library rather than
// database rows — there is no threat_actors table in this Supabase project (the nigeria_intel /
// global_intel schemas the feature was specced against don't exist), so nothing would come back
// from a query against it.
//
// Every group shown is publicly documented by a named vendor or by MITRE ATT&CK, and each card
// carries that citation. This page is explicit that it's reference material, not this
// platform's own attribution — a SOC page that silently implies it tracked these groups itself
// would be claiming a capability NovrSOC doesn't have.

interface ThreatActor {
    id: string;
    name: string;
    aliases: string[];
    origin: string;
    origin_code: string;
    motivation: 'financial' | 'espionage' | 'hacktivism' | 'destructive';
    targeted_sectors: string[];
    targeted_regions: string[];
    mitre_techniques: Array<{ id: string; name: string }>;
    confidence: 'high' | 'medium' | 'low';
    last_active: string;
    description: string;
    reference: string;
    reference_url: string;
}

const MOTIVATION_STYLE: Record<string, string> = {
    financial: 'bg-amber/10 text-amber border-amber/30',
    espionage: 'bg-purple/10 text-purple border-purple/30',
    hacktivism: 'bg-blue/10 text-blue border-blue/30',
    destructive: 'bg-red-500/10 text-red-500 border-red-500/30',
};

const CONFIDENCE_STYLE: Record<string, string> = {
    high: 'text-green',
    medium: 'text-amber',
    low: 'text-foreground-muted',
};

// Regional indicator flags from an ISO country code, so no image assets are needed.
function flagFor(code: string): string {
    if (!/^[A-Z]{2}$/.test(code)) return '🏳️';
    return String.fromCodePoint(...[...code].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
}

function ActorCard({ actor }: { actor: ThreatActor }) {
    return (
        <div className="bg-card border border-border rounded-xl p-4">
            <div className="flex items-start justify-between gap-3 flex-wrap mb-2">
                <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-lg leading-none">{flagFor(actor.origin_code)}</span>
                        <h3 className="text-sm font-black text-foreground">{actor.name}</h3>
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border uppercase ${MOTIVATION_STYLE[actor.motivation] ?? 'bg-card-muted text-foreground-muted border-border'}`}>
                            {actor.motivation}
                        </span>
                    </div>
                    {actor.aliases.length > 0 && (
                        <p className="text-[10px] text-foreground-muted mt-1">
                            Also known as: {actor.aliases.join(', ')}
                        </p>
                    )}
                </div>
                <div className="text-right shrink-0">
                    <p className="text-[10px] text-foreground-muted">{actor.origin}</p>
                    <p className={`text-[10px] font-bold ${CONFIDENCE_STYLE[actor.confidence]}`}>
                        {actor.confidence} confidence
                    </p>
                </div>
            </div>

            <p className="text-xs text-foreground-muted mb-3">{actor.description}</p>

            <div className="grid sm:grid-cols-2 gap-3 mb-3">
                <div>
                    <p className="text-[9px] font-bold text-foreground-muted uppercase tracking-wider mb-1">Targeted sectors</p>
                    <div className="flex flex-wrap gap-1">
                        {actor.targeted_sectors.map((s) => (
                            <span key={s} className="text-[9px] px-1.5 py-0.5 bg-card-muted text-foreground-muted rounded-full">{s}</span>
                        ))}
                    </div>
                </div>
                <div>
                    <p className="text-[9px] font-bold text-foreground-muted uppercase tracking-wider mb-1">Regions</p>
                    <div className="flex flex-wrap gap-1">
                        {actor.targeted_regions.map((r) => (
                            <span key={r} className="text-[9px] px-1.5 py-0.5 bg-card-muted text-foreground-muted rounded-full">{r}</span>
                        ))}
                    </div>
                </div>
            </div>

            <div className="mb-3">
                <p className="text-[9px] font-bold text-foreground-muted uppercase tracking-wider mb-1">MITRE ATT&amp;CK</p>
                <div className="flex flex-wrap gap-1">
                    {actor.mitre_techniques.map((t) => (
                        <span key={t.id} className="text-[9px] px-1.5 py-0.5 bg-purple/10 text-purple rounded-full" title={t.name}>
                            {t.id} · {t.name}
                        </span>
                    ))}
                </div>
            </div>

            <div className="flex items-center justify-between gap-3 flex-wrap pt-3 border-t border-border">
                <div className="text-[10px] text-foreground-muted">
                    Activity: {actor.last_active} · Source:{' '}
                    <a href={actor.reference_url} target="_blank" rel="noopener noreferrer" className="text-blue hover:text-purple underline">
                        {actor.reference}
                    </a>
                </div>
                {/* Pivots into the CTI platform pre-filled with the actor name, so an analyst can
                    go looking for related indicators instead of retyping it. */}
                <a
                    href={`/admin/threat/cti?q=${encodeURIComponent(actor.name)}`}
                    className="flex items-center gap-1.5 text-[10px] font-bold px-3 py-1.5 border border-orange text-orange rounded-lg hover:bg-orange/5 transition-colors shrink-0"
                >
                    <Crosshair size={11} /> Hunt for IOCs
                </a>
            </div>
        </div>
    );
}

export function ThreatActors() {
    const [tab, setTab] = useState<'nigerian' | 'global'>('nigerian');
    const [nigerian, setNigerian] = useState<ThreatActor[]>([]);
    const [global, setGlobal] = useState<ThreatActor[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        let cancelled = false;
        apiFetch(apiUrl('/api/threats/actors'), { cache: 'no-store' })
            .then((r) => r.json())
            .then((data) => {
                if (cancelled) return;
                setNigerian(Array.isArray(data?.nigerian) ? data.nigerian : []);
                setGlobal(Array.isArray(data?.global) ? data.global : []);
                setLoading(false);
            })
            .catch(() => {
                if (cancelled) return;
                setError('Could not load the threat actor library.');
                setLoading(false);
            });
        return () => { cancelled = true; };
    }, []);

    const shown = tab === 'nigerian' ? nigerian : global;

    return (
        <div className="space-y-4">
            <div>
                <h1 className="text-lg font-black text-foreground">Threat Actors</h1>
                <p className="text-xs text-foreground-muted">Global Threat Intel · Tracked groups, motivations, and ATT&amp;CK techniques</p>
            </div>

            <div className="bg-blue/5 border border-blue/20 rounded-xl p-4 flex gap-3">
                <Info size={16} className="text-blue shrink-0 mt-0.5" />
                <p className="text-xs text-foreground-muted">
                    A curated reference library of publicly documented threat actors, each linked to the vendor or
                    MITRE ATT&amp;CK entry it comes from. These profiles are not derived from this platform&apos;s own
                    telemetry, and their presence here does not mean the group has been observed against your estate.
                </p>
            </div>

            <div className="flex gap-2">
                {([
                    { key: 'nigerian' as const, label: `Nigeria & West Africa (${nigerian.length})` },
                    { key: 'global' as const, label: `Global — relevant sectors (${global.length})` },
                ]).map((t) => (
                    <button
                        key={t.key}
                        onClick={() => setTab(t.key)}
                        className={`text-xs px-4 py-2 rounded-lg font-bold transition-colors ${
                            tab === t.key ? 'bg-purple text-white' : 'bg-card-muted text-foreground-muted hover:text-purple'
                        }`}
                    >
                        {t.label}
                    </button>
                ))}
            </div>

            {loading ? (
                <div className="space-y-3">
                    {[0, 1, 2].map((i) => <div key={i} className="h-56 bg-card-muted rounded-xl animate-pulse" />)}
                </div>
            ) : error ? (
                <div className="bg-card border border-dashed border-grey-300 rounded-xl p-10 text-center">
                    <Target size={28} className="text-border mx-auto mb-2" />
                    <p className="text-xs text-foreground-muted">{error}</p>
                </div>
            ) : (
                <div className="space-y-3">
                    {shown.map((a) => <ActorCard key={a.id} actor={a} />)}
                </div>
            )}

            <p className="text-[10px] text-foreground-muted flex items-center gap-1">
                <ExternalLink size={10} /> Follow each card&apos;s source link for the original published research.
            </p>
        </div>
    );
}
