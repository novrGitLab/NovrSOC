'use client';

import { useEffect, useRef, useState } from 'react';
import { Maximize2, Minimize2, AlertCircle, RefreshCw } from 'lucide-react';
import { NigeriaMap2, type NigeriaStateData } from './NigeriaMap2';
import { apiUrl, apiFetch } from '@/lib/api';

const Card = ({ children }: { children: React.ReactNode }) => (
    <div className="bg-card border border-border rounded-xl overflow-hidden shadow-sm">
        <div className="h-[3px] bg-purple" />
        {children}
    </div>
);

const SectionHeader = ({ title }: { title: string }) => (
    <div className="flex items-center gap-2 mb-1">
        <div className="flex items-center gap-2 border-l-2 border-amber-500 pl-2">
            <h3 className="text-xs font-black text-foreground uppercase tracking-widest">{title}</h3>
        </div>
    </div>
);

interface NigeriaThreatsSummary {
    total_threats: number;
    threat_score: number;
    critical_states: number;
    states_affected: number;
    top_state: string | null;
    // null: not available from collector data (it has no per-type totals or time window).
    today_attacks: number | null;
    malware: number | null;
    phishing: number | null;
    botnets: number | null;
    ransomware: number | null;
    ddos: number | null;
    credential_theft: number | null;
    highest_attack_states: { name: string; count: number; state: string; threat_type: string }[];
    threat_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'CLEAR';
    error?: string;
}

interface NigeriaThreatsResponse {
    states: NigeriaStateData[];
    summary: NigeriaThreatsSummary;
    source: string;
    // True when demo rows from an earlier deploy (the seeder has been removed) are still in
    // nigeria_state_threats. The map is badged so they can't be mistaken for collected data.
    demo_data?: boolean;
    // Which intelligence feeds can currently contribute, derived server-side from what's
    // actually configured — so a quiet map can be explained rather than just looking broken.
    sources_active?: Array<{ name: string; active: boolean; detail: string }>;
    generated_at: string;
}

const THREAT_LEVEL_COLOR: Record<string, string> = {
    CRITICAL: 'text-red-500',
    HIGH: 'text-orange-500',
    MEDIUM: 'text-amber-500',
    LOW: 'text-blue-500',
    CLEAR: 'text-emerald-500',
};

export const NigeriaThreatMap = () => {
    const [colorMode, setColorMode] = useState<'threat' | 'region'>('threat');
    const [data, setData] = useState<NigeriaThreatsResponse | null>(null);
    const [isLoading, setIsLoading] = useState(true);
    const [fetchError, setFetchError] = useState<string | null>(null);
    const [popupState, setPopupState] = useState<NigeriaStateData | null>(null);
    const [isFullscreen, setIsFullscreen] = useState(false);
    const mapSectionRef = useRef<HTMLDivElement>(null);

    const loadData = () => {
        setIsLoading(true);
        setFetchError(null);
        apiFetch(apiUrl('/api/dashboard/nigeria-threats'), { cache: 'no-store' })
            .then(async (r) => {
                if (!r.ok) throw new Error(`HTTP ${r.status}`);
                return r.json();
            })
            .then((res) => {
                setData(res);
                setIsLoading(false);
            })
            .catch((err) => {
                setFetchError(err.message || 'Failed to fetch threat data');
                setIsLoading(false);
            });
    };

    useEffect(() => {
        loadData();
    }, []);

    // Runs the Nigerian collector on demand (GreyNoise + Feodo + CIRCL, plus FOFA when keyed),
    // then reloads. The run makes external calls per IP and takes tens of seconds, so the button
    // stays disabled with a live label rather than appearing to hang.
    const [collecting, setCollecting] = useState(false);
    const [collectResult, setCollectResult] = useState<string | null>(null);

    const runCollection = async () => {
        setCollecting(true);
        setCollectResult(null);
        try {
            const r = await apiFetch(apiUrl('/api/dashboard/nigeria-threats/collect'), { method: 'POST' });
            const body = await r.json();
            if (!r.ok) throw new Error(body?.error ?? `HTTP ${r.status}`);
            const run = body?.result ?? body;
            setCollectResult(
                typeof run?.ips_found === 'number'
                    ? `${run.ips_found} Nigerian IPs across ${run.states_updated?.length ?? 0} states`
                    : 'Collection complete'
            );
            loadData();
        } catch (err) {
            setCollectResult(err instanceof Error ? err.message : 'Collection failed');
        } finally {
            setCollecting(false);
        }
    };

    useEffect(() => {
        const handleFsChange = () => { if (!document.fullscreenElement) setIsFullscreen(false); };
        document.addEventListener('fullscreenchange', handleFsChange);
        return () => document.removeEventListener('fullscreenchange', handleFsChange);
    }, []);

    const toggleFullscreen = () => {
        if (!isFullscreen) {
            mapSectionRef.current?.requestFullscreen?.();
            setIsFullscreen(true);
        } else {
            document.exitFullscreen?.();
            setIsFullscreen(false);
        }
    };

    const summary = data?.summary;
    const states = data?.states ?? [];

    const STAT_CARDS: { title: string; value: number | string; color: string }[] = [
        { title: 'Threat Score', value: summary?.threat_score ?? 0, color: 'text-red-500' },
        { title: "Today's Attacks", value: summary?.today_attacks ?? '—', color: 'text-red-500' },
        { title: 'Critical States', value: summary?.critical_states ?? 0, color: 'text-purple' },
        { title: 'States Affected', value: summary ? `${summary.states_affected}/37` : '0/37', color: 'text-purple' },
        { title: 'Most Targeted', value: summary?.top_state ?? 'None', color: 'text-foreground' },
        { title: 'Malware', value: summary?.malware ?? '—', color: 'text-blue-500' },
        { title: 'Botnets', value: summary?.botnets ?? '—', color: 'text-blue-500' },
        { title: 'Phishing', value: summary?.phishing ?? '—', color: 'text-amber-500' },
        { title: 'Ransomware', value: summary?.ransomware ?? '—', color: 'text-red-500' },
        { title: 'DDoS', value: summary?.ddos ?? '—', color: 'text-blue-500' },
    ];

    const highestAttackStates = summary?.highest_attack_states ?? [];

    return (
        <Card>
            <div ref={mapSectionRef} className={isFullscreen ? 'fixed inset-0 z-40 bg-background p-6 overflow-auto' : 'p-6'}>
                {/* Header */}
                <div className="flex items-center justify-between mb-6">
                    <div>
                        <div className="flex items-center gap-2 flex-wrap">
                            <SectionHeader title="Nigeria National Threat Landscape" />
                            {data?.demo_data && (
                                <span
                                    title="Rows written by a since-removed demo seeder are still in the database. They are cleared automatically when the collector writes real counts."
                                    className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-amber-100 text-amber-800 border border-amber-200 uppercase"
                                >
                                    Demonstration data
                                </span>
                            )}
                        </div>
                        <p className="text-sm text-muted-foreground">
                            {data?.demo_data
                                ? 'Illustrative baseline — not live telemetry. Replaced automatically once real intelligence is collected.'
                                : 'Collected threat intelligence — GreyNoise, Feodo Tracker and CIRCL, geolocated to state by IPregistry.'}
                            {fetchError && <span className="text-red-500"> · Connection error: {fetchError}</span>}
                            {data?.summary.error && <span className="text-amber-500"> · {data.summary.error}</span>}
                        </p>

                        {/* Which feeds can contribute right now, straight from the API rather than
                            a hardcoded list — an inactive badge names the missing key. */}
                        {data?.sources_active && data.sources_active.length > 0 && (
                            <div className="flex gap-2 flex-wrap mt-2 items-center">
                                {data.sources_active.map((s) => (
                                    <span
                                        key={s.name}
                                        title={s.detail}
                                        className={`text-[9px] font-bold px-2 py-1 rounded-full ${
                                            s.active
                                                ? 'bg-green-100 text-green-700'
                                                : 'bg-card-muted text-foreground-muted'
                                        }`}
                                    >
                                        {s.name} {s.active ? '✓' : '○'}
                                    </span>
                                ))}
                                <button
                                    onClick={() => void runCollection()}
                                    disabled={collecting}
                                    className="text-[9px] font-bold px-2 py-1 rounded-full border border-purple text-purple hover:bg-purple/5 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                                >
                                    {collecting ? 'Collecting… (up to a minute)' : 'Refresh Intelligence'}
                                </button>
                                {collectResult && (
                                    <span className="text-[9px] text-muted-foreground">{collectResult}</span>
                                )}
                            </div>
                        )}

                        {/* Says where this map's numbers come from. */}
                        <p className="text-[10px] text-muted-foreground mt-2 max-w-2xl leading-relaxed">
                            Nigerian threat data is collected independently of endpoint monitoring and describes
                            Nigerian networks generally. Counts are cumulative; Wazuh alerts are not included.
                        </p>
                    </div>
                    <div className="text-right flex items-center gap-4">
                        {isLoading && <RefreshCw size={16} className="animate-spin text-muted-foreground" />}
                        <div>
                            <p className="text-xs uppercase text-muted-foreground">Threat Level</p>
                            <h2 className={`text-2xl font-black ${THREAT_LEVEL_COLOR[summary?.threat_level ?? ''] ?? 'text-muted-foreground'}`}>
                                {isLoading ? 'SYNCING...' : summary?.threat_level ?? 'CLEAR'}
                            </h2>
                        </div>
                    </div>
                </div>

                {/* Main Content Grid */}
                <div className="grid lg:grid-cols-5 gap-6">
                    {/* MAP - 3 Columns */}
                    <div className="lg:col-span-3 flex flex-col">
                        <div className="flex items-center justify-between mb-3">
                            <div>
                                <p className="text-xs font-semibold tracking-widest text-foreground uppercase">Live Attack Map</p>
                                <p className="text-xs text-muted-foreground mt-0.5">Inbound attacks targeting NovrSOC-protected clients</p>
                            </div>
                            <div className="flex items-center gap-1.5 flex-shrink-0">
                                <div className="flex items-center gap-0.5 bg-muted border border-border rounded-lg p-0.5 mr-1">
                                    {(['threat', 'region'] as const).map((mode) => (
                                        <button
                                            key={mode}
                                            onClick={() => setColorMode(mode)}
                                            className={`px-2.5 py-1 rounded-md text-[11px] font-semibold capitalize transition-colors ${
                                                colorMode === mode ? 'bg-purple text-white' : 'text-muted-foreground hover:text-foreground'
                                            }`}
                                        >
                                            {mode}
                                        </button>
                                    ))}
                                </div>
                                <button
                                    onClick={toggleFullscreen}
                                    className="p-1.5 rounded-lg hover:bg-muted text-muted-foreground hover:text-foreground transition-colors"
                                    title="Toggle fullscreen"
                                    aria-label="Toggle fullscreen"
                                >
                                    {isFullscreen ? <Minimize2 size={14} /> : <Maximize2 size={14} />}
                                </button>
                            </div>
                        </div>

                        <div className="relative rounded-xl border border-border bg-muted/40 p-4 min-h-[520px] flex-1 flex items-center justify-center">
                            <NigeriaMap2
                                liveStates={states}
                                colorMode={colorMode}
                                onStateSelect={setPopupState}
                                selectedState={popupState}
                                onCloseSelection={() => setPopupState(null)}
                            />
                        </div>
                    </div>

                    {/* STATS SIDEBAR - 2 Columns */}
                    <div className="lg:col-span-2 flex flex-col justify-between">
                        <div>
                            <p className="text-xs font-semibold tracking-widest text-foreground uppercase mb-3">Threat Metrics Breakdown</p>
                            <div className="grid grid-cols-2 gap-3">
                                {STAT_CARDS.map((stat, i) => (
                                    <div key={i} className="bg-card border border-border rounded-xl p-3.5 shadow-sm">
                                        <p className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider mb-1">{stat.title}</p>
                                        <p className={`text-xl font-black ${stat.color}`}>{stat.value}</p>
                                    </div>
                                ))}
                            </div>
                        </div>

                        {/* Selected State Mini Card if active */}
                        {popupState && (
                            <div className="mt-4 p-4 rounded-xl border border-purple/30 bg-purple/5">
                                <div className="flex items-center justify-between mb-1">
                                    <h4 className="font-bold text-sm text-foreground">{popupState.name} State</h4>
                                    <span className="text-xs px-2 py-0.5 rounded bg-purple text-white font-semibold">{popupState.threatLevel || 'CLEAR'}</span>
                                </div>
                                <p className="text-xs text-muted-foreground">Recorded Threat Events: <strong className="text-foreground">{popupState.threatCount || 0}</strong></p>
                            </div>
                        )}
                    </div>
                </div>

                {/* Data source badges */}
                <div className="flex items-center gap-2 mt-6 mb-3 px-1 flex-wrap">
                    <span className="text-[10px] text-muted-foreground uppercase tracking-wider font-medium">Data sources:</span>
                    {[
                        { name: 'IPregistry', active: !!data, color: 'bg-blue-500' },
                        { name: 'RIPE Stat', active: !!data, color: 'bg-blue-500' },
                        { name: 'AFRINIC', active: !!data, color: 'bg-emerald-500' },
                    ].map((source) => (
                        <div key={source.name} className="flex items-center gap-1.5 bg-card border border-border rounded-full px-2.5 py-1">
                            <div className={`w-1.5 h-1.5 rounded-full ${source.active ? source.color : 'bg-muted-foreground/30'}`} />
                            <span className="text-[9px] font-medium text-muted-foreground">{source.name}</span>
                        </div>
                    ))}
                </div>

                {/* Highest attack states */}
                <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 mt-4">
                    {highestAttackStates.map((item, i) => (
                        <div
                            key={i}
                            className="bg-card border border-border rounded-xl p-3 text-center cursor-pointer hover:border-purple/40 transition-colors"
                            onClick={() => {
                                const found = states.find((s) => s.name === item.state);
                                if (found) setPopupState(found);
                            }}
                        >
                            <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1 truncate">{item.name}</div>
                            <div className="font-black text-xl text-red-500">{item.count}</div>
                        </div>
                    ))}
                    {Array.from({ length: Math.max(0, 6 - highestAttackStates.length) }).map((_, i) => (
                        <div key={`empty-${i}`} className="bg-muted/50 border border-border rounded-xl p-3 text-center">
                            <div className="text-[10px] text-muted-foreground/40 uppercase tracking-wider mb-1">No data</div>
                            <div className="font-black text-xl text-muted-foreground/40">—</div>
                        </div>
                    ))}
                </div>
            </div>
        </Card>
    );
};