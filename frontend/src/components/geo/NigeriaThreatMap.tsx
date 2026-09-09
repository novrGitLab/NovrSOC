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

export interface FeedAdvisory {
    id: number;
    title: string;
    severity: string;
    published_at: string;
}

interface NigeriaThreatsSummary {
    total_threats: number;
    threat_score: number;
    critical_states: number;
    states_affected: number;
    top_state: string | null;
    today_attacks: number;
    malware: number;
    phishing: number;
    botnets: number;
    ransomware: number;
    ddos: number;
    credential_theft: number;
    highest_attack_states: { name: string; count: number; state: string; threat_type: string }[];
    threat_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'CLEAR';
    error?: string;
}

interface EnrichmentCoverage {
    unattributed_ips: number;
    ips_enriched: number;
    nigerian_confirmed: number;
    threats_added_by_enrichment: number;
}

interface NigeriaThreatsResponse {
    states: NigeriaStateData[];
    summary: NigeriaThreatsSummary;
    source: string;
    // True when Wazuh attributed no alerts to any Nigerian state and the backend fell back to
    // the illustrative baseline in nigeria_state_threats. The map is badged in that case — a
    // populated map must never be mistaken for live telemetry.
    demo_data?: boolean;
    enrichment_coverage?: EnrichmentCoverage;
    generated_at: string;
}

const TIME_RANGES: { value: '1h' | '24h' | '7d'; label: string }[] = [
    { value: '1h', label: 'Last 1hr' },
    { value: '24h', label: 'Last 24hr' },
    { value: '7d', label: 'Last 7 days' },
];

const THREAT_LEVEL_COLOR: Record<string, string> = {
    CRITICAL: 'text-red-500',
    HIGH: 'text-orange-500',
    MEDIUM: 'text-amber-500',
    LOW: 'text-blue-500',
    CLEAR: 'text-emerald-500',
};

// eslint-disable-next-line @typescript-eslint/no-unused-vars
export const NigeriaThreatMap = ({ advisories }: { advisories?: FeedAdvisory[] | null }) => {
    const [timeRange, setTimeRange] = useState<'1h' | '24h' | '7d'>('24h');
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
        apiFetch(apiUrl(`/api/dashboard/nigeria-threats?range=${timeRange}`), { cache: 'no-store' })
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
    }, [timeRange]);

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
        { title: "Today's Attacks", value: summary?.today_attacks ?? 0, color: 'text-red-500' },
        { title: 'Critical States', value: summary?.critical_states ?? 0, color: 'text-purple' },
        { title: 'States Affected', value: summary ? `${summary.states_affected}/37` : '0/37', color: 'text-purple' },
        { title: 'Most Targeted', value: summary?.top_state ?? 'None', color: 'text-foreground' },
        { title: 'Malware', value: summary?.malware ?? 0, color: 'text-blue-500' },
        { title: 'Botnets', value: summary?.botnets ?? 0, color: 'text-blue-500' },
        { title: 'Phishing', value: summary?.phishing ?? 0, color: 'text-amber-500' },
        { title: 'Ransomware', value: summary?.ransomware ?? 0, color: 'text-red-500' },
        { title: 'DDoS', value: summary?.ddos ?? 0, color: 'text-blue-500' },
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
                                    title="Wazuh reported no geolocated Nigerian activity in this window, so an illustrative baseline is shown instead of an empty map."
                                    className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-amber-100 text-amber-800 border border-amber-200 uppercase"
                                >
                                    Demonstration data
                                </span>
                            )}
                        </div>
                        <p className="text-sm text-muted-foreground">
                            {data?.demo_data
                                ? 'Illustrative baseline — not live telemetry. Replaced automatically once Wazuh reports geolocated Nigerian activity.'
                                : 'Real-time cyber activity across Nigerian states'}
                            {fetchError && <span className="text-red-500"> · Connection error: {fetchError}</span>}
                            {data?.summary.error && <span className="text-amber-500"> · {data.summary.error}</span>}
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
                                {TIME_RANGES.map((r) => (
                                    <button
                                        key={r.value}
                                        onClick={() => setTimeRange(r.value)}
                                        className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                                            timeRange === r.value ? 'bg-primary text-primary-foreground' : 'bg-muted text-muted-foreground border border-border hover:text-foreground'
                                        }`}
                                    >
                                        {r.label}
                                    </button>
                                ))}
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
                        { name: 'Wazuh', active: !!data && !data.summary.error, color: 'bg-purple' },
                        { name: 'IPregistry', active: !!data, color: 'bg-blue-500' },
                        { name: 'RIPE Stat', active: !!data, color: 'bg-blue-500' },
                        { name: 'AFRINIC', active: !!data, color: 'bg-emerald-500' },
                    ].map((source) => (
                        <div key={source.name} className="flex items-center gap-1.5 bg-card border border-border rounded-full px-2.5 py-1">
                            <div className={`w-1.5 h-1.5 rounded-full ${source.active ? source.color : 'bg-muted-foreground/30'}`} />
                            <span className="text-[9px] font-medium text-muted-foreground">{source.name}</span>
                        </div>
                    ))}
                    <span className="text-[10px] text-muted-foreground ml-auto">
                        {data?.enrichment_coverage?.nigerian_confirmed ?? 0} Nigerian IPs enriched beyond Wazuh&apos;s own geolocation
                    </span>
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