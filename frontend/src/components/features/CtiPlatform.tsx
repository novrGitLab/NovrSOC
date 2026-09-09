'use client';

import { useState, useEffect, useRef } from 'react';
import {
    Search, AlertTriangle, CheckCircle, RefreshCw, ExternalLink,
    Activity, Zap, Globe, Hash, Link as LinkIcon, Monitor,
    Plus, X, Trash2, Users, Rss, Download, Router as RouterIcon, MapPin, Building,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { StixExportButton } from '@/components/features/StixExportButton';

type IOCType = 'ip' | 'domain' | 'hash' | 'url';
type Verdict = 'clean' | 'suspicious' | 'malicious';

interface IOCResult {
    value: string;
    type: IOCType;
    risk_score: number;
    verdict: Verdict;
    sources: {
        leakix: { status: 'ok' | 'not_found' | 'unconfigured' | 'error'; exposed: boolean; service_count: number; leak_count: number } | null;
        abuseipdb: { confidence: number; total_reports: number; country: string | null; isp: string | null; is_tor: boolean } | null;
        urlhaus: { status: string; threat: string; tags: string[] } | null;
        threatfox: { malware: string; confidence: number; threat_type: string } | null;
        virustotal: { malicious: number; suspicious: number; total_engines: number; verdict: string; as_owner: string | undefined; tags: string[] } | null;
    };
    tags: string[];
    enriched_at: string;
    note?: string;
}

interface FeedIOC {
    ioc_value: string;
    ioc_type: IOCType;
    risk_score: number;
    country_code: string | null;
    isp: string | null;
    is_tor: boolean;
    tags: string[];
    last_seen: string;
}

interface ThreatPulse {
    id: string;
    name: string;
    description: string;
    tags: string[];
    created: string;
}

const VERDICT_CONFIG: Record<Verdict, { label: string; color: string; bg: string; icon: LucideIcon }> = {
    malicious: { label: 'MALICIOUS', color: 'text-red-500', bg: 'bg-red-500/10 border-red-500/30', icon: AlertTriangle },
    suspicious: { label: 'SUSPICIOUS', color: 'text-amber', bg: 'bg-grey-100 border-amber/30', icon: AlertTriangle },
    clean: { label: 'CLEAN', color: 'text-green', bg: 'bg-green/10 border-green/30', icon: CheckCircle },
};

const TYPE_ICONS: Record<IOCType, LucideIcon> = { ip: Globe, domain: Monitor, hash: Hash, url: LinkIcon };

const IOC_TYPES: { value: IOCType; label: string; placeholder: string }[] = [
    { value: 'ip', label: 'IP Address', placeholder: '185.220.101.47' },
    { value: 'domain', label: 'Domain', placeholder: 'suspicious-domain.com' },
    { value: 'hash', label: 'File Hash', placeholder: 'MD5 or SHA256 hash' },
    { value: 'url', label: 'URL', placeholder: 'https://suspicious-link.com/malware.exe' },
];

const TABS = [
    { id: 'search', label: 'IOC Search' },
    { id: 'feed', label: 'Live IOC Feed' },
    { id: 'pulses', label: 'Threat Feed Pulses' },
    { id: 'org', label: 'My Organisation' },
    { id: 'sharing', label: 'Threat Sharing' },
    { id: 'intel-feed', label: 'Intelligence Feed' },
    { id: 'network', label: 'Network Intelligence' },
] as const;
type Tab = (typeof TABS)[number]['id'];

// ── ORG CTI TYPES (Tabs 4-7 — /api/org-cti/*) ──────────────────────────────

type OrgIOCType = 'ip' | 'domain' | 'hash' | 'url' | 'email';
type OrgVerdict = 'malicious' | 'suspicious' | 'clean' | 'unknown';

interface OrgIOC {
    id: string;
    org_id: string;
    value: string;
    type: OrgIOCType;
    source: 'wazuh' | 'analyst' | 'shared' | 'feed';
    first_seen: string;
    last_seen: string;
    seen_count: number;
    risk_score: number;
    verdict: OrgVerdict;
    tags: string[];
    notes: string;
    shared: boolean;
    added_by: string;
}
interface OrgSummary {
    total: number; malicious: number; suspicious: number;
    by_type: { ip: number; domain: number; hash: number; url: number };
    wazuh_sourced: number; analyst_added: number;
}
interface SharedIOC {
    id: string; value: string; type: OrgIOCType; verdict: OrgVerdict;
    risk_score: number; seen_count: number; tags: string[]; shared_by_clients: number;
}
interface ASNInfo {
    asn: string; holder: string; is_announced: boolean;
    authoritative_rir: string | null; is_afrinic: boolean;
    top_country: string | null; prefix_count: number; prefixes: string[];
}
interface IPRouteInfo {
    ip: string; asn: string; asn_name: string; isp: string; prefix: string;
    country_code: string; is_nigerian: boolean; nigerian_isp: string | null; source: string;
}

const ORG_TYPE_BADGE: Record<OrgIOCType, string> = {
    ip: 'bg-blue/10 text-blue', domain: 'bg-purple/10 text-purple',
    url: 'bg-orange/10 text-orange', hash: 'bg-card-muted text-foreground-muted', email: 'bg-card-muted text-foreground-muted',
};
const ORG_VERDICT_BADGE: Record<OrgVerdict, string> = {
    malicious: 'bg-red text-white', suspicious: 'bg-amber/10 text-amber',
    clean: 'bg-green/10 text-green', unknown: 'bg-card-muted text-foreground-muted',
};

// Nigerian ISP ASN reference table. Verified live against RIPE Stat while building this —
// the obvious-looking assignment (sequential-ish AS numbers to household ISP names) doesn't
// hold: AS37076 is EMTS (9mobile)'s number, not Glo's, and Spectranet is AS37340, not
// AS328601 (that one belongs to an unrelated Congo-based holding company). Getting this table
// wrong would misattribute real network traffic during an actual investigation.
// MTN's registration predates AFRINIC's 2005 founding, so it stayed under RIPE — every other
// Nigerian ISP here registered after and is genuinely AFRINIC. Shown per-row rather than
// assumed, matching the live is_afrinic flag ASN Lookup returns for any other ASN typed in.
const NIGERIAN_ISPS = [
    { name: 'MTN Nigeria', asn: 'AS29465', registry: 'RIPE' },
    { name: 'Airtel Nigeria', asn: 'AS36873', registry: 'AFRINIC' },
    { name: 'Glo (Globacom)', asn: 'AS37148', registry: 'AFRINIC' },
    { name: '9mobile (EMTS)', asn: 'AS37076', registry: 'AFRINIC' },
    { name: 'MainOne', asn: 'AS37282', registry: 'AFRINIC' },
    { name: 'Spectranet', asn: 'AS37340', registry: 'AFRINIC' },
] as const;

function scoreColor(score: number): string {
    return score >= 70 ? 'text-red-500' : score >= 30 ? 'text-amber' : 'text-green';
}
function scoreBg(score: number): string {
    return score >= 70 ? 'bg-red-500' : score >= 30 ? 'bg-amber' : 'bg-green';
}

export function CtiPlatform() {
    const [iocValue, setIocValue] = useState('');
    const [iocType, setIocType] = useState<IOCType>('ip');
    const [result, setResult] = useState<IOCResult | null>(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [feed, setFeed] = useState<FeedIOC[]>([]);
    const [feedFilter, setFeedFilter] = useState<IOCType | 'all'>('all');
    const [activeTab, setActiveTab] = useState<Tab>('search');
    const [pulses, setPulses] = useState<ThreatPulse[]>([]);
    const [pulsesLoading, setPulsesLoading] = useState(false);
    const [stats, setStats] = useState({ total: 0, malicious: 0, suspicious: 0, clean: 0 });
    const inputRef = useRef<HTMLInputElement>(null);

    // My Organisation
    const [orgIocs, setOrgIocs] = useState<OrgIOC[]>([]);
    const [orgSummary, setOrgSummary] = useState<OrgSummary | null>(null);
    const [orgLoading, setOrgLoading] = useState(true);
    const [orgFilter, setOrgFilter] = useState({ type: '', verdict: '', source: '' });
    const [orgSearch, setOrgSearch] = useState('');
    const [showAddIoc, setShowAddIoc] = useState(false);
    const [newIoc, setNewIoc] = useState({ value: '', type: 'ip' as OrgIOCType, verdict: 'unknown' as OrgVerdict, tags: '', notes: '', shared: false });

    // Threat Sharing
    const [sharedIocs, setSharedIocs] = useState<SharedIOC[]>([]);
    const [participatingClients, setParticipatingClients] = useState(0);
    const [sharedLoading, setSharedLoading] = useState(true);

    // Network Intelligence
    const [asnInput, setAsnInput] = useState('');
    const [asnResult, setAsnResult] = useState<ASNInfo | null>(null);
    const [asnLoading, setAsnLoading] = useState(false);
    const [asnError, setAsnError] = useState<string | null>(null);
    const [ipRouteInput, setIpRouteInput] = useState('');
    const [ipRouteResult, setIpRouteResult] = useState<IPRouteInfo | null>(null);
    const [ipRouteLoading, setIpRouteLoading] = useState(false);
    const [ipRouteError, setIpRouteError] = useState<string | null>(null);

    // Deliberately doesn't set *Loading(true) synchronously here — react-hooks/set-state-in-effect
    // flags a useEffect body that synchronously calls setState. orgLoading/sharedLoading already
    // default to true from useState, which covers the mount case; a refetch after a filter
    // change or an add/remove just updates the table without a loading flash, which is fine.
    const loadOrgIocs = () => {
        const params = new URLSearchParams();
        if (orgFilter.type) params.set('type', orgFilter.type);
        if (orgFilter.verdict) params.set('verdict', orgFilter.verdict);
        if (orgFilter.source) params.set('source', orgFilter.source);
        apiFetch(apiUrl(`/api/org-cti/iocs?${params}`), { cache: 'no-store' })
            .then((r) => r.json())
            .then((data) => { setOrgIocs(Array.isArray(data?.iocs) ? data.iocs : []); setOrgSummary(data?.summary ?? null); })
            .catch(() => { setOrgIocs([]); setOrgSummary(null); })
            .finally(() => setOrgLoading(false));
    };

    const loadShared = () => {
        apiFetch(apiUrl('/api/org-cti/shared'), { cache: 'no-store' })
            .then((r) => r.json())
            .then((data) => { setSharedIocs(Array.isArray(data?.shared_iocs) ? data.shared_iocs : []); setParticipatingClients(data?.participating_clients ?? 0); })
            .catch(() => { setSharedIocs([]); setParticipatingClients(0); })
            .finally(() => setSharedLoading(false));
    };

    // Org IOCs feed the "My Organisation" tab, the Threat Sharing tab's contributions panel,
    // and Tab 1's "Your Organisation's History" section below — load once on mount rather than
    // lazily per-tab so switching to Search after a lookup already has org context ready.
    useEffect(() => {
        loadOrgIocs();
        loadShared();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);
    useEffect(() => {
        loadOrgIocs();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [orgFilter]);

    const addOrgIoc = async () => {
        if (!newIoc.value.trim()) return;
        await apiFetch(apiUrl('/api/org-cti/iocs'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                value: newIoc.value.trim(),
                type: newIoc.type,
                verdict: newIoc.verdict,
                tags: newIoc.tags.split(',').map((t) => t.trim()).filter(Boolean),
                notes: newIoc.notes,
                shared: newIoc.shared,
            }),
        });
        setShowAddIoc(false);
        setNewIoc({ value: '', type: 'ip', verdict: 'unknown', tags: '', notes: '', shared: false });
        loadOrgIocs();
        loadShared();
    };

    const shareOrgIoc = async (ioc: OrgIOC) => {
        if (ioc.source !== 'analyst') return; // only analyst-added IOCs are editable/shareable
        await apiFetch(apiUrl(`/api/org-cti/iocs/${ioc.id}`), {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ shared: !ioc.shared }),
        });
        loadOrgIocs();
        loadShared();
    };

    const removeOrgIoc = async (ioc: OrgIOC) => {
        if (ioc.source !== 'analyst') return;
        await apiFetch(apiUrl(`/api/org-cti/iocs/${ioc.id}`), { method: 'DELETE' });
        loadOrgIocs();
    };

    // Takes an explicit ASN rather than always reading `asnInput` state — the Nigerian ISP
    // reference table below calls setAsnInput(asn) and this in the same click handler, and
    // state updates aren't visible synchronously, so reading asnInput here would still see
    // the *previous* value on that first click.
    const lookupAsnFor = async (asnOverride?: string) => {
        const trimmed = (asnOverride ?? asnInput).trim();
        if (!trimmed) return;
        setAsnLoading(true);
        setAsnError(null);
        setAsnResult(null);
        try {
            const res = await apiFetch(apiUrl(`/api/org-cti/network/asn/${encodeURIComponent(trimmed)}`), { cache: 'no-store' });
            const data = await res.json();
            if (!res.ok) throw new Error(data?.error || `HTTP ${res.status}`);
            setAsnResult(data);
        } catch (err) {
            setAsnError(err instanceof Error ? err.message : 'ASN lookup failed');
        } finally {
            setAsnLoading(false);
        }
    };
    const lookupAsn = () => lookupAsnFor();

    const lookupIpRoute = async () => {
        const trimmed = ipRouteInput.trim();
        if (!trimmed) return;
        setIpRouteLoading(true);
        setIpRouteError(null);
        setIpRouteResult(null);
        try {
            const res = await apiFetch(apiUrl(`/api/geo/enrich?ip=${encodeURIComponent(trimmed)}`), { cache: 'no-store' });
            const data = await res.json();
            if (!res.ok) throw new Error(data?.error || `HTTP ${res.status}`);
            if (data?.is_private) throw new Error('Private/internal IP — no public routing data');
            setIpRouteResult(data);
        } catch (err) {
            setIpRouteError(err instanceof Error ? err.message : 'IP routing lookup failed');
        } finally {
            setIpRouteLoading(false);
        }
    };

    // Auto-detect IOC type as user types
    const detectType = (value: string): IOCType => {
        if (/^(\d{1,3}\.){3}\d{1,3}$/.test(value)) return 'ip';
        if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{64}$/.test(value)) return 'hash';
        if (/^https?:\/\//.test(value)) return 'url';
        if (/^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}\.[a-zA-Z]{2,}/.test(value)) return 'domain';
        return iocType;
    };

    const handleInput = (val: string) => {
        setIocValue(val);
        setIocType(detectType(val.trim()));
    };

    const loadFeed = () => {
        const params = new URLSearchParams({ limit: '50' });
        if (feedFilter !== 'all') params.set('type', feedFilter);
        apiFetch(apiUrl(`/api/cti/feed?${params}`), { cache: 'no-store' })
            .then((r) => r.json())
            .then((data) => setFeed(Array.isArray(data?.iocs) ? data.iocs : []))
            .catch(() => setFeed([]));
    };

    const loadStats = () => {
        apiFetch(apiUrl('/api/cti/stats'), { cache: 'no-store' })
            .then((r) => r.json())
            .then((data) => setStats({ total: data.total ?? 0, malicious: data.malicious ?? 0, suspicious: data.suspicious ?? 0, clean: data.clean ?? 0 }))
            .catch(() => {});
    };

    const loadPulses = () => {
        setPulsesLoading(true);
        apiFetch(apiUrl('/api/cti/pulses?limit=20'), { cache: 'no-store' })
            .then((r) => r.json())
            .then((data) => setPulses(Array.isArray(data?.pulses) ? data.pulses : []))
            .catch(() => setPulses([]))
            .finally(() => setPulsesLoading(false));
    };

    const lookup = async () => {
        const trimmed = iocValue.trim();
        if (!trimmed) return;

        setLoading(true);
        setError(null);
        setResult(null);

        try {
            const res = await apiFetch(apiUrl('/api/cti/lookup'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ value: trimmed, type: iocType }),
            });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();
            setResult(data);
            loadFeed();
            loadStats();
        } catch {
            setError('Lookup failed — check your connection or try again');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        loadFeed();
        loadStats();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [feedFilter]);

    useEffect(() => {
        if (activeTab === 'pulses' && pulses.length === 0 && !pulsesLoading) loadPulses();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [activeTab]);

    return (
        <div className="space-y-4">
            <div className="flex items-start justify-between">
                <div>
                    <h1 className="text-lg font-black text-foreground">CTI Platform</h1>
                    <p className="text-xs text-foreground-muted">Threat Intelligence · Search and correlate IOCs across 5 threat intelligence sources</p>
                </div>
                <div className="flex items-center gap-4">
                    <div className="flex items-center gap-2 text-xs text-foreground-muted">
                        <span className="w-2 h-2 rounded-full bg-green animate-pulse" />
                        4 threat feeds active
                    </div>
                    <StixExportButton />
                </div>
            </div>

            {/* Stats row */}
            <div className="grid grid-cols-4 gap-3">
                {[
                    { label: 'Total IOCs', value: stats.total, border: 'border-t-blue' },
                    { label: 'Malicious', value: stats.malicious, border: 'border-t-red-500' },
                    { label: 'Suspicious', value: stats.suspicious, border: 'border-t-amber' },
                    { label: 'Clean', value: stats.clean, border: 'border-t-green' },
                ].map((stat) => (
                    <div key={stat.label} className={`bg-card border border-border rounded-xl p-4 border-t-4 ${stat.border}`}>
                        <div className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider mb-1">{stat.label}</div>
                        <div className="font-heading font-black text-2xl text-foreground">{stat.value}</div>
                    </div>
                ))}
            </div>

            {/* Tabs */}
            <div className="flex gap-1 border-b border-border overflow-x-auto scrollbar-thin">
                {TABS.map((tab) => (
                    <button
                        key={tab.id}
                        onClick={() => setActiveTab(tab.id)}
                        className={`px-4 py-2.5 text-xs font-bold border-b-2 transition-colors whitespace-nowrap flex-shrink-0 ${
                            activeTab === tab.id ? 'border-blue text-blue' : 'border-transparent text-foreground-muted hover:text-foreground'
                        }`}
                    >
                        {tab.label}
                    </button>
                ))}
            </div>

            {/* ── SEARCH TAB ── */}
            {activeTab === 'search' && (
                <div className="space-y-4">
                    {/* Search bar */}
                    <div className="bg-card border border-border rounded-xl p-4">
                        <div className="flex flex-col md:flex-row gap-3">
                            {/* Type selector */}
                            <div className="flex gap-1 bg-card-muted rounded-lg p-1 overflow-x-auto">
                                {IOC_TYPES.map((t) => {
                                    const Icon = TYPE_ICONS[t.value];
                                    return (
                                        <button
                                            key={t.value}
                                            onClick={() => setIocType(t.value)}
                                            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium whitespace-nowrap transition-colors ${
                                                iocType === t.value ? 'bg-card text-blue shadow-sm border border-border' : 'text-foreground-muted hover:text-foreground'
                                            }`}
                                        >
                                            <Icon size={13} />
                                            {t.label}
                                        </button>
                                    );
                                })}
                            </div>

                            {/* Input */}
                            <div className="flex-1 relative">
                                <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-foreground-muted" />
                                <input
                                    ref={inputRef}
                                    type="text"
                                    value={iocValue}
                                    onChange={(e) => handleInput(e.target.value)}
                                    onKeyDown={(e) => e.key === 'Enter' && lookup()}
                                    placeholder={IOC_TYPES.find((t) => t.value === iocType)?.placeholder}
                                    className="w-full pl-9 pr-4 py-2 border border-border bg-card-muted rounded-lg text-sm focus:outline-none focus:border-blue focus:ring-1 focus:ring-blue/20 font-mono text-foreground placeholder:font-sans placeholder:text-foreground-muted"
                                />
                            </div>

                            {/* Search button */}
                            <button
                                onClick={lookup}
                                disabled={loading || !iocValue.trim()}
                                className="flex items-center gap-2 bg-orange hover:bg-orange-hover text-white px-5 py-2 rounded-lg text-xs font-black disabled:opacity-50 disabled:cursor-not-allowed transition-colors min-w-[100px] justify-center"
                            >
                                {loading ? (<><RefreshCw size={14} className="animate-spin" /> Scanning…</>) : (<><Search size={14} /> Lookup</>)}
                            </button>
                        </div>

                        {iocValue && (
                            <div className="mt-2 text-xs text-foreground-muted">
                                Detected type: <span className="text-blue font-medium">{iocType.toUpperCase()}</span> · Press Enter or click Lookup
                            </div>
                        )}
                    </div>

                    {error && (
                        <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 text-sm text-red-500">{error}</div>
                    )}

                    {result && (() => {
                        const cfg = VERDICT_CONFIG[result.verdict];
                        const VerdictIcon = cfg.icon;
                        return (
                            <div className={`border rounded-xl overflow-hidden ${cfg.bg}`}>
                                <div className="p-5 border-b border-border">
                                    <div className="flex items-start justify-between flex-wrap gap-3">
                                        <div className="flex items-center gap-3">
                                            <VerdictIcon size={24} className={cfg.color} />
                                            <div>
                                                <div className="font-mono font-bold text-lg text-foreground break-all">{result.value}</div>
                                                <div className="text-xs text-foreground-muted mt-0.5">
                                                    {result.type.toUpperCase()} · Enriched {new Date(result.enriched_at).toLocaleString()}
                                                    {result.note ? ` · ${result.note}` : ''}
                                                </div>
                                            </div>
                                        </div>
                                        <div className="text-right">
                                            <div className={`font-heading font-black text-3xl ${scoreColor(result.risk_score)}`}>
                                                {result.risk_score}<span className="text-lg font-normal text-foreground-muted">/100</span>
                                            </div>
                                            <div className={`text-sm font-bold mt-0.5 ${cfg.color}`}>{cfg.label}</div>
                                        </div>
                                    </div>

                                    <div className="mt-4 h-2 bg-card-muted rounded-full overflow-hidden">
                                        <div className={`h-full rounded-full transition-all duration-700 ${scoreBg(result.risk_score)}`} style={{ width: `${result.risk_score}%` }} />
                                    </div>

                                    {result.tags.length > 0 && (
                                        <div className="flex flex-wrap gap-1.5 mt-3">
                                            {result.tags.slice(0, 10).map((tag) => (
                                                <span key={tag} className="text-[10px] font-medium px-2 py-0.5 bg-card border border-border rounded-full text-foreground">{tag}</span>
                                            ))}
                                        </div>
                                    )}
                                </div>

                                {/* Source breakdown */}
                                <div className="grid grid-cols-1 sm:grid-cols-3 gap-0 divide-x divide-y divide-border">
                                    <div className="p-4">
                                        <div className="flex items-center gap-2 mb-2">
                                            <div className="w-2 h-2 rounded-full bg-purple" />
                                            <span className="text-xs font-semibold text-foreground">Host Exposure (LeakIX)</span>
                                        </div>
                                        {result.sources.leakix ? (
                                            result.sources.leakix.status === 'ok' ? (
                                                <>
                                                    <div className="text-sm font-bold text-foreground">
                                                        {result.sources.leakix.service_count} exposed service{result.sources.leakix.service_count === 1 ? '' : 's'}
                                                    </div>
                                                    <div className="text-xs text-foreground-muted mt-1">
                                                        {result.sources.leakix.leak_count > 0
                                                            ? `${result.sources.leakix.leak_count} known leak${result.sources.leakix.leak_count === 1 ? '' : 's'}`
                                                            : 'No known leaks'}
                                                    </div>
                                                </>
                                            ) : result.sources.leakix.status === 'not_found' ? (
                                                <div className="text-xs text-foreground-muted">No LeakIX records for this host</div>
                                            ) : (
                                                // Never render an unconfigured/failed lookup as "no exposure" — that
                                                // would read as a clean result the scan never actually established.
                                                <div className="text-xs text-amber">
                                                    {result.sources.leakix.status === 'unconfigured' ? 'Not checked — LEAKIX_API_KEY not set' : 'Lookup failed'}
                                                </div>
                                            )
                                        ) : (
                                            <div className="text-xs text-foreground-muted">Not applicable for this IOC type</div>
                                        )}
                                    </div>

                                    <div className="p-4">
                                        <div className="flex items-center gap-2 mb-2">
                                            <div className="w-2 h-2 rounded-full bg-red-500" />
                                            <span className="text-xs font-semibold text-foreground">IP Reputation Engine</span>
                                        </div>
                                        {result.sources.abuseipdb ? (
                                            <>
                                                <div className="text-sm font-bold text-foreground">{result.sources.abuseipdb.confidence}% confidence</div>
                                                <div className="text-xs text-foreground-muted mt-1">{result.sources.abuseipdb.total_reports} reports · {result.sources.abuseipdb.country ?? 'Unknown'}</div>
                                                {result.sources.abuseipdb.is_tor && (
                                                    <span className="text-[10px] font-bold bg-red-500 text-white px-1.5 py-0.5 rounded mt-1 inline-block">TOR EXIT NODE</span>
                                                )}
                                            </>
                                        ) : (
                                            <div className="text-xs text-foreground-muted">{result.type !== 'ip' ? 'IP-only service' : 'No data'}</div>
                                        )}
                                    </div>

                                    <div className="p-4">
                                        <div className="flex items-center gap-2 mb-2">
                                            <div className="w-2 h-2 rounded-full bg-blue" />
                                            <span className="text-xs font-semibold text-foreground">Multi-Engine Scanner</span>
                                        </div>
                                        {result.sources.virustotal ? (
                                            <>
                                                <div className="text-sm font-bold text-foreground">{result.sources.virustotal.malicious}/{result.sources.virustotal.total_engines} engines flagged</div>
                                                <div className="w-full h-1.5 bg-card-muted rounded-full mt-2 overflow-hidden">
                                                    <div
                                                        className="h-full rounded-full bg-red-500 transition-all duration-700"
                                                        style={{ width: `${(result.sources.virustotal.malicious / Math.max(1, result.sources.virustotal.total_engines)) * 100}%` }}
                                                    />
                                                </div>
                                                <div className={`text-xs font-semibold mt-1 ${
                                                    result.sources.virustotal.verdict === 'malicious' ? 'text-red-500' :
                                                    result.sources.virustotal.verdict === 'suspicious' ? 'text-amber' : 'text-green'
                                                }`}>
                                                    {result.sources.virustotal.verdict.toUpperCase()}
                                                </div>
                                                {result.sources.virustotal.as_owner && (
                                                    <div className="text-xs text-foreground-muted mt-1">{result.sources.virustotal.as_owner}</div>
                                                )}
                                            </>
                                        ) : (
                                            <div className="text-xs text-foreground-muted">Not found in Multi-Engine Scanner</div>
                                        )}
                                    </div>

                                    <div className="p-4">
                                        <div className="flex items-center gap-2 mb-2">
                                            <div className="w-2 h-2 rounded-full bg-amber" />
                                            <span className="text-xs font-semibold text-foreground">Malicious URL Database</span>
                                        </div>
                                        {result.sources.urlhaus ? (
                                            <>
                                                <div className="text-sm font-bold text-foreground">{result.sources.urlhaus.threat || 'Known malicious'}</div>
                                                <div className="text-xs text-foreground-muted mt-1">Status: {result.sources.urlhaus.status}</div>
                                            </>
                                        ) : (
                                            <div className="text-xs text-foreground-muted">Not in Malicious URL Database</div>
                                        )}
                                    </div>

                                    <div className="p-4">
                                        <div className="flex items-center gap-2 mb-2">
                                            <div className="w-2 h-2 rounded-full bg-blue" />
                                            <span className="text-xs font-semibold text-foreground">Malware Intelligence Feed</span>
                                        </div>
                                        {result.sources.threatfox ? (
                                            <>
                                                <div className="text-sm font-bold text-foreground">{result.sources.threatfox.malware}</div>
                                                <div className="text-xs text-foreground-muted mt-1">{result.sources.threatfox.threat_type} · {result.sources.threatfox.confidence}% confidence</div>
                                            </>
                                        ) : (
                                            <div className="text-xs text-foreground-muted">Not in Malware Intelligence Feed</div>
                                        )}
                                    </div>
                                </div>

                                {/* Actions */}
                                <div className="px-5 py-3 bg-card/60 flex flex-wrap gap-3 border-t border-border">
                                    <button className="text-xs text-blue hover:text-purple font-medium transition-colors">+ Add to Blocklist</button>
                                    <button className="text-xs text-blue hover:text-purple font-medium transition-colors">Create Incident</button>
                                    <button className="text-xs text-blue hover:text-purple font-medium transition-colors">Export IOC</button>
                                    <a
                                        href="https://www.circl.lu/doc/misp/feed-osint/"
                                        target="_blank" rel="noopener noreferrer"
                                        className="ml-auto text-xs text-foreground-muted hover:text-blue flex items-center gap-1 transition-colors"
                                    >
                                        View in Threat Feed <ExternalLink size={11} />
                                    </a>
                                </div>
                            </div>
                        );
                    })()}

                    {/* Your Organisation's History — cross-referenced against org-cti IOCs
                       already loaded for the My Organisation / Threat Sharing tabs, so this
                       needs no extra round-trip beyond the lookup itself. */}
                    {result && (() => {
                        const orgHistory = orgIocs.find((i) => i.value.toLowerCase() === result.value.toLowerCase());
                        const sharedMatch = sharedIocs.find((i) => i.value.toLowerCase() === result.value.toLowerCase());
                        const alreadyWatchlisted = orgIocs.some((i) => i.source === 'analyst' && i.value.toLowerCase() === result.value.toLowerCase());
                        return (
                            <div className="border border-border rounded-xl p-4 bg-card">
                                <h3 className="font-bold text-sm text-foreground mb-3">Your Organisation&apos;s History</h3>
                                {orgHistory ? (
                                    <div>
                                        <p className="text-sm text-foreground">This IOC has appeared in your alerts {orgHistory.seen_count} time{orgHistory.seen_count === 1 ? '' : 's'}</p>
                                        <p className="text-xs text-foreground-muted">First seen: {new Date(orgHistory.first_seen).toLocaleString()} · Last seen: {new Date(orgHistory.last_seen).toLocaleString()}</p>
                                        {orgHistory.tags[0] && <p className="text-xs text-foreground-muted mt-1">Associated rule: {orgHistory.tags[0]}</p>}
                                    </div>
                                ) : (
                                    <p className="text-sm text-foreground-muted">This IOC has not been seen in your organisation&apos;s alerts.</p>
                                )}

                                {sharedMatch && (
                                    <div className="mt-3 bg-purple/10 rounded-lg p-3">
                                        <p className="text-xs text-purple font-semibold">
                                            🔗 {sharedMatch.shared_by_clients} other NovrSOC client{sharedMatch.shared_by_clients > 1 ? 's have' : ' has'} also seen this IOC
                                        </p>
                                    </div>
                                )}

                                <button
                                    onClick={() => {
                                        setNewIoc({ value: result.value, type: result.type, verdict: result.verdict, tags: result.tags.slice(0, 3).join(', '), notes: '', shared: false });
                                        setShowAddIoc(true);
                                        setActiveTab('org');
                                    }}
                                    disabled={alreadyWatchlisted}
                                    className="mt-3 border border-purple text-purple text-xs font-bold px-3 py-1.5 rounded-lg hover:bg-purple/5 disabled:opacity-50 transition-colors"
                                >
                                    {alreadyWatchlisted ? '✓ Already on Watchlist' : '+ Add to Watchlist'}
                                </button>
                            </div>
                        );
                    })()}

                    {!result && !loading && !error && (
                        <div className="bg-card border border-border rounded-xl p-12 text-center">
                            <Search size={40} className="text-border mx-auto mb-3" />
                            <div className="font-heading font-semibold text-foreground mb-1">Search any IOC</div>
                            <div className="text-sm text-foreground-muted">Paste an IP address, domain, file hash, or URL above to get an instant threat verdict</div>
                            <div className="flex flex-wrap items-center justify-center gap-4 mt-6 text-xs text-foreground-muted">
                                {['185.220.101.47', 'malware.example.com'].map((ex) => (
                                    <button key={ex} onClick={() => { handleInput(ex); inputRef.current?.focus(); }} className="font-mono hover:text-blue transition-colors">
                                        {ex}
                                    </button>
                                ))}
                            </div>
                        </div>
                    )}
                </div>
            )}

            {/* ── FEED TAB ── */}
            {activeTab === 'feed' && (
                <div>
                    <div className="flex items-center gap-2 mb-4 flex-wrap">
                        <span className="text-xs text-foreground-muted">Filter:</span>
                        {(['all', 'ip', 'domain', 'hash', 'url'] as const).map((f) => (
                            <button
                                key={f}
                                onClick={() => setFeedFilter(f)}
                                className={`px-3 py-1.5 rounded-full text-xs font-medium transition-colors ${
                                    feedFilter === f ? 'bg-blue text-white' : 'bg-card border border-border text-foreground-muted hover:border-grey-300'
                                }`}
                            >
                                {f === 'all' ? 'All' : f.toUpperCase()}
                            </button>
                        ))}
                        <button onClick={loadFeed} className="ml-auto flex items-center gap-1.5 text-xs text-blue">
                            <RefreshCw size={12} /> Refresh
                        </button>
                    </div>

                    {feed.length === 0 ? (
                        <div className="bg-card border border-border rounded-xl p-10 text-center">
                            <Activity size={36} className="text-border mx-auto mb-3" />
                            <div className="text-sm text-foreground-muted">No IOCs in feed yet — run your first lookup to populate the feed</div>
                        </div>
                    ) : (
                        <div className="bg-card border border-border rounded-xl overflow-hidden overflow-x-auto">
                            <table className="w-full text-xs">
                                <thead>
                                    <tr className="border-b border-border">
                                        {['IOC Value', 'Type', 'Risk Score', 'Country', 'ISP', 'Tags', 'Last Seen'].map((h) => (
                                            <th key={h} className="text-left px-4 py-2.5 text-[10px] font-bold text-foreground-muted uppercase tracking-wider">{h}</th>
                                        ))}
                                    </tr>
                                </thead>
                                <tbody>
                                    {feed.map((ioc) => (
                                        <tr
                                            key={ioc.ioc_value}
                                            className="border-b border-border hover:bg-card-muted cursor-pointer transition-colors"
                                            onClick={() => { setIocValue(ioc.ioc_value); setIocType(ioc.ioc_type); setActiveTab('search'); }}
                                        >
                                            <td className="px-4 py-2.5 font-mono text-foreground max-w-[200px] truncate">{ioc.ioc_value}</td>
                                            <td className="px-4 py-2.5"><span className="text-[10px] font-bold bg-blue/10 text-blue px-2 py-0.5 rounded">{ioc.ioc_type.toUpperCase()}</span></td>
                                            <td className="px-4 py-2.5">
                                                <div className="flex items-center gap-2">
                                                    <div className="w-12 h-1.5 bg-card-muted rounded-full overflow-hidden">
                                                        <div className={`h-full rounded-full ${scoreBg(ioc.risk_score)}`} style={{ width: `${ioc.risk_score}%` }} />
                                                    </div>
                                                    <span className={`font-bold ${scoreColor(ioc.risk_score)}`}>{ioc.risk_score}</span>
                                                </div>
                                            </td>
                                            <td className="px-4 py-2.5 text-foreground-muted">{ioc.country_code || '—'}</td>
                                            <td className="px-4 py-2.5 text-foreground-muted max-w-[120px] truncate">{ioc.isp || '—'}</td>
                                            <td className="px-4 py-2.5">
                                                <div className="flex gap-1 flex-wrap">
                                                    {(ioc.tags || []).slice(0, 2).map((tag) => (
                                                        <span key={tag} className="text-[10px] bg-card-muted text-foreground-muted px-1.5 py-0.5 rounded">{tag}</span>
                                                    ))}
                                                    {ioc.is_tor && <span className="text-[10px] bg-red-500 text-white px-1.5 py-0.5 rounded font-bold">TOR</span>}
                                                </div>
                                            </td>
                                            <td className="px-4 py-2.5 text-foreground-muted whitespace-nowrap">{new Date(ioc.last_seen).toLocaleString()}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </div>
            )}

            {/* ── PULSES TAB ── */}
            {activeTab === 'pulses' && (
                <div className="space-y-3">
                    {pulsesLoading ? (
                        <div className="space-y-2">{Array.from({ length: 3 }).map((_, i) => <div key={i} className="h-20 bg-card-muted rounded-xl animate-pulse" />)}</div>
                    ) : pulses.length === 0 ? (
                        <div className="bg-card border border-border rounded-xl p-10 text-center">
                            <Zap size={36} className="text-border mx-auto mb-3" />
                            <div className="text-sm text-foreground-muted">No pulses found — subscribe to threat feeds to see live pulses here</div>
                            <a href="https://www.circl.lu/doc/misp/feed-osint/" target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 mt-3 text-xs text-blue hover:text-purple">
                                Browse Threat Feed <ExternalLink size={11} />
                            </a>
                        </div>
                    ) : (
                        pulses.map((pulse) => (
                            <div key={pulse.id} className="bg-card border border-border rounded-xl p-4">
                                <div className="flex items-start justify-between gap-3 mb-2">
                                    <div className="font-medium text-sm text-foreground">{pulse.name}</div>
                                    <div className="text-xs text-foreground-muted whitespace-nowrap">{new Date(pulse.created).toLocaleDateString()}</div>
                                </div>
                                {pulse.description && <div className="text-xs text-foreground-muted mb-2 line-clamp-2">{pulse.description}</div>}
                                <div className="flex items-center gap-2 flex-wrap">
                                    {pulse.tags?.slice(0, 4).map((tag) => (
                                        <span key={tag} className="text-[10px] bg-purple/10 text-purple px-2 py-0.5 rounded-full">{tag}</span>
                                    ))}
                                    <a href={`https://www.circl.lu/doc/misp/feed-osint/${pulse.id}.json`} target="_blank" rel="noopener noreferrer" className="ml-auto text-xs text-blue flex items-center gap-1 hover:text-purple">
                                        View pulse <ExternalLink size={10} />
                                    </a>
                                </div>
                            </div>
                        ))
                    )}
                </div>
            )}

            {/* ── MY ORGANISATION TAB ── */}
            {activeTab === 'org' && (
                <div className="space-y-4">
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                        {[
                            { label: 'Total IOCs', value: orgSummary?.total ?? 0, border: 'border-t-purple' },
                            { label: 'Malicious', value: orgSummary?.malicious ?? 0, border: 'border-t-red' },
                            { label: 'Suspicious', value: orgSummary?.suspicious ?? 0, border: 'border-t-amber' },
                            { label: 'Shared with Community', value: orgIocs.filter((i) => i.shared).length, border: 'border-t-blue' },
                        ].map((c) => (
                            <div key={c.label} className={`bg-card border border-border rounded-xl p-4 border-t-4 ${c.border}`}>
                                <div className="font-heading font-black text-2xl text-foreground">{c.value}</div>
                                <div className="text-[10px] text-foreground-muted uppercase tracking-wider mt-1">{c.label}</div>
                            </div>
                        ))}
                    </div>

                    <div className="flex items-center gap-4 text-xs text-foreground-muted">
                        <span>Wazuh Auto-Detected: <span className="font-bold text-foreground">{orgSummary?.wazuh_sourced ?? 0}</span></span>
                        <span>Analyst Added: <span className="font-bold text-foreground">{orgSummary?.analyst_added ?? 0}</span></span>
                    </div>

                    <div className="flex items-center gap-2 flex-wrap">
                        <select value={orgFilter.type} onChange={(e) => setOrgFilter((f) => ({ ...f, type: e.target.value }))}
                            className="bg-card border border-border rounded-lg px-3 py-2 text-xs text-foreground focus:outline-none focus:border-purple">
                            <option value="">All Types</option>
                            <option value="ip">IP Address</option>
                            <option value="domain">Domain</option>
                            <option value="hash">File Hash</option>
                            <option value="url">URL</option>
                        </select>
                        <select value={orgFilter.verdict} onChange={(e) => setOrgFilter((f) => ({ ...f, verdict: e.target.value }))}
                            className="bg-card border border-border rounded-lg px-3 py-2 text-xs text-foreground focus:outline-none focus:border-purple">
                            <option value="">All Verdicts</option>
                            <option value="malicious">Malicious</option>
                            <option value="suspicious">Suspicious</option>
                            <option value="unknown">Unknown</option>
                        </select>
                        <select value={orgFilter.source} onChange={(e) => setOrgFilter((f) => ({ ...f, source: e.target.value }))}
                            className="bg-card border border-border rounded-lg px-3 py-2 text-xs text-foreground focus:outline-none focus:border-purple">
                            <option value="">All Sources</option>
                            <option value="wazuh">Wazuh</option>
                            <option value="analyst">Analyst</option>
                        </select>
                        <input value={orgSearch} onChange={(e) => setOrgSearch(e.target.value)} placeholder="Search value…"
                            className="bg-card border border-border rounded-lg px-3 py-2 text-xs text-foreground focus:outline-none focus:border-purple" />
                        <button onClick={() => setShowAddIoc(true)} className="ml-auto flex items-center gap-1.5 bg-orange hover:bg-orange-hover text-white font-bold text-xs px-4 py-2 rounded-lg transition-colors">
                            <Plus size={13} /> Add IOC
                        </button>
                    </div>

                    {orgLoading ? (
                        <div className="space-y-2">{Array.from({ length: 4 }).map((_, i) => <div key={i} className="h-12 bg-card-muted rounded-xl animate-pulse" />)}</div>
                    ) : (
                        <div className="bg-card border border-border rounded-xl overflow-hidden">
                            <div className="overflow-x-auto scrollbar-thin">
                                <table className="w-full text-left text-xs">
                                    <thead>
                                        <tr className="bg-grey-800">
                                            {['Type', 'Value', 'Verdict', 'Risk', 'Source', 'First Seen', 'Last Seen', 'Times Seen', 'Actions'].map((h) => (
                                                <th key={h} className="px-4 py-3 text-[10px] font-semibold text-white uppercase tracking-widest whitespace-nowrap">{h}</th>
                                            ))}
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-border">
                                        {orgIocs.filter((i) => !orgSearch || i.value.toLowerCase().includes(orgSearch.toLowerCase())).map((ioc) => (
                                            <tr key={ioc.id} className="hover:bg-card-muted transition-colors">
                                                <td className="px-4 py-3"><span className={`text-[10px] font-bold px-2 py-1 rounded-full uppercase ${ORG_TYPE_BADGE[ioc.type]}`}>{ioc.type}</span></td>
                                                <td className="px-4 py-3 font-mono text-foreground max-w-xs truncate">{ioc.value}</td>
                                                <td className="px-4 py-3"><span className={`text-[10px] font-bold px-2 py-1 rounded-full uppercase ${ORG_VERDICT_BADGE[ioc.verdict]}`}>{ioc.verdict}</span></td>
                                                <td className="px-4 py-3"><span className={`font-bold ${ioc.risk_score >= 70 ? 'text-red' : ioc.risk_score >= 40 ? 'text-amber' : 'text-blue'}`}>{ioc.risk_score}</span></td>
                                                <td className="px-4 py-3 text-foreground-muted capitalize">{ioc.source}</td>
                                                <td className="px-4 py-3 text-foreground-muted whitespace-nowrap">{new Date(ioc.first_seen).toLocaleDateString()}</td>
                                                <td className="px-4 py-3 text-foreground-muted whitespace-nowrap">{new Date(ioc.last_seen).toLocaleDateString()}</td>
                                                <td className="px-4 py-3 font-semibold text-foreground">{ioc.seen_count}×</td>
                                                <td className="px-4 py-3">
                                                    <div className="flex items-center gap-2">
                                                        <button onClick={() => { handleInput(ioc.value); setIocType(ioc.type === 'email' ? 'domain' : ioc.type); setActiveTab('search'); }} className="text-purple font-medium hover:underline">Lookup</button>
                                                        {ioc.source === 'analyst' && (
                                                            <>
                                                                <button onClick={() => shareOrgIoc(ioc)} className="text-blue font-medium hover:underline">{ioc.shared ? 'Unshare' : 'Share'}</button>
                                                                <button onClick={() => removeOrgIoc(ioc)} className="text-red font-medium hover:underline flex items-center gap-1"><Trash2 size={11} /></button>
                                                            </>
                                                        )}
                                                    </div>
                                                </td>
                                            </tr>
                                        ))}
                                        {orgIocs.length === 0 && (
                                            <tr><td colSpan={9} className="px-4 py-10 text-center text-foreground-muted">No IOCs yet — they&apos;ll appear here automatically as Wazuh alerts come in, or add one manually.</td></tr>
                                        )}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}
                </div>
            )}

            {/* ── THREAT SHARING TAB ── */}
            {activeTab === 'sharing' && (
                <div className="space-y-4">
                    <div className="bg-purple/10 border border-purple/30 rounded-xl p-4">
                        <p className="text-sm font-bold text-purple flex items-center gap-2"><Users size={16} /> {participatingClients} NovrSOC clients are sharing threat intelligence</p>
                        <p className="text-xs text-foreground-muted mt-1">Any IOC you mark as shared is anonymously contributed to this feed — your organisation and internal notes are stripped before it&apos;s shown to other clients.</p>
                    </div>

                    <div className="bg-card border border-border rounded-xl p-4 flex items-center justify-between flex-wrap gap-3">
                        <div>
                            <p className="text-sm font-bold text-foreground">Your Contributions</p>
                            <p className="text-xs text-foreground-muted">{orgIocs.filter((i) => i.shared).length} IOC{orgIocs.filter((i) => i.shared).length === 1 ? '' : 's'} shared from your organisation</p>
                        </div>
                        <button onClick={() => setActiveTab('org')} className="text-xs font-bold text-blue hover:text-purple transition-colors">Manage in My Organisation →</button>
                    </div>

                    {sharedLoading ? (
                        <div className="space-y-2">{Array.from({ length: 4 }).map((_, i) => <div key={i} className="h-12 bg-card-muted rounded-xl animate-pulse" />)}</div>
                    ) : (
                        <div className="bg-card border border-border rounded-xl overflow-hidden">
                            <div className="overflow-x-auto scrollbar-thin">
                                <table className="w-full text-left text-xs">
                                    <thead>
                                        <tr className="bg-grey-800">
                                            {['Type', 'Value', 'Verdict', 'Risk Score', 'Shared By', 'Tags', ''].map((h) => (
                                                <th key={h} className="px-4 py-3 text-[10px] font-semibold text-white uppercase tracking-widest whitespace-nowrap">{h}</th>
                                            ))}
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-border">
                                        {sharedIocs.map((ioc) => (
                                            <tr key={ioc.id} className="hover:bg-card-muted transition-colors">
                                                <td className="px-4 py-3"><span className={`text-[10px] font-bold px-2 py-1 rounded-full uppercase ${ORG_TYPE_BADGE[ioc.type]}`}>{ioc.type}</span></td>
                                                <td className="px-4 py-3 font-mono text-foreground max-w-xs truncate">{ioc.value}</td>
                                                <td className="px-4 py-3"><span className={`text-[10px] font-bold px-2 py-1 rounded-full uppercase ${ORG_VERDICT_BADGE[ioc.verdict]}`}>{ioc.verdict}</span></td>
                                                <td className="px-4 py-3"><span className={`font-bold ${ioc.risk_score >= 70 ? 'text-red' : 'text-amber'}`}>{ioc.risk_score}</span></td>
                                                <td className="px-4 py-3 text-foreground-muted">{ioc.shared_by_clients} client{ioc.shared_by_clients === 1 ? '' : 's'}</td>
                                                <td className="px-4 py-3">
                                                    <div className="flex gap-1 flex-wrap">{ioc.tags.map((t) => <span key={t} className="text-[10px] bg-card-muted text-foreground-muted px-1.5 py-0.5 rounded">{t}</span>)}</div>
                                                </td>
                                                <td className="px-4 py-3">
                                                    <button onClick={() => { handleInput(ioc.value); setIocType(ioc.type === 'email' ? 'domain' : ioc.type); setActiveTab('search'); }} className="text-purple font-medium hover:underline">Lookup</button>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}
                </div>
            )}

            {/* ── INTELLIGENCE FEED TAB ── */}
            {activeTab === 'intel-feed' && (() => {
                type FeedEntry = { value: string; type: OrgIOCType; verdict: OrgVerdict; time: string; source: string };
                const combined: FeedEntry[] = [
                    ...orgIocs.map((i): FeedEntry => ({ value: i.value, type: i.type, verdict: i.verdict, time: i.last_seen, source: i.source === 'wazuh' ? 'Wazuh alert' : 'Manual add' })),
                    ...sharedIocs.map((i): FeedEntry => ({ value: i.value, type: i.type, verdict: i.verdict, time: new Date().toISOString(), source: 'Shared from community' })),
                    ...feed.slice(0, 15).map((i): FeedEntry => ({ value: i.ioc_value, type: i.ioc_type, verdict: i.risk_score >= 70 ? 'malicious' : i.risk_score >= 30 ? 'suspicious' : 'clean', time: i.last_seen, source: 'External feed lookup' })),
                ].sort((a, b) => (b.time > a.time ? 1 : -1));

                const today = new Date().toISOString().slice(0, 10);
                const todayCount = combined.filter((c) => c.time.startsWith(today)).length;
                const wazuhCount = combined.filter((c) => c.source === 'Wazuh alert').length;
                const externalCount = combined.filter((c) => c.source === 'External feed lookup').length;
                const communityCount = combined.filter((c) => c.source === 'Shared from community').length;

                const exportFeed = () => {
                    const header = 'Value,Type,Verdict,Source,Time';
                    const rows = combined.map((c) => [c.value, c.type, c.verdict, c.source, c.time].map((v) => `"${String(v).replace(/"/g, '""')}"`).join(','));
                    const blob = new Blob([[header, ...rows].join('\n')], { type: 'text/csv;charset=utf-8' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `cti-intelligence-feed-${today}.csv`;
                    a.click();
                    URL.revokeObjectURL(url);
                };

                return (
                    <div className="space-y-4">
                        <div className="flex items-center justify-between flex-wrap gap-3">
                            <div className="flex items-center gap-4 text-xs">
                                <span className="text-foreground-muted">Today: <span className="font-bold text-foreground">{todayCount}</span></span>
                                <span className="text-foreground-muted">From Wazuh: <span className="font-bold text-foreground">{wazuhCount}</span></span>
                                <span className="text-foreground-muted">From Feeds: <span className="font-bold text-foreground">{externalCount}</span></span>
                                <span className="text-foreground-muted">From Community: <span className="font-bold text-foreground">{communityCount}</span></span>
                            </div>
                            <button onClick={exportFeed} className="flex items-center gap-1.5 border border-purple text-purple text-xs font-bold px-3 py-1.5 rounded-lg hover:bg-purple/5 transition-colors">
                                <Download size={12} /> Export Feed
                            </button>
                        </div>

                        {combined.length === 0 ? (
                            <div className="bg-card border border-border rounded-xl p-10 text-center">
                                <Rss size={36} className="text-border mx-auto mb-3" />
                                <div className="text-sm text-foreground-muted">No IOCs yet — this aggregates Wazuh alerts, manual adds, shared community IOCs, and external feed lookups.</div>
                            </div>
                        ) : (
                            <div className="space-y-1.5">
                                {combined.slice(0, 50).map((c, i) => (
                                    <div key={i} className="bg-card border border-border rounded-lg px-4 py-2.5 flex items-center gap-3">
                                        <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${c.verdict === 'malicious' ? 'bg-red' : c.verdict === 'suspicious' ? 'bg-amber' : 'bg-green'}`} />
                                        <span className="font-mono text-xs text-foreground truncate flex-1">{c.value}</span>
                                        <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded-full uppercase flex-shrink-0 ${ORG_TYPE_BADGE[c.type]}`}>{c.type}</span>
                                        <span className="text-[10px] text-foreground-muted flex-shrink-0 hidden sm:inline">{c.source}</span>
                                        <span className="text-[10px] text-foreground-muted flex-shrink-0 whitespace-nowrap">{new Date(c.time).toLocaleString()}</span>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                );
            })()}

            {/* ── NETWORK INTELLIGENCE TAB ── */}
            {activeTab === 'network' && (
                <div className="space-y-4">
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                        {/* Tool 1: ASN Lookup */}
                        <div className="bg-card border border-border rounded-xl p-4">
                            <h3 className="font-bold text-sm text-foreground mb-1 flex items-center gap-2"><RouterIcon size={15} className="text-purple" /> ASN Lookup</h3>
                            <p className="text-xs text-foreground-muted mb-3">RIPE Stat routing data — holder, announced prefixes, authoritative RIR.</p>
                            <div className="flex gap-2">
                                <input value={asnInput} onChange={(e) => setAsnInput(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && lookupAsn()}
                                    placeholder="AS29465" className="flex-1 border border-border bg-card-muted rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-purple text-foreground" />
                                <button onClick={lookupAsn} disabled={asnLoading || !asnInput.trim()} className="bg-orange hover:bg-orange-hover text-white text-xs font-bold px-4 py-2 rounded-lg disabled:opacity-50 transition-colors flex items-center gap-1.5">
                                    {asnLoading ? <RefreshCw size={12} className="animate-spin" /> : <Search size={12} />} Lookup
                                </button>
                            </div>
                            {asnError && <p className="text-xs text-red mt-2">{asnError}</p>}
                            {asnResult && (
                                <div className="mt-3 bg-card-muted rounded-lg p-3 text-xs space-y-1.5">
                                    <div className="flex justify-between"><span className="text-foreground-muted">Holder</span><span className="font-bold text-foreground text-right">{asnResult.holder}</span></div>
                                    <div className="flex justify-between"><span className="text-foreground-muted">Announced</span><span className={`font-bold ${asnResult.is_announced ? 'text-green' : 'text-foreground-muted'}`}>{asnResult.is_announced ? 'Yes' : 'No'}</span></div>
                                    <div className="flex justify-between"><span className="text-foreground-muted">Country</span><span className="font-bold text-foreground">{asnResult.top_country ?? '—'}</span></div>
                                    <div className="flex justify-between"><span className="text-foreground-muted">Authoritative RIR</span><span className="font-bold text-foreground uppercase">{asnResult.authoritative_rir ?? '—'}</span></div>
                                    <div className="flex justify-between"><span className="text-foreground-muted">AFRINIC Allocation</span><span className={`font-bold ${asnResult.is_afrinic ? 'text-green' : 'text-foreground-muted'}`}>{asnResult.is_afrinic ? 'Yes' : 'No'}</span></div>
                                    <div className="flex justify-between"><span className="text-foreground-muted">Announced Prefixes</span><span className="font-bold text-foreground">{asnResult.prefix_count}</span></div>
                                    {asnResult.prefixes.length > 0 && (
                                        <div className="pt-2 border-t border-border mt-2">
                                            <p className="text-foreground-muted mb-1">Sample prefixes</p>
                                            <div className="flex flex-wrap gap-1">{asnResult.prefixes.slice(0, 8).map((p) => <span key={p} className="font-mono text-[10px] bg-card px-1.5 py-0.5 rounded border border-border">{p}</span>)}</div>
                                        </div>
                                    )}
                                </div>
                            )}
                        </div>

                        {/* Tool 2: IP Routing Analysis */}
                        <div className="bg-card border border-border rounded-xl p-4">
                            <h3 className="font-bold text-sm text-foreground mb-1 flex items-center gap-2"><MapPin size={15} className="text-purple" /> IP Routing Analysis</h3>
                            <p className="text-xs text-foreground-muted mb-3">What ASN routes this IP, its prefix, and Nigerian ISP confirmation.</p>
                            <div className="flex gap-2">
                                <input value={ipRouteInput} onChange={(e) => setIpRouteInput(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && lookupIpRoute()}
                                    placeholder="102.89.45.13" className="flex-1 border border-border bg-card-muted rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-purple text-foreground" />
                                <button onClick={lookupIpRoute} disabled={ipRouteLoading || !ipRouteInput.trim()} className="bg-orange hover:bg-orange-hover text-white text-xs font-bold px-4 py-2 rounded-lg disabled:opacity-50 transition-colors flex items-center gap-1.5">
                                    {ipRouteLoading ? <RefreshCw size={12} className="animate-spin" /> : <Search size={12} />} Lookup
                                </button>
                            </div>
                            {ipRouteError && <p className="text-xs text-red mt-2">{ipRouteError}</p>}
                            {ipRouteResult && (
                                <div className="mt-3 bg-card-muted rounded-lg p-3 text-xs space-y-1.5">
                                    <div className="flex justify-between"><span className="text-foreground-muted">ASN</span><span className="font-bold text-foreground">{ipRouteResult.asn || '—'} {ipRouteResult.asn_name ? `(${ipRouteResult.asn_name})` : ''}</span></div>
                                    <div className="flex justify-between"><span className="text-foreground-muted">Prefix</span><span className="font-mono font-bold text-foreground">{ipRouteResult.prefix || '—'}</span></div>
                                    <div className="flex justify-between"><span className="text-foreground-muted">ISP / Org</span><span className="font-bold text-foreground text-right">{ipRouteResult.isp || '—'}</span></div>
                                    <div className="flex justify-between"><span className="text-foreground-muted">Country</span><span className="font-bold text-foreground">{ipRouteResult.country_code || '—'}</span></div>
                                    <div className="flex justify-between"><span className="text-foreground-muted">Nigerian ISP</span><span className={`font-bold ${ipRouteResult.is_nigerian ? 'text-green' : 'text-foreground-muted'}`}>{ipRouteResult.is_nigerian ? (ipRouteResult.nigerian_isp ?? 'Confirmed') : 'No'}</span></div>
                                    <div className="flex justify-between"><span className="text-foreground-muted">Source</span><span className="text-foreground-muted">{ipRouteResult.source}</span></div>
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Nigerian ISP reference table */}
                    <div className="bg-card border border-border rounded-xl overflow-hidden">
                        <div className="px-4 py-3 border-b border-border flex items-center gap-2">
                            <Building size={14} className="text-purple" />
                            <h3 className="font-bold text-sm text-foreground">Nigerian ISP Reference</h3>
                        </div>
                        <div className="divide-y divide-border">
                            {NIGERIAN_ISPS.map((isp) => (
                                <button key={isp.asn} onClick={() => { setAsnInput(isp.asn); void lookupAsnFor(isp.asn); }}
                                    className="w-full flex items-center justify-between px-4 py-2.5 text-left hover:bg-card-muted transition-colors">
                                    <span className="text-sm font-medium text-foreground">{isp.name}</span>
                                    <span className="flex items-center gap-2">
                                        <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded-full uppercase ${isp.registry === 'AFRINIC' ? 'bg-green/10 text-green' : 'bg-blue/10 text-blue'}`}>{isp.registry}</span>
                                        <span className="text-xs font-mono text-blue">{isp.asn}</span>
                                    </span>
                                </button>
                            ))}
                        </div>
                    </div>
                </div>
            )}

            {/* Add IOC modal */}
            {showAddIoc && (
                <div className="fixed inset-0 bg-black/40 z-50 flex items-center justify-center p-4" onClick={() => setShowAddIoc(false)}>
                    <div className="bg-card border border-border rounded-xl p-6 max-w-md w-full" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-between mb-4">
                            <h3 className="font-heading font-semibold text-sm text-foreground">Add IOC to Watchlist</h3>
                            <button onClick={() => setShowAddIoc(false)} className="text-foreground-muted hover:text-foreground"><X size={16} /></button>
                        </div>
                        <div className="space-y-3">
                            <div>
                                <label className="text-xs font-medium text-foreground-muted uppercase tracking-wide">Value</label>
                                <input value={newIoc.value} onChange={(e) => setNewIoc((n) => ({ ...n, value: e.target.value }))} placeholder="185.220.101.47"
                                    className="w-full mt-1 border border-border bg-card-muted rounded-lg px-3 py-2 text-sm font-mono focus:outline-none focus:border-purple text-foreground" />
                            </div>
                            <div className="grid grid-cols-2 gap-3">
                                <div>
                                    <label className="text-xs font-medium text-foreground-muted uppercase tracking-wide">Type</label>
                                    <select value={newIoc.type} onChange={(e) => setNewIoc((n) => ({ ...n, type: e.target.value as OrgIOCType }))}
                                        className="w-full mt-1 border border-border bg-card-muted rounded-lg px-3 py-2 text-sm focus:outline-none text-foreground">
                                        {(['ip', 'domain', 'hash', 'url', 'email'] as const).map((t) => <option key={t} value={t}>{t.toUpperCase()}</option>)}
                                    </select>
                                </div>
                                <div>
                                    <label className="text-xs font-medium text-foreground-muted uppercase tracking-wide">Verdict</label>
                                    <select value={newIoc.verdict} onChange={(e) => setNewIoc((n) => ({ ...n, verdict: e.target.value as OrgVerdict }))}
                                        className="w-full mt-1 border border-border bg-card-muted rounded-lg px-3 py-2 text-sm focus:outline-none text-foreground">
                                        {(['unknown', 'suspicious', 'malicious', 'clean'] as const).map((v) => <option key={v} value={v}>{v.charAt(0).toUpperCase() + v.slice(1)}</option>)}
                                    </select>
                                </div>
                            </div>
                            <div>
                                <label className="text-xs font-medium text-foreground-muted uppercase tracking-wide">Tags (comma-separated)</label>
                                <input value={newIoc.tags} onChange={(e) => setNewIoc((n) => ({ ...n, tags: e.target.value }))} placeholder="c2, ransomware"
                                    className="w-full mt-1 border border-border bg-card-muted rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-purple text-foreground" />
                            </div>
                            <div>
                                <label className="text-xs font-medium text-foreground-muted uppercase tracking-wide">Notes</label>
                                <textarea value={newIoc.notes} onChange={(e) => setNewIoc((n) => ({ ...n, notes: e.target.value }))} rows={2}
                                    className="w-full mt-1 border border-border bg-card-muted rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-purple text-foreground resize-none" />
                            </div>
                            <label className="flex items-center gap-2 text-xs text-foreground-muted cursor-pointer">
                                <input type="checkbox" checked={newIoc.shared} onChange={(e) => setNewIoc((n) => ({ ...n, shared: e.target.checked }))} className="accent-purple" />
                                Share anonymously with NovrSOC community
                            </label>
                            <button onClick={addOrgIoc} disabled={!newIoc.value.trim()} className="w-full bg-orange hover:bg-orange-hover text-white text-sm font-bold py-2.5 rounded-lg disabled:opacity-50 transition-colors">
                                Add IOC
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
