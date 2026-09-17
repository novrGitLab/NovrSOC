'use client';

import { useState, useEffect } from 'react';
import { AlertTriangle, Shield, RefreshCw, ExternalLink, Server, Clock } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';

interface CVESummary {
    id: string;
    description: string;
    cvss_score: number;
    severity: string;
    published: string;
    is_kev: boolean;
    kev_due: string | null;
}

interface KEVEntry {
    cveID: string;
    vendorProject: string;
    product: string;
    vulnerabilityName: string;
    dateAdded: string;
    shortDescription: string;
    requiredAction: string;
    dueDate: string;
    knownRansomwareCampaignUse: string;
}

interface AssetVulnerability {
    id: number;
    cve_id: string;
    cvss_score: number | null;
    severity: string | null;
    priority_score: number;
    detected_at: string;
    host_packages: { agent_id: string; agent_name: string | null; package_name: string; version: string | null; os: string | null } | null;
}

const SEVERITY_CONFIG: Record<string, { color: string; bg: string; border: string }> = {
    CRITICAL: { color: 'text-red-500', bg: 'bg-red-500/10', border: 'border-red-500/30' },
    HIGH: { color: 'text-red-500', bg: 'bg-red-500/5', border: 'border-red-500/20' },
    MEDIUM: { color: 'text-amber', bg: 'bg-grey-100', border: 'border-amber/30' },
    LOW: { color: 'text-blue', bg: 'bg-blue/10', border: 'border-blue/30' },
};

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

// Sector filter. Maps a sector to the vendor/product keywords that show up in NVD CVE
// descriptions for software that sector actually runs. This is a keyword heuristic over free
// text, NOT an authoritative product taxonomy — it narrows a 30-day CVE firehose to what is
// plausibly relevant, and the UI says so rather than implying certified sector mapping. A CVE
// matching no keyword is shown under 'All' only.
const SECTOR_KEYWORDS: Record<string, string[]> = {
    Banking: ['oracle', 'sap', 'finacle', 'temenos', 'swift', 'jack henry', 'fiserv', 'core banking'],
    Telecom: ['cisco', 'juniper', 'nokia', 'ericsson', 'huawei', 'mikrotik', 'zyxel', 'asterisk'],
    Government: ['sharepoint', 'exchange', 'active directory', 'citrix', 'fortinet', 'ivanti'],
    Healthcare: ['dicom', 'hl7', 'epic', 'cerner', 'philips', 'ge healthcare', 'medtronic'],
    Energy: ['scada', 'modbus', 'siemens', 'schneider', 'rockwell', 'iec 61850', 'plc'],
    Fintech: ['stripe', 'paystack', 'flutterwave', 'node.js', 'postgres', 'redis', 'kubernetes'],
    Education: ['moodle', 'canvas', 'blackboard', 'wordpress', 'drupal'],
};
const SECTORS = ['All', ...Object.keys(SECTOR_KEYWORDS)];

const TABS = [
    { id: 'recent', label: 'Recent CVEs' },
    { id: 'kev', label: 'Known Exploited Vulnerabilities' },
    { id: 'assets', label: 'Asset Vulnerabilities' },
] as const;
type Tab = (typeof TABS)[number]['id'];

function cvssColor(score: number): string {
    return score >= 9.0 ? 'text-red-500' : score >= 7.0 ? 'text-red-500' : score >= 4.0 ? 'text-amber' : 'text-blue';
}
function cvssBarColor(score: number): string {
    return score >= 9.0 ? 'bg-red-500' : score >= 7.0 ? 'bg-red-500' : score >= 4.0 ? 'bg-amber' : 'bg-blue';
}

export function ThreatAdvisory() {
    const [activeTab, setActiveTab] = useState<Tab>('recent');
    const [recentCVEs, setRecentCVEs] = useState<CVESummary[]>([]);
    const [kevEntries, setKevEntries] = useState<KEVEntry[]>([]);
    const [assets, setAssets] = useState<AssetVulnerability[]>([]);
    const [assetsLoaded, setAssetsLoaded] = useState(false);
    const [loading, setLoading] = useState(false);
    const [severityFilter, setSeverityFilter] = useState<string>('ALL');
    const [kevInfo, setKevInfo] = useState<{ count: number; released: string } | null>(null);
    const [selectedCVE, setSelectedCVE] = useState<CVESummary | null>(null);
    // A rolling window, not a calendar period ("This Week" is the last 7 days, not
    // Mon-today) — 90 for "All Time" rather than truly unbounded because the NVD API this
    // hits (services/nvd.ts's getRecentCVEs) rejects a pubStartDate/pubEndDate range wider
    // than 120 days; 90 leaves margin. Both this and severityFilter ride the same request
    // (see loadRecent below), so they already apply as AND, not two separate client-side passes.
    // 30 days, not 7: a week of NVD publications is a thin view for an advisory page, and the
    // sector filter below needs enough volume to be useful after narrowing.
    const [days, setDays] = useState(30);
    const [sector, setSector] = useState('All');
    // { [cve]: agentNames[] } from GET /api/threat/advisory/affected-agents — which of THIS
    // estate's agents actually carry each CVE, per Wazuh's own vulnerability index.
    const [affectedAgents, setAffectedAgents] = useState<Record<string, string[]>>({});

    const loadRecent = () => {
        setLoading(true);
        const params = new URLSearchParams({ days: String(days) });
        if (severityFilter !== 'ALL') params.set('severity', severityFilter);
        apiFetch(apiUrl(`/api/threat/advisory/recent?${params}`), { cache: 'no-store' })
            .then((r) => r.json())
            .then((data) => setRecentCVEs(Array.isArray(data?.cves) ? data.cves : []))
            .catch(() => setRecentCVEs([]))
            .finally(() => setLoading(false));
    };

    const loadKEV = () => {
        setLoading(true);
        apiFetch(apiUrl('/api/threat/advisory/kev'), { cache: 'no-store' })
            .then((r) => r.json())
            .then((data) => {
                setKevEntries(Array.isArray(data?.recent) ? data.recent : []);
                setKevInfo(data?.count !== undefined ? { count: data.count, released: data.released } : null);
            })
            .catch(() => setKevEntries([]))
            .finally(() => setLoading(false));
    };

    const loadAssets = () => {
        setLoading(true);
        apiFetch(apiUrl('/api/threat/advisory/assets'), { cache: 'no-store' })
            .then((r) => r.json())
            .then((data) => setAssets(Array.isArray(data?.assets) ? data.assets : []))
            .catch(() => setAssets([]))
            .finally(() => { setLoading(false); setAssetsLoaded(true); });
    };

    useEffect(() => {
        apiFetch(apiUrl('/api/threat/advisory/affected-agents'), { cache: 'no-store' })
            .then((r) => r.json())
            .then((d) => setAffectedAgents(d?.affected && typeof d.affected === 'object' ? d.affected : {}))
            .catch(() => setAffectedAgents({}));
    }, []);

    useEffect(() => {
        if (activeTab === 'recent') loadRecent();
        if (activeTab === 'kev') loadKEV();
        if (activeTab === 'assets' && !assetsLoaded) loadAssets();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [activeTab, severityFilter, days]);

    const stats = {
        critical: recentCVEs.filter((c) => c.severity === 'CRITICAL').length,
        high: recentCVEs.filter((c) => c.severity === 'HIGH').length,
        kev: recentCVEs.filter((c) => c.is_kev).length,
        total: recentCVEs.length,
    };

    return (
        <div className="space-y-4">
            <div className="flex items-start justify-between">
                <div>
                    <h1 className="text-lg font-black text-foreground">Threat Advisory</h1>
                    <p className="text-xs text-foreground-muted">Threat Intelligence · CVE vulnerabilities prioritised by CVSS score and CISA Known Exploited status</p>
                </div>
                <button
                    onClick={() => (activeTab === 'recent' ? loadRecent() : activeTab === 'kev' ? loadKEV() : loadAssets())}
                    className="flex items-center gap-2 border border-blue text-blue text-xs font-bold px-4 py-2 rounded-lg hover:bg-blue/10 transition-colors flex-shrink-0"
                >
                    <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
                    Refresh
                </button>
            </div>

            {/* Stats */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {[
                    { label: 'Total CVEs', value: stats.total, border: 'border-t-blue' },
                    { label: 'Critical', value: stats.critical, border: 'border-t-red-500' },
                    { label: 'High', value: stats.high, border: 'border-t-amber' },
                    { label: 'Actively Exploited', value: stats.kev, border: 'border-t-red-500', pulse: true },
                ].map((stat) => (
                    <div key={stat.label} className={`bg-card border border-border rounded-xl p-4 border-t-4 ${stat.border}`}>
                        <div className="flex items-center gap-1.5 mb-1">
                            <span className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">{stat.label}</span>
                            {stat.pulse && stat.value > 0 && <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" />}
                        </div>
                        <div className="font-heading font-black text-2xl text-foreground">{stat.value}</div>
                    </div>
                ))}
            </div>

            {/* Tabs */}
            <div className="flex gap-1 border-b border-border">
                {TABS.map((tab) => (
                    <button
                        key={tab.id}
                        onClick={() => setActiveTab(tab.id)}
                        className={`px-4 py-2.5 text-xs font-bold border-b-2 transition-colors ${
                            activeTab === tab.id ? 'border-blue text-blue' : 'border-transparent text-foreground-muted hover:text-foreground'
                        }`}
                    >
                        {tab.label}
                    </button>
                ))}
            </div>

            {/* ── RECENT CVEs ── */}
            {activeTab === 'recent' && (
                <div>
                    <div className="flex items-center gap-3 mb-4 flex-wrap">
                        <div className="flex gap-1 bg-card-muted rounded-lg p-1 overflow-x-auto">
                            {['ALL', ...SEVERITY_ORDER].map((s) => (
                                <button
                                    key={s}
                                    onClick={() => setSeverityFilter(s)}
                                    className={`px-3 py-1.5 rounded-md text-xs font-medium whitespace-nowrap transition-colors ${
                                        severityFilter === s ? 'bg-card text-blue shadow-sm border border-border' : 'text-foreground-muted hover:text-foreground'
                                    }`}
                                >
                                    {s}
                                </button>
                            ))}
                        </div>

                        {/* Sector filter — narrows the feed by vendor/product keywords that
                            appear in the CVE text. Keyword-based, so it is a relevance aid, not
                            an authoritative sector classification. */}
                        <select
                            value={sector}
                            onChange={(e) => setSector(e.target.value)}
                            aria-label="Filter CVEs by sector"
                            title="Keyword-based relevance filter, not an authoritative sector mapping"
                            className="bg-card border border-border rounded-lg px-2.5 py-1.5 text-xs font-bold text-foreground focus:outline-none"
                        >
                            {SECTORS.map((sec) => (
                                <option key={sec} value={sec}>{sec === 'All' ? 'All sectors' : sec}</option>
                            ))}
                        </select>

                        <div className="flex items-center gap-2 md:ml-auto text-xs text-foreground-muted">
                            <Clock size={12} />
                            {[
                                { label: 'Today', d: 1 },
                                { label: 'This Week', d: 7 },
                                { label: 'This Month', d: 30 },
                                { label: 'All Time', d: 90 },
                            ].map(({ label, d }) => (
                                <button
                                    key={d}
                                    onClick={() => setDays(d)}
                                    className={`px-2 py-1 rounded whitespace-nowrap ${days === d ? 'bg-blue text-white' : 'hover:bg-card-muted text-foreground-muted'}`}
                                >
                                    {label}
                                </button>
                            ))}
                        </div>
                    </div>

                    {loading ? (
                        <div className="flex items-center justify-center py-20">
                            <RefreshCw size={24} className="animate-spin text-blue" />
                        </div>
                    ) : recentCVEs.length === 0 ? (
                        <div className="bg-card border border-border rounded-xl p-12 text-center">
                            <Shield size={40} className="text-border mx-auto mb-3" />
                            <div className="text-sm text-foreground-muted">No CVEs found for selected filters</div>
                        </div>
                    ) : (
                        <div className="space-y-2">
                            {recentCVEs.filter((cve) => {
                                if (sector === 'All') return true;
                                const keywords = SECTOR_KEYWORDS[sector] ?? [];
                                const haystack = `${cve.id} ${cve.description}`.toLowerCase();
                                return keywords.some((k) => haystack.includes(k));
                            }).map((cve) => {
                                const cfg = SEVERITY_CONFIG[cve.severity] || SEVERITY_CONFIG.LOW;
                                return (
                                    <div
                                        key={cve.id}
                                        onClick={() => setSelectedCVE(selectedCVE?.id === cve.id ? null : cve)}
                                        className={`bg-card border rounded-xl p-4 cursor-pointer hover:shadow-sm transition-all ${
                                            cve.is_kev ? 'border-red-500/40' : 'border-border'
                                        } ${selectedCVE?.id === cve.id ? 'ring-2 ring-blue/20' : ''}`}
                                    >
                                        <div className="flex items-start justify-between gap-3">
                                            <div className="flex items-start gap-3 flex-1 min-w-0">
                                                <span className={`text-[10px] font-bold px-2 py-0.5 rounded flex-shrink-0 mt-0.5 border ${cfg.bg} ${cfg.color} ${cfg.border}`}>
                                                    {cve.severity}
                                                </span>
                                                <div className="flex-1 min-w-0">
                                                    <div className="flex items-center gap-2 flex-wrap">
                                                        <span className="font-mono font-bold text-sm text-blue">{cve.id}</span>
                                                        {(affectedAgents[cve.id]?.length ?? 0) > 0 && (
                                                            <span
                                                                className="text-[10px] font-bold bg-red-500/10 text-red-500 border border-red-500/30 px-1.5 py-0.5 rounded"
                                                                title={affectedAgents[cve.id].join(', ')}
                                                            >
                                                                {affectedAgents[cve.id].length} agent{affectedAgents[cve.id].length === 1 ? '' : 's'} affected
                                                            </span>
                                                        )}
                                                        {cve.is_kev && (
                                                            <span className="text-[10px] font-bold bg-red-500 text-white px-1.5 py-0.5 rounded animate-pulse">
                                                                ACTIVELY EXPLOITED
                                                            </span>
                                                        )}
                                                    </div>
                                                    <p className="text-xs text-foreground-muted mt-1 line-clamp-2">{cve.description}</p>
                                                    {cve.is_kev && cve.kev_due && (
                                                        <div className="text-xs text-red-500 font-medium mt-1">⚠ CISA remediation due: {cve.kev_due}</div>
                                                    )}
                                                </div>
                                            </div>

                                            <div className="ml-2 text-right flex-shrink-0">
                                                <div className={`font-heading font-black text-xl ${cvssColor(cve.cvss_score)}`}>{cve.cvss_score.toFixed(1)}</div>
                                                <div className="text-[10px] text-foreground-muted">CVSS</div>
                                                <div className="w-16 h-1.5 bg-card-muted rounded-full mt-1 overflow-hidden">
                                                    <div className={`h-full rounded-full ${cvssBarColor(cve.cvss_score)}`} style={{ width: `${(cve.cvss_score / 10) * 100}%` }} />
                                                </div>
                                            </div>
                                        </div>

                                        {selectedCVE?.id === cve.id && (
                                            <div className="mt-4 pt-4 border-t border-border flex items-center gap-3 flex-wrap">
                                                <a
                                                    href={`https://nvd.nist.gov/vuln/detail/${cve.id}`}
                                                    target="_blank" rel="noopener noreferrer"
                                                    onClick={(e) => e.stopPropagation()}
                                                    className="flex items-center gap-1 text-xs text-blue hover:text-purple"
                                                >
                                                    View Vulnerability Details <ExternalLink size={11} />
                                                </a>
                                                {cve.is_kev && (
                                                    <a
                                                        href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                                                        target="_blank" rel="noopener noreferrer"
                                                        onClick={(e) => e.stopPropagation()}
                                                        className="flex items-center gap-1 text-xs text-red-500 hover:text-red-hover"
                                                    >
                                                        View Known Exploited Vulnerabilities entry <ExternalLink size={11} />
                                                    </a>
                                                )}
                                                <button onClick={(e) => e.stopPropagation()} className="ml-auto text-xs bg-orange hover:bg-orange-hover text-white px-3 py-1.5 rounded-lg transition-colors">
                                                    Create Ticket
                                                </button>
                                                <button onClick={(e) => e.stopPropagation()} className="text-xs border border-border text-foreground-muted px-3 py-1.5 rounded-lg hover:border-grey-300 transition-colors">
                                                    Mark Patched
                                                </button>
                                            </div>
                                        )}
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </div>
            )}

            {/* ── KEV CATALOG ── */}
            {activeTab === 'kev' && (
                <div>
                    {kevInfo && (
                        <div className="bg-red-500/5 border border-red-500/20 rounded-xl p-4 mb-4 flex items-center gap-3">
                            <AlertTriangle size={18} className="text-red-500 flex-shrink-0" />
                            <div>
                                <div className="text-sm font-semibold text-foreground">{kevInfo.count.toLocaleString()} Known Exploited Vulnerabilities</div>
                                <div className="text-xs text-foreground-muted">
                                    CISA catalog · Last updated {new Date(kevInfo.released).toLocaleDateString()} · Mandatory remediation for US federal agencies
                                </div>
                            </div>
                        </div>
                    )}

                    {loading ? (
                        <div className="flex items-center justify-center py-20">
                            <RefreshCw size={24} className="animate-spin text-blue" />
                        </div>
                    ) : kevEntries.length === 0 ? (
                        <div className="bg-card border border-border rounded-xl p-12 text-center">
                            <Shield size={40} className="text-border mx-auto mb-3" />
                            <div className="text-sm text-foreground-muted">KEV catalog unavailable right now</div>
                        </div>
                    ) : (
                        <div className="bg-card border border-border rounded-xl overflow-hidden overflow-x-auto">
                            <table className="w-full text-xs">
                                <thead>
                                    <tr className="border-b border-border">
                                        {['CVE ID', 'Vendor / Product', 'Vulnerability', 'Date Added', 'Due Date', 'Ransomware'].map((h) => (
                                            <th key={h} className="text-left px-4 py-2.5 text-[10px] font-bold text-foreground-muted uppercase tracking-wider">{h}</th>
                                        ))}
                                    </tr>
                                </thead>
                                <tbody>
                                    {kevEntries.map((entry) => (
                                        <tr key={entry.cveID} className="border-b border-border hover:bg-card-muted transition-colors">
                                            <td className="px-4 py-2.5">
                                                <a href={`https://nvd.nist.gov/vuln/detail/${entry.cveID}`} target="_blank" rel="noopener noreferrer" className="font-mono text-blue hover:text-purple font-bold">
                                                    {entry.cveID}
                                                </a>
                                            </td>
                                            <td className="px-4 py-2.5 text-foreground">
                                                <div className="font-medium">{entry.vendorProject}</div>
                                                <div className="text-foreground-muted">{entry.product}</div>
                                            </td>
                                            <td className="px-4 py-2.5 text-foreground-muted max-w-[200px]">
                                                <div className="line-clamp-2">{entry.vulnerabilityName}</div>
                                            </td>
                                            <td className="px-4 py-2.5 text-foreground-muted whitespace-nowrap">{entry.dateAdded}</td>
                                            <td className="px-4 py-2.5 whitespace-nowrap">
                                                <span className={`font-medium ${new Date(entry.dueDate) < new Date() ? 'text-red-500' : 'text-foreground-muted'}`}>
                                                    {entry.dueDate}
                                                    {new Date(entry.dueDate) < new Date() && ' ⚠ OVERDUE'}
                                                </span>
                                            </td>
                                            <td className="px-4 py-2.5">
                                                {entry.knownRansomwareCampaignUse === 'Known' ? (
                                                    <span className="text-[10px] font-bold bg-red-500 text-white px-1.5 py-0.5 rounded">RANSOMWARE</span>
                                                ) : (
                                                    <span className="text-foreground-muted">—</span>
                                                )}
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </div>
            )}

            {/* ── ASSET VULNERABILITIES ── */}
            {activeTab === 'assets' && (
                loading ? (
                    <div className="flex items-center justify-center py-20">
                        <RefreshCw size={24} className="animate-spin text-blue" />
                    </div>
                ) : assets.length === 0 ? (
                    <div className="bg-card border border-border rounded-xl p-10 text-center">
                        <Server size={40} className="text-border mx-auto mb-3" />
                        <div className="font-heading font-semibold text-foreground mb-1">Asset Vulnerability Mapping</div>
                        <div className="text-sm text-foreground-muted max-w-sm mx-auto">
                            Connect Wazuh agents to automatically map CVEs to your installed software.
                            Once configured, vulnerable packages appear here ranked by exploitability and asset criticality.
                        </div>
                    </div>
                ) : (
                    <div className="bg-card border border-border rounded-xl overflow-hidden overflow-x-auto">
                        <table className="w-full text-xs">
                            <thead>
                                <tr className="border-b border-border">
                                    {['CVE', 'Host', 'Package', 'Version', 'OS', 'CVSS', 'Detected'].map((h) => (
                                        <th key={h} className="text-left px-4 py-2.5 text-[10px] font-bold text-foreground-muted uppercase tracking-wider">{h}</th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody>
                                {assets.map((a) => (
                                    <tr key={a.id} className="border-b border-border hover:bg-card-muted transition-colors">
                                        <td className="px-4 py-2.5">
                                            <a href={`https://nvd.nist.gov/vuln/detail/${a.cve_id}`} target="_blank" rel="noopener noreferrer" className="font-mono text-blue hover:text-purple font-bold">{a.cve_id}</a>
                                        </td>
                                        <td className="px-4 py-2.5 text-foreground">{a.host_packages?.agent_name ?? a.host_packages?.agent_id ?? '—'}</td>
                                        <td className="px-4 py-2.5 text-foreground-muted">{a.host_packages?.package_name ?? '—'}</td>
                                        <td className="px-4 py-2.5 text-foreground-muted font-mono">{a.host_packages?.version ?? '—'}</td>
                                        <td className="px-4 py-2.5 text-foreground-muted">{a.host_packages?.os ?? '—'}</td>
                                        <td className="px-4 py-2.5">
                                            {a.cvss_score !== null ? <span className={`font-bold ${cvssColor(a.cvss_score)}`}>{a.cvss_score.toFixed(1)}</span> : <span className="text-foreground-muted">—</span>}
                                        </td>
                                        <td className="px-4 py-2.5 text-foreground-muted whitespace-nowrap">{new Date(a.detected_at).toLocaleDateString()}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )
            )}
        </div>
    );
}
