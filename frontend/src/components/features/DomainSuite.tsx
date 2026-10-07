'use client';

import { useEffect, useState } from 'react';
import {
    Globe,
    Plus,
    RefreshCw,
    Trash2,
    X,
    Loader2,
    AlertTriangle,
    Shield,
    ShieldCheck,
    ShieldAlert,
    ExternalLink,
    ChevronDown,
    ChevronUp,
    Copy,
    Check,
    Lock,
    Mail,
    Server,
    FileText,
    History,
    Search,
} from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { EmptyState } from '@/components/shared/EmptyState';
import { ExportButton } from '@/components/shared/ExportButton';

interface DomainAlerts {
    lookalike: boolean;
    dns_change: boolean;
    expiry: boolean;
    new_cert: boolean;
}

interface WhoisInfo {
    registrar: string;
    created: string | null;
    expires: string | null;
    nameservers: string[];
    daysUntilExpiry: number | null;
}

interface CertRow {
    domain: string;
    issuer: string;
    not_before: string;
    not_after: string;
    suspicious: boolean;
}

interface Lookalike {
    domain: string;
    // null for pattern-generated candidates: they are not scored or checked for registration.
    similarity: number | null;
    risk: 'HIGH' | 'MEDIUM' | 'LOW' | null;
    registered?: string;
}

interface DomainAlertEvent {
    type: string;
    message: string;
    severity: 'HIGH' | 'MEDIUM' | 'LOW';
    time: string;
}

interface DnsRecord {
    type: string;
    name: string;
    value: string;
    ttl: number;
}

interface LastScan {
    scanned_at: string;
    whois: WhoisInfo | null;
    ssl_grade: string | null;
    ct_logs: CertRow[];
    lookalikes: Lookalike[];
    dns_records: DnsRecord[];
    email_security: { spf: boolean; dmarc: boolean; dkim: boolean } | null;
    alert_history: DomainAlertEvent[];
}

interface MonitoredDomain {
    id: string;
    domain: string;
    brand_keywords: string[];
    similarity_threshold: number;
    alerts: DomainAlerts;
    status: 'active';
    added_at: string;
    last_scan: LastScan | null;
}

interface ScanResult {
    domain: string;
    scanned_at: string;
    whois: WhoisInfo | null;
    ct_logs: CertRow[];
    lookalikes: Lookalike[];
}

interface DnsResult {
    domain: string;
    records: DnsRecord[];
    email_security: { spf: boolean; dmarc: boolean; dkim: boolean };
    checked_at: string;
}

const RISK_BADGE: Record<NonNullable<Lookalike['risk']>, string> = {
    HIGH: 'bg-red-500/15 text-red-500 border-red-500/30',
    MEDIUM: 'bg-amber-500/15 text-amber-500 border-amber-500/30',
    LOW: 'bg-slate-500/10 text-foreground-muted border-border',
};

const DNS_TYPES = ['A', 'MX', 'TXT', 'NS'] as const;
type DetailTab = 'overview' | 'lookalikes' | 'certs' | 'dns' | 'alerts';

function HealthBadge({ ok, label }: { ok: boolean | null; label: string }) {
    if (ok === null) {
        return (
            <span className="inline-flex items-center gap-1 text-[11px] font-semibold px-2.5 py-0.5 rounded-full border bg-card-muted/50 text-foreground-muted border-border">
                <span className="w-1.5 h-1.5 rounded-full bg-foreground-muted/40" />
                {label}: —
            </span>
        );
    }
    return (
        <span
            className={`inline-flex items-center gap-1 text-[11px] font-semibold px-2.5 py-0.5 rounded-full border transition-all ${
                ok
                    ? 'bg-emerald-500/10 text-emerald-500 border-emerald-500/30'
                    : 'bg-red-500/10 text-red-500 border-red-500/30'
            }`}
        >
            <span className={`w-1.5 h-1.5 rounded-full ${ok ? 'bg-emerald-500' : 'bg-red-500'}`} />
            {label}
        </span>
    );
}

export function DomainSuite() {
    const [domains, setDomains] = useState<MonitoredDomain[]>([]);
    const [loading, setLoading] = useState(true);
    const [showAddModal, setShowAddModal] = useState(false);

    // Add-domain form state
    const [domainInput, setDomainInput] = useState('');
    const [keywordInput, setKeywordInput] = useState('');
    const [keywords, setKeywords] = useState<string[]>([]);
    const [threshold, setThreshold] = useState(80);
    const [alerts, setAlerts] = useState<DomainAlerts>({ lookalike: true, dns_change: true, expiry: true, new_cert: true });
    const [saving, setSaving] = useState(false);

    // Scan / DNS state
    const [scanningId, setScanningId] = useState<string | null>(null);
    const [scanResults, setScanResults] = useState<Record<string, ScanResult>>({});
    const [dnsLoadingId, setDnsLoadingId] = useState<string | null>(null);
    const [dnsResults, setDnsResults] = useState<Record<string, DnsResult>>({});

    // UI state
    const [expanded, setExpanded] = useState<Set<string>>(new Set());
    const [activeTabs, setActiveTabs] = useState<Record<string, DetailTab>>({});
    const [dnsTab, setDnsTab] = useState<(typeof DNS_TYPES)[number]>('A');
    const [copiedDomain, setCopiedDomain] = useState<string | null>(null);

    const load = () => {
        setLoading(true);
        apiFetch(apiUrl('/api/brand/domains'), { cache: 'no-store' })
            .then((r) => r.json())
            .then((data) => {
                const list: MonitoredDomain[] = Array.isArray(data?.domains) ? data.domains : [];
                setDomains(list);
                setExpanded(new Set(list.map((d) => d.id)));
                const defaultTabs: Record<string, DetailTab> = {};
                list.forEach((d) => {
                    defaultTabs[d.id] = 'overview';
                });
                setActiveTabs(defaultTabs);
            })
            .catch(() => setDomains([]))
            .finally(() => setLoading(false));
    };

    useEffect(load, []);

    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text);
        setCopiedDomain(text);
        setTimeout(() => setCopiedDomain(null), 2000);
    };

    const addKeyword = () => {
        const v = keywordInput.trim().toLowerCase();
        if (v && !keywords.includes(v)) setKeywords([...keywords, v]);
        setKeywordInput('');
    };

    const resetForm = () => {
        setDomainInput('');
        setKeywordInput('');
        setKeywords([]);
        setThreshold(80);
        setAlerts({ lookalike: true, dns_change: true, expiry: true, new_cert: true });
    };

    const addDomain = async () => {
        const cleaned = domainInput.trim().replace(/^https?:\/\//, '').replace(/\/$/, '');
        if (!cleaned) return;
        setSaving(true);
        try {
            const res = await apiFetch(apiUrl('/api/brand/domains'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain: cleaned, brand_keywords: keywords, similarity_threshold: threshold, alerts }),
            });
            if (res.ok) {
                resetForm();
                setShowAddModal(false);
                load();
            }
        } finally {
            setSaving(false);
        }
    };

    const removeDomain = async (id: string) => {
        await apiFetch(apiUrl(`/api/brand/domains/${id}`), { method: 'DELETE' });
        setDomains((prev) => prev.filter((d) => d.id !== id));
    };

    const runScan = async (id: string) => {
        setScanningId(id);
        try {
            const res = await apiFetch(apiUrl(`/api/brand/domains/${id}/scan`));
            const data = await res.json();
            setScanResults((prev) => ({ ...prev, [id]: data }));
            setExpanded((prev) => new Set(prev).add(id));
        } finally {
            setScanningId(null);
        }
    };

    const viewDns = async (id: string) => {
        setDnsLoadingId(id);
        try {
            const res = await apiFetch(apiUrl(`/api/brand/domains/${id}/dns`));
            const data = await res.json();
            setDnsResults((prev) => ({ ...prev, [id]: data }));
            setExpanded((prev) => new Set(prev).add(id));
            setActiveTabs((prev) => ({ ...prev, [id]: 'dns' }));
        } finally {
            setDnsLoadingId(null);
        }
    };

    const toggleExpanded = (id: string) => {
        setExpanded((prev) => {
            const next = new Set(prev);
            if (next.has(id)) next.delete(id);
            else next.add(id);
            return next;
        });
    };

    const setTabForDomain = (domainId: string, tab: DetailTab) => {
        setActiveTabs((prev) => ({ ...prev, [domainId]: tab }));
    };

    const viewFor = (d: MonitoredDomain) => {
        const liveScan = scanResults[d.id];
        const liveDns = dnsResults[d.id];
        return {
            whois: liveScan?.whois ?? d.last_scan?.whois ?? null,
            ct_logs: liveScan?.ct_logs ?? d.last_scan?.ct_logs ?? [],
            lookalikes: liveScan?.lookalikes ?? d.last_scan?.lookalikes ?? [],
            scanned_at: liveScan?.scanned_at ?? d.last_scan?.scanned_at ?? null,
            dns_records: liveDns?.records ?? d.last_scan?.dns_records ?? [],
            email_security: liveDns?.email_security ?? d.last_scan?.email_security ?? null,
            ssl_grade: d.last_scan?.ssl_grade ?? null,
            alert_history: d.last_scan?.alert_history ?? [],
        };
    };

    const allViews = domains.map((d) => ({ domain: d.domain, ...viewFor(d) }));
    const totalLookalikes = allViews.reduce((sum, v) => sum + v.lookalikes.length, 0);
    const suspiciousCerts = allViews.reduce((sum, v) => sum + v.ct_logs.filter((c) => c.suspicious).length, 0);
    const dmarcIssues = allViews.filter((v) => v.email_security && !v.email_security.dmarc).length;
    const highAlerts = allViews.flatMap((v) => v.alert_history.filter((a) => a.severity === 'HIGH').map((a) => ({ ...a, domain: v.domain })));

    return (
        <div id="report-content" className="space-y-5 max-w-7xl mx-auto">
            {/* Page Header */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border pb-4">
                <div>
                    <div className="flex items-center gap-2.5">
                        <div className="w-8 h-8 rounded-lg bg-primary/10 flex items-center justify-center text-primary">
                            <Shield className="w-4 h-4 text-orange" />
                        </div>
                        <h1 className="text-xl font-bold tracking-tight text-foreground">Domain Suite</h1>
                    </div>
                    <p className="text-xs text-foreground-muted mt-1">
                        Brand Protection · Typosquatting detection, DNS telemetry, and SSL certificate transparency
                    </p>
                </div>
                <div className="flex items-center gap-2.5">
                    <ExportButton elementId="report-content" filename="domain-suite" title="Domain Suite" />
                    <button
                        onClick={() => setShowAddModal(true)}
                        className="flex items-center gap-2 bg-orange hover:bg-orange-hover text-white text-xs font-semibold px-4 py-2 rounded-lg shadow-sm transition-all active:scale-[0.98]"
                    >
                        <Plus size={15} />
                        Add Domain
                    </button>
                </div>
            </div>

            {!loading && domains.length > 0 && (
                <div className="space-y-4">
                    {/* Summary Metric Cards */}
                    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3.5">
                        <div className="bg-card border border-border rounded-xl p-4 flex items-center justify-between shadow-xs">
                            <div>
                                <p className="text-[11px] font-semibold text-foreground-muted uppercase tracking-wider">Monitored Domains</p>
                                <p className="text-2xl font-black text-foreground mt-1">{domains.length}</p>
                            </div>
                            <div className="w-10 h-10 rounded-xl bg-blue/10 flex items-center justify-center text-blue">
                                <Globe size={20} />
                            </div>
                        </div>

                        <div className="bg-card border border-border rounded-xl p-4 flex items-center justify-between shadow-xs">
                            <div>
                                <p className="text-[11px] font-semibold text-foreground-muted uppercase tracking-wider">Lookalike Threats</p>
                                <p className="text-2xl font-black text-red-500 mt-1">{totalLookalikes}</p>
                            </div>
                            <div className="w-10 h-10 rounded-xl bg-red-500/10 flex items-center justify-center text-red-500">
                                <ShieldAlert size={20} />
                            </div>
                        </div>

                        <div className="bg-card border border-border rounded-xl p-4 flex items-center justify-between shadow-xs">
                            <div>
                                <p className="text-[11px] font-semibold text-foreground-muted uppercase tracking-wider">Suspicious Certs</p>
                                <p className="text-2xl font-black text-amber-500 mt-1">{suspiciousCerts}</p>
                            </div>
                            <div className="w-10 h-10 rounded-xl bg-amber-500/10 flex items-center justify-center text-amber-500">
                                <Lock size={20} />
                            </div>
                        </div>

                        <div className="bg-card border border-border rounded-xl p-4 flex items-center justify-between shadow-xs">
                            <div>
                                <p className="text-[11px] font-semibold text-foreground-muted uppercase tracking-wider">DMARC Vulnerabilities</p>
                                <p className="text-2xl font-black text-purple mt-1">{dmarcIssues}</p>
                            </div>
                            <div className="w-10 h-10 rounded-xl bg-purple/10 flex items-center justify-center text-purple">
                                <Mail size={20} />
                            </div>
                        </div>
                    </div>

                    {/* Active Alert Banner */}
                    {highAlerts.length > 0 && (
                        <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-3.5 space-y-2">
                            <div className="flex items-center gap-2">
                                <AlertTriangle size={15} className="text-red-500 flex-shrink-0" />
                                <span className="text-xs font-bold text-red-500 uppercase tracking-wide">High Priority Domain Alerts</span>
                            </div>
                            <div className="space-y-1.5 pl-6">
                                {highAlerts.map((a, i) => (
                                    <div key={i} className="flex items-start gap-2 text-xs">
                                        <span className="text-red-500 font-mono font-semibold">{a.domain}:</span>
                                        <span className="text-foreground-muted">{a.message}</span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                </div>
            )}

            {/* Main Content Area */}
            {loading ? (
                <div className="space-y-3.5">
                    {Array.from({ length: 3 }).map((_, i) => (
                        <div key={i} className="h-32 bg-card-muted/60 border border-border rounded-xl animate-pulse" />
                    ))}
                </div>
            ) : domains.length === 0 ? (
                <EmptyState
                    icon={Globe}
                    title="No domains monitored yet"
                    description="Add your brand domain to start continuous monitoring for typosquatting, DNS spoofing, and unauthorized SSL certificates."
                    actionLabel="Add Your First Domain"
                    onAction={() => setShowAddModal(true)}
                />
            ) : (
                <div className="space-y-4">
                    {domains.map((d) => {
                        const view = viewFor(d);
                        const isOpen = expanded.has(d.id);
                        const activeTab = activeTabs[d.id] || 'overview';

                        return (
                            <div key={d.id} className="bg-card border border-border rounded-xl shadow-xs overflow-hidden transition-all">
                                {/* Domain Header */}
                                <div className="p-4 sm:p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
                                    <div className="flex items-start gap-3.5 min-w-0">
                                        <div className="w-11 h-11 rounded-xl bg-primary/10 flex items-center justify-center flex-shrink-0 border border-border">
                                            <Globe size={20} className="text-blue" />
                                        </div>

                                        <div className="min-w-0 space-y-1">
                                            <div className="flex items-center gap-2.5 flex-wrap">
                                                <span className="text-base font-bold text-foreground font-mono tracking-tight">{d.domain}</span>
                                                <button
                                                    onClick={() => copyToClipboard(d.domain)}
                                                    className="text-foreground-muted hover:text-foreground transition-colors"
                                                    title="Copy domain"
                                                >
                                                    {copiedDomain === d.domain ? <Check size={13} className="text-emerald-500" /> : <Copy size={13} />}
                                                </button>
                                                <span className="inline-flex items-center gap-1.5 text-[11px] font-semibold text-emerald-500 bg-emerald-500/10 border border-emerald-500/20 px-2 py-0.5 rounded-full">
                                                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                                                    Active
                                                </span>
                                            </div>

                                            <p className="text-xs text-foreground-muted truncate">
                                                Keywords: <span className="text-foreground font-medium">{d.brand_keywords.join(', ') || 'None'}</span>
                                                {' · '}Threshold: <span className="text-foreground font-medium">{d.similarity_threshold}%</span>
                                                {view.whois?.registrar && ` · ${view.whois.registrar}`}
                                                {view.whois?.expires && ` · Expires: ${view.whois.expires.slice(0, 10)}`}
                                            </p>

                                            {/* Security Health Strip */}
                                            <div className="flex flex-wrap items-center gap-1.5 pt-1">
                                                {view.ssl_grade ? (
                                                    <span className="inline-flex items-center gap-1 text-[11px] font-semibold px-2.5 py-0.5 rounded-full border bg-blue/10 text-blue border-blue/30">
                                                        <Lock size={10} /> SSL: {view.ssl_grade}
                                                    </span>
                                                ) : (
                                                    <span className="inline-flex items-center gap-1 text-[11px] font-semibold px-2.5 py-0.5 rounded-full border bg-card-muted/50 text-foreground-muted border-border">
                                                        <Lock size={10} /> SSL: —
                                                    </span>
                                                )}
                                                <HealthBadge ok={view.email_security?.spf ?? null} label="SPF" />
                                                <HealthBadge ok={view.email_security?.dmarc ?? null} label="DMARC" />
                                                <HealthBadge ok={view.email_security?.dkim ?? null} label="DKIM" />
                                            </div>
                                        </div>
                                    </div>

                                    {/* Action Buttons */}
                                    <div className="flex items-center gap-2 self-end md:self-center flex-shrink-0">
                                        <button
                                            onClick={() => runScan(d.id)}
                                            disabled={scanningId === d.id}
                                            className="flex items-center gap-1.5 text-xs font-semibold text-white bg-blue hover:bg-blue/90 rounded-lg px-3.5 py-2 transition-all disabled:opacity-50"
                                        >
                                            {scanningId === d.id ? <Loader2 size={13} className="animate-spin" /> : <RefreshCw size={13} />}
                                            {scanningId === d.id ? 'Scanning…' : 'Run Scan'}
                                        </button>

                                        <button
                                            onClick={() => viewDns(d.id)}
                                            disabled={dnsLoadingId === d.id}
                                            className="flex items-center gap-1.5 text-xs font-semibold text-foreground border border-border hover:bg-card-muted rounded-lg px-3 py-2 transition-colors disabled:opacity-50"
                                        >
                                            {dnsLoadingId === d.id ? <Loader2 size={13} className="animate-spin" /> : <Server size={13} />}
                                            View DNS
                                        </button>

                                        <button
                                            onClick={() => toggleExpanded(d.id)}
                                            className="flex items-center gap-1 text-xs font-semibold text-foreground-muted hover:text-foreground border border-border hover:bg-card-muted rounded-lg px-3 py-2 transition-colors"
                                        >
                                            {isOpen ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                                            {isOpen ? 'Collapse' : 'Details'}
                                        </button>

                                        <button
                                            onClick={() => removeDomain(d.id)}
                                            title="Delete domain"
                                            className="p-2 text-foreground-muted hover:text-red-500 hover:bg-red-500/10 border border-border hover:border-red-500/30 rounded-lg transition-colors"
                                        >
                                            <Trash2 size={14} />
                                        </button>
                                    </div>
                                </div>

                                {/* Expanded Detail Drawer with Sub-Tabs */}
                                {isOpen && (
                                    <div className="border-t border-border bg-card-muted/30">
                                        {/* Drawer Tabs */}
                                        <div className="flex items-center gap-1 px-4 pt-3 border-b border-border/80 overflow-x-auto">
                                            {[
                                                { id: 'overview', label: 'Overview & WHOIS', icon: FileText, count: null },
                                                { id: 'lookalikes', label: 'Lookalikes', icon: ShieldAlert, count: view.lookalikes.length },
                                                { id: 'certs', label: 'Cert Logs', icon: Lock, count: view.ct_logs.length },
                                                { id: 'dns', label: 'DNS & Email', icon: Server, count: view.dns_records.length },
                                                { id: 'alerts', label: 'Alert History', icon: History, count: view.alert_history.length },
                                            ].map((tab) => {
                                                const Icon = tab.icon;
                                                const active = activeTab === tab.id;
                                                return (
                                                    <button
                                                        key={tab.id}
                                                        onClick={() => setTabForDomain(d.id, tab.id as DetailTab)}
                                                        className={`flex items-center gap-2 text-xs font-semibold px-3.5 py-2 rounded-t-lg border-b-2 transition-all whitespace-nowrap ${
                                                            active
                                                                ? 'border-blue text-blue bg-card'
                                                                : 'border-transparent text-foreground-muted hover:text-foreground hover:bg-card/50'
                                                        }`}
                                                    >
                                                        <Icon size={14} />
                                                        {tab.label}
                                                        {tab.count !== null && (
                                                            <span className={`text-[10px] px-1.5 py-0.2 rounded-full font-bold ${active ? 'bg-blue/15 text-blue' : 'bg-card-muted text-foreground-muted'}`}>
                                                                {tab.count}
                                                            </span>
                                                        )}
                                                    </button>
                                                );
                                            })}
                                        </div>

                                        {/* Tab Content Panes */}
                                        <div className="p-4 sm:p-5">
                                            {/* Overview / WHOIS */}
                                            {activeTab === 'overview' && (
                                                <div className="space-y-4">
                                                    {view.whois ? (
                                                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 p-4 rounded-xl bg-card border border-border">
                                                            <div>
                                                                <p className="text-[11px] font-semibold text-foreground-muted uppercase tracking-wider">Registrar</p>
                                                                <p className="text-sm font-bold text-foreground mt-0.5">{view.whois.registrar}</p>
                                                            </div>
                                                            <div>
                                                                <p className="text-[11px] font-semibold text-foreground-muted uppercase tracking-wider">Creation Date</p>
                                                                <p className="text-sm font-bold text-foreground mt-0.5">{view.whois.created?.slice(0, 10) ?? '—'}</p>
                                                            </div>
                                                            <div>
                                                                <p className="text-[11px] font-semibold text-foreground-muted uppercase tracking-wider">Expiry Date</p>
                                                                <p className="text-sm font-bold text-foreground mt-0.5">{view.whois.expires?.slice(0, 10) ?? '—'}</p>
                                                            </div>
                                                            <div>
                                                                <p className="text-[11px] font-semibold text-foreground-muted uppercase tracking-wider">Days Until Expiry</p>
                                                                <p className={`text-sm font-bold mt-0.5 ${view.whois.daysUntilExpiry !== null && view.whois.daysUntilExpiry < 30 ? 'text-amber-500' : 'text-foreground'}`}>
                                                                    {view.whois.daysUntilExpiry !== null ? `${view.whois.daysUntilExpiry} days` : '—'}
                                                                </p>
                                                            </div>
                                                        </div>
                                                    ) : (
                                                        <div className="p-6 text-center rounded-xl bg-card border border-dashed border-border">
                                                            <p className="text-xs text-foreground-muted">WHOIS record has not been queried yet.</p>
                                                            <button onClick={() => runScan(d.id)} className="mt-2 text-xs font-semibold text-blue hover:underline">
                                                                Click here to run full domain scan
                                                            </button>
                                                        </div>
                                                    )}

                                                    {view.scanned_at && (
                                                        <p className="text-[11px] text-foreground-muted text-right">
                                                            Telemetry synchronized: {new Date(view.scanned_at).toLocaleString()}
                                                        </p>
                                                    )}
                                                </div>
                                            )}

                                            {/* Lookalikes Tab */}
                                            {activeTab === 'lookalikes' && (
                                                <div className="bg-card rounded-xl border border-border overflow-hidden">
                                                    {view.lookalikes.length === 0 ? (
                                                        <p className="text-xs text-foreground-muted p-5 text-center">No typosquatted or lookalike domains detected for current keywords.</p>
                                                    ) : (
                                                        <div className="overflow-x-auto">
                                                            <table className="w-full text-left text-xs">
                                                                <thead className="bg-card-muted/50 border-b border-border">
                                                                    <tr>
                                                                        <th className="px-4 py-2.5 font-bold text-foreground-muted uppercase text-[10px]">Detected Lookalike</th>
                                                                        <th className="px-4 py-2.5 font-bold text-foreground-muted uppercase text-[10px]">Similarity Match</th>
                                                                        <th className="px-4 py-2.5 font-bold text-foreground-muted uppercase text-[10px]">Threat Level</th>
                                                                        <th className="px-4 py-2.5 font-bold text-foreground-muted uppercase text-[10px]">Registration</th>
                                                                    </tr>
                                                                </thead>
                                                                <tbody className="divide-y divide-border font-mono">
                                                                    {view.lookalikes.map((l) => (
                                                                        <tr key={l.domain} className="hover:bg-card-muted/30 transition-colors">
                                                                            <td className="px-4 py-2.5 font-bold text-foreground flex items-center gap-2">
                                                                                <Globe size={13} className="text-foreground-muted" />
                                                                                {l.domain}
                                                                            </td>
                                                                            <td className="px-4 py-2.5">
                                                                                {l.similarity === null ? (
                                                                                    <span className="text-[11px] font-sans text-foreground-muted">Not scored</span>
                                                                                ) : (
                                                                                    <div className="flex items-center gap-2 max-w-[120px]">
                                                                                        <div className="w-full bg-border rounded-full h-1.5 overflow-hidden">
                                                                                            <div className="bg-blue h-full" style={{ width: `${l.similarity}%` }} />
                                                                                        </div>
                                                                                        <span className="text-[11px] font-sans font-semibold text-foreground">{l.similarity}%</span>
                                                                                    </div>
                                                                                )}
                                                                            </td>
                                                                            <td className="px-4 py-2.5 font-sans">
                                                                                {l.risk === null ? (
                                                                                    <span className="text-[10px] text-foreground-muted">Unverified candidate</span>
                                                                                ) : (
                                                                                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${RISK_BADGE[l.risk]}`}>
                                                                                        {l.risk}
                                                                                    </span>
                                                                                )}
                                                                            </td>
                                                                            <td className="px-4 py-2.5 font-sans text-foreground-muted">{l.registered ?? 'Not checked'}</td>
                                                                        </tr>
                                                                    ))}
                                                                </tbody>
                                                            </table>
                                                        </div>
                                                    )}
                                                </div>
                                            )}

                                            {/* Certs Tab */}
                                            {activeTab === 'certs' && (
                                                <div className="bg-card rounded-xl border border-border overflow-hidden">
                                                    {view.ct_logs.length === 0 ? (
                                                        <p className="text-xs text-foreground-muted p-5 text-center">No certificates identified in public Transparency Logs.</p>
                                                    ) : (
                                                        <div className="overflow-x-auto">
                                                            <table className="w-full text-left text-xs">
                                                                <thead className="bg-card-muted/50 border-b border-border">
                                                                    <tr>
                                                                        <th className="px-4 py-2.5 font-bold text-foreground-muted uppercase text-[10px]">Domain Scope</th>
                                                                        <th className="px-4 py-2.5 font-bold text-foreground-muted uppercase text-[10px]">CA Issuer</th>
                                                                        <th className="px-4 py-2.5 font-bold text-foreground-muted uppercase text-[10px]">Valid From</th>
                                                                        <th className="px-4 py-2.5 font-bold text-foreground-muted uppercase text-[10px]">Expires</th>
                                                                    </tr>
                                                                </thead>
                                                                <tbody className="divide-y divide-border font-mono">
                                                                    {view.ct_logs.map((c, i) => (
                                                                        <tr key={i} className="hover:bg-card-muted/30 transition-colors">
                                                                            <td className={`px-4 py-2.5 ${c.suspicious ? 'text-red-500 font-bold' : 'text-foreground'}`}>
                                                                                {c.suspicious && <AlertTriangle size={12} className="inline mr-1.5" />}
                                                                                {c.domain}
                                                                            </td>
                                                                            <td className="px-4 py-2.5 font-sans text-foreground-muted">{c.issuer}</td>
                                                                            <td className="px-4 py-2.5 font-sans text-foreground-muted">{c.not_before?.slice(0, 10)}</td>
                                                                            <td className="px-4 py-2.5 font-sans text-foreground-muted">{c.not_after?.slice(0, 10)}</td>
                                                                        </tr>
                                                                    ))}
                                                                </tbody>
                                                            </table>
                                                        </div>
                                                    )}
                                                </div>
                                            )}

                                            {/* DNS Tab */}
                                            {activeTab === 'dns' && (
                                                <div className="space-y-3">
                                                    <div className="flex items-center gap-1.5 bg-card border border-border rounded-lg p-1 w-fit">
                                                        {DNS_TYPES.map((t) => (
                                                            <button
                                                                key={t}
                                                                onClick={() => setDnsTab(t)}
                                                                className={`text-xs font-semibold px-3 py-1 rounded-md transition-all ${
                                                                    dnsTab === t ? 'bg-blue text-white shadow-xs' : 'text-foreground-muted hover:text-foreground'
                                                                }`}
                                                            >
                                                                {t} Records
                                                            </button>
                                                        ))}
                                                    </div>

                                                    <div className="bg-card rounded-xl border border-border overflow-hidden">
                                                        {view.dns_records.filter((r) => r.type === dnsTab).length === 0 ? (
                                                            <p className="text-xs text-foreground-muted p-5 text-center">No {dnsTab} records returned for this hostname.</p>
                                                        ) : (
                                                            <div className="divide-y divide-border font-mono text-xs">
                                                                {view.dns_records
                                                                    .filter((r) => r.type === dnsTab)
                                                                    .map((r, i) => (
                                                                        <div key={i} className="p-3 flex items-center justify-between gap-3 hover:bg-card-muted/20">
                                                                            <div className="flex items-center gap-3 min-w-0">
                                                                                <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-primary/10 text-primary border border-border">
                                                                                    {r.type}
                                                                                </span>
                                                                                <span className="text-foreground-muted font-sans text-xs">{r.name}</span>
                                                                                <span className="text-foreground font-semibold truncate">{r.value}</span>
                                                                            </div>
                                                                            <span className="text-[11px] font-sans text-foreground-muted flex-shrink-0">TTL: {r.ttl}s</span>
                                                                        </div>
                                                                    ))}
                                                            </div>
                                                        )}
                                                    </div>
                                                </div>
                                            )}

                                            {/* Alert History Tab */}
                                            {activeTab === 'alerts' && (
                                                <div className="bg-card rounded-xl border border-border overflow-hidden">
                                                    {view.alert_history.length === 0 ? (
                                                        <p className="text-xs text-foreground-muted p-5 text-center">No security events or configuration changes logged.</p>
                                                    ) : (
                                                        <div className="divide-y divide-border p-3 space-y-2">
                                                            {view.alert_history.map((a, i) => (
                                                                <div key={i} className="flex items-center justify-between gap-3 text-xs pt-1">
                                                                    <div className="flex items-center gap-2 min-w-0">
                                                                        <span
                                                                            className={`text-[9px] font-bold px-2 py-0.5 rounded-full ${
                                                                                a.severity === 'HIGH'
                                                                                    ? 'bg-red-500/10 text-red-500 border border-red-500/30'
                                                                                    : 'bg-amber-500/10 text-amber-500 border border-amber-500/30'
                                                                            }`}
                                                                        >
                                                                            {a.severity}
                                                                        </span>
                                                                        <span className="text-foreground">{a.message}</span>
                                                                    </div>
                                                                    <span className="text-foreground-muted text-[11px] flex-shrink-0">{a.time}</span>
                                                                </div>
                                                            ))}
                                                        </div>
                                                    )}
                                                </div>
                                            )}
                                        </div>
                                    </div>
                                )}
                            </div>
                        );
                    })}
                </div>
            )}

            {/* Modal: Add Domain */}
            {showAddModal && (
                <div className="fixed inset-0 bg-black/60 backdrop-blur-xs flex items-center justify-center z-50 p-4 animate-in fade-in duration-150">
                    <div className="bg-card border border-border rounded-2xl p-6 w-full max-w-lg shadow-2xl space-y-5">
                        <div className="flex items-center justify-between border-b border-border pb-3">
                            <h3 className="font-bold text-base text-foreground flex items-center gap-2">
                                <Plus size={18} className="text-orange" />
                                Add Domain to Brand Monitor
                            </h3>
                            <button onClick={() => { setShowAddModal(false); resetForm(); }} className="text-foreground-muted hover:text-foreground">
                                <X size={18} />
                            </button>
                        </div>

                        <div className="space-y-4 text-xs">
                            <div>
                                <label className="font-semibold text-foreground-muted uppercase tracking-wider block mb-1">Target FQDN / Domain</label>
                                <input
                                    type="text"
                                    value={domainInput}
                                    onChange={(e) => setDomainInput(e.target.value)}
                                    placeholder="e.g., cybernovr.com"
                                    className="w-full bg-card-muted border border-border rounded-lg px-3.5 py-2.5 text-sm font-mono text-foreground focus:outline-none focus:border-blue"
                                />
                            </div>

                            <div>
                                <label className="font-semibold text-foreground-muted uppercase tracking-wider block mb-1">Brand Name Variants & Keywords</label>
                                <div className="flex gap-2">
                                    <input
                                        type="text"
                                        value={keywordInput}
                                        onChange={(e) => setKeywordInput(e.target.value)}
                                        onKeyDown={(e) => {
                                            if (e.key === 'Enter') {
                                                e.preventDefault();
                                                addKeyword();
                                            }
                                        }}
                                        placeholder="Add keyword and hit Enter..."
                                        className="flex-1 bg-card-muted border border-border rounded-lg px-3 py-2 text-foreground focus:outline-none focus:border-blue"
                                    />
                                    <button onClick={addKeyword} className="bg-card border border-border hover:bg-card-muted px-3 py-2 rounded-lg font-bold text-foreground">
                                        Add
                                    </button>
                                </div>
                                {keywords.length > 0 && (
                                    <div className="flex flex-wrap gap-1.5 mt-2">
                                        {keywords.map((k) => (
                                            <span key={k} className="inline-flex items-center gap-1.5 text-[11px] font-semibold px-2.5 py-1 bg-primary/10 text-primary rounded-md border border-border">
                                                {k}
                                                <button onClick={() => setKeywords(keywords.filter((x) => x !== k))} className="hover:text-red-500">
                                                    <X size={11} />
                                                </button>
                                            </span>
                                        ))}
                                    </div>
                                )}
                            </div>

                            <div>
                                <div className="flex justify-between items-center mb-1">
                                    <label className="font-semibold text-foreground-muted uppercase tracking-wider">Similarity Fuzzy Threshold</label>
                                    <span className="font-mono font-bold text-blue">{threshold}%</span>
                                </div>
                                <input
                                    type="range"
                                    min={70}
                                    max={100}
                                    value={threshold}
                                    onChange={(e) => setThreshold(Number(e.target.value))}
                                    className="w-full accent-blue cursor-pointer"
                                />
                            </div>

                            <div className="border-t border-border pt-3">
                                <label className="font-semibold text-foreground-muted uppercase tracking-wider block mb-2">Automated Threat Triggers</label>
                                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                                    {([
                                        ['lookalike', 'New lookalike domain registered'],
                                        ['dns_change', 'DNS record modification'],
                                        ['expiry', 'Domain expiration < 30 days'],
                                        ['new_cert', 'Unauthorized SSL cert issued'],
                                    ] as const).map(([key, label]) => (
                                        <label key={key} className="flex items-center gap-2 p-2 rounded-lg bg-card-muted/40 border border-border cursor-pointer hover:bg-card-muted">
                                            <input
                                                type="checkbox"
                                                checked={alerts[key]}
                                                onChange={(e) => setAlerts({ ...alerts, [key]: e.target.checked })}
                                                className="rounded accent-blue"
                                            />
                                            <span className="text-foreground">{label}</span>
                                        </label>
                                    ))}
                                </div>
                            </div>
                        </div>

                        <div className="flex gap-3 pt-2">
                            <button
                                onClick={() => {
                                    setShowAddModal(false);
                                    resetForm();
                                }}
                                className="flex-1 border border-border text-foreground-muted hover:text-foreground py-2.5 rounded-lg font-semibold transition-colors"
                            >
                                Cancel
                            </button>
                            <button
                                onClick={addDomain}
                                disabled={saving || !domainInput.trim()}
                                className="flex-1 bg-orange hover:bg-orange-hover disabled:opacity-50 text-white py-2.5 rounded-lg font-bold transition-all shadow-sm"
                            >
                                {saving ? 'Registering…' : 'Start Monitoring'}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}