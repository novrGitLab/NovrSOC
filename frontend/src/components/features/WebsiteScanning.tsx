'use client';

import { useState, useEffect } from 'react';
import {
    Search, RefreshCw, AlertTriangle, ShieldCheck, ShieldAlert, Clock, Zap, ExternalLink,
} from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';

type ScanType = 'quick' | 'full';
type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

interface Finding {
    severity: Severity;
    title: string;
    description: string;
    recommendation: string;
}

interface SSLResult {
    grade: string;
    status: string;
    endpoints: { ipAddress: string; grade: string; hasWarnings: boolean; isExceptional: boolean }[];
}

interface RdapResult {
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

interface ScanResult {
    domain: string;
    scan_type: ScanType;
    started_at: string;
    completed_at?: string;
    ssl: SSLResult | null;
    rdap: RdapResult | null;
    findings: Finding[];
    vuln_critical: number;
    vuln_high: number;
    vuln_medium: number;
    vuln_low: number;
}

interface HistoryScan {
    id: string;
    target_domain: string;
    scan_type: ScanType;
    ssl_grade: string | null;
    vuln_critical: number;
    vuln_high: number;
    vuln_medium: number;
    scanned_at: string;
}

const SEVERITY_STYLE: Record<Severity, { label: string; text: string; bg: string; border: string; borderL: string }> = {
    critical: { label: 'CRITICAL', text: 'text-red-500', bg: 'bg-red-500/10', border: 'border-red-500/30', borderL: 'border-l-red-500' },
    high: { label: 'HIGH', text: 'text-red-500', bg: 'bg-red-500/5', border: 'border-red-500/20', borderL: 'border-l-red-500' },
    medium: { label: 'MEDIUM', text: 'text-purple', bg: 'bg-purple/10', border: 'border-purple/30', borderL: 'border-l-purple' },
    low: { label: 'LOW', text: 'text-foreground-muted', bg: 'bg-card-muted', border: 'border-border', borderL: 'border-l-grey-300' },
    info: { label: 'INFO', text: 'text-blue', bg: 'bg-blue/10', border: 'border-blue/30', borderL: 'border-l-blue' },
};

function gradeColor(grade: string): string {
    if (grade === 'A+' || grade === 'A' || grade === 'A-') return 'text-blue bg-blue/10 border-blue/30';
    if (grade === 'B') return 'text-purple bg-purple/10 border-purple/30';
    return 'text-red-500 bg-red-500/10 border-red-500/30';
}

const TABS = [
    { id: 'scan', label: 'Scan Website' },
    { id: 'history', label: 'Scan History' },
] as const;
type Tab = (typeof TABS)[number]['id'];

export function WebsiteScanning() {
    const [domain, setDomain] = useState('');
    const [scanType, setScanType] = useState<ScanType>('quick');
    const [authorised, setAuthorised] = useState(false);
    const [scanning, setScanning] = useState(false);
    const [result, setResult] = useState<ScanResult | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [history, setHistory] = useState<HistoryScan[]>([]);
    const [activeTab, setActiveTab] = useState<Tab>('scan');

    const loadHistory = () => {
        apiFetch(apiUrl('/api/webscan/history'), { cache: 'no-store' })
            .then((r) => r.json())
            .then((data) => setHistory(Array.isArray(data?.scans) ? data.scans : []))
            .catch(() => setHistory([]));
    };

    useEffect(loadHistory, []);

    const startScan = async () => {
        const cleanDomain = domain.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
        if (!cleanDomain || !authorised) return;

        setScanning(true);
        setError(null);
        setResult(null);

        try {
            const res = await apiFetch(apiUrl('/api/webscan/start'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain: cleanDomain, scan_type: scanType, authorised: true }),
            });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();
            setResult(data);
            loadHistory();
        } catch {
            setError('Scan failed — check the domain and try again');
        } finally {
            setScanning(false);
        }
    };

    return (
        <div className="space-y-4">
            <div>
                <h1 className="text-lg font-black text-foreground">Website Scanning</h1>
                <p className="text-xs text-foreground-muted">Threat Intelligence · SSL, DNS security, and domain risk assessment for monitored websites</p>
            </div>

            {/* Tabs */}
            <div className="flex gap-1 border-b border-border">
                {TABS.map((t) => (
                    <button
                        key={t.id}
                        onClick={() => setActiveTab(t.id)}
                        className={`px-4 py-2.5 text-xs font-bold border-b-2 transition-colors ${
                            activeTab === t.id ? 'border-blue text-blue' : 'border-transparent text-foreground-muted hover:text-foreground'
                        }`}
                    >
                        {t.id === 'history' ? `Scan History (${history.length})` : t.label}
                    </button>
                ))}
            </div>

            {activeTab === 'scan' && (
                <div className="space-y-4">
                    {/* Scan form */}
                    <div className="bg-card border border-border rounded-xl p-4 space-y-3">
                        <div className="flex flex-col md:flex-row gap-3">
                            <input
                                type="text"
                                value={domain}
                                onChange={(e) => setDomain(e.target.value)}
                                onKeyDown={(e) => e.key === 'Enter' && authorised && startScan()}
                                placeholder="cybernovr.com"
                                className="flex-1 px-4 py-2.5 border border-border bg-card-muted rounded-lg text-sm font-mono focus:outline-none focus:border-blue focus:ring-1 focus:ring-blue/20 text-foreground placeholder:font-sans placeholder:text-foreground-muted"
                            />
                            <div className="flex gap-1 bg-card-muted rounded-lg p-1">
                                {(['quick', 'full'] as const).map((t) => (
                                    <button
                                        key={t}
                                        onClick={() => setScanType(t)}
                                        className={`px-3 py-1.5 rounded-md text-xs font-medium whitespace-nowrap transition-colors ${
                                            scanType === t ? 'bg-card text-blue shadow-sm border border-border' : 'text-foreground-muted hover:text-foreground'
                                        }`}
                                    >
                                        {t === 'quick' ? 'Quick (SSL + DNS + RDAP)' : 'Full (+ Nuclei/Nmap)'}
                                    </button>
                                ))}
                            </div>
                            <button
                                onClick={startScan}
                                disabled={scanning || !domain.trim() || !authorised}
                                className="flex items-center gap-2 bg-amber hover:opacity-90 text-white px-5 py-2.5 rounded-lg text-xs font-black disabled:opacity-50 transition-colors min-w-[110px] justify-center"
                            >
                                {scanning ? (<><RefreshCw size={14} className="animate-spin" /> Scanning…</>) : (<><Search size={14} /> Start Scan</>)}
                            </button>
                        </div>

                        <label className="flex items-center gap-2 text-xs text-foreground-muted cursor-pointer">
                            <input type="checkbox" checked={authorised} onChange={(e) => setAuthorised(e.target.checked)} className="accent-blue" />
                            I confirm I am authorised to scan this domain
                        </label>
                    </div>

                    {/* DAST coming soon card */}
                    <div className="bg-card-muted border border-dashed border-grey-300 rounded-xl p-4 flex items-center gap-3 flex-wrap">
                        <Zap size={18} className="text-purple flex-shrink-0" />
                        <div className="flex-1 min-w-[200px]">
                            <div className="text-sm font-semibold text-foreground">Full DAST Vulnerability Scanning</div>
                            <div className="text-xs text-foreground-muted">Nuclei (5000+ templates) + Nmap port scanning — requires EC2-4 Scanner instance. Coming when AWS is provisioned.</div>
                        </div>
                        <span className="text-[10px] font-bold bg-purple/10 text-purple px-2 py-1 rounded-full whitespace-nowrap">COMING SOON</span>
                    </div>

                    {error && <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 text-sm text-red-500">{error}</div>}

                    {/* Result */}
                    {result && (
                        <div className="space-y-4">
                            <div className="bg-card border border-border rounded-xl p-5">
                                <div className="flex items-start justify-between gap-4 flex-wrap mb-4">
                                    <div>
                                        <div className="font-mono text-sm font-bold text-foreground">{result.domain}</div>
                                        <div className="text-xs text-foreground-muted mt-1">
                                            {result.scan_type === 'full' ? 'Full scan' : 'Quick scan'} · {result.completed_at ? new Date(result.completed_at).toLocaleString() : 'In progress'}
                                        </div>
                                    </div>
                                    {result.ssl && (
                                        <div className={`flex items-center gap-2 px-4 py-2 rounded-xl border ${gradeColor(result.ssl.grade)}`}>
                                            <span className="text-2xl font-heading font-black">{result.ssl.grade}</span>
                                            <span className="text-[10px] font-bold uppercase tracking-wide">SSL Grade</span>
                                        </div>
                                    )}
                                </div>

                                {/* RDAP strip */}
                                {result.rdap && (
                                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-[11px] p-3 bg-card-muted rounded-lg mb-4">
                                        <div>
                                            <p className="text-foreground-muted font-bold uppercase tracking-wider text-[9px] mb-1">Registrar</p>
                                            <p className="text-foreground font-bold">{result.rdap.registrar}</p>
                                        </div>
                                        <div>
                                            <p className="text-foreground-muted font-bold uppercase tracking-wider text-[9px] mb-1">Expires</p>
                                            <p className="text-foreground font-bold">{result.rdap.expires ? new Date(result.rdap.expires).toLocaleDateString() : '—'}</p>
                                        </div>
                                        <div>
                                            <p className="text-foreground-muted font-bold uppercase tracking-wider text-[9px] mb-1">Days Until Expiry</p>
                                            <p className={`font-bold ${result.rdap.daysUntilExpiry !== null && result.rdap.daysUntilExpiry < 30 ? 'text-red-500' : 'text-foreground'}`}>
                                                {result.rdap.daysUntilExpiry ?? '—'}
                                            </p>
                                        </div>
                                        <div>
                                            <p className="text-foreground-muted font-bold uppercase tracking-wider text-[9px] mb-1">DNSSEC</p>
                                            <p className={`font-bold flex items-center gap-1 ${result.rdap.dnssec ? 'text-blue' : 'text-red-500'}`}>
                                                {result.rdap.dnssec ? <ShieldCheck size={12} /> : <ShieldAlert size={12} />}
                                                {result.rdap.dnssec ? 'Enabled' : 'Not enabled'}
                                            </p>
                                        </div>
                                    </div>
                                )}

                                {/* Summary counts */}
                                <div className="grid grid-cols-4 gap-3">
                                    {[
                                        { label: 'Critical', value: result.vuln_critical, color: 'text-red-500' },
                                        { label: 'High', value: result.vuln_high, color: 'text-red-500' },
                                        { label: 'Medium', value: result.vuln_medium, color: 'text-purple' },
                                        { label: 'Low', value: result.vuln_low, color: 'text-foreground-muted' },
                                    ].map((s) => (
                                        <div key={s.label} className="border border-border rounded-lg p-3 text-center">
                                            <p className={`text-xl font-heading font-black ${s.color}`}>{s.value}</p>
                                            <p className="text-[9px] font-bold text-foreground-muted uppercase tracking-wider">{s.label}</p>
                                        </div>
                                    ))}
                                </div>

                                {/* Actions */}
                                <div className="flex flex-wrap gap-3 mt-4 pt-4 border-t border-border">
                                    <button className="text-xs font-bold px-3 py-1.5 border border-border text-foreground-muted rounded-lg hover:bg-card-muted transition-colors">Export Report</button>
                                    <button className="text-xs font-bold px-3 py-1.5 bg-orange hover:bg-orange-hover text-white rounded-lg transition-colors">Create Cases for Findings</button>
                                    <button onClick={startScan} className="text-xs font-bold px-3 py-1.5 border border-blue text-blue rounded-lg hover:bg-blue/10 transition-colors ml-auto">Rescan</button>
                                </div>
                            </div>

                            {/* Findings */}
                            {result.findings.length > 0 && (
                                <div className="space-y-2">
                                    {result.findings.map((f, i) => {
                                        const cfg = SEVERITY_STYLE[f.severity];
                                        return (
                                            <div key={i} className={`bg-card border border-border border-l-4 ${cfg.borderL} rounded-xl p-4`}>
                                                <div className="flex items-start justify-between gap-3 mb-1.5">
                                                    <div className="flex items-center gap-2">
                                                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${cfg.bg} ${cfg.text} ${cfg.border}`}>{cfg.label}</span>
                                                        <span className="text-sm font-bold text-foreground">{f.title}</span>
                                                    </div>
                                                </div>
                                                <p className="text-xs text-foreground-muted mb-1.5">{f.description}</p>
                                                <p className="text-xs text-blue">→ {f.recommendation}</p>
                                            </div>
                                        );
                                    })}
                                </div>
                            )}
                        </div>
                    )}

                    {!result && !scanning && !error && (
                        <div className="bg-card border border-border rounded-xl p-12 text-center">
                            <AlertTriangle size={40} className="text-border mx-auto mb-3" />
                            <div className="font-heading font-semibold text-foreground mb-1">Scan a website</div>
                            <div className="text-sm text-foreground-muted">Enter a domain, confirm authorisation, and start a scan to check SSL configuration, DNS security, and domain risk.</div>
                        </div>
                    )}
                </div>
            )}

            {/* History tab */}
            {activeTab === 'history' && (
                <div>
                    {history.length === 0 ? (
                        <div className="bg-card border border-border rounded-xl p-10 text-center">
                            <Clock size={36} className="text-border mx-auto mb-3" />
                            <div className="text-sm text-foreground-muted">No scans yet — scan your first website above</div>
                        </div>
                    ) : (
                        <div className="bg-card border border-border rounded-xl overflow-hidden overflow-x-auto">
                            <table className="w-full text-xs">
                                <thead>
                                    <tr className="border-b border-border">
                                        {['Domain', 'Scan Type', 'SSL Grade', 'Critical', 'High', 'Medium', 'Scanned', ''].map((h) => (
                                            <th key={h} className="text-left px-4 py-2.5 text-[10px] font-bold text-foreground-muted uppercase tracking-wider">{h}</th>
                                        ))}
                                    </tr>
                                </thead>
                                <tbody>
                                    {history.map((scan) => (
                                        <tr
                                            key={scan.id}
                                            className="border-b border-border hover:bg-card-muted cursor-pointer transition-colors"
                                            onClick={() => { setDomain(scan.target_domain); setActiveTab('scan'); }}
                                        >
                                            <td className="px-4 py-2.5 font-mono text-foreground">{scan.target_domain}</td>
                                            <td className="px-4 py-2.5 text-foreground-muted capitalize">{scan.scan_type}</td>
                                            <td className="px-4 py-2.5">
                                                {scan.ssl_grade ? <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${gradeColor(scan.ssl_grade)}`}>{scan.ssl_grade}</span> : '—'}
                                            </td>
                                            <td className="px-4 py-2.5 font-bold text-red-500">{scan.vuln_critical}</td>
                                            <td className="px-4 py-2.5 font-bold text-red-500">{scan.vuln_high}</td>
                                            <td className="px-4 py-2.5 font-bold text-purple">{scan.vuln_medium}</td>
                                            <td className="px-4 py-2.5 text-foreground-muted whitespace-nowrap">{new Date(scan.scanned_at).toLocaleString()}</td>
                                            <td className="px-4 py-2.5">
                                                <span className="text-blue flex items-center gap-1"><ExternalLink size={11} /> View</span>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}
