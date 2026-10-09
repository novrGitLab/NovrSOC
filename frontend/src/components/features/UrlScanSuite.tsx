'use client';

import { useState, useEffect } from 'react';
import {
    Link as LinkIcon, Search, RefreshCw, ExternalLink, Clock, Shield, Zap,
} from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { verdictFromScore } from '@/lib/severity';

type Verdict = 'clean' | 'suspicious' | 'malicious';

interface ScanResult {
    url: string;
    risk_score: number;
    verdict: Verdict;
    tags: string[];
    threat_type: string | null;
    redirect_chain: string[];
    scan_duration_ms: number;
    scanned_at: string;
    sources: {
        urlhaus?: { status: string; threat: string; tags: string[]; reference: string };
        urlhaus_host?: { url_count: number; urls_sample: unknown[] };
        threatfox?: { malware: string; confidence: number; threat_type: string };
        safe_browsing?: { threat_type: string; platform: string };
        urlscan?: { total_scans: number; latest_malicious: boolean; latest_score: number; latest_scan_time: string | null; screenshot: string | null };
    };
}

interface HistoryScan {
    id: string;
    submitted_url: string;
    risk_score: number;
    verdict: Verdict;
    scan_duration_ms: number;
    scanned_at: string;
}

const VERDICT_STYLE: Record<Verdict, { label: string; text: string; bg: string; border: string }> = {
    malicious: { label: 'MALICIOUS', text: 'text-red-500', bg: 'bg-red-500/10', border: 'border-red-500/30' },
    suspicious: { label: 'SUSPICIOUS', text: 'text-amber', bg: 'bg-grey-100', border: 'border-amber/30' },
    clean: { label: 'CLEAN', text: 'text-green', bg: 'bg-green/10', border: 'border-green/30' },
};

const TABS = [
    { id: 'scan', label: 'Scan URL' },
    { id: 'history', label: 'Scan History' },
] as const;
type Tab = (typeof TABS)[number]['id'];

function scoreColor(score: number): string {
    return ({ malicious: 'text-red-500', suspicious: 'text-amber', clean: 'text-green' } as const)[verdictFromScore(score)];
}
function scoreBg(score: number): string {
    return ({ malicious: 'bg-red-500', suspicious: 'bg-amber', clean: 'bg-green' } as const)[verdictFromScore(score)];
}

export function UrlScanSuite() {
    const [url, setUrl] = useState('');
    const [scanning, setScanning] = useState(false);
    const [result, setResult] = useState<ScanResult | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [history, setHistory] = useState<HistoryScan[]>([]);
    const [activeTab, setActiveTab] = useState<Tab>('scan');

    const loadHistory = () => {
        apiFetch(apiUrl('/api/urlscan/history?limit=20'), { cache: 'no-store' })
            .then((r) => r.json())
            .then((data) => setHistory(Array.isArray(data?.scans) ? data.scans : []))
            .catch(() => setHistory([]));
    };

    useEffect(loadHistory, []);

    const submitScan = async () => {
        const trimmed = url.trim();
        if (!trimmed) return;

        const fullUrl = trimmed.startsWith('http') ? trimmed : `https://${trimmed}`;

        setScanning(true);
        setError(null);
        setResult(null);

        try {
            const res = await apiFetch(apiUrl('/api/urlscan/submit'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: fullUrl }),
            });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();
            setResult(data);
            loadHistory();
        } catch {
            setError('Scan failed — check the URL and try again');
        } finally {
            setScanning(false);
        }
    };

    return (
        <div className="space-y-4">
            <div>
                <h1 className="text-lg font-black text-foreground">URL Scan Suite</h1>
                <p className="text-xs text-foreground-muted">Threat Intelligence · Submit suspicious URLs for instant multi-source threat analysis</p>
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
                    {/* Submit bar */}
                    <div className="bg-card border border-border rounded-xl p-4">
                        <div className="flex gap-3">
                            <div className="flex-1 relative">
                                <LinkIcon size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-foreground-muted" />
                                <input
                                    type="text"
                                    value={url}
                                    onChange={(e) => setUrl(e.target.value)}
                                    onKeyDown={(e) => e.key === 'Enter' && submitScan()}
                                    placeholder="https://suspicious-link.com/payload.exe"
                                    className="w-full pl-9 pr-4 py-2.5 border border-border bg-card-muted rounded-lg text-sm font-mono focus:outline-none focus:border-blue focus:ring-1 focus:ring-blue/20 text-foreground placeholder:font-sans placeholder:text-foreground-muted"
                                />
                            </div>
                            <button
                                onClick={submitScan}
                                disabled={scanning || !url.trim()}
                                className="flex items-center gap-2 bg-orange hover:bg-orange-hover text-white px-5 py-2.5 rounded-lg text-xs font-black disabled:opacity-50 transition-colors min-w-[110px] justify-center"
                            >
                                {scanning ? (<><RefreshCw size={14} className="animate-spin" /> Scanning…</>) : (<><Search size={14} /> Scan URL</>)}
                            </button>
                        </div>

                        <div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-foreground-muted">
                            <span>Try:</span>
                            {['http://malware.testing.google.test/testing/malware/', 'https://cybernovr.com'].map((ex) => (
                                <button key={ex} onClick={() => setUrl(ex)} className="font-mono hover:text-blue transition-colors truncate max-w-[220px]">
                                    {ex}
                                </button>
                            ))}
                        </div>
                    </div>

                    {/* Sandbox coming soon card */}
                    <div className="bg-card-muted border border-dashed border-grey-300 rounded-xl p-4 flex items-center gap-3 flex-wrap">
                        <Zap size={18} className="text-purple flex-shrink-0" />
                        <div className="flex-1 min-w-[200px]">
                            <div className="text-sm font-semibold text-foreground">Live Sandbox Detonation</div>
                            <div className="text-xs text-foreground-muted">
                                Full Puppeteer/Playwright headless browser detonation — requires EC2-4 Scanner instance. Screenshots, HTTP request logs, JavaScript execution capture. Coming when AWS is provisioned.
                            </div>
                        </div>
                        <span className="text-[10px] font-bold bg-purple/10 text-purple px-2 py-1 rounded-full whitespace-nowrap">COMING SOON</span>
                    </div>

                    {error && <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 text-sm text-red-500">{error}</div>}

                    {/* Scan result */}
                    {result && (() => {
                        const cfg = VERDICT_STYLE[result.verdict];
                        return (
                            <div className={`border rounded-xl overflow-hidden ${cfg.bg} ${cfg.border}`}>
                                <div className="p-5 border-b border-border">
                                    <div className="flex items-start justify-between mb-3 gap-3 flex-wrap">
                                        <div>
                                            <div className="font-mono text-sm font-bold text-foreground break-all">{result.url}</div>
                                            <div className="text-xs text-foreground-muted mt-1">
                                                Scanned in {result.scan_duration_ms}ms · {new Date(result.scanned_at).toLocaleString()}
                                            </div>
                                        </div>
                                        <div className="text-right flex-shrink-0">
                                            <div className={`font-heading font-black text-3xl ${scoreColor(result.risk_score)}`}>
                                                {result.risk_score}<span className="text-base font-normal text-foreground-muted">/100</span>
                                            </div>
                                            <div className={`text-sm font-bold ${cfg.text}`}>{cfg.label}</div>
                                        </div>
                                    </div>

                                    <div className="h-2 bg-card rounded-full overflow-hidden">
                                        <div className={`h-full rounded-full ${scoreBg(result.risk_score)} transition-all duration-700`} style={{ width: `${result.risk_score}%` }} />
                                    </div>

                                    {result.tags.filter(Boolean).length > 0 && (
                                        <div className="flex flex-wrap gap-1.5 mt-3">
                                            {[...new Set(result.tags.filter(Boolean))].map((tag) => (
                                                <span key={tag} className="text-[10px] font-medium px-2 py-0.5 bg-card border border-border rounded-full text-foreground">{tag}</span>
                                            ))}
                                        </div>
                                    )}
                                </div>

                                {/* Sources */}
                                <div className="grid grid-cols-1 sm:grid-cols-3 gap-0 divide-x divide-y divide-border">
                                    <div className="p-4">
                                        <div className="flex items-center gap-2 mb-2">
                                            <div className="w-2 h-2 rounded-full bg-amber" />
                                            <span className="text-xs font-semibold text-foreground">Malicious URL Database</span>
                                        </div>
                                        {result.sources.urlhaus ? (
                                            <>
                                                <div className="text-sm font-bold text-red-500">{result.sources.urlhaus.threat}</div>
                                                <div className="text-xs text-foreground-muted mt-1">Status: {result.sources.urlhaus.status}</div>
                                                <a href={result.sources.urlhaus.reference} target="_blank" rel="noopener noreferrer" className="text-xs text-blue flex items-center gap-1 mt-1 hover:text-purple">
                                                    View full report <ExternalLink size={10} />
                                                </a>
                                            </>
                                        ) : (
                                            <div className="text-xs text-foreground-muted">Not in Malicious URL Database ✓</div>
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
                                            <div className="text-xs text-foreground-muted">Not in Malware Intelligence Feed ✓</div>
                                        )}
                                    </div>

                                    <div className="p-4">
                                        <div className="flex items-center gap-2 mb-2">
                                            <div className="w-2 h-2 rounded-full bg-purple" />
                                            <span className="text-xs font-semibold text-foreground">URL Analysis Engine</span>
                                        </div>
                                        {result.sources.urlscan ? (
                                            <>
                                                <div className="text-sm font-bold text-foreground">{result.sources.urlscan.total_scans} historical scans</div>
                                                <div className={`text-xs mt-1 font-medium ${result.sources.urlscan.latest_malicious ? 'text-red-500' : 'text-green'}`}>
                                                    {result.sources.urlscan.latest_malicious ? '⚠ Previously flagged as malicious' : '✓ No malicious history'}
                                                </div>
                                                {result.sources.urlscan.latest_scan_time && (
                                                    <div className="text-xs text-foreground-muted mt-0.5">Last scanned: {new Date(result.sources.urlscan.latest_scan_time).toLocaleDateString()}</div>
                                                )}
                                                {result.sources.urlscan.screenshot && (
                                                    <a href={result.sources.urlscan.screenshot} target="_blank" rel="noopener noreferrer" className="text-xs text-blue hover:text-purple flex items-center gap-1 mt-1">
                                                        View screenshot <ExternalLink size={10} />
                                                    </a>
                                                )}
                                            </>
                                        ) : (
                                            <div className="text-xs text-foreground-muted">No scan history found</div>
                                        )}
                                    </div>

                                    <div className="p-4">
                                        <div className="flex items-center gap-2 mb-2">
                                            <div className="w-2 h-2 rounded-full bg-red-500" />
                                            <span className="text-xs font-semibold text-foreground">Threat Classification Engine</span>
                                        </div>
                                        {result.sources.safe_browsing ? (
                                            <>
                                                <div className="text-sm font-bold text-red-500">{result.sources.safe_browsing.threat_type}</div>
                                                <div className="text-xs text-foreground-muted mt-1">{result.sources.safe_browsing.platform}</div>
                                            </>
                                        ) : (
                                            <div className="text-xs text-foreground-muted">Not yet configured</div>
                                        )}
                                    </div>

                                    <div className="p-4">
                                        <div className="flex items-center gap-2 mb-2">
                                            <div className="w-2 h-2 rounded-full bg-purple" />
                                            <span className="text-xs font-semibold text-foreground">Host Reputation</span>
                                        </div>
                                        {result.sources.urlhaus_host ? (
                                            <>
                                                <div className="text-sm font-bold text-red-500">{result.sources.urlhaus_host.url_count} malicious URLs hosted</div>
                                                <div className="text-xs text-foreground-muted mt-1">from this host</div>
                                            </>
                                        ) : (
                                            <div className="text-xs text-foreground-muted">No malicious URLs on this host ✓</div>
                                        )}
                                    </div>
                                </div>

                                {/* Actions */}
                                <div className="px-5 py-3 bg-card/60 flex flex-wrap gap-3 border-t border-border">
                                    <button className="text-xs text-blue hover:text-purple font-medium transition-colors">Create Case</button>
                                    <button className="text-xs text-blue hover:text-purple font-medium transition-colors">Add to Blocklist</button>
                                    <a
                                        href={`https://urlhaus.abuse.ch/browse/?search=${encodeURIComponent(result.url)}`}
                                        target="_blank" rel="noopener noreferrer"
                                        className="ml-auto text-xs text-foreground-muted hover:text-blue flex items-center gap-1 transition-colors"
                                    >
                                        View full report <ExternalLink size={11} />
                                    </a>
                                </div>
                            </div>
                        );
                    })()}

                    {!result && !scanning && !error && (
                        <div className="bg-card border border-border rounded-xl p-12 text-center">
                            <Shield size={40} className="text-border mx-auto mb-3" />
                            <div className="font-heading font-semibold text-foreground mb-1">Submit a URL to scan</div>
                            <div className="text-sm text-foreground-muted">Paste any suspicious link above. We check it against multiple threat intelligence sources instantly.</div>
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
                            <div className="text-sm text-foreground-muted">No scans yet — submit your first URL above</div>
                        </div>
                    ) : (
                        <div className="bg-card border border-border rounded-xl overflow-hidden overflow-x-auto">
                            <table className="w-full text-xs">
                                <thead>
                                    <tr className="border-b border-border">
                                        {['URL', 'Verdict', 'Risk Score', 'Duration', 'Scanned'].map((h) => (
                                            <th key={h} className="text-left px-4 py-2.5 text-[10px] font-bold text-foreground-muted uppercase tracking-wider">{h}</th>
                                        ))}
                                    </tr>
                                </thead>
                                <tbody>
                                    {history.map((scan) => {
                                        const cfg = VERDICT_STYLE[scan.verdict] ?? VERDICT_STYLE.clean;
                                        return (
                                            <tr
                                                key={scan.id}
                                                className="border-b border-border hover:bg-card-muted cursor-pointer transition-colors"
                                                onClick={() => { setUrl(scan.submitted_url); setActiveTab('scan'); }}
                                            >
                                                <td className="px-4 py-2.5 font-mono text-foreground max-w-[300px] truncate">{scan.submitted_url}</td>
                                                <td className="px-4 py-2.5"><span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${cfg.bg} ${cfg.text} ${cfg.border}`}>{cfg.label}</span></td>
                                                <td className="px-4 py-2.5"><span className={`font-bold ${scoreColor(scan.risk_score)}`}>{scan.risk_score}</span></td>
                                                <td className="px-4 py-2.5 text-foreground-muted">{scan.scan_duration_ms}ms</td>
                                                <td className="px-4 py-2.5 text-foreground-muted whitespace-nowrap">{new Date(scan.scanned_at).toLocaleString()}</td>
                                            </tr>
                                        );
                                    })}
                                </tbody>
                            </table>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}
