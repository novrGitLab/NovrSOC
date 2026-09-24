'use client';

import { useState } from 'react';
import { Eye, Search, AlertTriangle, CheckCircle2, Siren } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';

// Dark web exposure monitoring.
//
// Coverage here is narrower than the term usually implies, and the page says so rather than
// leaving the impression of broad dark web surveillance: only ransomware leak-site victim
// listings (Ransomwatch) are actually searched. The Tor search engine and paste-site APIs that
// would normally round this out are dead — see services/darkweb.ts. The per-source panel below
// reports what really ran, because "no results" from an unimplemented source is indistinguishable
// from "no results" from a clean one unless you say which is which.

interface Finding {
    source: string;
    group: string | null;
    title: string;
    date: string | null;
    url: string | null;
    type: string;
    severity: string;
    matched_query: string;
}

interface SourceStatus { name: string; ok: boolean; detail: string }

interface ScanResult {
    results: Finding[];
    total: number;
    critical: number;
    searched: string[];
    sources: SourceStatus[];
    scanned_at: string;
}

const MAX_KEYWORDS = 20; // matches the backend's cap

export function DarkWebMonitor() {
    const [keywords, setKeywords] = useState<string[]>(['Cybernovr', 'cybernovr.com']);
    const [newKeyword, setNewKeyword] = useState('');
    const [scanning, setScanning] = useState(false);
    const [result, setResult] = useState<ScanResult | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [creating, setCreating] = useState(false);
    const [caseMsg, setCaseMsg] = useState<string | null>(null);

    const addKeyword = () => {
        const kw = newKeyword.trim();
        if (!kw || keywords.length >= MAX_KEYWORDS) return;
        if (!keywords.some((k) => k.toLowerCase() === kw.toLowerCase())) setKeywords((prev) => [...prev, kw]);
        setNewKeyword('');
    };
    const removeKeyword = (kw: string) => setKeywords((prev) => prev.filter((k) => k !== kw));

    const scan = async () => {
        setScanning(true);
        setError(null);
        setResult(null);
        setCaseMsg(null);
        try {
            const params = new URLSearchParams();
            keywords.forEach((k) => params.append('keywords', k));
            const res = await apiFetch(apiUrl(`/api/brand/darkweb?${params}`), { cache: 'no-store' });
            const data = await res.json();
            if (!res.ok) throw new Error(data?.error ?? `HTTP ${res.status}`);
            setResult(data as ScanResult);
        } catch (e) {
            setError(e instanceof Error ? e.message : 'Scan failed');
        } finally {
            setScanning(false);
        }
    };

    // Raising a case is an explicit action, not a side effect of scanning — running a search
    // several times while tuning terms must not fill the case queue with duplicates.
    const createIncident = async () => {
        if (!result || result.critical === 0) return;
        setCreating(true);
        setCaseMsg(null);
        try {
            const top = result.results[0];
            const res = await apiFetch(apiUrl('/api/cases'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    title: `CRITICAL: ${top.matched_query || keywords[0]} listed on ransomware leak site`,
                    severity: 'critical',
                    summary: `Dark web scan matched ${result.critical} ransomware leak-site listing(s). First match: "${top.title}" posted by group "${top.group ?? 'unknown'}"${top.date ? ` on ${top.date.slice(0, 10)}` : ''}. Search terms: ${result.searched.join(', ')}.`,
                }),
            });
            const data = await res.json();
            setCaseMsg(res.ok ? `Case ${data?.case_number ?? ''} created — see Cases` : (data?.error ?? 'Could not create case'));
        } catch {
            setCaseMsg('Could not create case — backend unreachable');
        } finally {
            setCreating(false);
        }
    };

    const grouped = {
        critical: (result?.results ?? []).filter((r) => r.severity === 'critical'),
        high: (result?.results ?? []).filter((r) => r.severity === 'high'),
        medium: (result?.results ?? []).filter((r) => r.severity === 'medium'),
    };

    return (
        <div className="space-y-4">
            <div className="flex items-start gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-red-500/10 flex items-center justify-center shrink-0">
                    <Eye className="w-4 h-4 text-red-500" />
                </div>
                <div>
                    <h1 className="text-lg font-black text-foreground">Dark Web Monitor</h1>
                    <p className="text-xs text-foreground-muted">Brand Protection · Ransomware leak-site exposure checks</p>
                </div>
            </div>

            {/* Search */}
            <div className="bg-card border border-border rounded-xl p-4 space-y-3">
                <div>
                    <label htmlFor="dw-keyword" className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">Search keywords</label>
                    <div className="flex flex-wrap gap-2 mt-2 mb-2">
                        {keywords.length === 0 && <span className="text-[11px] text-foreground-muted">Add at least one keyword to scan.</span>}
                        {keywords.map((kw) => (
                            <span key={kw} className="flex items-center gap-1 bg-purple/10 text-purple px-3 py-1.5 rounded-full text-xs font-bold">
                                {kw}
                                <button onClick={() => removeKeyword(kw)} aria-label={`Remove ${kw}`} className="ml-0.5 hover:text-red-500 font-black leading-none">×</button>
                            </span>
                        ))}
                    </div>
                    <div className="flex gap-2">
                        <input id="dw-keyword" value={newKeyword} onChange={(e) => setNewKeyword(e.target.value)}
                            onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); addKeyword(); } }}
                            placeholder="Company name, domain, executive or product name…"
                            className="flex-1 min-w-0 bg-card border border-border rounded-xl px-3 py-2.5 text-sm text-foreground focus:outline-none focus:border-purple" />
                        <button onClick={addKeyword} disabled={!newKeyword.trim() || keywords.length >= MAX_KEYWORDS}
                            className="bg-purple text-white text-xs font-bold px-4 py-2.5 rounded-xl hover:opacity-90 disabled:opacity-50">
                            Add
                        </button>
                    </div>
                    <p className="text-[10px] text-foreground-muted mt-2">
                        Up to {MAX_KEYWORDS} keywords. For a domain, its bare name is searched too (cybernovr.com also searches &quot;cybernovr&quot;).
                    </p>
                </div>
                <button onClick={() => void scan()} disabled={scanning || keywords.length === 0}
                    className="flex items-center justify-center gap-2 w-full bg-purple text-white text-xs font-black px-6 py-3 rounded-xl hover:opacity-90 disabled:opacity-50 transition-opacity">
                    <Search size={14} /> {scanning ? 'Scanning…' : 'Scan Now'}
                </button>
                <p className="text-[10px] text-foreground-muted">
                    Terms shorter than 4 characters are skipped — they match thousands of unrelated victim names.
                </p>
            </div>

            {error && <div className="bg-red-500/5 border border-red-500/30 rounded-xl p-4 text-xs text-red-500">{error}</div>}

            {result && (
                <>
                    {/* Source coverage */}
                    <div className="bg-card border border-border rounded-xl p-4">
                        <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider mb-3">Sources consulted</p>
                        <div className="space-y-2">
                            {result.sources.map((s) => (
                                <div key={s.name} className="flex items-start gap-2.5 text-xs">
                                    <span className={`shrink-0 mt-0.5 ${s.ok ? 'text-emerald-500' : 'text-foreground-muted'}`}>{s.ok ? '●' : '○'}</span>
                                    <div>
                                        <span className={`font-bold ${s.ok ? 'text-foreground' : 'text-foreground-muted'}`}>{s.name}</span>
                                        <p className="text-[10px] text-foreground-muted leading-snug">{s.detail}</p>
                                    </div>
                                </div>
                            ))}
                        </div>
                        <p className="text-[10px] text-foreground-muted mt-3">
                            Searched: {result.searched.join(', ')}
                        </p>
                    </div>

                    {/* Findings */}
                    {result.total === 0 ? (
                        <div className="bg-emerald-500/5 border border-emerald-500/30 rounded-xl p-8 text-center">
                            <CheckCircle2 className="w-8 h-8 text-emerald-500 mx-auto mb-3" />
                            <p className="text-sm font-bold text-emerald-500 mb-1">No listings found for {keywords.join(', ')}</p>
                            <p className="text-xs text-foreground-muted max-w-md mx-auto">
                                No ransomware leak-site listing matched your search terms. This covers the
                                sources marked active above only — it is not a guarantee of no dark web exposure.
                            </p>
                        </div>
                    ) : (
                        <>
                            <div className="bg-red-500/5 border border-red-500/30 rounded-xl p-4 flex items-center justify-between gap-3 flex-wrap">
                                <div className="flex items-center gap-3">
                                    <AlertTriangle className="w-5 h-5 text-red-500 shrink-0" />
                                    <div>
                                        <p className="text-sm font-bold text-red-500">{result.total} listing{result.total === 1 ? '' : 's'} matched</p>
                                        <p className="text-[11px] text-foreground-muted">{result.critical} critical</p>
                                    </div>
                                </div>
                                <button onClick={() => void createIncident()} disabled={creating}
                                    className="flex items-center gap-1.5 bg-red-500 text-white text-xs font-bold px-4 py-2.5 rounded-xl hover:bg-red-600 disabled:opacity-50 transition-colors">
                                    <Siren size={13} /> {creating ? 'Creating…' : 'Create case'}
                                </button>
                            </div>
                            {caseMsg && <p className="text-[11px] text-foreground-muted">{caseMsg}</p>}

                            {([['🔴 Ransomware Listings', grouped.critical], ['🟠 Dark Web Mentions', grouped.high], ['🟡 Paste Site Mentions', grouped.medium]] as [string, Finding[]][])
                                .filter(([, list]) => list.length > 0)
                                .map(([label, list]) => (
                                    <div key={label} className="space-y-2">
                                        <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">{label} ({list.length})</p>
                                        {list.map((f, i) => (
                                            <div key={`${f.title}-${i}`} className="bg-card border border-border rounded-xl p-4">
                                                <div className="flex items-start justify-between gap-3 flex-wrap">
                                                    <div className="min-w-0">
                                                        <div className="flex items-center gap-2 flex-wrap mb-1">
                                                            <span className="text-[9px] font-black px-2 py-0.5 rounded-full bg-red-500/10 text-red-500 uppercase">{f.severity}</span>
                                                            <span className="text-[10px] text-foreground-muted">{f.source}</span>
                                                            {f.group && <span className="text-[9px] bg-card-muted text-foreground-muted px-1.5 py-0.5 rounded-full">{f.group}</span>}
                                                        </div>
                                                        <p className="text-sm text-foreground break-words">{f.title}</p>
                                                        <p className="text-[10px] text-foreground-muted mt-0.5">
                                                            matched &ldquo;{f.matched_query}&rdquo;{f.date ? ` · discovered ${f.date.slice(0, 10)}` : ''}
                                                        </p>
                                                    </div>
                                                    {f.url && (
                                                        <a href={f.url} target="_blank" rel="noopener noreferrer"
                                                            className="text-[11px] font-bold text-purple hover:underline shrink-0">View source</a>
                                                    )}
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                ))}
                        </>
                    )}
                </>
            )}
        </div>
    );
}
