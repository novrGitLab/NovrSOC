'use client';

import { useState } from 'react';
import { apiUrl } from '@/lib/api';

// The landing page's free scanner. Extracted into its own client component so app/page.tsx can
// stay a server component — it's ~700 lines of otherwise static marketing content, and making
// the whole thing 'use client' just to hold three pieces of scanner state would ship all of it
// to the browser for no reason.
//
// Talks to POST /api/public/scan (unauthenticated, 10/hour per IP). Uses plain fetch rather than
// apiFetch: this route takes no auth, and apiFetch signs the user out on a 401, which would be
// wrong behaviour for an anonymous visitor on the marketing site. The origin comes from
// apiUrl(), not a local NEXT_PUBLIC_BACKEND_URL read — lib/api.ts is the single place that knows
// the backend host, and it carries the Railway fallback for builds where the env var is unset.

interface ScanResult {
    target: string;
    ioc_type: string;
    verdict: 'clean' | 'suspicious' | 'malicious';
    risk_score: number;
    sources_checked: number;
    detections: number;
    summary: string;
}

const VERDICT_STYLE: Record<string, string> = {
    malicious: 'bg-red-100 text-red-700 border border-red-200',
    suspicious: 'bg-amber-100 text-amber-700 border border-amber-200',
    clean: 'bg-green-100 text-green-700 border border-green-200',
};

const EXAMPLES = ['185.220.101.47', 'cybernovr.com', '8.8.8.8'];

export function HomepageScanner() {
    const [input, setInput] = useState('');
    const [result, setResult] = useState<ScanResult | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [scanning, setScanning] = useState(false);

    // Takes an optional explicit target so the "Try:" chips can scan in one click — setInput()
    // alone wouldn't be visible to this call, since the state update isn't applied until the
    // next render.
    const handleScan = async (override?: string) => {
        const target = (override ?? input).trim();
        if (!target || scanning) return;

        setScanning(true);
        setResult(null);
        setError(null);
        try {
            const res = await fetch(apiUrl('/api/public/scan'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target }),
            });
            const data = await res.json();
            // The backend returns its own message for a bad target (400) and for the hourly
            // rate limit (429) — surface those verbatim rather than a generic failure.
            if (!res.ok || data?.error) {
                setError(data?.message ?? 'Scan failed. Please try again.');
                return;
            }
            setResult(data as ScanResult);
        } catch {
            setError('Scan failed. Please try again.');
        } finally {
            setScanning(false);
        }
    };

    const riskColor = (score: number) =>
        score > 70 ? 'text-red-600' : score > 40 ? 'text-amber-600' : 'text-green-600';

    return (
        <div className="bg-white rounded-3xl border border-gray-200 p-6 shadow-xl text-left">
            <div className="flex flex-col sm:flex-row gap-3 mb-4">
                <input
                    type="text"
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    onKeyDown={(e) => { if (e.key === 'Enter') void handleScan(); }}
                    placeholder="185.220.101.47 · malware.example.com · https://phishing-site.com"
                    aria-label="URL, IP address, or domain to scan"
                    className="flex-1 border border-gray-200 rounded-xl px-4 py-3.5 text-sm text-gray-900
                               focus:outline-none focus:border-purple-500 focus:ring-2
                               focus:ring-purple-100 placeholder-gray-300"
                />
                <button
                    onClick={() => void handleScan()}
                    disabled={scanning || !input.trim()}
                    className="bg-purple-700 text-white font-bold px-6 py-3.5 rounded-xl
                               hover:bg-purple-800 disabled:opacity-40 disabled:cursor-not-allowed
                               transition-colors whitespace-nowrap text-sm shadow-sm min-w-[120px]"
                >
                    {scanning ? (
                        <span className="flex items-center gap-2 justify-center">
                            <span className="w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                            Scanning
                        </span>
                    ) : 'Scan Now →'}
                </button>
            </div>

            <div className="flex gap-2 flex-wrap items-center mb-2">
                <span className="text-[10px] text-gray-400 mr-1">Try:</span>
                {EXAMPLES.map((ex) => (
                    <button
                        key={ex}
                        onClick={() => { setInput(ex); void handleScan(ex); }}
                        disabled={scanning}
                        className="text-[10px] bg-gray-100 text-gray-500 px-2 py-1 rounded-full
                                   hover:bg-purple-100 hover:text-purple-700 disabled:opacity-40 transition-colors"
                    >
                        {ex}
                    </button>
                ))}
            </div>

            {scanning && (
                <p className="text-xs text-gray-400 mt-3">
                    Querying threat intelligence sources — this can take a few seconds.
                </p>
            )}

            {result && (
                <div className="mt-4 border-t border-gray-100 pt-4">
                    <div className="flex items-start justify-between gap-3 mb-4 flex-wrap">
                        <div>
                            <div className="text-xs text-gray-400 mb-1">Scanned target</div>
                            <div className="font-bold text-gray-900 font-mono text-sm break-all">{result.target}</div>
                        </div>
                        <div className={`px-4 py-2 rounded-xl text-xs font-black uppercase tracking-wider ${VERDICT_STYLE[result.verdict] ?? 'bg-gray-100 text-gray-700 border border-gray-200'}`}>
                            {result.verdict}
                        </div>
                    </div>

                    <div className="grid grid-cols-3 gap-3 mb-4">
                        {[
                            { label: 'Risk Score', value: `${result.risk_score}/100`, color: riskColor(result.risk_score) },
                            { label: 'Sources Checked', value: String(result.sources_checked), color: 'text-gray-900' },
                            { label: 'Detections', value: String(result.detections), color: result.detections > 0 ? 'text-red-600' : 'text-green-600' },
                        ].map((tile) => (
                            <div key={tile.label} className="bg-gray-50 rounded-xl p-3 text-center border border-gray-100">
                                <div className={`text-xl font-black ${tile.color}`}>{tile.value}</div>
                                <div className="text-[10px] text-gray-400 mt-0.5">{tile.label}</div>
                            </div>
                        ))}
                    </div>

                    <p className="text-xs text-gray-500 mb-4 leading-relaxed bg-gray-50 rounded-xl p-3">
                        {result.summary}
                    </p>

                    <div className="flex items-center justify-between gap-4 flex-wrap">
                        <p className="text-[10px] text-gray-400">
                            Full report includes source-by-source breakdown, historical data, and remediation guidance.
                        </p>
                        <a href="/login" className="text-xs font-bold text-purple-700 hover:underline whitespace-nowrap">
                            Full Report →
                        </a>
                    </div>
                </div>
            )}

            {error && (
                <p className="mt-3 text-xs text-red-600 bg-red-50 rounded-lg p-3">{error}</p>
            )}

            <p className="text-[10px] text-gray-400 mt-3 text-center">
                Powered by GreyNoise · VirusTotal · AbuseIPDB · URLScan · ThreatFox · URLhaus · IPregistry · CIRCL · LeakIX
            </p>
        </div>
    );
}
