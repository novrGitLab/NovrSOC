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
// wrong behaviour for an anonymous visitor on the marketing site.

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
    malicious: 'bg-red-100 text-red-700',
    suspicious: 'bg-amber-100 text-amber-700',
    clean: 'bg-green-100 text-green-700',
};

export function HomepageScanner() {
    const [input, setInput] = useState('');
    const [result, setResult] = useState<ScanResult | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [scanning, setScanning] = useState(false);

    const handleScan = async () => {
        const target = input.trim();
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

    return (
        <div className="bg-white border border-[#EEF0F6] rounded-2xl p-6 shadow-sm text-left">
            <div className="flex flex-col sm:flex-row gap-3">
                <input
                    type="text"
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    onKeyDown={(e) => { if (e.key === 'Enter') void handleScan(); }}
                    placeholder="Enter URL, IP, or domain — e.g. example.com"
                    aria-label="URL, IP address, or domain to scan"
                    className="flex-1 border border-[#EEF0F6] rounded-xl px-4 py-3 text-sm text-[#1C1F2E] focus:outline-none focus:border-[#520385]"
                />
                <button
                    onClick={() => void handleScan()}
                    disabled={scanning || !input.trim()}
                    className="bg-[#520385] text-white font-bold px-6 py-3 rounded-xl hover:bg-[#420270] disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap text-sm transition-colors"
                >
                    {scanning ? 'Scanning…' : 'Scan Now →'}
                </button>
            </div>

            {scanning && (
                <p className="text-xs text-[#7A8099] mt-4">
                    Querying threat intelligence sources — this can take a few seconds.
                </p>
            )}

            {result && (
                <div className="mt-4 border-t border-[#EEF0F6] pt-4">
                    <div className="flex items-center justify-between gap-3 mb-3 flex-wrap">
                        <div className="text-sm font-bold text-[#1C1F2E] break-all">
                            Scan results: {result.target}
                        </div>
                        <span className={`text-xs font-bold px-3 py-1 rounded-full ${VERDICT_STYLE[result.verdict] ?? 'bg-gray-100 text-gray-700'}`}>
                            {result.verdict.toUpperCase()}
                        </span>
                    </div>

                    <div className="grid grid-cols-3 gap-3 mb-3">
                        {[
                            { value: result.risk_score, label: 'Risk Score' },
                            { value: result.sources_checked, label: 'Sources Checked' },
                            { value: result.detections, label: 'Detections' },
                        ].map((tile) => (
                            <div key={tile.label} className="bg-[#F8F9FC] rounded-xl p-3 text-center">
                                <div className="text-lg font-black text-[#1C1F2E]">{tile.value}</div>
                                <div className="text-[10px] text-[#7A8099]">{tile.label}</div>
                            </div>
                        ))}
                    </div>

                    <p className="text-xs text-[#7A8099] mb-3">{result.summary}</p>

                    <a href="/login" className="text-xs text-[#520385] font-bold hover:underline">
                        Sign in for the full threat report →
                    </a>
                </div>
            )}

            {error && (
                <p className="mt-3 text-xs text-red-600">{error}</p>
            )}

            <p className="text-[10px] text-[#7A8099] mt-3">
                Free scan, no account needed — 10 per hour. Sign in for the full threat report, MITRE mapping, and history.
            </p>
        </div>
    );
}
