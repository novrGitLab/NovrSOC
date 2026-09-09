'use client';

import { useEffect, useState } from 'react';
import { Download, Check, AlertTriangle } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';

// Downloads the org's IOCs as a STIX 2.1 bundle from GET /api/intelligence/stix.
//
// Deliberately NOT a plain <a href={apiUrl(...)} download> — that endpoint is behind
// requireAuth, and a browser-initiated navigation doesn't carry the Bearer token that
// apiFetch attaches, so the link would just 401. Fetching to a blob and clicking a synthetic
// anchor is what makes an authenticated download work.

export function StixExportButton() {
    const [total, setTotal] = useState<number | null>(null);
    const [busy, setBusy] = useState(false);
    const [done, setDone] = useState(false);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        let cancelled = false;
        apiFetch(apiUrl('/api/intelligence/stix/summary'), { cache: 'no-store' })
            .then((r) => r.json())
            .then((d) => { if (!cancelled) setTotal(typeof d?.total === 'number' ? d.total : 0); })
            .catch(() => { if (!cancelled) setTotal(0); })
        return () => { cancelled = true; };
    }, []);

    const download = async () => {
        setBusy(true);
        setError(null);
        setDone(false);
        let url: string | null = null;
        try {
            const res = await apiFetch(apiUrl('/api/intelligence/stix?download=true'), { cache: 'no-store' });
            if (!res.ok) {
                const body = await res.json().catch(() => ({}));
                setError(body?.error ?? `Export failed (HTTP ${res.status})`);
                return;
            }
            const blob = await res.blob();
            url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `novrsoc-stix-${new Date().toISOString().slice(0, 10)}.json`;
            document.body.appendChild(a);
            a.click();
            a.remove();
            setDone(true);
            setTimeout(() => setDone(false), 3000);
        } catch {
            setError('Export failed. Please try again.');
        } finally {
            // Revoking immediately can cancel the download in some browsers — give it a beat.
            if (url) setTimeout(() => URL.revokeObjectURL(url as string), 10_000);
            setBusy(false);
        }
    };

    const empty = total === 0;

    return (
        <div className="flex flex-col items-end gap-1">
            <button
                onClick={() => void download()}
                disabled={busy || empty}
                title={
                    empty
                        ? 'No enriched IOCs to export yet — scan indicators in the CTI Platform and they will appear here.'
                        : 'Download all enriched IOCs as a STIX 2.1 bundle'
                }
                className="flex items-center gap-1.5 text-[11px] font-bold px-3 py-1.5 border border-border rounded-lg text-foreground hover:border-purple hover:text-purple disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
                {done ? <Check size={13} className="text-green" /> : <Download size={13} />}
                {busy ? 'Building bundle…' : done ? 'Downloaded' : 'Export STIX'}
                {total !== null && total > 0 && (
                    <span className="text-foreground-muted font-medium">({total})</span>
                )}
            </button>
            {empty && (
                <span className="text-[9px] text-foreground-muted">No enriched IOCs yet</span>
            )}
            {error && (
                <span className="text-[9px] text-red-500 flex items-center gap-1">
                    <AlertTriangle size={9} /> {error}
                </span>
            )}
        </div>
    );
}
