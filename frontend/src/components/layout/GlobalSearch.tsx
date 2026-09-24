'use client';

import { useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import { Search, Briefcase, Siren, Megaphone, Crosshair } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';

// Header search across cases, advisories, cached IOC lookups and recent Wazuh alerts
// (GET /api/search). Admin only — the endpoint is analyst-authenticated.
//
// Results are stored with the query they answer, and "loading" is derived by comparing that to
// the current query, so a fast typist never sees the previous query's results under the new one
// and no setState runs synchronously inside the debounce effect.

interface SearchResult {
    type: 'case' | 'advisory' | 'ioc' | 'alert';
    title: string;
    subtitle: string;
    badge?: string;
    url: string;
}

const ICON: Record<SearchResult['type'], typeof Search> = { case: Briefcase, alert: Siren, advisory: Megaphone, ioc: Crosshair };

const BADGE: Record<string, string> = {
    critical: 'bg-red-500/10 text-red-500',
    high: 'bg-orange/10 text-orange',
    medium: 'bg-amber-500/10 text-amber-500',
};

export function GlobalSearch() {
    const router = useRouter();
    const [query, setQuery] = useState('');
    const [open, setOpen] = useState(false);
    const [found, setFound] = useState<{ q: string; results: SearchResult[]; error?: string } | null>(null);
    const [active, setActive] = useState(0);
    const boxRef = useRef<HTMLDivElement>(null);
    const inputRef = useRef<HTMLInputElement>(null);

    const q = query.trim();
    const ready = found?.q === q;
    const results = ready ? found.results : [];
    const loading = q.length >= 2 && !ready;

    useEffect(() => {
        if (q.length < 2) return;
        const timer = setTimeout(() => {
            apiFetch(apiUrl(`/api/search?q=${encodeURIComponent(q)}`), { cache: 'no-store' })
                .then(async (r) => {
                    const data = await r.json().catch(() => ({}));
                    if (!r.ok) throw new Error(data?.error ?? `HTTP ${r.status}`);
                    setFound({ q, results: Array.isArray(data?.results) ? data.results : [] });
                })
                .catch((e: unknown) => setFound({ q, results: [], error: e instanceof Error ? e.message : 'Search failed' }));
        }, 300);
        return () => clearTimeout(timer);
    }, [q]);

    // Outside click closes; Ctrl/⌘+K focuses from anywhere on the page.
    useEffect(() => {
        const onMouseDown = (e: MouseEvent) => {
            if (boxRef.current && !boxRef.current.contains(e.target as Node)) setOpen(false);
        };
        const onKeyDown = (e: KeyboardEvent) => {
            if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
                e.preventDefault();
                inputRef.current?.focus();
                setOpen(true);
            }
        };
        document.addEventListener('mousedown', onMouseDown);
        document.addEventListener('keydown', onKeyDown);
        return () => {
            document.removeEventListener('mousedown', onMouseDown);
            document.removeEventListener('keydown', onKeyDown);
        };
    }, []);

    const go = (r: SearchResult) => {
        setQuery('');
        setOpen(false);
        router.push(r.url);
    };

    const onKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
        if (e.key === 'Escape') { setOpen(false); inputRef.current?.blur(); return; }
        if (results.length === 0) return;
        if (e.key === 'ArrowDown') { e.preventDefault(); setActive((i) => (i + 1) % results.length); }
        if (e.key === 'ArrowUp') { e.preventDefault(); setActive((i) => (i - 1 + results.length) % results.length); }
        if (e.key === 'Enter') { e.preventDefault(); go(results[Math.min(active, results.length - 1)]); }
    };

    const showPanel = open && q.length >= 2;

    return (
        <div ref={boxRef} className="relative w-full max-w-[480px]">
            <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-grey-500 pointer-events-none" />
            <input
                ref={inputRef}
                type="search"
                value={query}
                onChange={(e) => { setQuery(e.target.value); setActive(0); setOpen(true); }}
                onFocus={() => setOpen(true)}
                onKeyDown={onKeyDown}
                placeholder="Search cases, alerts, IOCs, advisories…"
                aria-label="Search cases, alerts, IOCs and advisories"
                role="combobox"
                aria-expanded={showPanel}
                aria-controls="global-search-results"
                className="w-full bg-grey-50 border border-grey-100 rounded-lg pl-9 pr-16 py-2 text-sm text-grey-800 placeholder:text-grey-500 focus:outline-none focus:border-blue focus:ring-1 focus:ring-blue/20"
            />
            {loading ? (
                <span className="absolute right-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 border-2 border-blue/30 border-t-blue rounded-full animate-spin" aria-hidden />
            ) : (
                <kbd className="absolute right-3 top-1/2 -translate-y-1/2 border border-grey-100 rounded px-1.5 py-0.5 text-xs text-grey-500 font-mono pointer-events-none">⌘K</kbd>
            )}

            {showPanel && (
                <div id="global-search-results" role="listbox" className="absolute top-full left-0 right-0 mt-1 bg-white border border-grey-100 rounded-xl shadow-xl z-50 max-h-96 overflow-y-auto">
                    {loading && results.length === 0 ? (
                        <p className="px-4 py-5 text-center text-xs text-grey-500">Searching…</p>
                    ) : found?.error && ready ? (
                        <p className="px-4 py-5 text-center text-xs text-red">Search failed: {found.error}</p>
                    ) : results.length === 0 ? (
                        <p className="px-4 py-5 text-center text-xs text-grey-500">No results for &quot;{q}&quot;</p>
                    ) : (
                        <>
                            {results.map((r, i) => {
                                const Icon = ICON[r.type] ?? Search;
                                return (
                                    <button
                                        key={`${r.type}-${r.url}-${i}`}
                                        role="option"
                                        aria-selected={i === active}
                                        onMouseEnter={() => setActive(i)}
                                        onClick={() => go(r)}
                                        className={`w-full text-left flex items-center gap-3 px-4 py-2.5 border-b border-grey-100 last:border-0 ${i === active ? 'bg-grey-50' : ''}`}
                                    >
                                        <Icon size={15} className="text-grey-500 shrink-0" />
                                        <div className="flex-1 min-w-0">
                                            <p className="text-xs font-bold text-grey-800 truncate">{r.title}</p>
                                            <p className="text-[10px] text-grey-500 truncate capitalize">{r.type} · {r.subtitle}</p>
                                        </div>
                                        {r.badge && (
                                            <span className={`text-[9px] font-bold px-2 py-0.5 rounded-full shrink-0 uppercase ${BADGE[r.badge] ?? 'bg-grey-50 text-grey-500'}`}>{r.badge}</span>
                                        )}
                                    </button>
                                );
                            })}
                            <p className="px-4 py-2 text-center text-[10px] text-grey-500 border-t border-grey-100">
                                {results.length} result{results.length === 1 ? '' : 's'} · ↑↓ to move · Enter to open
                            </p>
                        </>
                    )}
                </div>
            )}
        </div>
    );
}
