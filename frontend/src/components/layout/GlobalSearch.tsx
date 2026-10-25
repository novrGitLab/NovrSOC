'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import {
    Search, Briefcase, Siren, Megaphone, Crosshair, Server, Bug, ShieldAlert,
    Fingerprint, Users as UsersIcon, Building2, Compass, AlertTriangle, type LucideIcon,
} from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { getAdminUser } from '@/lib/admin-auth';
import { ADMIN_NAV } from '@/config/nav';
import type { NavRole } from './Sidebar';

// Header search (2026 redesign, Stage 3) — cases, stored and Wazuh-indexer alerts, cached IOC
// lookups, advisories, VMS assets/findings, CVEs, Threat Intelligence indicators, threat actors
// and CNII organisations (GET /api/search — admin only; each entity checks its own permission,
// so results reflect what the signed-in role can actually see, down to TLP markings for Threat
// Intelligence), plus application navigation, matched entirely client-side against config/nav.ts
// with no network call and no debounce.
//
// Results are stored with the query they answer, and "loading" is derived by comparing that to
// the current query, so a fast typist never sees the previous query's results under the new one
// and no setState runs synchronously inside the debounce effect.

type BackendType = 'case' | 'advisory' | 'ioc' | 'alert' | 'vms_asset' | 'vms_finding' | 'cve' | 'ti_indicator' | 'threat_actor' | 'cnii_org';
interface BackendResult { type: BackendType; title: string; subtitle: string; badge?: string; url: string }
interface SourceStatus { entity: BackendType; ok: boolean; error?: string }
interface NavResult { type: 'nav'; title: string; subtitle: string; url: string }
type SearchResult = BackendResult | NavResult;

const ICON: Record<SearchResult['type'], LucideIcon> = {
    case: Briefcase, alert: Siren, advisory: Megaphone, ioc: Crosshair,
    vms_asset: Server, vms_finding: Bug, cve: ShieldAlert, ti_indicator: Fingerprint,
    threat_actor: UsersIcon, cnii_org: Building2, nav: Compass,
};
const ENTITY_LABEL: Record<SearchResult['type'], string> = {
    case: 'case', alert: 'alert', advisory: 'advisory', ioc: 'IOC', vms_asset: 'VMS asset', vms_finding: 'VMS finding',
    cve: 'CVE', ti_indicator: 'indicator', threat_actor: 'threat actor', cnii_org: 'CNII', nav: 'page',
};

const BADGE: Record<string, string> = {
    critical: 'bg-red-500/10 text-red-500',
    high: 'bg-orange/10 text-orange',
    medium: 'bg-amber-500/10 text-amber-500',
};

/** Pages this role can reach, flattened from the sidebar's own data (config/nav.ts) — the same
 * visibility rule Sidebar.tsx applies, so search never suggests a page the role can't open. */
function navItemsFor(role: string): { label: string; href: string }[] {
    const out: { label: string; href: string }[] = [];
    for (const section of ADMIN_NAV) {
        for (const item of section.items) {
            if (item.roles === 'all' || (item.roles as NavRole[]).includes(role as NavRole)) out.push({ label: item.label, href: item.href });
        }
    }
    return out;
}

export function GlobalSearch() {
    const router = useRouter();
    const [role] = useState<string>(() => (typeof window === 'undefined' ? '' : getAdminUser().role));
    const navItems = useMemo(() => navItemsFor(role), [role]);
    const [query, setQuery] = useState('');
    const [open, setOpen] = useState(false);
    const [found, setFound] = useState<{ q: string; results: BackendResult[]; sources: SourceStatus[]; error?: string } | null>(null);
    const [active, setActive] = useState(0);
    const boxRef = useRef<HTMLDivElement>(null);
    const inputRef = useRef<HTMLInputElement>(null);

    const q = query.trim();
    const ready = found?.q === q;
    const backendResults = ready ? found.results : [];
    const loading = q.length >= 2 && !ready;
    const navResults: NavResult[] = useMemo(() => {
        if (q.length < 2) return [];
        const needle = q.toLowerCase();
        return navItems.filter((n) => n.label.toLowerCase().includes(needle)).slice(0, 4).map((n) => ({ type: 'nav' as const, title: n.label, subtitle: 'Go to page', url: n.href }));
    }, [q, navItems]);
    const results: SearchResult[] = [...navResults, ...backendResults];
    const failedSources = ready ? (found.sources ?? []).filter((s) => !s.ok) : [];

    useEffect(() => {
        if (q.length < 2) return;
        const timer = setTimeout(() => {
            apiFetch(apiUrl(`/api/search?q=${encodeURIComponent(q)}`), { cache: 'no-store' })
                .then(async (r) => {
                    const data = await r.json().catch(() => ({}));
                    if (!r.ok) throw new Error(data?.error ?? `HTTP ${r.status}`);
                    setFound({ q, results: Array.isArray(data?.results) ? data.results : [], sources: Array.isArray(data?.sources) ? data.sources : [] });
                })
                .catch((e: unknown) => setFound({ q, results: [], sources: [], error: e instanceof Error ? e.message : 'Search failed' }));
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
                placeholder="Search cases, assets, findings, indicators, pages…"
                aria-label="Search cases, assets, findings, indicators, advisories and pages"
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
                                            <p className="text-[10px] text-grey-500 truncate">{ENTITY_LABEL[r.type]} · {r.subtitle}</p>
                                        </div>
                                        {'badge' in r && r.badge && (
                                            <span className={`text-[9px] font-bold px-2 py-0.5 rounded-full shrink-0 uppercase ${BADGE[r.badge] ?? 'bg-grey-50 text-grey-500'}`}>{r.badge}</span>
                                        )}
                                    </button>
                                );
                            })}
                            <div className="px-4 py-2 border-t border-grey-100">
                                <p className="text-center text-[10px] text-grey-500">
                                    {results.length} result{results.length === 1 ? '' : 's'} · ↑↓ to move · Enter to open
                                </p>
                                {/* A source that failed is named here, distinct from a source that
                                    simply found nothing — the panel never implies "nothing found"
                                    when a source could not be checked at all. */}
                                {failedSources.length > 0 && (
                                    <p className="flex items-center justify-center gap-1 text-center text-[10px] text-amber mt-1">
                                        <AlertTriangle size={10} aria-hidden />
                                        Could not check: {failedSources.map((s) => ENTITY_LABEL[s.entity] ?? s.entity).join(', ')}
                                    </p>
                                )}
                            </div>
                        </>
                    )}
                </div>
            )}
        </div>
    );
}
