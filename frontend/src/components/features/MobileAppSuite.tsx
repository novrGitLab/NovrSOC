'use client';

import { useEffect, useState } from 'react';
import { Smartphone, Plus, Apple, CheckCircle, ExternalLink, Search, Info, Trash2 } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { EmptyState } from '@/components/shared/EmptyState';
import { ExportButton } from '@/components/shared/ExportButton';

interface OfficialApp {
    id: string;
    name: string;
    bundle_id: string;
    platform: 'iOS' | 'Android';
    developer: string;
    store_url_ios: string | null;
    store_url_android: string | null;
    added_at: string;
    last_scanned: string | null;
    verified: boolean | null;
}

interface RogueApp {
    id: string;
    name: string;
    platform: string;
    developer: string;
    bundle_id: string;
    downloads: number;
    risk: string;
    detected: string;
    reason: string;
    store_url: string;
}

interface AppStoreHit {
    name: string;
    bundle_id: string;
    developer: string;
    store_url: string;
    icon_url: string;
    price: string;
    rating: number | null;
    review_count: number | null;
}

interface PlayStoreHit {
    name: string;
    bundle_id: string;
    developer: string;
    store_url: string;
    icon_url: string;
    rating: number | null;
}

interface ScanResponse {
    brand_name: string;
    scanned_at: string;
    appstore: AppStoreHit[];
    playstore: PlayStoreHit[];
}

function riskBadge(risk: string): string {
    if (risk === 'HIGH') return 'bg-red-500 text-white';
    if (risk === 'MEDIUM') return 'border border-purple text-purple';
    return 'border border-grey-300 text-foreground-muted';
}

export function MobileAppSuite() {
    const [apps, setApps] = useState<OfficialApp[]>([]);
    const [rogueApps, setRogueApps] = useState<RogueApp[]>([]);
    const [loading, setLoading] = useState(true);
    const [scanning, setScanning] = useState(false);
    const [scanResult, setScanResult] = useState<ScanResponse | null>(null);
    const [showAddModal, setShowAddModal] = useState(false);
    const [name, setName] = useState('');
    const [bundleId, setBundleId] = useState('');
    const [platform, setPlatform] = useState<'iOS' | 'Android' | 'Both'>('iOS');
    const [developer, setDeveloper] = useState('');
    const [appStoreUrl, setAppStoreUrl] = useState('');
    const [playStoreUrl, setPlayStoreUrl] = useState('');
    const [saving, setSaving] = useState(false);
    const [appSearch, setAppSearch] = useState('');

    const load = () => {
        setLoading(true);
        Promise.all([
            apiFetch(apiUrl('/api/brand/apps'), { cache: 'no-store' }).then((r) => r.json()).catch(() => ({ apps: [] })),
            apiFetch(apiUrl('/api/brand/apps/alerts'), { cache: 'no-store' }).then((r) => r.json()).catch(() => ({ rogueApps: [] })),
        ]).then(([appsRes, alertRes]) => {
            setApps(Array.isArray(appsRes?.apps) ? appsRes.apps : []);
            setRogueApps(Array.isArray(alertRes?.rogueApps) ? alertRes.rogueApps : []);
            setLoading(false);
        });
    };

    useEffect(load, []);

    const addApp = async () => {
        if (!name.trim()) return;
        setSaving(true);
        try {
            const platforms: Array<'iOS' | 'Android'> = platform === 'Both' ? ['iOS', 'Android'] : [platform];
            await Promise.all(platforms.map((p) => apiFetch(apiUrl('/api/brand/apps'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    name: name.trim(),
                    bundle_id: bundleId.trim() || undefined,
                    platform: p,
                    developer: developer.trim() || undefined,
                    store_url_ios: appStoreUrl.trim() || undefined,
                    store_url_android: playStoreUrl.trim() || undefined,
                }),
            })));
            setName(''); setBundleId(''); setDeveloper(''); setAppStoreUrl(''); setPlayStoreUrl('');
            setShowAddModal(false);
            load();
        } finally {
            setSaving(false);
        }
    };

    const runScan = async () => {
        setScanning(true);
        try {
            const brandName = apps[0]?.name ?? 'cybernovr';
            const res = await apiFetch(apiUrl('/api/brand/apps/scan'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ brand_name: brandName }),
            });
            const data: ScanResponse = await res.json();
            setScanResult(data);
        } finally {
            setScanning(false);
        }
    };

    const officialDevelopers = new Set(apps.map((a) => a.developer.toLowerCase()).filter(Boolean));
    const isOfficial = (developer: string) => officialDevelopers.size > 0 && officialDevelopers.has(developer.toLowerCase());

    // No `category` field exists on OfficialApp — this data model only tracks name, developer,
    // bundle ID, and platform (iOS/Android) for a monitored app listing, not a store category.
    // `platform` is matched here as the closest real equivalent to a "store" filter.
    const filteredApps = apps.filter((app) => {
        const q = appSearch.trim().toLowerCase();
        if (!q) return true;
        return (
            app.name.toLowerCase().includes(q) ||
            app.developer.toLowerCase().includes(q) ||
            app.bundle_id.toLowerCase().includes(q) ||
            app.platform.toLowerCase().includes(q)
        );
    });

    // No DELETE /api/brand/apps/:id endpoint exists on the backend yet — this removes the
    // entry from local state only (it reappears on next refresh/reload). Wire this to a real
    // delete call once that route exists.
    const handleRemoveApp = (id: string) => {
        if (!confirm('Remove this app from monitoring?')) return;
        setApps((prev) => prev.filter((a) => a.id !== id));
    };

    return (
        <div id="report-content" className="space-y-4">
            <div className="flex items-start justify-between">
                <div>
                    <h1 className="text-lg font-black text-foreground">Mobile App Suite</h1>
                    <p className="text-xs text-foreground-muted">Brand Protection · Detect fake and malicious mobile apps impersonating your brand</p>
                </div>
                <ExportButton elementId="report-content" filename="mobile-app-suite" title="Mobile App Suite" />
            </div>

            {/* Info banner */}
            <div className="flex items-start gap-2 bg-blue/5 border border-blue/20 rounded-lg p-3">
                <Info size={14} className="text-blue flex-shrink-0 mt-0.5" />
                <p className="text-xs text-foreground-muted">
                    Mobile App Suite monitors the Apple App Store and Google Play Store for apps using your brand name.
                    If someone publishes a fake app pretending to be you, NovrSOC detects it and alerts you before your clients download it.
                </p>
            </div>

            {/* Step 1 */}
            <div>
                <div className="flex items-center justify-between mb-2 gap-3">
                    <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider flex-shrink-0">Step 1 — Your Official Apps</p>
                    <button onClick={() => setShowAddModal(true)} className="flex items-center gap-1.5 text-[11px] font-bold text-blue hover:underline flex-shrink-0">
                        <Plus size={12} /> Add Official App
                    </button>
                </div>
                {apps.length > 0 && (
                    <div className="mb-3">
                        <div className="relative">
                            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-foreground-muted" />
                            <input
                                value={appSearch}
                                onChange={(e) => setAppSearch(e.target.value)}
                                placeholder="Search apps by name, developer, platform, or bundle ID…"
                                className="w-full pl-9 pr-4 py-2.5 bg-card-muted border border-border rounded-xl text-sm text-foreground placeholder:text-foreground-muted focus:outline-none focus:border-blue"
                            />
                        </div>
                        <p className="text-[10px] text-foreground-muted mt-1.5">
                            Showing {filteredApps.length} of {apps.length} app{apps.length === 1 ? '' : 's'}
                        </p>
                    </div>
                )}
                {loading ? (
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        {Array.from({ length: 2 }).map((_, i) => <div key={i} className="h-16 bg-card-muted rounded-xl animate-pulse" />)}
                    </div>
                ) : apps.length === 0 ? (
                    <EmptyState icon={Smartphone} title="No apps configured" description="Add your official app listings to begin monitoring for clones and fakes." actionLabel="Add Official App" onAction={() => setShowAddModal(true)} />
                ) : filteredApps.length === 0 ? (
                    <div className="bg-card border border-border rounded-xl py-8 text-center">
                        <p className="text-xs text-foreground-muted">No apps match &quot;{appSearch}&quot;</p>
                    </div>
                ) : (
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        {filteredApps.map((app) => (
                            <div key={app.id} className="bg-card border border-border rounded-xl p-4 flex items-center gap-3">
                                <div className="w-10 h-10 rounded-lg bg-blue/10 flex items-center justify-center flex-shrink-0">
                                    {app.platform === 'iOS' ? <Apple size={18} className="text-blue" /> : <Smartphone size={18} className="text-blue" />}
                                </div>
                                <div className="min-w-0 flex-1">
                                    <div className="flex items-center gap-1.5">
                                        <span className="text-sm font-bold text-foreground truncate">{app.name}</span>
                                        {app.verified && <CheckCircle size={13} className="text-blue flex-shrink-0" />}
                                    </div>
                                    <p className="text-[11px] text-foreground-muted font-mono truncate">{app.bundle_id}</p>
                                    <p className="text-[11px] text-foreground-muted">{app.developer}</p>
                                </div>
                                <div className="flex flex-col items-end gap-1.5 flex-shrink-0">
                                    <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-card-muted text-foreground-muted">{app.platform}</span>
                                    <button
                                        onClick={() => handleRemoveApp(app.id)}
                                        className="text-[10px] text-red-500 font-medium hover:underline flex items-center gap-1"
                                    >
                                        <Trash2 size={11} /> Remove
                                    </button>
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>

            {/* Step 2 */}
            <div>
                <div className="flex items-center justify-between mb-2">
                    <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">Step 2 — Scan Results</p>
                    <button
                        onClick={runScan}
                        disabled={scanning}
                        className="flex items-center gap-2 bg-amber hover:opacity-90 disabled:opacity-60 text-white text-xs font-black px-4 py-2 rounded-lg transition-colors"
                    >
                        <Search size={12} className={scanning ? 'animate-pulse' : ''} />
                        {scanning ? 'Searching…' : 'Search Both Stores'}
                    </button>
                </div>

                {!scanResult ? (
                    <div className="bg-card border border-border rounded-xl py-10 text-center">
                        <p className="text-xs text-foreground-muted">Run a scan to search the Apple App Store and Google Play for apps using your brand name.</p>
                    </div>
                ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div className="bg-card border border-border rounded-xl overflow-hidden">
                            <div className="px-4 py-2.5 border-b border-border flex items-center gap-2">
                                <Apple size={14} className="text-foreground-muted" />
                                <p className="text-xs font-bold text-foreground">Apple App Store ({scanResult.appstore.length})</p>
                            </div>
                            {scanResult.appstore.length === 0 ? (
                                <p className="text-xs text-foreground-muted text-center py-8">No results found</p>
                            ) : (
                                <div className="divide-y divide-border max-h-96 overflow-y-auto">
                                    {scanResult.appstore.map((hit, i) => {
                                        const official = isOfficial(hit.developer);
                                        return (
                                            <div key={i} className="p-3 flex items-center gap-3">
                                                {/* eslint-disable-next-line @next/next/no-img-element */}
                                                <img src={hit.icon_url} alt="" className="w-9 h-9 rounded-lg flex-shrink-0 bg-card-muted" />
                                                <div className="min-w-0 flex-1">
                                                    <p className="text-xs font-bold text-foreground truncate">{hit.name}</p>
                                                    <p className="text-[10px] text-foreground-muted">Developer: {hit.developer}</p>
                                                    <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded mt-1 inline-block ${official ? 'bg-blue/10 text-blue' : 'bg-grey-100 text-amber'}`}>
                                                        {official ? '✅ Your Official App' : '⚠️ Unknown Developer'}
                                                    </span>
                                                </div>
                                                <div className="flex flex-col items-end gap-1 flex-shrink-0">
                                                    <a href={hit.store_url} target="_blank" rel="noreferrer" className="text-[10px] font-bold text-blue hover:underline flex items-center gap-1">
                                                        View <ExternalLink size={9} />
                                                    </a>
                                                    {!official && <button className="text-[10px] font-bold text-red-500 hover:underline">Report to Apple</button>}
                                                </div>
                                            </div>
                                        );
                                    })}
                                </div>
                            )}
                        </div>

                        <div className="bg-card border border-border rounded-xl overflow-hidden">
                            <div className="px-4 py-2.5 border-b border-border flex items-center gap-2">
                                <Smartphone size={14} className="text-foreground-muted" />
                                <p className="text-xs font-bold text-foreground">Google Play Store ({scanResult.playstore.length})</p>
                            </div>
                            {scanResult.playstore.length === 0 ? (
                                <p className="text-xs text-foreground-muted text-center py-8">No results found</p>
                            ) : (
                                <div className="divide-y divide-border max-h-96 overflow-y-auto">
                                    {scanResult.playstore.map((hit, i) => {
                                        const official = isOfficial(hit.developer);
                                        return (
                                            <div key={i} className="p-3 flex items-center gap-3">
                                                {/* eslint-disable-next-line @next/next/no-img-element */}
                                                <img src={hit.icon_url} alt="" className="w-9 h-9 rounded-lg flex-shrink-0 bg-card-muted" />
                                                <div className="min-w-0 flex-1">
                                                    <p className="text-xs font-bold text-foreground truncate">{hit.name}</p>
                                                    <p className="text-[10px] text-foreground-muted">Developer: {hit.developer}</p>
                                                    <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded mt-1 inline-block ${official ? 'bg-blue/10 text-blue' : 'bg-grey-100 text-amber'}`}>
                                                        {official ? '✅ Your Official App' : '⚠️ Unknown Developer'}
                                                    </span>
                                                </div>
                                                <div className="flex flex-col items-end gap-1 flex-shrink-0">
                                                    <a href={hit.store_url} target="_blank" rel="noreferrer" className="text-[10px] font-bold text-blue hover:underline flex items-center gap-1">
                                                        View <ExternalLink size={9} />
                                                    </a>
                                                    {!official && <button className="text-[10px] font-bold text-red-500 hover:underline">Report to Google</button>}
                                                </div>
                                            </div>
                                        );
                                    })}
                                </div>
                            )}
                        </div>
                    </div>
                )}
            </div>

            {/* Step 3 */}
            <div>
                <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider mb-2">Step 3 — Rogue App Alerts</p>
                <div className="bg-card border border-border rounded-xl overflow-hidden">
                    {loading ? (
                        <div className="p-4 space-y-2">{Array.from({ length: 2 }).map((_, i) => <div key={i} className="h-6 bg-card-muted rounded animate-pulse" />)}</div>
                    ) : rogueApps.length === 0 ? (
                        <p className="text-xs text-foreground-muted text-center py-10">Rogue app detection is not connected yet — run a store scan above to search the app stores.</p>
                    ) : (
                        <table className="w-full text-xs">
                            <thead>
                                <tr className="border-b border-border">
                                    {['App Name', 'Store', 'Developer', 'Downloads', 'Risk', 'Action'].map((h) => (
                                        <th key={h} className="text-left px-4 py-2.5 text-[10px] font-bold text-foreground-muted uppercase tracking-wider">{h}</th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody>
                                {rogueApps.map((app) => (
                                    <tr key={app.id} className="border-b border-border hover:bg-card-muted">
                                        <td className="px-4 py-2.5">
                                            <p className="font-semibold text-foreground">{app.name}</p>
                                            {app.reason && <p className="text-[10px] text-foreground-muted mt-0.5 max-w-[240px]">{app.reason}</p>}
                                        </td>
                                        <td className="px-4 py-2.5 text-foreground-muted">{app.platform}</td>
                                        <td className="px-4 py-2.5 text-foreground-muted">{app.developer}</td>
                                        <td className="px-4 py-2.5 text-foreground-muted">{app.downloads.toLocaleString()}+</td>
                                        <td className="px-4 py-2.5">
                                            <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${riskBadge(app.risk)}`}>{app.risk}</span>
                                        </td>
                                        <td className="px-4 py-2.5">
                                            <div className="flex items-center gap-3">
                                                <a href={app.store_url} target="_blank" rel="noreferrer" className="text-[10px] font-bold text-blue hover:underline flex items-center gap-1">
                                                    View <ExternalLink size={10} />
                                                </a>
                                                <button className="text-[10px] font-bold text-red-500 hover:underline">Report to Store</button>
                                                <button className="text-[10px] font-bold text-foreground-muted hover:text-foreground">Mark Safe</button>
                                            </div>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    )}
                </div>
            </div>

            {showAddModal && (
                <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 px-4">
                    <div className="bg-card border border-border rounded-2xl p-6 w-full max-w-md shadow-xl">
                        <h3 className="font-heading font-bold text-lg text-foreground mb-4">Add Official App</h3>
                        <div className="space-y-4">
                            <div>
                                <label className="text-xs font-medium text-foreground-muted uppercase tracking-wide">App Name</label>
                                <input type="text" value={name} onChange={(e) => setName(e.target.value)} placeholder="NovrSOC"
                                    className="w-full mt-1 bg-card-muted border border-border rounded-lg px-3 py-2.5 text-sm text-foreground placeholder:text-foreground-muted focus:outline-none focus:border-blue" />
                            </div>
                            <div>
                                <label className="text-xs font-medium text-foreground-muted uppercase tracking-wide">Platform</label>
                                <select value={platform} onChange={(e) => setPlatform(e.target.value as 'iOS' | 'Android' | 'Both')}
                                    className="w-full mt-1 bg-card-muted border border-border rounded-lg px-3 py-2.5 text-sm text-foreground focus:outline-none focus:border-blue">
                                    <option value="iOS">iOS</option>
                                    <option value="Android">Android</option>
                                    <option value="Both">Both</option>
                                </select>
                            </div>
                            <div>
                                <label className="text-xs font-medium text-foreground-muted uppercase tracking-wide">Bundle ID</label>
                                <input type="text" value={bundleId} onChange={(e) => setBundleId(e.target.value)} placeholder="com.cybernovr.novrsoc"
                                    className="w-full mt-1 bg-card-muted border border-border rounded-lg px-3 py-2.5 text-sm font-mono text-foreground placeholder:text-foreground-muted focus:outline-none focus:border-blue" />
                            </div>
                            <div>
                                <label className="text-xs font-medium text-foreground-muted uppercase tracking-wide">Official Developer Name</label>
                                <input type="text" value={developer} onChange={(e) => setDeveloper(e.target.value)} placeholder="Cybernovr Ltd"
                                    className="w-full mt-1 bg-card-muted border border-border rounded-lg px-3 py-2.5 text-sm text-foreground placeholder:text-foreground-muted focus:outline-none focus:border-blue" />
                            </div>
                            <div>
                                <label className="text-xs font-medium text-foreground-muted uppercase tracking-wide">App Store URL <span className="normal-case text-foreground-muted/70">(optional)</span></label>
                                <input type="text" value={appStoreUrl} onChange={(e) => setAppStoreUrl(e.target.value)} placeholder="https://apps.apple.com/..."
                                    className="w-full mt-1 bg-card-muted border border-border rounded-lg px-3 py-2.5 text-sm text-foreground placeholder:text-foreground-muted focus:outline-none focus:border-blue" />
                            </div>
                            <div>
                                <label className="text-xs font-medium text-foreground-muted uppercase tracking-wide">Play Store URL <span className="normal-case text-foreground-muted/70">(optional)</span></label>
                                <input type="text" value={playStoreUrl} onChange={(e) => setPlayStoreUrl(e.target.value)} placeholder="https://play.google.com/..."
                                    className="w-full mt-1 bg-card-muted border border-border rounded-lg px-3 py-2.5 text-sm text-foreground placeholder:text-foreground-muted focus:outline-none focus:border-blue" />
                            </div>
                        </div>
                        <div className="flex gap-3 mt-6">
                            <button onClick={() => setShowAddModal(false)} className="flex-1 border border-border text-foreground-muted py-2.5 rounded-lg text-sm hover:border-grey-300 transition-colors">Cancel</button>
                            <button onClick={addApp} disabled={saving || !name.trim()} className="flex-1 bg-orange hover:bg-orange-hover disabled:opacity-60 text-white py-2.5 rounded-lg text-sm font-semibold transition-colors">
                                {saving ? 'Saving…' : 'Save'}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
