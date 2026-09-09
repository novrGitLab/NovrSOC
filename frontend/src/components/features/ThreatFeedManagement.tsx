'use client';

import { useState } from 'react';
import {
    Database, Plus, X, RefreshCw, Eye, Pencil, Trash2, CheckCircle2, AlertTriangle,
} from 'lucide-react';

// Mock data only — this domain has no backend route yet (routes/threat-intel.ts and
// routes/ctip.ts power the built-in CTI Platform sources, not custom feed management).
// See the final delivery report for which of the new pages in this batch are wired to a
// real endpoint vs. UI-only like this one.

interface Feed {
    id: string;
    name: string;
    type: string;
    format: string;
    url: string;
    status: 'active' | 'configured' | 'error' | 'disabled';
    last_updated: string | null;
    ioc_count: number;
    update_interval: string;
    categories: string[];
    is_free: boolean;
}

const ACTIVE_FEEDS: Feed[] = [
    { id: 'feed_001', name: 'Abuse.ch URLHaus', type: 'url', format: 'csv', url: 'https://urlhaus.abuse.ch/downloads/csv_recent/', status: 'active', last_updated: '2026-08-24 06:00', ioc_count: 847293, update_interval: '5 minutes', categories: ['malware', 'phishing'], is_free: true },
    { id: 'feed_002', name: 'Abuse.ch ThreatFox', type: 'mixed', format: 'json', url: 'https://threatfox-api.abuse.ch/api/v1/', status: 'active', last_updated: '2026-08-24 06:00', ioc_count: 234817, update_interval: '1 hour', categories: ['malware', 'c2', 'botnet'], is_free: true },
    { id: 'feed_003', name: 'CIRCL OSINT Feed', type: 'mixed', format: 'json', url: 'https://www.circl.lu/doc/misp/feed-osint/manifest.json', status: 'active', last_updated: '2026-09-09 00:00', ioc_count: 0, update_interval: '6 hours', categories: ['ip', 'domain', 'hash', 'url'], is_free: true },
    { id: 'feed_004', name: 'CISA Known Exploited Vulnerabilities', type: 'cve', format: 'json', url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', status: 'active', last_updated: '2026-08-24 00:00', ioc_count: 1073, update_interval: '24 hours', categories: ['cve', 'vulnerability'], is_free: true },
    { id: 'feed_005', name: 'Emerging Threats Rules', type: 'suricata', format: 'rules', url: 'https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz', status: 'configured', last_updated: null, ioc_count: 0, update_interval: '24 hours', categories: ['ids', 'suricata'], is_free: true },
];

const AVAILABLE_FEEDS = [
    { name: 'MISP Community', type: 'stix', cost: 'Free', description: 'Community threat sharing platform' },
    { name: 'Shodan Feeds', type: 'json', cost: '$49 one-time', description: 'Internet-wide scan data' },
    { name: 'VirusTotal Intelligence', type: 'json', cost: '$299/mo', description: 'Enterprise threat intelligence' },
    { name: 'Recorded Future', type: 'stix', cost: 'Enterprise', description: 'Premium threat intelligence' },
    { name: 'TAXII Feed (custom)', type: 'taxii', cost: 'Varies', description: 'Any STIX/TAXII compatible source' },
    { name: 'Nigeria Cybercrime Feed', type: 'csv', cost: 'Free (NGCERT)', description: 'Nigerian Computer Emergency Response Team IOCs' },
];

const STATUS_DOT: Record<Feed['status'], string> = {
    active: 'bg-green', configured: 'bg-amber', error: 'bg-red', disabled: 'bg-grey-300',
};

const TABS = [
    { id: 'active', label: 'Active Feeds' },
    { id: 'available', label: 'Available Feeds' },
    { id: 'health', label: 'Feed Health' },
] as const;
type Tab = (typeof TABS)[number]['id'];

export function ThreatFeedManagement() {
    const [feeds, setFeeds] = useState<Feed[]>(ACTIVE_FEEDS);
    const [tab, setTab] = useState<Tab>('active');
    const [showAdd, setShowAdd] = useState(false);
    const [newFeed, setNewFeed] = useState({ name: '', url: '', format: 'json', type: 'mixed', interval: '1 hour', apiKey: '' });
    const [testing, setTesting] = useState(false);
    const [testResult, setTestResult] = useState<string | null>(null);

    const toggleFeed = (id: string) => {
        setFeeds((prev) => prev.map((f) => (f.id === id ? { ...f, status: f.status === 'disabled' ? 'active' : 'disabled' } : f)));
    };
    const removeFeed = (id: string) => setFeeds((prev) => prev.filter((f) => f.id !== id));

    const testConnection = () => {
        setTesting(true);
        setTestResult(null);
        setTimeout(() => {
            setTesting(false);
            setTestResult(newFeed.url.startsWith('http') ? 'Connection successful — feed responded in 340ms' : 'Could not reach that URL');
        }, 900);
    };

    const addFeed = () => {
        if (!newFeed.name || !newFeed.url) return;
        setFeeds((prev) => [
            ...prev,
            {
                id: `feed_${Date.now()}`,
                name: newFeed.name,
                type: newFeed.type,
                format: newFeed.format,
                url: newFeed.url,
                status: 'configured',
                last_updated: null,
                ioc_count: 0,
                update_interval: newFeed.interval,
                categories: [],
                is_free: true,
            },
        ]);
        setShowAdd(false);
        setNewFeed({ name: '', url: '', format: 'json', type: 'mixed', interval: '1 hour', apiKey: '' });
        setTestResult(null);
    };

    return (
        <div className="space-y-4">
            <div className="flex items-start justify-between gap-4 flex-wrap">
                <div>
                    <h1 className="text-lg font-black text-foreground">Threat Feed Management</h1>
                    <p className="text-xs text-foreground-muted">Threat Intelligence · Manage external feeds that supplement the built-in CTI Platform sources.</p>
                </div>
                <button onClick={() => setShowAdd(true)} className="flex items-center gap-2 bg-orange hover:bg-orange-hover text-white text-xs font-bold px-4 py-2.5 rounded-lg transition-colors flex-shrink-0">
                    <Plus size={14} /> Add Feed
                </button>
            </div>

            <div className="flex gap-1 border-b border-border">
                {TABS.map((t) => (
                    <button key={t.id} onClick={() => setTab(t.id)}
                        className={`px-4 py-2.5 text-xs font-bold border-b-2 transition-colors ${tab === t.id ? 'border-blue text-blue' : 'border-transparent text-foreground-muted hover:text-foreground'}`}>
                        {t.label}
                    </button>
                ))}
            </div>

            {tab === 'active' && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {feeds.map((f) => (
                        <div key={f.id} className="bg-card border border-border rounded-xl p-4">
                            <div className="flex items-start justify-between gap-3 mb-2">
                                <div className="min-w-0">
                                    <div className="flex items-center gap-2">
                                        <span className={`w-2 h-2 rounded-full flex-shrink-0 ${STATUS_DOT[f.status]}`} />
                                        <p className="text-sm font-bold text-foreground truncate">{f.name}</p>
                                    </div>
                                    <p className="text-[10px] text-foreground-muted font-mono mt-0.5 truncate">{f.url}</p>
                                </div>
                                <button onClick={() => toggleFeed(f.id)} aria-label="Toggle feed"
                                    className={`w-10 h-5 rounded-full transition-colors flex-shrink-0 relative ${f.status === 'disabled' ? 'bg-card-muted' : 'bg-blue'}`}>
                                    <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-transform ${f.status === 'disabled' ? 'translate-x-0.5' : 'translate-x-5'}`} />
                                </button>
                            </div>

                            <div className="grid grid-cols-3 gap-2 my-3 text-center">
                                <div className="bg-card-muted rounded-lg py-2">
                                    <p className="text-sm font-black text-foreground">{f.ioc_count.toLocaleString()}</p>
                                    <p className="text-[9px] text-foreground-muted uppercase tracking-wide">IOCs</p>
                                </div>
                                <div className="bg-card-muted rounded-lg py-2">
                                    <p className="text-sm font-black text-foreground uppercase">{f.format}</p>
                                    <p className="text-[9px] text-foreground-muted uppercase tracking-wide">Format</p>
                                </div>
                                <div className="bg-card-muted rounded-lg py-2">
                                    <p className="text-sm font-black text-foreground">{f.update_interval}</p>
                                    <p className="text-[9px] text-foreground-muted uppercase tracking-wide">Interval</p>
                                </div>
                            </div>

                            <div className="flex items-center justify-between gap-2 mb-3">
                                <div className="flex flex-wrap gap-1">
                                    {f.categories.map((c) => (
                                        <span key={c} className="text-[9px] font-bold px-1.5 py-0.5 bg-blue/10 text-blue rounded-full uppercase">{c}</span>
                                    ))}
                                </div>
                                <span className="text-[10px] text-foreground-muted flex-shrink-0">{f.last_updated ?? 'Never run'}</span>
                            </div>

                            <div className="flex gap-2">
                                <button className="flex-1 flex items-center justify-center gap-1.5 text-[10px] font-bold px-3 py-1.5 bg-blue hover:opacity-90 text-white rounded-lg transition-colors"><Eye size={11} /> View IOCs</button>
                                <button className="flex items-center gap-1 text-[10px] font-bold px-3 py-1.5 border border-border text-foreground-muted rounded-lg hover:bg-card-muted transition-colors"><Pencil size={11} /> Edit</button>
                                <button onClick={() => removeFeed(f.id)} className="flex items-center gap-1 text-[10px] font-bold px-3 py-1.5 border border-red/30 text-red rounded-lg hover:bg-red/10 transition-colors"><Trash2 size={11} /></button>
                            </div>
                        </div>
                    ))}
                </div>
            )}

            {tab === 'available' && (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {AVAILABLE_FEEDS.map((f) => (
                        <div key={f.name} className="bg-card border border-border rounded-xl p-4">
                            <div className="flex items-center gap-2 mb-2">
                                <Database size={16} className="text-purple flex-shrink-0" />
                                <p className="text-sm font-bold text-foreground">{f.name}</p>
                            </div>
                            <p className="text-xs text-foreground-muted mb-3">{f.description}</p>
                            <div className="flex items-center justify-between">
                                <span className="text-[9px] font-bold px-2 py-0.5 bg-card-muted text-foreground-muted rounded-full uppercase">{f.type}</span>
                                <span className={`text-xs font-bold ${f.cost === 'Free' || f.cost.startsWith('Free') ? 'text-green' : 'text-foreground'}`}>{f.cost}</span>
                            </div>
                            <button onClick={() => { setNewFeed((n) => ({ ...n, name: f.name, format: f.type })); setShowAdd(true); }}
                                className="w-full mt-3 flex items-center justify-center gap-1.5 text-[10px] font-bold px-3 py-2 border border-purple text-purple rounded-lg hover:bg-purple/5 transition-colors">
                                <Plus size={11} /> Add This Feed
                            </button>
                        </div>
                    ))}
                </div>
            )}

            {tab === 'health' && (
                <div className="bg-card border border-border rounded-xl overflow-hidden">
                    <div className="overflow-x-auto scrollbar-thin">
                        <table className="w-full text-left">
                            <thead>
                                <tr className="bg-grey-800">
                                    {['Feed', 'Last Successful Update', 'Next Update', 'Success Rate', 'Avg Response', 'Errors'].map((c) => (
                                        <th key={c} className="px-4 py-3 text-[10px] font-semibold text-white uppercase tracking-widest whitespace-nowrap">{c}</th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-border text-sm">
                                {feeds.map((f) => {
                                    const healthy = f.status === 'active';
                                    return (
                                        <tr key={f.id}>
                                            <td className="px-4 py-3 font-medium text-foreground whitespace-nowrap">{f.name}</td>
                                            <td className="px-4 py-3 text-foreground-muted whitespace-nowrap">{f.last_updated ?? '—'}</td>
                                            <td className="px-4 py-3 text-foreground-muted whitespace-nowrap">{healthy ? f.update_interval + ' from now' : '—'}</td>
                                            <td className="px-4 py-3">
                                                <span className={`font-bold ${healthy ? 'text-green' : 'text-amber'}`}>{healthy ? '99.4%' : '—'}</span>
                                            </td>
                                            <td className="px-4 py-3 text-foreground-muted whitespace-nowrap">{healthy ? '312ms' : '—'}</td>
                                            <td className="px-4 py-3">
                                                {healthy ? (
                                                    <span className="inline-flex items-center gap-1 text-green text-xs font-bold"><CheckCircle2 size={12} /> None</span>
                                                ) : (
                                                    <span className="inline-flex items-center gap-1 text-amber text-xs font-bold"><AlertTriangle size={12} /> Not yet run</span>
                                                )}
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}

            {showAdd && (
                <div className="fixed inset-0 bg-black/40 z-50 flex items-center justify-center p-4" onClick={() => setShowAdd(false)}>
                    <div className="bg-card border border-border rounded-xl p-6 max-w-md w-full" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-between mb-4">
                            <h3 className="font-heading font-semibold text-sm text-foreground">Add Feed</h3>
                            <button onClick={() => setShowAdd(false)} className="text-foreground-muted hover:text-foreground"><X size={16} /></button>
                        </div>
                        <div className="space-y-3">
                            <div>
                                <label className="text-xs font-medium text-foreground-muted uppercase tracking-wide">Feed Name</label>
                                <input value={newFeed.name} onChange={(e) => setNewFeed((n) => ({ ...n, name: e.target.value }))} placeholder="e.g. MISP Community"
                                    className="w-full mt-1 border border-border bg-card-muted rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue text-foreground" />
                            </div>
                            <div>
                                <label className="text-xs font-medium text-foreground-muted uppercase tracking-wide">Feed URL</label>
                                <input value={newFeed.url} onChange={(e) => setNewFeed((n) => ({ ...n, url: e.target.value }))} placeholder="https://..."
                                    className="w-full mt-1 border border-border bg-card-muted rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue text-foreground font-mono" />
                            </div>
                            <div className="grid grid-cols-2 gap-3">
                                <div>
                                    <label className="text-xs font-medium text-foreground-muted uppercase tracking-wide">Format</label>
                                    <select value={newFeed.format} onChange={(e) => setNewFeed((n) => ({ ...n, format: e.target.value }))}
                                        className="w-full mt-1 border border-border bg-card-muted rounded-lg px-3 py-2 text-sm focus:outline-none text-foreground">
                                        {['csv', 'json', 'stix', 'taxii', 'rules'].map((f) => <option key={f} value={f}>{f.toUpperCase()}</option>)}
                                    </select>
                                </div>
                                <div>
                                    <label className="text-xs font-medium text-foreground-muted uppercase tracking-wide">Type</label>
                                    <select value={newFeed.type} onChange={(e) => setNewFeed((n) => ({ ...n, type: e.target.value }))}
                                        className="w-full mt-1 border border-border bg-card-muted rounded-lg px-3 py-2 text-sm focus:outline-none text-foreground">
                                        {['ip', 'domain', 'hash', 'url', 'mixed', 'cve'].map((t) => <option key={t} value={t}>{t.toUpperCase()}</option>)}
                                    </select>
                                </div>
                            </div>
                            <div>
                                <label className="text-xs font-medium text-foreground-muted uppercase tracking-wide">Update Interval</label>
                                <select value={newFeed.interval} onChange={(e) => setNewFeed((n) => ({ ...n, interval: e.target.value }))}
                                    className="w-full mt-1 border border-border bg-card-muted rounded-lg px-3 py-2 text-sm focus:outline-none text-foreground">
                                    {['5 minutes', '1 hour', '6 hours', '24 hours'].map((i) => <option key={i} value={i}>{i}</option>)}
                                </select>
                            </div>
                            <div>
                                <label className="text-xs font-medium text-foreground-muted uppercase tracking-wide">API Key (optional)</label>
                                <input value={newFeed.apiKey} onChange={(e) => setNewFeed((n) => ({ ...n, apiKey: e.target.value }))} type="password"
                                    className="w-full mt-1 border border-border bg-card-muted rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-blue text-foreground" />
                            </div>

                            <button onClick={testConnection} disabled={!newFeed.url || testing}
                                className="w-full flex items-center justify-center gap-2 border border-blue text-blue text-xs font-bold py-2 rounded-lg hover:bg-blue/5 disabled:opacity-50 transition-colors">
                                {testing ? <RefreshCw size={12} className="animate-spin" /> : null}
                                {testing ? 'Testing…' : 'Test Connection'}
                            </button>
                            {testResult && <div className="text-xs text-foreground-muted bg-card-muted rounded-lg px-3 py-2">{testResult}</div>}

                            <button onClick={addFeed} disabled={!newFeed.name || !newFeed.url}
                                className="w-full bg-orange hover:bg-orange-hover text-white text-sm font-bold py-2.5 rounded-lg disabled:opacity-50 transition-colors">
                                Save Feed
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
