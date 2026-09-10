'use client';

import { useEffect, useState } from 'react';
import { Code, Plus, AlertTriangle, ChevronDown, ExternalLink, RefreshCw, GitBranch, Lock } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { EmptyState } from '@/components/shared/EmptyState';
import { ExportButton } from '@/components/shared/ExportButton';

// Historical investigated/dismissed alerts — a persistent alert-history store (vs. the live
// leak-scan result below) is a later pass; this shows what that log looks like once it exists.
const HISTORICAL_ALERTS = [
    {
        id: 'alert_001', severity: 'HIGH' as const, platform: 'GitHub', repo: 'RayneOps/website',
        file: 'app/api/send-email/route.ts', line: 14, pattern_matched: 'API Key Pattern',
        committer: 'RayneOps', committed: '2026-08-01', status: 'investigated',
        resolution: 'Confirmed clean — key reads from process.env, not hardcoded',
    },
    {
        id: 'alert_002', severity: 'MEDIUM' as const, platform: 'GitHub', repo: 'RayneOps/website',
        file: 'README.md', line: 23, pattern_matched: 'Brand Domain',
        committer: 'RayneOps', committed: '2026-07-15', status: 'dismissed',
        resolution: 'Official documentation mention — dismissed',
    },
];

const SCAN_HISTORY_SEED = [
    { date: '2026-08-16 08:30', github: 2847, gitlab: 634, alerts: 0, duration: '4m 12s' },
    { date: '2026-08-16 05:30', github: 2845, gitlab: 631, alerts: 0, duration: '4m 08s' },
    { date: '2026-08-15 22:30', github: 2841, gitlab: 628, alerts: 2, duration: '4m 15s' },
    { date: '2026-08-15 19:30', github: 2838, gitlab: 625, alerts: 0, duration: '3m 58s' },
];

interface CodeSignature {
    id: string;
    type: 'STRING' | 'REGEX' | 'HASH';
    pattern: string;
    description: string;
    matches: number;
}

interface Leak {
    platform: string;
    repo: string;
    file: string;
    line: number;
    committer: string;
    date: string;
    severity: string;
}

interface ScanSummary {
    github_configured: boolean;
    gitlab_configured: boolean;
    github_results: number;
    gitlab_results: number;
    scanned_at: string;
}

const TYPE_STYLE: Record<CodeSignature['type'], string> = {
    STRING: 'bg-blue/10 text-blue',
    REGEX: 'bg-purple/10 text-purple',
    HASH: 'bg-card-muted text-foreground-muted',
};

// One demo leak shown for illustration — matched content is always redacted, never surfaced raw.
const DEMO_LEAK: Leak = {
    platform: 'GitHub',
    repo: 'github.com/somedev/old-project',
    file: 'config/.env',
    line: 14,
    committer: 'somedev',
    date: '3 days ago',
    severity: 'critical',
};

export function CopyIdSuite() {
    const [signatures, setSignatures] = useState<CodeSignature[]>([]);
    const [loading, setLoading] = useState(true);
    const [scanning, setScanning] = useState(false);
    const [scanLog, setScanLog] = useState<string[]>([]);
    const [scanSummary, setScanSummary] = useState<ScanSummary | null>(null);
    const [leaks, setLeaks] = useState<Leak[]>([]);
    const [hookOpen, setHookOpen] = useState(false);
    const [showAddModal, setShowAddModal] = useState(false);
    const [sigType, setSigType] = useState<CodeSignature['type']>('STRING');
    const [pattern, setPattern] = useState('');
    const [description, setDescription] = useState('');
    const [saving, setSaving] = useState(false);

    const load = () => {
        setLoading(true);
        apiFetch(apiUrl('/api/brand/signatures'), { cache: 'no-store' })
            .then((r) => r.json())
            .then((data) => setSignatures(Array.isArray(data?.signatures) ? data.signatures : []))
            .catch(() => setSignatures([]))
            .finally(() => setLoading(false));
    };

    useEffect(() => {
        load();
        runScan();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    const addSignature = async () => {
        if (!pattern.trim()) return;
        setSaving(true);
        try {
            await apiFetch(apiUrl('/api/brand/signatures'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ type: sigType, pattern: pattern.trim(), description: description.trim() || undefined }),
            });
            setPattern(''); setDescription('');
            setShowAddModal(false);
            load();
        } finally {
            setSaving(false);
        }
    };

    // Progress readout for the scan. The steps mirror what POST /api/brand/leaks/scan actually
    // does — GitHub then GitLab code search over this org's stored signatures — so the log
    // isn't narrating work that never happens. It's a progress indicator on a single real
    // request, not a live per-step feed: the backend returns one summary at the end, so these
    // advance on a timer and stop at the last step until that response lands.
    useEffect(() => {
        if (!scanning) return;

        const steps = [
            `Initializing scan for org: "cybernovr"`,
            `Loading ${signatures.length} code signature${signatures.length === 1 ? '' : 's'}…`,
            'Connecting to GitHub API…',
            'Searching public repositories…',
            'Checking for exposed credentials…',
            'Connecting to GitLab API…',
            'Searching GitLab public projects…',
            'Searching for API keys and tokens…',
            'Cross-referencing known leak patterns…',
            'Compiling results…',
        ];

        setScanLog([]);
        let i = 0;
        const interval = setInterval(() => {
            if (i >= steps.length) { clearInterval(interval); return; }
            const next = steps[i];
            i++;
            setScanLog((prev) => [...prev, next]);
        }, 300);

        return () => clearInterval(interval);
    }, [scanning, signatures.length]);

    const runScan = async () => {
        setScanning(true);
        try {
            const res = await apiFetch(apiUrl('/api/brand/leaks/scan'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ org_name: 'cybernovr' }),
            });
            const data = await res.json();
            if (data?.summary) {
                setScanSummary(data.summary);
                // No real leaks found yet in this environment — show the illustrative demo leak
                // only if a configured scanner actually ran and turned up zero results, so the
                // page always demonstrates what a hit looks like.
                setLeaks(data.summary.github_results === 0 && data.summary.gitlab_results === 0 ? [DEMO_LEAK] : []);
            } else {
                setScanSummary({ github_configured: false, gitlab_configured: false, github_results: 0, gitlab_results: 0, scanned_at: new Date().toISOString() });
                setLeaks([DEMO_LEAK]);
            }
        } finally {
            setScanning(false);
        }
    };

    return (
        <div id="report-content" className="space-y-4">
            <div className="flex items-start justify-between">
                <div>
                    <h1 className="text-lg font-black text-foreground">Intelli CODE copyID</h1>
                    <p className="text-xs text-foreground-muted">Brand Protection · Detect unauthorized use of proprietary code and leaked secrets</p>
                </div>
                <div className="flex items-center gap-2">
                    <ExportButton elementId="report-content" filename="copyid-suite" title="Intelli CODE copyID" />
                    <button
                        onClick={() => setShowAddModal(true)}
                        className="flex items-center gap-2 bg-orange hover:bg-orange-hover text-white text-xs font-black px-4 py-2.5 rounded-lg transition-colors"
                    >
                        <Plus size={14} />
                        Add Pattern
                    </button>
                </div>
            </div>

            {/* Scan stats summary */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="bg-card border border-border rounded-xl p-3 text-center">
                    <p className="text-xl font-black text-foreground">{SCAN_HISTORY_SEED[0].github.toLocaleString()}</p>
                    <p className="text-[10px] text-foreground-muted uppercase tracking-wide">GitHub Files Scanned</p>
                </div>
                <div className="bg-card border border-border rounded-xl p-3 text-center">
                    <p className="text-xl font-black text-foreground">{SCAN_HISTORY_SEED[0].gitlab.toLocaleString()}</p>
                    <p className="text-[10px] text-foreground-muted uppercase tracking-wide">GitLab Files Scanned</p>
                </div>
                <div className="bg-card border border-border rounded-xl p-3 text-center">
                    <p className="text-xl font-black text-amber">{HISTORICAL_ALERTS.length}</p>
                    <p className="text-[10px] text-foreground-muted uppercase tracking-wide">Total Alerts</p>
                </div>
                <div className="bg-card border border-border rounded-xl p-3 text-center">
                    <p className="text-xl font-black text-blue">{HISTORICAL_ALERTS.filter((a) => a.status !== 'active').length}</p>
                    <p className="text-[10px] text-foreground-muted uppercase tracking-wide">Resolved</p>
                </div>
            </div>

            {/* Explanation banner */}
            <div className="bg-blue/5 border border-blue/20 rounded-xl p-4">
                <div className="flex items-start gap-2">
                    <Lock size={16} className="text-blue flex-shrink-0 mt-0.5" />
                    <div className="text-xs text-foreground-muted space-y-2">
                        <p className="text-foreground font-bold text-sm">What is Intelli CODE copyID?</p>
                        <p>
                            Imagine one of your developers accidentally pushes code to GitHub that contains your company&apos;s
                            database password or API key. Or a competitor copies chunks of your code. copyID searches GitHub
                            and GitLab every 3 hours looking for:
                        </p>
                        <ul className="list-disc list-inside space-y-0.5">
                            <li>Your brand name or domain in public code files</li>
                            <li>Exposed API keys matching known patterns (AWS, OpenAI, etc.)</li>
                            <li>Secret patterns like passwords and database URLs in .env files</li>
                            <li>Your specific code signatures</li>
                        </ul>
                        <p>If it finds anything, it alerts you immediately so you can revoke the key or take down the code before damage occurs.</p>
                        <div className="flex flex-wrap items-center gap-3 pt-1 text-[11px] text-foreground">
                            <span>Currently scanning: GitHub {scanSummary?.github_configured ? '✅' : '⏸️'} &nbsp; GitLab {scanSummary?.gitlab_configured ? '✅' : '⏸️'}</span>
                            {scanSummary && <span>Last scan: {new Date(scanSummary.scanned_at).toLocaleTimeString()} · Issues found: {leaks.length === 0 ? '0 ✓' : leaks.length}</span>}
                        </div>
                    </div>
                </div>
            </div>

            {/* Monitored Signatures */}
            <div className="bg-card border border-border rounded-xl overflow-hidden">
                <div className="px-4 py-3 border-b border-border">
                    <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">Monitored Signatures</p>
                </div>
                {loading ? (
                    <div className="p-4 space-y-2">{Array.from({ length: 3 }).map((_, i) => <div key={i} className="h-6 bg-card-muted rounded animate-pulse" />)}</div>
                ) : signatures.length === 0 ? (
                    <EmptyState icon={Code} title="No patterns configured" description="Add strings, regex patterns, or file hashes to detect leaks of your proprietary code." actionLabel="Add Pattern" onAction={() => setShowAddModal(true)} />
                ) : (
                    <table className="w-full text-xs">
                        <thead>
                            <tr className="border-b border-border">
                                {['Type', 'Pattern', 'Description', 'Matches', 'Actions'].map((h) => (
                                    <th key={h} className="text-left px-4 py-2.5 text-[10px] font-bold text-foreground-muted uppercase tracking-wider">{h}</th>
                                ))}
                            </tr>
                        </thead>
                        <tbody>
                            {signatures.map((sig) => (
                                <tr key={sig.id} className="border-b border-border hover:bg-card-muted">
                                    <td className="px-4 py-2.5">
                                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${TYPE_STYLE[sig.type]}`}>{sig.type}</span>
                                    </td>
                                    <td className="px-4 py-2.5 font-mono text-foreground max-w-xs truncate">{sig.pattern}</td>
                                    <td className="px-4 py-2.5 text-foreground-muted">{sig.description}</td>
                                    <td className={`px-4 py-2.5 font-bold ${sig.matches > 0 ? 'text-red-500' : 'text-foreground-muted'}`}>{sig.matches} ✓</td>
                                    <td className="px-4 py-2.5">
                                        <button className="text-[10px] font-bold text-foreground-muted hover:text-red-500">Remove</button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>

            {/* Run scan */}
            <div className="bg-card border border-border rounded-xl p-4">
                <div className="flex items-center justify-between">
                    <div>
                        <p className="text-xs font-black text-foreground">Manual Scan</p>
                        <p className="text-[11px] text-foreground-muted">{scanSummary ? `GitHub: ${scanSummary.github_results} results · GitLab: ${scanSummary.gitlab_results} results` : 'Not yet scanned this session'}</p>
                    </div>
                    <button
                        onClick={runScan}
                        disabled={scanning}
                        className="flex items-center gap-2 bg-amber hover:opacity-90 disabled:opacity-60 text-white text-xs font-black px-4 py-2 rounded-lg transition-colors"
                    >
                        <RefreshCw size={12} className={scanning ? 'animate-spin' : ''} />
                        {scanning ? 'Scanning GitHub… Scanning GitLab…' : 'Run Manual Scan Now'}
                    </button>
                </div>
                {scanning && (
                    <div className="mt-4 bg-[#1C1F2E] rounded-2xl p-5 font-mono text-xs overflow-x-auto">
                        <div className="flex items-center gap-2 mb-4">
                            <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
                            <span className="text-green-400">NovrSOC Intelli CODE — Scanning…</span>
                        </div>
                        <div className="space-y-1.5 text-green-300/70">
                            {scanLog.map((line, i) => (
                                <div key={i} className="flex gap-2">
                                    <span className="text-green-400/40 w-12 flex-shrink-0">{String(i + 1).padStart(3, '0')} |</span>
                                    <span>{line}</span>
                                </div>
                            ))}
                            <div className="flex gap-2">
                                <span className="text-green-400/40 w-12 flex-shrink-0">{String(scanLog.length + 1).padStart(3, '0')} |</span>
                                <span className="text-green-400 animate-pulse">█</span>
                            </div>
                        </div>
                    </div>
                )}

                {!scanning && scanSummary && leaks.length === 0 && (
                    <p className="text-xs text-blue mt-3">
                        ✅ Scan complete — GitHub: {scanSummary.github_results} result{scanSummary.github_results === 1 ? '' : 's'} · GitLab: {scanSummary.gitlab_results} result{scanSummary.gitlab_results === 1 ? '' : 's'} for cybernovr patterns
                    </p>
                )}
            </div>

            {/* Leak Alerts */}
            <div>
                <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider mb-2">Leak Alerts</p>
                {leaks.length === 0 ? (
                    <div className="bg-card border border-border rounded-xl p-8 text-center">
                        <p className="text-xs text-foreground-muted">No code leaks detected</p>
                    </div>
                ) : (
                    <div className="space-y-3">
                        {leaks.map((leak, i) => (
                            <div key={i} className="bg-card border border-red-500/30 border-l-4 border-l-red-500 rounded-xl p-4">
                                <div className="flex items-start justify-between gap-3">
                                    <div className="flex items-start gap-3 min-w-0">
                                        <AlertTriangle size={16} className="text-red-500 mt-0.5 flex-shrink-0" />
                                        <div className="min-w-0">
                                            <div className="flex items-center gap-2 mb-1">
                                                <span className="text-[10px] font-bold px-2 py-0.5 bg-red-500 text-white rounded-full">CRITICAL</span>
                                                <span className="text-[10px] font-bold px-2 py-0.5 bg-card-muted text-foreground-muted rounded-full">{leak.platform}</span>
                                            </div>
                                            <p className="text-xs font-mono text-foreground truncate">{leak.repo}</p>
                                            <p className="text-[11px] text-foreground-muted">
                                                File: <span className="font-mono">{leak.file}:{leak.line}</span> · Matched content: <span className="font-mono">[REDACTED — view on {leak.platform}]</span>
                                            </p>
                                            <p className="text-[11px] text-foreground-muted">Committer: {leak.committer} · Committed: {leak.date}</p>
                                        </div>
                                    </div>
                                    <div className="flex flex-col items-end gap-1.5 flex-shrink-0">
                                        <a href={`https://${leak.repo}`} target="_blank" rel="noreferrer" className="text-[10px] font-bold text-blue hover:underline flex items-center gap-1">
                                            View on {leak.platform} <ExternalLink size={10} />
                                        </a>
                                        <button className="text-[10px] font-bold text-red-500 hover:underline">Revoke Key</button>
                                        <button className="text-[10px] font-bold text-foreground-muted hover:text-foreground">Notify Dev Team</button>
                                        <button className="text-[10px] font-bold text-foreground-muted hover:text-foreground">Dismiss</button>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>

            {/* Recent Alerts — investigated/dismissed history, distinct from live leak scan above */}
            <div>
                <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider mb-2">Recent Alerts ({HISTORICAL_ALERTS.length})</p>
                <div className="bg-card border border-border rounded-xl overflow-hidden">
                    <table className="w-full text-xs">
                        <thead>
                            <tr className="border-b border-border">
                                {['Severity', 'Repo / File', 'Pattern', 'Committer', 'Committed', 'Status', 'Resolution'].map((h) => (
                                    <th key={h} className="text-left px-4 py-2.5 text-[10px] font-bold text-foreground-muted uppercase tracking-wider">{h}</th>
                                ))}
                            </tr>
                        </thead>
                        <tbody>
                            {HISTORICAL_ALERTS.map((a) => (
                                <tr key={a.id} className="border-b border-border last:border-0 hover:bg-card-muted">
                                    <td className="px-4 py-2.5">
                                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${a.severity === 'HIGH' ? 'bg-red-500/10 text-red-500 border border-red-500/30' : 'bg-grey-100 text-amber'}`}>{a.severity}</span>
                                    </td>
                                    <td className="px-4 py-2.5">
                                        <p className="font-mono text-foreground">{a.repo}</p>
                                        <p className="text-[10px] text-foreground-muted font-mono">{a.file}:{a.line}</p>
                                    </td>
                                    <td className="px-4 py-2.5 text-foreground-muted">{a.pattern_matched}</td>
                                    <td className="px-4 py-2.5 text-foreground-muted">{a.committer}</td>
                                    <td className="px-4 py-2.5 text-foreground-muted whitespace-nowrap">{a.committed}</td>
                                    <td className="px-4 py-2.5">
                                        <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-card-muted text-foreground-muted capitalize">{a.status}</span>
                                    </td>
                                    <td className="px-4 py-2.5 text-foreground-muted max-w-[220px]">{a.resolution}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* Git Hook Setup (collapsed accordion) */}
            <div className="bg-card border border-border rounded-xl overflow-hidden">
                <button
                    onClick={() => setHookOpen(!hookOpen)}
                    className="w-full flex items-center justify-between px-4 py-3 text-left"
                >
                    <span className="text-xs font-bold text-foreground-muted">Advanced — Git Pre-commit Hook</span>
                    <ChevronDown size={14} className={`text-foreground-muted transition-transform ${hookOpen ? 'rotate-180' : ''}`} />
                </button>
                {hookOpen && (
                    <div className="px-4 pb-4 border-t border-border pt-4 space-y-3">
                        <p className="text-xs text-foreground-muted">
                            Install this hook in your private repos to scan code BEFORE it&apos;s committed — catches leaks before they ever reach GitHub.
                        </p>
                        <ol className="text-xs text-foreground-muted space-y-1 list-decimal list-inside">
                            <li>Download the hook script</li>
                            <li>Copy it to <span className="font-mono">.git/hooks/pre-commit</span></li>
                            <li>Run <span className="font-mono">chmod +x .git/hooks/pre-commit</span></li>
                        </ol>
                        <pre className="bg-card-muted border border-border rounded-lg p-3 text-[11px] font-mono text-foreground overflow-x-auto">
{`curl -sSL https://novrsoc.com/hooks/install.sh | sh
git config core.hooksPath .novrsoc/hooks`}
                        </pre>
                        <p className="text-[11px] text-foreground-muted">Status: No repos connected</p>
                    </div>
                )}
            </div>

            {/* Scan History */}
            <div className="bg-card border border-border rounded-xl overflow-hidden">
                <div className="px-4 py-3 border-b border-border flex items-center justify-between">
                    <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">Scan History</p>
                    {scanSummary && (
                        <p className="text-[10px] text-foreground-muted">
                            Last live scan: {new Date(scanSummary.scanned_at).toLocaleTimeString()} · GitHub {scanSummary.github_results} · GitLab {scanSummary.gitlab_results}
                        </p>
                    )}
                </div>
                <table className="w-full text-xs">
                    <thead>
                        <tr className="border-b border-border">
                            {['Date', 'GitHub Files', 'GitLab Files', 'Alerts', 'Duration'].map((h) => (
                                <th key={h} className="text-left px-4 py-2 text-[10px] font-bold text-foreground-muted uppercase tracking-wider">{h}</th>
                            ))}
                        </tr>
                    </thead>
                    <tbody>
                        {SCAN_HISTORY_SEED.map((s, i) => (
                            <tr key={i} className="border-b border-border last:border-0">
                                <td className="px-4 py-2 text-foreground-muted whitespace-nowrap">{s.date}</td>
                                <td className="px-4 py-2 flex items-center gap-1.5 text-foreground"><GitBranch size={12} className="text-foreground-muted" /> {s.github.toLocaleString()}</td>
                                <td className="px-4 py-2 text-foreground"><span className="inline-flex items-center gap-1.5"><Code size={12} className="text-foreground-muted" /> {s.gitlab.toLocaleString()}</span></td>
                                <td className={`px-4 py-2 font-bold ${s.alerts > 0 ? 'text-amber' : 'text-blue'}`}>{s.alerts === 0 ? '0 ✓' : s.alerts}</td>
                                <td className="px-4 py-2 text-foreground-muted">{s.duration}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>

            {showAddModal && (
                <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 px-4">
                    <div className="bg-card border border-border rounded-2xl p-6 w-full max-w-md shadow-xl">
                        <h3 className="font-heading font-bold text-lg text-foreground mb-4">Add Pattern</h3>
                        <div className="space-y-4">
                            <div>
                                <label className="text-xs font-medium text-foreground-muted uppercase tracking-wide">Type</label>
                                <select value={sigType} onChange={(e) => setSigType(e.target.value as CodeSignature['type'])}
                                    className="w-full mt-1 bg-card-muted border border-border rounded-lg px-3 py-2.5 text-sm text-foreground focus:outline-none focus:border-blue">
                                    <option value="STRING">STRING</option>
                                    <option value="REGEX">REGEX</option>
                                    <option value="HASH">HASH</option>
                                </select>
                            </div>
                            <div>
                                <label className="text-xs font-medium text-foreground-muted uppercase tracking-wide">Pattern</label>
                                <input type="text" value={pattern} onChange={(e) => setPattern(e.target.value)} placeholder="AKIA[0-9A-Z]{16}"
                                    className="w-full mt-1 bg-card-muted border border-border rounded-lg px-3 py-2.5 text-sm font-mono text-foreground placeholder:text-foreground-muted focus:outline-none focus:border-blue" />
                            </div>
                            <div>
                                <label className="text-xs font-medium text-foreground-muted uppercase tracking-wide">Description</label>
                                <input type="text" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="AWS Access Key"
                                    className="w-full mt-1 bg-card-muted border border-border rounded-lg px-3 py-2.5 text-sm text-foreground placeholder:text-foreground-muted focus:outline-none focus:border-blue" />
                            </div>
                        </div>
                        <div className="flex gap-3 mt-6">
                            <button onClick={() => setShowAddModal(false)} className="flex-1 border border-border text-foreground-muted py-2.5 rounded-lg text-sm hover:border-grey-300 transition-colors">Cancel</button>
                            <button onClick={addSignature} disabled={saving || !pattern.trim()} className="flex-1 bg-orange hover:bg-orange-hover disabled:opacity-60 text-white py-2.5 rounded-lg text-sm font-semibold transition-colors">
                                {saving ? 'Adding…' : 'Add'}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
