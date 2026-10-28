'use client';

// AI Threat Intelligence & Behavioral Analysis — demo section for the AI Intelligence Analyst
// page. No behavioral-baseline engine, anomaly scorer, or event-correlation service exists in
// this codebase yet, so everything in this file is explicitly, persistently labelled DEMO /
// SIMULATED, per the brief: "do not claim actual ML detection, predictive capabilities, or
// LLM-generated summaries unless those systems are running." The page's real AI capability (the
// Q&A analyst and the threat/Nigeria briefings above this section, both backed by
// POST /api/ti/analyst/ask and AiPanel) is untouched and stays exactly as real as it already was.
//
// Every event, score, and the one correlated "attack sequence" below is generated client-side
// from a fixed pool — never derived from, or written into, real alert counts or incident records.
// IPs use IANA-reserved documentation ranges (RFC 5737/2544) so a demo 5-tuple can never be
// mistaken for a real address. The MITRE tactic/technique labels on the demo sequence are real,
// public ATT&CK identifiers used only to illustrate the scenario — they are not a claim that any
// evidence maps to them.

import { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, Activity, Radio, Shield, TrendingUp, X, Network } from 'lucide-react';
import { useReducedMotion } from '@/components/features/vms/ui';

type Severity = 'low' | 'medium' | 'high' | 'critical';
const SEV_STYLE: Record<Severity, string> = { low: 'bg-blue/10 text-blue', medium: 'bg-amber/10 text-amber', high: 'bg-orange/10 text-orange', critical: 'bg-red/10 text-red' };

interface FiveTuple { src_ip: string; dst_ip: string; src_port: number; dst_port: number; protocol: 'TCP' | 'UDP' }
interface FeedEvent extends FiveTuple {
    id: string; title: string; kind: 'auth' | 'scan' | 'network' | 'anomaly';
    severity: Severity; confidence: 'low' | 'medium' | 'high'; asset: string; at: number;
    explanation: string; impact: string; recommendation: string;
}
interface SequenceStep extends FiveTuple { stage: string; mitre_tactic: string; mitre_id: string; at: number; asset: string }

const ips = (base: string) => `${base}.${1 + Math.floor(Math.random() * 253)}`;
const demoSrc = () => ips('203.0.113');
const demoDst = () => ips('198.18.0');
const PORTS = [22, 3389, 443, 80, 8080, 445, 3306, 21];
const ASSETS = ['web-edge-01', 'db-core-03', 'vpn-gw-01', 'file-srv-02', 'auth-svc-01', 'mail-relay-01'];

const FEED_TEMPLATES: { kind: FeedEvent['kind']; title: string; severity: Severity; explanation: string; impact: string; recommendation: string }[] = [
    { kind: 'auth', title: 'Repeated Failed Authentication', severity: 'medium', explanation: 'Several failed sign-in attempts against the same account in a short window — a pattern consistent with password guessing, not a single mistyped password.', impact: 'If successful, the attacker gains the account\'s own access level — the account\'s privileges set the ceiling on what this could lead to.', recommendation: 'Lock the account after the next failed attempt and require a password reset; review for the same source attempting other accounts.' },
    { kind: 'scan', title: 'Port Scan Detected', severity: 'low', explanation: 'A sequence of connection attempts across multiple ports on one host in quick succession — typical reconnaissance behaviour, not yet an exploitation attempt.', impact: 'Reconnaissance alone does not compromise anything, but it often precedes a targeted attempt against whichever port responds.', recommendation: 'Confirm the source is not an authorised scanner; if not, block it at the perimeter and watch the target host for follow-up activity.' },
    { kind: 'network', title: 'Suspicious Outbound Traffic', severity: 'high', explanation: 'An internal host sending data to an address it has no prior history of contacting, at a volume above its normal baseline for this hour.', impact: 'Could indicate data exfiltration or a command-and-control channel if the host is already compromised.', recommendation: 'Isolate the host for inspection and capture the traffic for analysis before it is lost to log rotation.' },
    { kind: 'anomaly', title: 'Behavioral Anomaly — Off-Hours Access', severity: 'medium', explanation: 'A login from an account that has never previously authenticated outside its normal working hours, now doing so.', impact: "May be legitimate (a genuine after-hours task) or may indicate the account's credentials are in someone else's hands.", recommendation: "Confirm with the account's owner directly; if they did not initiate this session, treat the credential as compromised." },
];

function makeFeedEvent(id: number): FeedEvent {
    const t = FEED_TEMPLATES[id % FEED_TEMPLATES.length];
    return {
        id: `feed-${id}`, ...t, confidence: id % 3 === 0 ? 'high' : id % 3 === 1 ? 'medium' : 'low',
        asset: ASSETS[id % ASSETS.length], at: Date.now(),
        src_ip: demoSrc(), dst_ip: demoDst(), src_port: PORTS[id % PORTS.length], dst_port: PORTS[(id + 3) % PORTS.length],
        protocol: id % 4 === 0 ? 'UDP' : 'TCP',
    };
}

// One fixed, illustrative attack sequence — real MITRE ATT&CK tactic/technique names used only to
// show how a correlation engine would present a chain, not a claim that any evidence maps to them.
function buildSequence(): SequenceStep[] {
    const srcIp = demoSrc();
    const stages: { stage: string; mitre_tactic: string; mitre_id: string }[] = [
        { stage: 'Initial Access', mitre_tactic: 'Credential Access', mitre_id: 'T1110 (Brute Force)' },
        { stage: 'Valid Account Use', mitre_tactic: 'Persistence', mitre_id: 'T1078 (Valid Accounts)' },
        { stage: 'Lateral Movement', mitre_tactic: 'Lateral Movement', mitre_id: 'T1021 (Remote Services)' },
        { stage: 'Data Staging & Exfiltration', mitre_tactic: 'Exfiltration', mitre_id: 'T1041 (Exfiltration Over C2 Channel)' },
    ];
    const base = Date.now() - 42 * 60_000;
    return stages.map((s, i) => ({
        ...s, src_ip: i === 0 ? srcIp : demoSrc(), dst_ip: demoDst(), src_port: PORTS[i], dst_port: PORTS[i + 1] ?? 443,
        protocol: 'TCP', at: base + i * 11 * 60_000, asset: ASSETS[i],
    }));
}

interface Baseline { metric: string; baseline: number; observed: number; anomaly_score: number; confidence: 'low' | 'medium' | 'high'; unit: string }
function buildBaselines(): Baseline[] {
    return [
        { metric: 'Failed logins / hour', baseline: 3, observed: 27, anomaly_score: 88, confidence: 'high', unit: '' },
        { metric: 'Distinct ports probed / host / hour', baseline: 2, observed: 19, anomaly_score: 74, confidence: 'medium', unit: '' },
        { metric: 'Outbound data volume', baseline: 40, observed: 310, anomaly_score: 81, confidence: 'high', unit: 'MB' },
        { metric: 'Off-hours authentications', baseline: 1, observed: 4, anomaly_score: 46, confidence: 'low', unit: '' },
    ];
}

const DemoBadge = () => <span className="text-[9px] font-black px-1.5 py-0.5 rounded bg-red/10 text-red tracking-wide">DEMO</span>;

export function AiThreatIntelligenceDemo() {
    const [feed, setFeed] = useState<FeedEvent[]>(() => Array.from({ length: 4 }, (_, i) => makeFeedEvent(i)));
    const [cursor, setCursor] = useState(4);
    const [selected, setSelected] = useState<FeedEvent | null>(null);
    const [showSequence, setShowSequence] = useState(false);
    const sequence = useMemo(() => buildSequence(), []);
    const baselines = useMemo(() => buildBaselines(), []);
    const reducedMotion = useReducedMotion();

    useEffect(() => {
        const id = setInterval(() => {
            setFeed((f) => [makeFeedEvent(cursor), ...f].slice(0, 8));
            setCursor((c) => c + 1);
        }, 2000);
        return () => clearInterval(id);
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    return (
        <div className="space-y-4">
            <div className="rounded-xl border border-amber/40 bg-amber/10 px-3 py-2 flex items-start gap-2">
                <AlertTriangle className="w-4 h-4 text-amber shrink-0 mt-0.5" aria-hidden />
                <p className="text-[11px] text-amber font-semibold">DEMO / SIMULATED — behavioral baselines, anomaly scores, the correlation sequence and every event below are synthetic, generated in your browser for demonstration. None of this is read from, or written into, real alerts, cases or incident records. The AI Q&amp;A and threat/Nigeria briefings above this section are the platform&apos;s real AI capability and are unaffected.</p>
            </div>

            {/* Behavioral analysis */}
            <div className="bg-card border border-border rounded-xl p-4">
                <div className="flex items-center gap-2 mb-3"><TrendingUp className="w-4 h-4 text-purple" aria-hidden /><h3 className="text-sm font-black text-foreground">Behavioral Analysis</h3><DemoBadge /></div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    {baselines.map((b) => (
                        <div key={b.metric} className="rounded-lg border border-border p-3">
                            <div className="flex items-center justify-between mb-1">
                                <p className="text-[11px] font-semibold text-foreground">{b.metric}</p>
                                <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${b.anomaly_score >= 75 ? 'bg-red/10 text-red' : b.anomaly_score >= 50 ? 'bg-orange/10 text-orange' : 'bg-blue/10 text-blue'}`}>anomaly {b.anomaly_score}</span>
                            </div>
                            <div className="flex items-center gap-3 text-[11px] text-foreground-muted">
                                <span>Baseline: <span className="font-bold text-foreground">{b.baseline}{b.unit}</span></span>
                                <span>Observed: <span className="font-bold text-red">{b.observed}{b.unit}</span></span>
                                <span className="ml-auto">Confidence: {b.confidence}</span>
                            </div>
                            <div className="mt-1.5 h-1.5 w-full rounded-full bg-card-muted overflow-hidden">
                                <span className="block h-full rounded-full bg-red" style={{ width: `${Math.min(100, (b.observed / Math.max(b.baseline, 1)) * 10)}%` }} />
                            </div>
                        </div>
                    ))}
                </div>
            </div>

            {/* Correlation engine */}
            <div className="bg-card border border-border rounded-xl p-4">
                <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2"><Network className="w-4 h-4 text-purple" aria-hidden /><h3 className="text-sm font-black text-foreground">Threat Correlation Engine</h3><DemoBadge /></div>
                    <button onClick={() => setShowSequence((v) => !v)} className="text-[10px] font-bold text-blue hover:underline">{showSequence ? 'Hide' : 'Show'} sequence</button>
                </div>
                <p className="text-[11px] text-foreground-muted mb-2">One illustrative attack sequence, grouped as a correlation engine would present related events across a kill chain.</p>
                {showSequence && (
                    <ol className="space-y-2">
                        {sequence.map((s, i) => (
                            <li key={i} className="rounded-lg border border-border p-2.5 flex items-start gap-3">
                                <span className="shrink-0 w-6 h-6 rounded-full bg-purple/10 text-purple text-[10px] font-black flex items-center justify-center">{i + 1}</span>
                                <div className="min-w-0 flex-1">
                                    <p className="text-[11px] font-bold text-foreground">{s.stage} <span className="text-foreground-muted font-normal">· {s.asset}</span></p>
                                    <p className="font-mono text-[10px] text-foreground-muted">{s.src_ip}:{s.src_port} → {s.dst_ip}:{s.dst_port} ({s.protocol})</p>
                                    <p className="text-[10px] text-foreground-muted">MITRE ATT&amp;CK: {s.mitre_tactic} — {s.mitre_id}</p>
                                </div>
                                <span className="text-[9px] text-foreground-muted shrink-0">+{i * 11}m</span>
                            </li>
                        ))}
                    </ol>
                )}
            </div>

            {/* Live intelligence feed */}
            <div className="bg-card border border-border rounded-xl p-4">
                <div className="flex items-center gap-2 mb-3">
                    <span className="relative flex h-2 w-2 shrink-0">
                        {!reducedMotion && <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red opacity-60" />}
                        <span className="relative inline-flex h-2 w-2 rounded-full bg-red" />
                    </span>
                    <Radio className="w-4 h-4 text-purple" aria-hidden /><h3 className="text-sm font-black text-foreground">Live Intelligence Feed</h3><DemoBadge />
                    <span className="text-[10px] text-foreground-muted ml-auto">Updates every 2s · click an event for detail</span>
                </div>
                <ul className="divide-y divide-border">
                    {feed.map((e) => (
                        <li key={e.id}>
                            <button onClick={() => setSelected(e)} className="w-full text-left py-2 flex items-center gap-3 hover:bg-card-muted rounded-lg px-1.5 -mx-1.5">
                                <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded shrink-0 ${SEV_STYLE[e.severity]}`}>{e.severity}</span>
                                <span className="min-w-0 flex-1">
                                    <span className="block text-[11px] font-semibold text-foreground truncate">{e.title}</span>
                                    <span className="block text-[10px] text-foreground-muted font-mono truncate">{e.asset} · {e.src_ip}:{e.src_port} → {e.dst_ip}:{e.dst_port}</span>
                                </span>
                                <span className="text-[9px] text-foreground-muted shrink-0">just now</span>
                            </button>
                        </li>
                    ))}
                </ul>
            </div>

            {/* Investigation panel */}
            {selected && (
                <div className="fixed inset-0 bg-black/40 z-50 flex items-center justify-center p-4" onClick={() => setSelected(null)}>
                    <div className="bg-card border border-border rounded-xl max-w-lg w-full p-5 space-y-3" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-start justify-between">
                            <div className="flex items-center gap-2"><Shield className="w-4 h-4 text-purple" aria-hidden /><h3 className="text-sm font-black text-foreground">AI Investigation — {selected.title}</h3></div>
                            <button onClick={() => setSelected(null)} aria-label="Close" className="text-foreground-muted hover:text-foreground"><X className="w-4 h-4" /></button>
                        </div>
                        <DemoBadge />
                        <div className="text-xs text-foreground space-y-2">
                            <p><span className="font-bold">What&apos;s happening: </span>{selected.explanation}</p>
                            <p><span className="font-bold">Possible impact: </span>{selected.impact}</p>
                            <p><span className="font-bold">Recommended action: </span>{selected.recommendation}</p>
                        </div>
                        <div className="rounded-lg bg-card-muted p-2.5 text-[11px] space-y-1">
                            <p className="font-bold text-foreground flex items-center gap-1.5"><Activity className="w-3.5 h-3.5" aria-hidden /> Evidence</p>
                            <p className="font-mono text-foreground-muted">{selected.src_ip}:{selected.src_port} → {selected.dst_ip}:{selected.dst_port} ({selected.protocol})</p>
                            <p className="text-foreground-muted">Asset: {selected.asset} · Confidence: {selected.confidence}</p>
                        </div>
                        <p className="text-[9px] text-foreground-muted">Simulated event — not a real investigation artifact. Use the AI Q&amp;A above for a real, cited answer about actual stored intelligence.</p>
                    </div>
                </div>
            )}
        </div>
    );
}
