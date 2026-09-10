'use client';

import { useState, useEffect } from 'react';
import { ArrowLeft, CheckCircle2, XCircle, RefreshCw, Download, Mail, Calendar, ArrowUpRight } from 'lucide-react';
import { RadarChart, PolarGrid, PolarAngleAxis, Radar, ResponsiveContainer } from 'recharts';
import { apiUrl, apiFetch } from '@/lib/api';
import { VendorAssessmentQuestionnaire } from './VendorAssessmentQuestionnaire';

interface VendorIssue {
    severity: 'critical' | 'high' | 'medium' | 'low';
    text: string;
}

interface Vendor {
    id: string;
    name: string;
    domain: string;
    relationship: string;
    discovery: 'auto' | 'manual';
    score: number;
    risk_level: 'low' | 'medium' | 'high';
    ssl_grade: string;
    spf: boolean;
    dmarc: boolean;
    dkim: boolean;
    dnssec: boolean;
    breach_count: number;
    open_ports: number[];
    last_assessed: string;
    issues: VendorIssue[];
}

const RISK_BADGE: Record<string, string> = {
    low: 'bg-green/10 text-green border-green/30',
    medium: 'bg-amber/10 text-amber border-amber/30',
    high: 'bg-red-500/10 text-red-500 border-red-500/30',
};
const SEVERITY_STYLE: Record<string, { label: string; text: string; bg: string; border: string }> = {
    critical: { label: 'CRITICAL', text: 'text-red-500', bg: 'bg-red-500/10', border: 'border-red-500/30' },
    high: { label: 'HIGH', text: 'text-red-500', bg: 'bg-red-500/5', border: 'border-red-500/20' },
    medium: { label: 'MEDIUM', text: 'text-amber', bg: 'bg-grey-100', border: 'border-amber/30' },
    low: { label: 'LOW', text: 'text-foreground-muted', bg: 'bg-card-muted', border: 'border-border' },
};

function scoreColor(score: number): string {
    if (score >= 80) return 'text-blue';
    if (score >= 60) return 'text-purple';
    if (score >= 40) return 'text-amber';
    return 'text-red-500';
}
function scoreBarColor(score: number): string {
    if (score >= 80) return 'bg-blue';
    if (score >= 60) return 'bg-purple';
    if (score >= 40) return 'bg-amber';
    return 'bg-red-500';
}

const FILTERS = [
    { id: 'all', label: 'All' },
    { id: 'high', label: 'High Risk' },
    { id: 'auto', label: 'Auto-Discovered' },
    { id: 'manual', label: 'Manual' },
] as const;
type Filter = (typeof FILTERS)[number]['id'];
type Sort = 'score_desc' | 'score_asc' | 'name';

// Score breakdown for the radar chart — derived client-side from the vendor's flags/counts
// since the backend only returns the composite score, not a per-dimension breakdown.
function scoreBreakdown(v: Vendor) {
    const sslScore = { 'A+': 100, A: 90, 'A-': 80, B: 60, C: 40, D: 20, F: 0 }[v.ssl_grade] ?? 50;
    const emailScore = ([v.spf, v.dmarc, v.dkim].filter(Boolean).length / 3) * 100;
    const domainScore = v.dnssec ? 100 : 60;
    const breachScore = Math.max(0, 100 - v.breach_count * 40);
    const exposureScore = Math.max(0, 100 - (v.open_ports.length - 1) * 20);
    return [
        { dimension: 'SSL/TLS', value: sslScore },
        { dimension: 'Email Security', value: Math.round(emailScore) },
        { dimension: 'Domain Health', value: domainScore },
        { dimension: 'Breach History', value: breachScore },
        { dimension: 'Exposure', value: exposureScore },
    ];
}

export function VendorAssessments() {
    const [vendors, setVendors] = useState<Vendor[]>([]);
    const [loading, setLoading] = useState(true);
    const [filter, setFilter] = useState<Filter>('all');
    const [sort, setSort] = useState<Sort>('score_desc');
    const [selectedVendor, setSelectedVendor] = useState<Vendor | null>(null);

    useEffect(() => {
        apiFetch(apiUrl('/api/vendors'), { cache: 'no-store' })
            .then((r) => r.json())
            .then((data) => setVendors(Array.isArray(data?.vendors) ? data.vendors : []))
            .catch(() => setVendors([]))
            .finally(() => setLoading(false));
    }, []);

    const filtered = vendors
        .filter((v) => {
            if (filter === 'high') return v.risk_level === 'high';
            if (filter === 'auto') return v.discovery === 'auto';
            if (filter === 'manual') return v.discovery === 'manual';
            return true;
        })
        .sort((a, b) => {
            if (sort === 'score_desc') return b.score - a.score;
            if (sort === 'score_asc') return a.score - b.score;
            return a.name.localeCompare(b.name);
        });

    const summary = {
        total: vendors.length,
        high: vendors.filter((v) => v.risk_level === 'high').length,
        medium: vendors.filter((v) => v.risk_level === 'medium').length,
        low: vendors.filter((v) => v.risk_level === 'low').length,
        avg: vendors.length > 0 ? (vendors.reduce((s, v) => s + v.score, 0) / vendors.length).toFixed(1) : '0.0',
    };

    if (selectedVendor) {
        const breakdown = scoreBreakdown(selectedVendor);
        const sortedIssues = [...selectedVendor.issues].sort((a, b) => {
            const order = { critical: 0, high: 1, medium: 2, low: 3 };
            return order[a.severity] - order[b.severity];
        });

        return (
            <div className="space-y-4">
                <button onClick={() => setSelectedVendor(null)} className="flex items-center gap-1.5 text-xs font-bold text-blue hover:text-purple transition-colors">
                    <ArrowLeft size={14} /> Back to Vendors
                </button>

                <div className="bg-card border border-border rounded-xl p-5">
                    <div className="flex items-start justify-between flex-wrap gap-4">
                        <div>
                            <h1 className="text-lg font-black text-foreground">{selectedVendor.name}</h1>
                            <p className="text-xs text-foreground-muted font-mono mt-0.5">{selectedVendor.domain} · {selectedVendor.relationship}</p>
                            <p className="text-[10px] text-foreground-muted mt-1">Last assessed: Today · {selectedVendor.discovery === 'auto' ? 'Auto-discovered' : 'Manually added'}</p>
                        </div>
                        <div className="text-right">
                            <div className={`font-heading font-black text-4xl ${scoreColor(selectedVendor.score)}`}>{selectedVendor.score}<span className="text-lg font-normal text-foreground-muted">/100</span></div>
                            <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border uppercase ${RISK_BADGE[selectedVendor.risk_level]}`}>{selectedVendor.risk_level} risk</span>
                        </div>
                    </div>
                </div>

                {/* Radar chart */}
                <div className="bg-card border border-border rounded-xl p-5">
                    <p className="text-xs font-black text-foreground mb-3">Score Breakdown</p>
                    <div className="h-64">
                        <ResponsiveContainer width="100%" height="100%">
                            <RadarChart data={breakdown} outerRadius="75%">
                                <PolarGrid stroke="var(--color-border)" />
                                <PolarAngleAxis dataKey="dimension" tick={{ fill: 'var(--color-foreground-muted)', fontSize: 10 }} />
                                <Radar dataKey="value" stroke="var(--color-blue)" fill="var(--color-blue)" fillOpacity={0.25} />
                            </RadarChart>
                        </ResponsiveContainer>
                    </div>
                    <div className="grid grid-cols-5 gap-2 mt-2">
                        {breakdown.map((b) => (
                            <div key={b.dimension} className="text-center">
                                <p className="text-xs font-black text-foreground">{Math.round(b.value)}</p>
                                <p className="text-[9px] text-foreground-muted">{b.dimension}</p>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Issues */}
                <div className="space-y-2">
                    <p className="text-xs font-black text-foreground">Issues ({sortedIssues.length})</p>
                    {sortedIssues.length === 0 ? (
                        <div className="bg-card border border-border rounded-xl p-6 text-center">
                            <CheckCircle2 size={28} className="text-green mx-auto mb-2" />
                            <p className="text-xs text-foreground-muted">No issues found — this vendor is in good standing.</p>
                        </div>
                    ) : (
                        sortedIssues.map((issue, i) => {
                            const cfg = SEVERITY_STYLE[issue.severity];
                            return (
                                <div key={i} className="bg-card border border-border rounded-xl p-4">
                                    <div className="flex items-center gap-2 mb-1">
                                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${cfg.bg} ${cfg.text} ${cfg.border}`}>{cfg.label}</span>
                                        <span className="text-sm font-bold text-foreground">{issue.text}</span>
                                    </div>
                                    <p className="text-xs text-blue mt-1">→ Recommended action: {recommendationFor(issue)}</p>
                                </div>
                            );
                        })
                    )}
                </div>

                {/* Control questionnaire — the attested half of the review. Kept distinct from
                    the automated score above, which is derived from externally observable
                    signals (TLS, SPF/DMARC/DKIM, DNSSEC, breaches, exposed ports) and never
                    from these answers. */}
                <VendorAssessmentQuestionnaire vendorId={selectedVendor.id} vendorName={selectedVendor.name} />

                {/* Technical details */}
                <div className="bg-card border border-border rounded-xl p-5">
                    <p className="text-xs font-black text-foreground mb-3">Technical Details</p>
                    <div className="grid grid-cols-2 gap-y-2 text-xs">
                        {[
                            ['Domain', selectedVendor.domain],
                            ['SSL Grade', selectedVendor.ssl_grade],
                            ['DNSSEC', selectedVendor.dnssec ? '✓ Enabled' : '✗ Not enabled'],
                            ['SPF', selectedVendor.spf ? '✓ Configured' : '✗ Missing'],
                            ['DMARC', selectedVendor.dmarc ? '✓ Configured' : '✗ Missing'],
                            ['DKIM', selectedVendor.dkim ? '✓ Configured' : '✗ Missing'],
                            ['Open Ports', selectedVendor.open_ports.join(', ')],
                            ['Breaches', String(selectedVendor.breach_count)],
                        ].map(([label, value]) => (
                            <div key={label} className="flex justify-between border-b border-border pb-2 pr-4">
                                <span className="text-foreground-muted">{label}</span>
                                <span className="font-bold text-foreground font-mono">{value}</span>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Actions */}
                <div className="flex flex-wrap gap-2">
                    <button className="flex items-center gap-1.5 text-xs font-bold px-3 py-2 border border-border text-foreground-muted rounded-lg hover:bg-card-muted transition-colors"><Download size={12} /> Export PDF Report</button>
                    <button className="flex items-center gap-1.5 text-xs font-bold px-3 py-2 border border-blue text-blue rounded-lg hover:bg-blue/10 transition-colors"><Mail size={12} /> Send Vendor Security Requirements</button>
                    <button className="flex items-center gap-1.5 text-xs font-bold px-3 py-2 border border-border text-foreground-muted rounded-lg hover:bg-card-muted transition-colors"><Calendar size={12} /> Schedule Re-assessment</button>
                    <button className="flex items-center gap-1.5 text-xs font-bold px-3 py-2 bg-orange hover:bg-orange-hover text-white rounded-lg transition-colors"><ArrowUpRight size={12} /> Escalate to Management</button>
                </div>
            </div>
        );
    }

    return (
        <div className="space-y-4">
            <div>
                <h1 className="text-lg font-black text-foreground">Vendor Assessments</h1>
                <p className="text-xs text-foreground-muted">Threat Intelligence · Monitor the security posture of third-party vendors and supply-chain partners. NovrSOC scores each vendor across SSL, email security, domain health, and breach history.</p>
            </div>

            {/* Summary bar */}
            {!loading && (
                <div className="bg-card border border-border rounded-xl p-4 flex flex-wrap items-center gap-x-6 gap-y-2 text-xs">
                    <span className="font-bold text-foreground">{summary.total} vendors assessed</span>
                    <span className="text-red-500 font-bold">{summary.high} HIGH risk</span>
                    <span className="text-amber font-bold">{summary.medium} MEDIUM risk</span>
                    <span className="text-green font-bold">{summary.low} LOW risk</span>
                    <span className="ml-auto text-foreground-muted">Avg score: <span className="font-bold text-foreground">{summary.avg}</span></span>
                </div>
            )}

            {/* Filter bar */}
            <div className="flex items-center gap-2 flex-wrap">
                {FILTERS.map((f) => (
                    <button key={f.id} onClick={() => setFilter(f.id)}
                        className={`px-3 py-1.5 rounded-full text-xs font-medium transition-colors ${filter === f.id ? 'bg-blue text-white' : 'bg-card border border-border text-foreground-muted hover:border-grey-300'}`}>
                        {f.label}
                    </button>
                ))}
                <select value={sort} onChange={(e) => setSort(e.target.value as Sort)}
                    className="ml-auto bg-card border border-border rounded-lg px-3 py-1.5 text-xs text-foreground focus:outline-none">
                    <option value="score_desc">Score ↓</option>
                    <option value="score_asc">Score ↑</option>
                    <option value="name">Name</option>
                </select>
            </div>

            {loading ? (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">{Array.from({ length: 6 }).map((_, i) => <div key={i} className="h-48 bg-card-muted rounded-xl animate-pulse" />)}</div>
            ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {filtered.map((v) => (
                        <div key={v.id} className="bg-card border border-border rounded-xl p-4">
                            <div className="flex items-start justify-between mb-2">
                                <div>
                                    <p className="text-sm font-bold text-foreground">{v.name}</p>
                                    <p className="text-[10px] text-foreground-muted font-mono">{v.domain} · {v.relationship}</p>
                                </div>
                                <span className="text-[9px] font-bold px-1.5 py-0.5 bg-card-muted text-foreground-muted rounded-full uppercase flex-shrink-0">{v.discovery}</span>
                            </div>

                            <div className="flex items-center gap-3 my-3">
                                <span className={`font-heading font-black text-3xl ${scoreColor(v.score)}`}>{v.score}</span>
                                <div className="flex-1">
                                    <div className="h-1.5 bg-card-muted rounded-full overflow-hidden mb-1">
                                        <div className={`h-full rounded-full ${scoreBarColor(v.score)}`} style={{ width: `${v.score}%` }} />
                                    </div>
                                    <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded-full border uppercase ${RISK_BADGE[v.risk_level]}`}>{v.risk_level} risk</span>
                                </div>
                            </div>

                            <div className="grid grid-cols-2 gap-x-2 gap-y-1 text-[10px] mb-3">
                                <span className="text-foreground-muted">SSL: <span className="font-bold text-foreground">{v.ssl_grade}</span></span>
                                <span className="text-foreground-muted">SPF: {v.spf ? <CheckCircle2 size={10} className="inline text-green" /> : <XCircle size={10} className="inline text-red-500" />}</span>
                                <span className="text-foreground-muted">DMARC: {v.dmarc ? <CheckCircle2 size={10} className="inline text-green" /> : <XCircle size={10} className="inline text-red-500" />}</span>
                                <span className="text-foreground-muted">DKIM: {v.dkim ? <CheckCircle2 size={10} className="inline text-green" /> : <XCircle size={10} className="inline text-red-500" />}</span>
                            </div>

                            <div className="flex items-center justify-between text-[10px] text-foreground-muted mb-3">
                                <span>Breaches: <span className="font-bold text-foreground">{v.breach_count}</span></span>
                                <span>Open Ports: <span className="font-bold text-foreground">{v.open_ports.length}</span></span>
                            </div>

                            <p className="text-[10px] text-foreground-muted mb-3">{v.issues.length} issue{v.issues.length === 1 ? '' : 's'} found · Last assessed: Today</p>

                            <div className="flex gap-2">
                                <button onClick={() => setSelectedVendor(v)} className="flex-1 text-[10px] font-bold px-3 py-1.5 bg-blue hover:opacity-90 text-white rounded-lg transition-colors">View Full Report</button>
                                <button className="text-[10px] font-bold px-3 py-1.5 border border-border text-foreground-muted rounded-lg hover:bg-card-muted transition-colors flex items-center gap-1"><RefreshCw size={10} /> Re-assess</button>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}

function recommendationFor(issue: VendorIssue): string {
    if (issue.text.toLowerCase().includes('breach')) return 'Request their incident report and remediation proof';
    if (issue.text.toLowerCase().includes('ssl') || issue.text.toLowerCase().includes('tls')) return 'Request SSL Labs report from vendor';
    if (issue.text.toLowerCase().includes('dmarc') || issue.text.toLowerCase().includes('spf') || issue.text.toLowerCase().includes('dkim')) return 'Send vendor email security requirements';
    if (issue.text.toLowerCase().includes('port')) return 'Request confirmation that exposed services are intentional and patched';
    if (issue.text.toLowerCase().includes('dnssec')) return 'Recommend DNSSEC be enabled with their registrar';
    return 'Follow up with vendor security team';
}
