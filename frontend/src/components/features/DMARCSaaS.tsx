'use client';

import { useState, useEffect } from 'react';
import { Plus, Copy, CheckCircle2, XCircle, ChevronRight } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { GaugeChart } from '@/components/shared/GaugeChart';
import { EmailSecurityScan } from './EmailSecurityScan';

interface DmarcDomain {
    domain: string;
    policy: 'reject' | 'quarantine' | 'none';
    dkim_pass_rate: number;
    spf_pass_rate: number;
    total_messages: number;
    compliant: number;
    failed: number;
    unauthorized_senders: number;
    last_report: string;
    status: 'protected' | 'warning' | 'at_risk';
}

interface UnauthorizedSender {
    ip: string;
    country: string;
    isp: string;
    messages_sent: number;
    spf: 'pass' | 'fail';
    dkim: 'pass' | 'fail';
    disposition: 'reject' | 'quarantine' | 'none';
    first_seen: string;
    threat_level: 'AUTHORIZED' | 'HIGH' | 'MEDIUM';
    note: string;
    // Present when services/maxmind.ts has a local GeoLite2 database to enrich with
    geo_city?: string;
    geo_region?: string;
    geo_country?: string;
    geo_lat?: number;
    geo_lng?: number;
}

const POLICY_STYLE: Record<string, string> = {
    reject: 'bg-blue/10 text-blue border-blue/30',
    quarantine: 'bg-purple/10 text-purple border-purple/30',
    none: 'bg-card-muted text-foreground-muted border-border',
};
const STATUS_STYLE: Record<string, { label: string; dot: string; text: string }> = {
    protected: { label: 'PROTECTED', dot: 'bg-green', text: 'text-green' },
    warning: { label: 'WARNING', dot: 'bg-amber', text: 'text-amber' },
    at_risk: { label: 'AT RISK', dot: 'bg-red-500', text: 'text-red-500' },
};
const DISPOSITION_STYLE: Record<string, string> = {
    reject: 'text-red-500',
    quarantine: 'text-purple',
    none: 'text-foreground-muted',
};
const THREAT_STYLE: Record<string, string> = {
    AUTHORIZED: 'bg-blue/10 text-blue border-blue/30',
    HIGH: 'bg-red-500/10 text-red-500 border-red-500/30',
    MEDIUM: 'bg-grey-100 text-amber border-amber/30',
};

const TABS = [
    { id: 'domains', label: 'Domains' },
    { id: 'feed', label: 'Report Feed' },
    { id: 'guide', label: 'Policy Guide' },
] as const;
type Tab = (typeof TABS)[number]['id'];

const POLICY_STEPS = [
    { policy: 'none', label: 'p=none', desc: 'Monitoring only', color: 'bg-grey-500' },
    { policy: 'quarantine', label: 'p=quarantine', desc: 'Send to spam', color: 'bg-purple' },
    { policy: 'reject', label: 'p=reject', desc: 'Block completely', color: 'bg-blue' },
];

export function DMARCSaaS() {
    const [domains, setDomains] = useState<DmarcDomain[]>([]);
    const [senders, setSenders] = useState<UnauthorizedSender[]>([]);
    const [loading, setLoading] = useState(true);
    const [activeTab, setActiveTab] = useState<Tab>('domains');
    const [showAddModal, setShowAddModal] = useState(false);
    const [newDomain, setNewDomain] = useState('');
    const [copied, setCopied] = useState(false);
    const [selectedSender, setSelectedSender] = useState<UnauthorizedSender | null>(null);

    useEffect(() => {
        setLoading(true);
        Promise.all([
            apiFetch(apiUrl('/api/email/dmarc/domains'), { cache: 'no-store' }).then((r) => r.json()).catch(() => ({ domains: [] })),
            apiFetch(apiUrl('/api/email/dmarc/senders'), { cache: 'no-store' }).then((r) => r.json()).catch(() => ({ senders: [] })),
        ]).then(([domainsRes, sendersRes]) => {
            setDomains(Array.isArray(domainsRes?.domains) ? domainsRes.domains : []);
            setSenders(Array.isArray(sendersRes?.senders) ? sendersRes.senders : []);
            setLoading(false);
        });
    }, []);

    const totalMessages = domains.reduce((s, d) => s + d.total_messages, 0);
    const totalCompliant = domains.reduce((s, d) => s + d.compliant, 0);
    const complianceRate = totalMessages > 0 ? ((totalCompliant / totalMessages) * 100).toFixed(1) : '0.0';
    const unauthorizedTotal = domains.reduce((s, d) => s + d.unauthorized_senders, 0);

    const addDomain = async () => {
        if (!newDomain.trim()) return;
        await apiFetch(apiUrl('/api/email/dmarc/domains'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ domain: newDomain.trim() }),
        });
        setNewDomain('');
        setShowAddModal(false);
    };

    const dnsRecord = (domain: string) => `_dmarc.${domain || 'yourdomain.com'} TXT "v=DMARC1; p=reject; rua=mailto:dmarc@reports.novrsoc.com"`;

    const copyRecord = (text: string) => {
        navigator.clipboard.writeText(text).then(() => { setCopied(true); setTimeout(() => setCopied(false), 2000); });
    };

    return (
        <div className="space-y-4">
            <div className="flex items-start justify-between flex-wrap gap-3">
                <div>
                    <h1 className="text-lg font-black text-foreground">DMARC SaaS</h1>
                    <p className="text-xs text-foreground-muted">Email Security · Aggregate and analyze DMARC reports to protect domains from email spoofing. Monitor authentication pass rates and enforce strict delivery policies.</p>
                </div>
                <button onClick={() => setShowAddModal(true)} className="flex items-center gap-2 bg-orange hover:bg-orange-hover text-white text-xs font-black px-4 py-2.5 rounded-lg transition-colors flex-shrink-0">
                    <Plus size={14} />
                    Add Domain
                </button>
            </div>

            {/* On-demand scan for any domain — including ones not yet added for DMARC report
                aggregation, so this works as a pre-onboarding check as well as a health check. */}
            <EmailSecurityScan />

            {/* KPIs */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {[
                    { label: 'Protected Domains', value: domains.length, border: 'border-t-blue' },
                    { label: 'Total Messages Analyzed', value: totalMessages.toLocaleString(), border: 'border-t-blue' },
                    { label: 'Unauthorized Senders Blocked', value: unauthorizedTotal, border: 'border-t-red-500', pulse: true },
                    { label: 'Overall Compliance Rate', value: `${complianceRate}%`, border: 'border-t-green' },
                ].map((k) => (
                    <div key={k.label} className={`bg-card border border-border rounded-xl p-4 border-t-4 ${k.border}`}>
                        <div className="flex items-center gap-1.5 mb-1">
                            <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">{k.label}</p>
                            {k.pulse && Number(unauthorizedTotal) > 0 && <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" />}
                        </div>
                        <p className="font-heading font-black text-2xl text-foreground">{k.value}</p>
                    </div>
                ))}
            </div>

            {/* Tabs */}
            <div className="flex gap-1 border-b border-border">
                {TABS.map((t) => (
                    <button key={t.id} onClick={() => setActiveTab(t.id)}
                        className={`px-4 py-2.5 text-xs font-bold border-b-2 transition-colors ${activeTab === t.id ? 'border-blue text-blue' : 'border-transparent text-foreground-muted hover:text-foreground'}`}>
                        {t.label}
                    </button>
                ))}
            </div>

            {loading ? (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {Array.from({ length: 2 }).map((_, i) => <div key={i} className="h-56 bg-card-muted rounded-xl animate-pulse" />)}
                </div>
            ) : (
                <>
                    {/* DOMAINS TAB */}
                    {activeTab === 'domains' && (
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                            {domains.map((d) => {
                                const pct = d.total_messages > 0 ? Math.round((d.compliant / d.total_messages) * 100) : 0;
                                const status = STATUS_STYLE[d.status];
                                return (
                                    <div key={d.domain} className="bg-card border border-border rounded-xl p-5">
                                        <div className="flex items-start justify-between mb-4">
                                            <div>
                                                <div className="flex items-center gap-2">
                                                    <span className="font-mono font-bold text-sm text-foreground">{d.domain}</span>
                                                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border uppercase ${POLICY_STYLE[d.policy]}`}>{d.policy}</span>
                                                </div>
                                                <span className={`flex items-center gap-1.5 text-[10px] font-bold mt-1 ${status.text}`}>
                                                    <span className={`w-1.5 h-1.5 rounded-full ${status.dot}`} />
                                                    {status.label}
                                                </span>
                                            </div>
                                            <div className="relative flex-shrink-0">
                                                <GaugeChart value={pct} size={64} strokeWidth={7} />
                                                <span className="absolute inset-0 flex items-center justify-center text-xs font-black text-foreground">{pct}%</span>
                                            </div>
                                        </div>

                                        <div className="grid grid-cols-4 gap-2 text-center mb-4">
                                            {[
                                                ['Total', d.total_messages],
                                                ['Compliant', d.compliant],
                                                ['Failed', d.failed],
                                                ['Rogue', d.unauthorized_senders],
                                            ].map(([label, value]) => (
                                                <div key={label} className="bg-card-muted rounded-lg py-2">
                                                    <p className="text-sm font-black text-foreground">{value}</p>
                                                    <p className="text-[9px] text-foreground-muted uppercase tracking-wide">{label}</p>
                                                </div>
                                            ))}
                                        </div>

                                        <div className="space-y-2 mb-4">
                                            <div>
                                                <div className="flex justify-between text-[10px] text-foreground-muted mb-1"><span>DKIM pass rate</span><span className="font-bold text-foreground">{d.dkim_pass_rate}%</span></div>
                                                <div className="h-1.5 bg-card-muted rounded-full overflow-hidden"><div className="h-full bg-blue rounded-full" style={{ width: `${d.dkim_pass_rate}%` }} /></div>
                                            </div>
                                            <div>
                                                <div className="flex justify-between text-[10px] text-foreground-muted mb-1"><span>SPF pass rate</span><span className="font-bold text-foreground">{d.spf_pass_rate}%</span></div>
                                                <div className="h-1.5 bg-card-muted rounded-full overflow-hidden"><div className="h-full bg-purple rounded-full" style={{ width: `${d.spf_pass_rate}%` }} /></div>
                                            </div>
                                        </div>

                                        <div className="flex gap-2">
                                            <button onClick={() => setActiveTab('feed')} className="text-[10px] font-bold px-3 py-1.5 border border-border text-foreground-muted rounded-lg hover:bg-card-muted transition-colors">View Reports</button>
                                            <button onClick={() => setActiveTab('guide')} className="text-[10px] font-bold px-3 py-1.5 bg-blue hover:opacity-90 text-white rounded-lg transition-colors">Update Policy</button>
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    )}

                    {/* REPORT FEED TAB */}
                    {activeTab === 'feed' && (
                        <div className="bg-card border border-border rounded-xl overflow-hidden overflow-x-auto">
                            <table className="w-full text-xs">
                                <thead>
                                    <tr className="border-b border-border">
                                        {['IP', 'Country', 'ISP', 'Messages', 'SPF', 'DKIM', 'Disposition', 'Threat', ''].map((h) => (
                                            <th key={h} className="text-left px-4 py-2.5 text-[10px] font-bold text-foreground-muted uppercase tracking-wider">{h}</th>
                                        ))}
                                    </tr>
                                </thead>
                                <tbody>
                                    {senders.map((s) => (
                                        <tr key={s.ip} onClick={() => setSelectedSender(s)} className="border-b border-border hover:bg-card-muted cursor-pointer transition-colors">
                                            <td className="px-4 py-2.5 font-mono text-foreground">{s.ip}</td>
                                            <td className="px-4 py-2.5 text-foreground-muted">{s.country}{s.geo_city ? ` · ${s.geo_city}` : ''}</td>
                                            <td className="px-4 py-2.5 text-foreground-muted">{s.isp}</td>
                                            <td className="px-4 py-2.5 text-foreground font-bold">{s.messages_sent}</td>
                                            <td className="px-4 py-2.5">{s.spf === 'pass' ? <CheckCircle2 size={14} className="text-green" /> : <XCircle size={14} className="text-red-500" />}</td>
                                            <td className="px-4 py-2.5">{s.dkim === 'pass' ? <CheckCircle2 size={14} className="text-green" /> : <XCircle size={14} className="text-red-500" />}</td>
                                            <td className={`px-4 py-2.5 font-bold uppercase ${DISPOSITION_STYLE[s.disposition]}`}>{s.disposition}</td>
                                            <td className="px-4 py-2.5"><span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${THREAT_STYLE[s.threat_level]}`}>{s.threat_level}</span></td>
                                            <td className="px-4 py-2.5"><ChevronRight size={14} className="text-foreground-muted" /></td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}

                    {/* POLICY GUIDE TAB */}
                    {activeTab === 'guide' && (
                        <div className="space-y-4">
                            <div className="bg-card border border-border rounded-xl p-5">
                                <p className="text-xs font-black text-foreground mb-4">DMARC Policy Progression</p>
                                <div className="flex items-center gap-2">
                                    {POLICY_STEPS.map((step, i) => (
                                        <div key={step.policy} className="flex items-center flex-1">
                                            <div className="flex flex-col items-center flex-1">
                                                <div className={`w-10 h-10 rounded-full ${step.color} flex items-center justify-center text-white font-black text-sm`}>{i + 1}</div>
                                                <p className="text-xs font-bold text-foreground mt-2 font-mono">{step.label}</p>
                                                <p className="text-[10px] text-foreground-muted">{step.desc}</p>
                                            </div>
                                            {i < POLICY_STEPS.length - 1 && <div className="h-0.5 flex-1 bg-border -mt-8" />}
                                        </div>
                                    ))}
                                </div>
                            </div>

                            {domains.map((d) => (
                                <div key={d.domain} className="bg-card border border-border rounded-xl p-4 flex items-center justify-between flex-wrap gap-3">
                                    <div>
                                        <p className="font-mono font-bold text-sm text-foreground">{d.domain}</p>
                                        <p className="text-xs text-foreground-muted">Currently at step {POLICY_STEPS.findIndex((s) => s.policy === d.policy) + 1}: <span className="font-mono">p={d.policy}</span></p>
                                    </div>
                                    {d.policy !== 'reject' && (
                                        <button className="text-[10px] font-bold px-3 py-1.5 bg-blue hover:opacity-90 text-white rounded-lg transition-colors">Upgrade Policy</button>
                                    )}
                                </div>
                            ))}

                            <div className="bg-card-muted border border-border rounded-xl p-4">
                                <p className="text-xs font-black text-foreground mb-2">Add this DNS TXT record to enable DMARC reporting:</p>
                                <div className="flex items-center gap-2 bg-card border border-border rounded-lg p-3">
                                    <code className="text-[11px] font-mono text-foreground flex-1 break-all">{dnsRecord('')}</code>
                                    <button onClick={() => copyRecord(dnsRecord(''))} className="flex items-center gap-1 text-[10px] font-bold text-blue hover:text-purple flex-shrink-0">
                                        <Copy size={12} /> {copied ? 'Copied ✓' : 'Copy Record'}
                                    </button>
                                </div>
                            </div>
                        </div>
                    )}
                </>
            )}

            {/* Slide-out sender detail */}
            {selectedSender && (
                <div className="fixed inset-0 bg-black/40 flex items-center justify-end z-50" onClick={() => setSelectedSender(null)}>
                    <div className="bg-card border-l border-border h-full w-full max-w-md p-6 overflow-y-auto" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-between mb-4">
                            <h3 className="font-heading font-bold text-lg text-foreground">Sender Detail</h3>
                            <button onClick={() => setSelectedSender(null)} className="text-foreground-muted hover:text-foreground">✕</button>
                        </div>
                        <div className="space-y-3 text-xs">
                            <div className="flex justify-between border-b border-border pb-2"><span className="text-foreground-muted">IP Address</span><span className="font-mono font-bold text-foreground">{selectedSender.ip}</span></div>
                            <div className="flex justify-between border-b border-border pb-2"><span className="text-foreground-muted">Country</span><span className="font-bold text-foreground">{selectedSender.geo_country ?? selectedSender.country}</span></div>
                            {selectedSender.geo_city && (
                                <div className="flex justify-between border-b border-border pb-2"><span className="text-foreground-muted">City / Region</span><span className="font-bold text-foreground">{selectedSender.geo_city}{selectedSender.geo_region ? `, ${selectedSender.geo_region}` : ''}</span></div>
                            )}
                            <div className="flex justify-between border-b border-border pb-2"><span className="text-foreground-muted">ISP</span><span className="font-bold text-foreground">{selectedSender.isp}</span></div>
                            <div className="flex justify-between border-b border-border pb-2"><span className="text-foreground-muted">Messages Sent</span><span className="font-bold text-foreground">{selectedSender.messages_sent}</span></div>
                            <div className="flex justify-between border-b border-border pb-2"><span className="text-foreground-muted">First Seen</span><span className="font-bold text-foreground">{selectedSender.first_seen}</span></div>
                            <div className="pt-2">
                                <p className="text-foreground-muted mb-1">Note</p>
                                <p className="text-foreground">{selectedSender.note}</p>
                            </div>
                        </div>
                        <div className="flex flex-col gap-2 mt-6">
                            <button className="text-xs font-bold px-3 py-2 bg-red hover:bg-red-hover text-white rounded-lg transition-colors">Block IP</button>
                            <button className="text-xs font-bold px-3 py-2 border border-border text-foreground-muted rounded-lg hover:bg-card-muted transition-colors">Report as Phishing</button>
                            <button className="text-xs font-bold px-3 py-2 border border-blue text-blue rounded-lg hover:bg-blue/10 transition-colors">Mark Authorized</button>
                        </div>
                    </div>
                </div>
            )}

            {/* Add domain modal */}
            {showAddModal && (
                <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 px-4">
                    <div className="bg-card border border-border rounded-2xl p-6 w-full max-w-md shadow-xl">
                        <h3 className="font-heading font-bold text-lg text-foreground mb-4">Add Domain to DMARC Monitoring</h3>
                        <div className="space-y-4">
                            <div>
                                <label className="text-xs font-medium text-foreground-muted uppercase tracking-wide">Domain Name</label>
                                <input type="text" value={newDomain} onChange={(e) => setNewDomain(e.target.value)} placeholder="yourdomain.com"
                                    className="w-full mt-1 bg-card-muted border border-border rounded-lg px-3 py-2.5 text-sm text-foreground placeholder:text-foreground-muted focus:outline-none focus:border-blue" />
                            </div>
                            {newDomain.trim() && (
                                <div className="bg-card-muted border border-border rounded-lg p-3">
                                    <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider mb-1">Generated DNS Record</p>
                                    <code className="text-[10px] font-mono text-foreground break-all">{dnsRecord(newDomain.trim())}</code>
                                </div>
                            )}
                        </div>
                        <div className="flex gap-3 mt-6">
                            <button onClick={() => setShowAddModal(false)} className="flex-1 border border-border text-foreground-muted py-2.5 rounded-lg text-sm hover:border-grey-300 transition-colors">Cancel</button>
                            <button onClick={addDomain} disabled={!newDomain.trim()} className="flex-1 bg-orange hover:bg-orange-hover disabled:opacity-60 text-white py-2.5 rounded-lg text-sm font-semibold transition-colors">Start Monitoring</button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
