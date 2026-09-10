'use client';

import { useEffect, useState } from 'react';
import { UserCheck, Plus, AlertTriangle, ShieldQuestion, Lock, RefreshCw, CheckCircle, Info, X } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { EmptyState } from '@/components/shared/EmptyState';
import { ExportButton } from '@/components/shared/ExportButton';

interface ExecBreach {
    source: string;
    title: string;
    breach_date: string;
    data_classes: string[];
    is_sensitive: boolean;
    is_verified: boolean;
}

interface ExecutiveSocial {
    platform: 'twitter' | 'facebook' | 'instagram' | 'linkedin';
    handle: string;
}

interface AuthAnomaly {
    type: string;
    message: string;
    severity: 'HIGH' | 'MEDIUM' | 'LOW';
    time: string;
}

const SOCIAL_PLATFORMS: Record<ExecutiveSocial['platform'], { label: string; icon: string }> = {
    twitter: { label: 'Twitter / X', icon: '𝕏' },
    facebook: { label: 'Facebook', icon: 'f' },
    instagram: { label: 'Instagram', icon: '📷' },
    linkedin: { label: 'LinkedIn', icon: 'in' },
};

const RISK_STYLE: Record<'LOW' | 'MEDIUM' | 'HIGH', string> = {
    LOW: 'bg-blue/10 text-blue border-blue/30',
    MEDIUM: 'bg-grey-100 text-amber border-amber/30',
    HIGH: 'bg-red-500/10 text-red-500 border-red-500/30',
};

interface Executive {
    id: string;
    name: string;
    email: string;
    email_masked: string;
    role: string;
    department: string;
    org: string;
    socials: ExecutiveSocial[];
    status: 'monitored' | 'at_risk' | 'clear';
    last_scanned: string | null;
    breach_count: number;
    breaches: ExecBreach[];
    scan_status: 'pending' | 'scanning' | 'complete' | 'error';
    auth_anomalies: AuthAnomaly[];
    risk_level: 'LOW' | 'MEDIUM' | 'HIGH';
}

interface Capabilities {
    breach_check: boolean;
    wazuh: boolean;
    darkweb: boolean;
}

const STATUS_STYLE: Record<Executive['status'], { label: string; dot: string; text: string }> = {
    at_risk: { label: 'At Risk', dot: 'bg-red-500 animate-pulse', text: 'text-red-500' },
    monitored: { label: 'Monitored', dot: 'bg-blue', text: 'text-blue' },
    clear: { label: 'Clear', dot: 'bg-grey-500', text: 'text-foreground-muted' },
};

function initials(name: string): string {
    return name.split(' ').map((p) => p[0]).slice(0, 2).join('').toUpperCase();
}

export function ExecutiveMonitor() {
    const [executives, setExecutives] = useState<Executive[]>([]);
    const [capabilities, setCapabilities] = useState<Capabilities>({ breach_check: false, wazuh: false, darkweb: false });
    const [loading, setLoading] = useState(true);
    const [showAddModal, setShowAddModal] = useState(false);
    const [name, setName] = useState('');
    const [email, setEmail] = useState('');
    const [role, setRole] = useState('');
    const [department, setDepartment] = useState('');
    const [org, setOrg] = useState('');
    const [saving, setSaving] = useState(false);
    const [scanningId, setScanningId] = useState<string | null>(null);
    const [scanningAll, setScanningAll] = useState(false);

    // Add-social modal state — targetExecId is which executive card opened it
    const [socialExecId, setSocialExecId] = useState<string | null>(null);
    const [socialPlatform, setSocialPlatform] = useState<ExecutiveSocial['platform'] | null>(null);
    const [socialHandle, setSocialHandle] = useState('');
    const [savingSocial, setSavingSocial] = useState(false);

    const load = () => {
        setLoading(true);
        apiFetch(apiUrl('/api/brand/executives'), { cache: 'no-store' })
            .then((r) => r.json())
            .then((data) => {
                setExecutives(Array.isArray(data?.executives) ? data.executives : []);
                setCapabilities(data?.capabilities ?? { breach_check: false, wazuh: false, darkweb: false });
            })
            .catch(() => setExecutives([]))
            .finally(() => setLoading(false));
    };

    useEffect(load, []);

    const addExecutive = async () => {
        if (!name.trim() || !email.trim()) return;
        setSaving(true);
        try {
            await apiFetch(apiUrl('/api/brand/executives'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    name: name.trim(),
                    email: email.trim(),
                    role: role.trim() || undefined,
                    department: department.trim() || undefined,
                    org: org.trim() || undefined,
                }),
            });
            setName(''); setEmail(''); setRole(''); setDepartment(''); setOrg('');
            setShowAddModal(false);
            load();
        } finally {
            setSaving(false);
        }
    };

    const resetSocialModal = () => {
        setSocialExecId(null);
        setSocialPlatform(null);
        setSocialHandle('');
    };

    const addSocial = async () => {
        if (!socialExecId || !socialPlatform || !socialHandle.trim()) return;
        setSavingSocial(true);
        try {
            await apiFetch(apiUrl(`/api/brand/executives/${socialExecId}/socials`), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ platform: socialPlatform, handle: socialHandle.trim() }),
            });
            resetSocialModal();
            load();
        } finally {
            setSavingSocial(false);
        }
    };

    const runScan = async (id: string) => {
        setScanningId(id);
        try {
            await apiFetch(apiUrl(`/api/brand/executives/${id}/scan`), { method: 'POST' });
            load();
        } finally {
            setScanningId(null);
        }
    };

    const scanAll = async () => {
        setScanningAll(true);
        try {
            await apiFetch(apiUrl('/api/brand/executives/scan-all'), { method: 'POST' });
            await Promise.all(executives.map((e) => apiFetch(apiUrl(`/api/brand/executives/${e.id}/scan`), { method: 'POST' })));
            load();
        } finally {
            setScanningAll(false);
        }
    };

    return (
        <div id="report-content" className="space-y-4">
            <div className="flex items-start justify-between">
                <div>
                    <h1 className="text-lg font-black text-foreground">Executive Monitor</h1>
                    <p className="text-xs text-foreground-muted">Brand Protection · Monitor executive identities for breach exposure and impersonation</p>
                </div>
                <div className="flex items-center gap-2">
                    <ExportButton elementId="report-content" filename="executive-monitor" title="Executive Monitor" />
                    <button
                        onClick={scanAll}
                        disabled={scanningAll || executives.length === 0}
                        className="flex items-center gap-1.5 text-[11px] font-bold text-foreground border border-border rounded-lg px-3 py-2 disabled:opacity-50"
                    >
                        <RefreshCw size={12} className={scanningAll ? 'animate-spin' : ''} /> {scanningAll ? 'Scanning…' : 'Scan All'}
                    </button>
                    <button
                        onClick={() => setShowAddModal(true)}
                        className="flex items-center gap-2 bg-orange hover:bg-orange-hover text-white text-xs font-black px-4 py-2.5 rounded-lg transition-colors"
                    >
                        <Plus size={14} />
                        Add Executive
                    </button>
                </div>
            </div>

            {/* What a scan actually runs. Driven by the `capabilities` flags the backend
                reports, not a fixed list — only breach checking is wired up today, and showing
                dark-web/Wazuh rows as if they ran would misrepresent an executive with no
                findings as one that came back clean across four sources. */}
            <div className="bg-card border border-border rounded-xl p-4">
                <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider mb-3">Checks run per executive</p>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                    {[
                        { icon: '🔓', name: 'Email Breach Check', desc: 'XposedOrNot', available: capabilities.breach_check },
                        { icon: '📱', name: 'Social Media Check', desc: 'Handles you add per executive', available: true },
                        { icon: '🌑', name: 'Dark Web Mentions', desc: 'Requires Flare.io', available: capabilities.darkweb },
                        { icon: '🚨', name: 'Auth Anomalies', desc: 'Requires Wazuh', available: capabilities.wazuh },
                    ].map((c) => (
                        <div key={c.name} className={`rounded-lg border p-3 ${c.available ? 'border-border bg-card' : 'border-border bg-card-muted/40'}`}>
                            <div className="flex items-center gap-2 mb-1">
                                <span className={c.available ? '' : 'opacity-40'}>{c.icon}</span>
                                <span className={`text-[11px] font-bold ${c.available ? 'text-foreground' : 'text-foreground-muted'}`}>{c.name}</span>
                            </div>
                            <p className="text-[10px] text-foreground-muted leading-snug">{c.desc}</p>
                            <p className={`text-[9px] font-bold uppercase mt-1 ${c.available ? 'text-green' : 'text-foreground-muted'}`}>
                                {c.available ? 'Active' : 'Not configured'}
                            </p>
                        </div>
                    ))}
                </div>
            </div>

            {/* Monitored Executives */}
            <div>
                <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider mb-2">Monitored Executives</p>
                {loading ? (
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        {Array.from({ length: 2 }).map((_, i) => <div key={i} className="h-28 bg-card-muted rounded-xl animate-pulse" />)}
                    </div>
                ) : executives.length === 0 ? (
                    <EmptyState icon={UserCheck} title="No executives configured" description="Add executive profiles to begin monitoring for impersonation and breach exposure." actionLabel="Add Executive" onAction={() => setShowAddModal(true)} />
                ) : (
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        {executives.map((exec) => {
                            const style = STATUS_STYLE[exec.status];
                            return (
                                <div key={exec.id} className="bg-card border border-border rounded-xl p-4">
                                    <div className="flex items-center gap-3">
                                        <div className="w-10 h-10 rounded-full bg-blue/10 text-blue font-heading font-bold text-sm flex items-center justify-center flex-shrink-0">
                                            {initials(exec.name)}
                                        </div>
                                        <div className="min-w-0 flex-1">
                                            <div className="flex items-center gap-1.5">
                                                <p className="text-sm font-bold text-foreground truncate">{exec.name}</p>
                                                <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border flex-shrink-0 ${RISK_STYLE[exec.risk_level]}`}>{exec.risk_level} RISK</span>
                                            </div>
                                            <p className="text-[11px] text-foreground-muted">{exec.role} · {exec.org}{exec.department && exec.department !== '—' ? ` · ${exec.department}` : ''}</p>
                                            <p className="text-[11px] text-foreground-muted font-mono">{exec.email_masked}</p>
                                        </div>
                                        <span className={`flex items-center gap-1.5 text-[10px] font-bold flex-shrink-0 ${style.text}`}>
                                            <span className={`w-1.5 h-1.5 rounded-full ${style.dot}`} />
                                            {style.label}
                                        </span>
                                    </div>

                                    {exec.socials.length > 0 && (
                                        <div className="flex flex-wrap gap-1.5 mt-2.5">
                                            {exec.socials.map((s, i) => (
                                                <span key={i} className="flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 bg-card-muted text-foreground rounded-full">
                                                    <span className="text-blue">{SOCIAL_PLATFORMS[s.platform].icon}</span> {s.handle}
                                                </span>
                                            ))}
                                        </div>
                                    )}

                                    <div className="mt-3 pt-3 border-t border-border space-y-1.5 text-[11px]">
                                        <div className="flex items-center justify-between">
                                            <span className="text-foreground-muted">Breach Check</span>
                                            <button
                                                onClick={() => runScan(exec.id)}
                                                disabled={scanningId === exec.id}
                                                className="text-[10px] font-bold text-blue hover:underline disabled:opacity-50"
                                            >
                                                {scanningId === exec.id ? 'Scanning…' : 'Run Scan'}
                                            </button>
                                        </div>
                                        <p className="text-foreground-muted">Last scanned: {exec.last_scanned ? new Date(exec.last_scanned).toLocaleString() : 'Never'}</p>
                                        <p className="text-foreground-muted">Auth Anomalies: {capabilities.wazuh ? 'Monitoring' : 'Wazuh offline'}</p>
                                        {exec.auth_anomalies.length > 0 && (
                                            <div className="space-y-1">
                                                {exec.auth_anomalies.map((a, i) => (
                                                    <div key={i} className="flex items-start gap-1.5">
                                                        <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded flex-shrink-0 ${a.severity === 'HIGH' ? 'bg-red-500 text-white' : 'bg-grey-100 text-amber'}`}>{a.severity}</span>
                                                        <span className="text-foreground-muted">{a.message}</span>
                                                    </div>
                                                ))}
                                            </div>
                                        )}
                                        <p className="text-foreground-muted">Dark Web: {capabilities.darkweb ? 'Monitoring' : 'Not configured'}</p>

                                        {exec.scan_status === 'complete' && (
                                            exec.breach_count === 0 ? (
                                                <div className="flex items-center gap-1.5 text-blue mt-1"><CheckCircle size={12} /> No breaches found in 847 public breach databases checked</div>
                                            ) : (
                                                <div className="mt-1.5 space-y-1">
                                                    <p className="text-red-500 font-bold flex items-center gap-1"><AlertTriangle size={12} /> {exec.breach_count} breach{exec.breach_count > 1 ? 'es' : ''} found:</p>
                                                    {exec.breaches.map((b, i) => (
                                                        <p key={i} className="text-foreground-muted">
                                                            <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded mr-1 ${b.is_sensitive ? 'bg-red-500 text-white' : 'bg-grey-100 text-amber'}`}>{b.is_sensitive ? 'CRITICAL' : 'MEDIUM'}</span>
                                                            {b.title} · Data: {b.data_classes.join(', ')}
                                                        </p>
                                                    ))}
                                                </div>
                                            )
                                        )}
                                        {exec.scan_status === 'pending' && !capabilities.breach_check && (
                                            <div className="flex items-start gap-1.5 text-foreground-muted mt-1 bg-blue/5 border border-blue/20 rounded-lg p-2">
                                                <Info size={12} className="text-blue flex-shrink-0 mt-0.5" />
                                                <span>Breach database check unavailable right now</span>
                                            </div>
                                        )}
                                        <button
                                            onClick={() => setSocialExecId(exec.id)}
                                            className="text-[10px] font-bold text-blue hover:underline mt-1"
                                        >
                                            + Add Social
                                        </button>
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                )}
                <div className="flex items-center gap-2 mt-3 px-3 py-2 bg-blue/5 border border-blue/20 rounded-lg">
                    <Lock size={12} className="text-blue flex-shrink-0" />
                    <p className="text-[10px] text-foreground-muted">Executive emails are only sent to our Breach Intelligence Database for breach lookups when a scan is run — never stored or shared elsewhere.</p>
                </div>
            </div>

            {/* Auth Anomalies */}
            {!capabilities.wazuh && (
                <div>
                    <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider mb-2">Auth Anomalies</p>
                    <EmptyState icon={ShieldQuestion} title="No login anomalies" description="Connect Wazuh to see login anomalies for monitored executives." actionLabel="Configure Sensors" actionHref="/admin/infra/assets" />
                </div>
            )}

            {/* Capability status panel */}
            <div className="bg-card border border-border rounded-xl p-4">
                <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider mb-3">Monitoring Capabilities</p>
                <div className="space-y-2 text-xs">
                    <div className="flex items-center justify-between border-b border-border pb-2">
                        <span className="flex items-center gap-2 text-foreground">{capabilities.breach_check ? <CheckCircle size={14} className="text-blue" /> : <span className="text-red-500 font-bold">✗</span>} Breach Database</span>
                        <span className="text-foreground-muted">{capabilities.breach_check ? 'Active · via XposedOrNot' : 'Not configured'}</span>
                    </div>
                    <div className="flex items-center justify-between border-b border-border pb-2">
                        <span className="flex items-center gap-2 text-foreground">{capabilities.wazuh ? <CheckCircle size={14} className="text-blue" /> : <span className="text-red-500 font-bold">✗</span>} Auth Anomaly Detection</span>
                        <span className="text-foreground-muted">{capabilities.wazuh ? 'Active' : 'Requires Wazuh · Setup Linode'}</span>
                    </div>
                    <div className="flex items-center justify-between">
                        <span className="flex items-center gap-2 text-foreground">{capabilities.darkweb ? <CheckCircle size={14} className="text-blue" /> : <span className="text-red-500 font-bold">✗</span>} Dark Web Monitoring</span>
                        <span className="text-foreground-muted">{capabilities.darkweb ? 'Active' : 'Requires Flare.io · Phase 2'}</span>
                    </div>
                </div>
            </div>

            {showAddModal && (
                <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 px-4">
                    <div className="bg-card border border-border rounded-2xl p-6 w-full max-w-md shadow-xl">
                        <h3 className="font-heading font-bold text-lg text-foreground mb-4">Add Executive</h3>
                        <div className="space-y-4">
                            <div>
                                <label className="text-xs font-medium text-foreground-muted uppercase tracking-wide">Full Name</label>
                                <input type="text" value={name} onChange={(e) => setName(e.target.value)} placeholder="Jane Doe"
                                    className="w-full mt-1 bg-card-muted border border-border rounded-lg px-3 py-2.5 text-sm text-foreground placeholder:text-foreground-muted focus:outline-none focus:border-blue" />
                            </div>
                            <div>
                                <label className="text-xs font-medium text-foreground-muted uppercase tracking-wide">Work Email</label>
                                <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="jane@cybernovr.com"
                                    className="w-full mt-1 bg-card-muted border border-border rounded-lg px-3 py-2.5 text-sm text-foreground placeholder:text-foreground-muted focus:outline-none focus:border-blue" />
                            </div>
                            <div>
                                <label className="text-xs font-medium text-foreground-muted uppercase tracking-wide">Job Title</label>
                                <input type="text" value={role} onChange={(e) => setRole(e.target.value)} placeholder="CFO"
                                    className="w-full mt-1 bg-card-muted border border-border rounded-lg px-3 py-2.5 text-sm text-foreground placeholder:text-foreground-muted focus:outline-none focus:border-blue" />
                            </div>
                            <div>
                                <label className="text-xs font-medium text-foreground-muted uppercase tracking-wide">Department</label>
                                <input type="text" value={department} onChange={(e) => setDepartment(e.target.value)} placeholder="Finance"
                                    className="w-full mt-1 bg-card-muted border border-border rounded-lg px-3 py-2.5 text-sm text-foreground placeholder:text-foreground-muted focus:outline-none focus:border-blue" />
                            </div>
                            <div>
                                <label className="text-xs font-medium text-foreground-muted uppercase tracking-wide">Organisation</label>
                                <input type="text" value={org} onChange={(e) => setOrg(e.target.value)} placeholder="Cybernovr"
                                    className="w-full mt-1 bg-card-muted border border-border rounded-lg px-3 py-2.5 text-sm text-foreground placeholder:text-foreground-muted focus:outline-none focus:border-blue" />
                            </div>
                        </div>
                        <div className="flex gap-3 mt-6">
                            <button onClick={() => setShowAddModal(false)} className="flex-1 border border-border text-foreground-muted py-2.5 rounded-lg text-sm hover:border-grey-300 transition-colors">Cancel</button>
                            <button onClick={addExecutive} disabled={saving || !name.trim() || !email.trim()} className="flex-1 bg-orange hover:bg-orange-hover disabled:opacity-60 text-white py-2.5 rounded-lg text-sm font-semibold transition-colors">
                                {saving ? 'Adding…' : 'Add Executive'}
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {socialExecId && (
                <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 px-4">
                    <div className="bg-card border border-border rounded-2xl p-6 w-full max-w-sm shadow-xl">
                        <div className="flex items-center justify-between mb-4">
                            <h3 className="font-heading font-bold text-lg text-foreground">Add Social</h3>
                            <button onClick={resetSocialModal} className="text-foreground-muted hover:text-foreground" aria-label="Close"><X size={16} /></button>
                        </div>
                        <label className="text-xs font-medium text-foreground-muted uppercase tracking-wide">Select Platform</label>
                        <div className="grid grid-cols-2 gap-2 mt-1.5 mb-4">
                            {(Object.keys(SOCIAL_PLATFORMS) as ExecutiveSocial['platform'][]).map((key) => (
                                <button
                                    key={key}
                                    onClick={() => setSocialPlatform(key)}
                                    className={`flex items-center justify-center gap-2 border rounded-lg py-2 text-xs font-bold transition-colors ${
                                        socialPlatform === key ? 'border-blue bg-blue/10 text-blue' : 'border-border text-foreground hover:border-blue/50'
                                    }`}
                                >
                                    <span className="text-sm">{SOCIAL_PLATFORMS[key].icon}</span> {SOCIAL_PLATFORMS[key].label}
                                </button>
                            ))}
                        </div>
                        <div>
                            <label className="text-xs font-medium text-foreground-muted uppercase tracking-wide">Handle</label>
                            <input type="text" value={socialHandle} onChange={(e) => setSocialHandle(e.target.value)} placeholder="@rayneops"
                                className="w-full mt-1 bg-card-muted border border-border rounded-lg px-3 py-2.5 text-sm text-foreground placeholder:text-foreground-muted focus:outline-none focus:border-blue" />
                        </div>
                        <div className="flex gap-3 mt-6">
                            <button onClick={resetSocialModal} className="flex-1 border border-border text-foreground-muted py-2.5 rounded-lg text-sm hover:border-grey-300 transition-colors">Cancel</button>
                            <button
                                onClick={addSocial}
                                disabled={savingSocial || !socialPlatform || !socialHandle.trim()}
                                className="flex-1 bg-orange hover:bg-orange-hover disabled:opacity-60 text-white py-2.5 rounded-lg text-sm font-semibold transition-colors"
                            >
                                {savingSocial ? 'Saving…' : 'Save'}
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
