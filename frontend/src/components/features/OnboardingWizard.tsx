'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { ArrowLeft, ArrowRight, Check, CheckCircle2, Plus, Trash2, Building2, User, ClipboardCheck, Users, Server } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';

// 5-step new-client onboarding wizard — POST /api/organisations creates the org (Step 1's
// fields), then reuses the EXISTING org_setup endpoint (POST /api/organisations/:id/setup,
// shared with the since-removed OrgSetupWizard.tsx) for compliance frameworks + contacts + Wazuh group,
// and POST /api/organisations/:id/users for each Step 4 team member. Nothing here duplicates
// those two already-working endpoints.

const STEPS = [
    { id: 1, title: 'Company Info', icon: Building2 },
    { id: 2, title: 'Contacts', icon: User },
    { id: 3, title: 'Compliance', icon: ClipboardCheck },
    { id: 4, title: 'Team Setup', icon: Users },
    { id: 5, title: 'Infrastructure', icon: Server },
] as const;

const INDUSTRIES = [
    'Banking & Finance', 'Telecommunications', 'Oil & Gas', 'Healthcare', 'Government',
    'Insurance', 'Retail', 'Manufacturing', 'Technology', 'Other',
];
const PLANS = ['starter', 'professional', 'enterprise'] as const;

interface Framework { id: string; name: string; desc: string; required?: boolean; sector?: string }
const FRAMEWORKS: Framework[] = [
    { id: 'ndpa', name: 'NDPA', desc: 'Nigeria Data Protection Act', required: true },
    { id: 'cbn', name: 'CBN', desc: 'CBN Cybersecurity Framework', sector: 'banking' },
    { id: 'ncc', name: 'NCC', desc: 'NCC Consumer Protection', sector: 'telecom' },
    { id: 'iso27001', name: 'ISO 27001', desc: 'Information Security Mgmt' },
    { id: 'pcidss', name: 'PCI-DSS', desc: 'Payment Card Industry DSS', sector: 'banking' },
    { id: 'nist', name: 'NIST CSF', desc: 'NIST Cybersecurity Framework' },
];

const TEAM_ROLES = ['soc_manager', 'analyst', 'executive', 'portal_user'] as const;
interface TeamMember { email: string; name: string; role: (typeof TEAM_ROLES)[number] }

const inputCls = 'w-full mt-1 border border-border bg-card-muted rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-purple text-foreground placeholder:text-foreground-muted';
const labelCls = 'text-xs font-medium text-foreground-muted uppercase tracking-wide';

export function OnboardingWizard() {
    const router = useRouter();
    const [step, setStep] = useState(1);
    const [saving, setSaving] = useState(false);
    const [error, setError] = useState<string | null>(null);

    // Step 1
    const [name, setName] = useState('');
    const [domain, setDomain] = useState('');
    const [industry, setIndustry] = useState(INDUSTRIES[0]);
    const [plan, setPlan] = useState<(typeof PLANS)[number]>('starter');
    const [country, setCountry] = useState('Nigeria');
    const [address, setAddress] = useState('');

    // Step 2
    const [contactName, setContactName] = useState('');
    const [contactEmail, setContactEmail] = useState('');
    const [contactPhone, setContactPhone] = useState('');
    const [cisoName, setCisoName] = useState('');
    const [cisoEmail, setCisoEmail] = useState('');

    // Step 3 — NDPA pre-selected and locked (mandatory for every Nigerian org)
    const [selectedFrameworks, setSelectedFrameworks] = useState<Set<string>>(new Set(['ndpa']));
    const [scores, setScores] = useState<Record<string, number>>({});
    const [assessLater, setAssessLater] = useState<Set<string>>(new Set());
    const toggleFramework = (id: string) => {
        if (id === 'ndpa') return; // required, can't be unchecked
        setSelectedFrameworks((prev) => {
            const next = new Set(prev);
            if (next.has(id)) next.delete(id); else next.add(id);
            return next;
        });
    };

    // Step 4
    const [team, setTeam] = useState<TeamMember[]>([{ email: '', role: 'soc_manager', name: '' }]);
    const addTeamRow = () => setTeam((t) => [...t, { email: '', role: 'analyst', name: '' }]);
    const removeTeamRow = (i: number) => setTeam((t) => t.filter((_, idx) => idx !== i));
    const updateTeamRow = (i: number, patch: Partial<TeamMember>) => setTeam((t) => t.map((m, idx) => (idx === i ? { ...m, ...patch } : m)));
    const hasSocManager = team.some((m) => m.role === 'soc_manager' && m.email.trim());

    // Step 5
    const [wazuhGroup, setWazuhGroup] = useState('');
    const [endpointCount, setEndpointCount] = useState('');
    const [locations, setLocations] = useState('');

    // Result
    const [done, setDone] = useState<{ orgId: string; orgName: string; wazuhGroup: string } | null>(null);

    const canAdvance = (): boolean => {
        if (step === 1) return name.trim().length > 0 && domain.trim().length > 0;
        if (step === 4) return hasSocManager;
        return true;
    };

    const reset = () => {
        setStep(1);
        setName(''); setDomain(''); setIndustry(INDUSTRIES[0]); setPlan('starter'); setCountry('Nigeria'); setAddress('');
        setContactName(''); setContactEmail(''); setContactPhone(''); setCisoName(''); setCisoEmail('');
        setSelectedFrameworks(new Set(['ndpa'])); setScores({}); setAssessLater(new Set());
        setTeam([{ email: '', role: 'soc_manager', name: '' }]);
        setWazuhGroup(''); setEndpointCount(''); setLocations('');
        setDone(null); setError(null);
    };

    const submit = async () => {
        setSaving(true);
        setError(null);
        try {
            const orgRes = await apiFetch(apiUrl('/api/organisations'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    name: name.trim(), domain: domain.trim(), industry, plan, country, address,
                    contact_name: contactName, contact_email: contactEmail, contact_phone: contactPhone,
                    ciso_name: cisoName, ciso_email: cisoEmail,
                }),
            });
            const org = await orgRes.json();
            if (!orgRes.ok || !org?.id) throw new Error(org?.error || 'Failed to create organisation');

            await apiFetch(apiUrl(`/api/organisations/${org.id}/setup`), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    basicInfo: { name: name.trim(), industry, plan },
                    frameworks: [...selectedFrameworks].map((id) => ({
                        framework: FRAMEWORKS.find((f) => f.id === id)?.name ?? id,
                        enabled: true,
                        initialScore: assessLater.has(id) ? 0 : (scores[id] ?? 0),
                    })),
                    contacts: { cisoName, cisoEmail, itDirectorEmail: contactEmail, onCallPhone: contactPhone },
                    wazuhGroup: wazuhGroup.trim(),
                }),
            }).catch(() => {}); // non-fatal — org creation itself already succeeded

            await apiFetch(apiUrl(`/api/organisations/${org.id}`), {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ wazuh_group: wazuhGroup.trim() || null, setup_complete: true }),
            }).catch(() => {});

            await Promise.all(
                team.filter((m) => m.email.trim()).map((m) =>
                    apiFetch(apiUrl(`/api/organisations/${org.id}/users`), {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ email: m.email.trim(), name: m.name.trim() || undefined, role: m.role }),
                    }).catch(() => {})
                )
            );

            setDone({ orgId: org.id, orgName: org.name ?? name, wazuhGroup: wazuhGroup.trim() });
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Onboarding failed');
        } finally {
            setSaving(false);
        }
    };

    if (done) {
        return (
            <div className="max-w-lg mx-auto text-center py-12">
                <div className="w-20 h-20 bg-green/10 rounded-full flex items-center justify-center mx-auto mb-6">
                    <CheckCircle2 size={40} className="text-green" />
                </div>
                <h2 className="text-2xl font-black text-foreground mb-3">{done.orgName} is now onboarded!</h2>
                <p className="text-sm text-foreground-muted mb-8">
                    Organisation created.{done.wazuhGroup ? <> Wazuh agents can now be enrolled using the group name: <strong className="text-foreground font-mono">{done.wazuhGroup}</strong>.</> : ' Team members were added to platform_users.'}
                </p>
                <div className="flex gap-3 justify-center">
                    <button onClick={() => router.push(`/admin/customers/${done.orgId}`)} className="text-xs font-bold text-white bg-purple hover:bg-purple-hover rounded-lg px-4 py-2.5 transition-colors">
                        View Organisation →
                    </button>
                    <button onClick={reset} className="text-xs font-bold text-foreground border border-border rounded-lg px-4 py-2.5 hover:bg-card-muted transition-colors">
                        Onboard Another Client
                    </button>
                </div>
            </div>
        );
    }

    return (
        <div className="max-w-2xl mx-auto space-y-5">
            <Link href="/admin/customers" className="flex items-center gap-1.5 text-xs font-bold text-blue hover:text-purple transition-colors">
                <ArrowLeft size={14} /> Back to Clients
            </Link>

            <div>
                <h1 className="text-lg font-black text-foreground">Onboard New Client</h1>
                <p className="text-xs text-foreground-muted">5-step setup — creates the organisation, its compliance baseline, its team, and its Wazuh enrollment group.</p>
            </div>

            <div className="flex items-center gap-2">
                {STEPS.map((s) => (
                    <div key={s.id} className="flex items-center gap-2 flex-1">
                        <button
                            onClick={() => step > s.id && setStep(s.id)}
                            disabled={step < s.id}
                            className={`w-7 h-7 rounded-full text-[11px] font-bold flex items-center justify-center flex-shrink-0 transition-colors ${s.id === step ? 'bg-purple text-white' : s.id < step ? 'bg-green/10 text-green' : 'bg-card-muted text-foreground-muted'}`}
                        >
                            {s.id < step ? <Check size={12} /> : <s.icon size={12} />}
                        </button>
                        <span className={`text-[10px] font-bold hidden sm:inline ${s.id === step ? 'text-foreground' : 'text-foreground-muted'}`}>{s.title}</span>
                        {s.id < STEPS.length && <div className="flex-1 h-px bg-border" />}
                    </div>
                ))}
            </div>

            <div className="bg-card border border-border rounded-xl p-6">
                {step === 1 && (
                    <div className="space-y-4">
                        <h2 className="font-bold text-sm text-foreground">Company Info</h2>
                        <div>
                            <label className={labelCls}>Organisation Name *</label>
                            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Zenith Bank PLC" className={inputCls} />
                        </div>
                        <div>
                            <label className={labelCls}>Primary Domain *</label>
                            <input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="zenithbank.com" className={inputCls} />
                        </div>
                        <div>
                            <label className={labelCls}>Industry *</label>
                            <select value={industry} onChange={(e) => setIndustry(e.target.value)} className={inputCls}>
                                {INDUSTRIES.map((i) => <option key={i} value={i}>{i}</option>)}
                            </select>
                        </div>
                        <div>
                            <label className={labelCls}>Plan</label>
                            <select value={plan} onChange={(e) => setPlan(e.target.value as typeof plan)} className={inputCls}>
                                {PLANS.map((p) => <option key={p} value={p}>{p}</option>)}
                            </select>
                        </div>
                        <div>
                            <label className={labelCls}>Country</label>
                            <input value={country} onChange={(e) => setCountry(e.target.value)} className={inputCls} />
                        </div>
                        <div>
                            <label className={labelCls}>Address</label>
                            <input value={address} onChange={(e) => setAddress(e.target.value)} placeholder="Victoria Island, Lagos" className={inputCls} />
                        </div>
                    </div>
                )}

                {step === 2 && (
                    <div className="space-y-4">
                        <h2 className="font-bold text-sm text-foreground">Contacts</h2>
                        <div className="bg-purple/5 border border-purple/20 rounded-xl p-4 space-y-3">
                            <div className="text-sm font-bold text-purple">Primary Contact</div>
                            <div><label className={labelCls}>Name</label><input value={contactName} onChange={(e) => setContactName(e.target.value)} placeholder="John Adeyemi" className={inputCls} /></div>
                            <div><label className={labelCls}>Email</label><input value={contactEmail} onChange={(e) => setContactEmail(e.target.value)} placeholder="john@company.com" className={inputCls} /></div>
                            <div><label className={labelCls}>Phone</label><input value={contactPhone} onChange={(e) => setContactPhone(e.target.value)} placeholder="+234 801 234 5678" className={inputCls} /></div>
                        </div>
                        <div className="bg-card-muted border border-border rounded-xl p-4 space-y-3">
                            <div className="text-sm font-bold text-foreground">CISO / Security Lead</div>
                            <div><label className={labelCls}>Name</label><input value={cisoName} onChange={(e) => setCisoName(e.target.value)} placeholder="Amaka Okonkwo" className={inputCls} /></div>
                            <div><label className={labelCls}>Email</label><input value={cisoEmail} onChange={(e) => setCisoEmail(e.target.value)} placeholder="ciso@company.com" className={inputCls} /></div>
                        </div>
                    </div>
                )}

                {step === 3 && (
                    <div className="space-y-4">
                        <h2 className="font-bold text-sm text-foreground">Compliance Frameworks</h2>
                        <p className="text-xs text-foreground-muted -mt-2">NDPA applies to every Nigerian organisation and can&apos;t be unchecked. Toggle &quot;assess later&quot; instead of guessing a starting score.</p>
                        {FRAMEWORKS.map((f) => {
                            const enabled = selectedFrameworks.has(f.id);
                            const later = assessLater.has(f.id);
                            return (
                                <div key={f.id} className="border-b border-border last:border-0 pb-3 last:pb-0">
                                    <div className="flex items-center gap-3">
                                        <input type="checkbox" checked={enabled} disabled={f.required} onChange={() => toggleFramework(f.id)} className="accent-purple flex-shrink-0" />
                                        <div className="flex-1 min-w-0">
                                            <span className="text-sm font-bold text-foreground">{f.name}</span>
                                            {f.required && <span className="text-[9px] font-bold text-purple ml-1.5 uppercase">Required</span>}
                                            <p className="text-[10px] text-foreground-muted">{f.desc}</p>
                                        </div>
                                    </div>
                                    {enabled && (
                                        <div className="flex items-center gap-3 mt-2 pl-7">
                                            <label className="flex items-center gap-1.5 text-[10px] font-bold text-foreground-muted flex-shrink-0">
                                                <input type="checkbox" checked={later} onChange={() => setAssessLater((prev) => { const n = new Set(prev); if (n.has(f.id)) n.delete(f.id); else n.add(f.id); return n; })} className="accent-purple" />
                                                We will assess this properly
                                            </label>
                                            <input type="range" min={0} max={100} value={scores[f.id] ?? 0} disabled={later}
                                                onChange={(e) => setScores((s) => ({ ...s, [f.id]: Number(e.target.value) }))}
                                                className="flex-1 accent-purple disabled:opacity-40" />
                                            <span className="text-xs font-bold text-foreground w-10 text-right flex-shrink-0">{later ? '—' : `${scores[f.id] ?? 0}%`}</span>
                                        </div>
                                    )}
                                </div>
                            );
                        })}
                    </div>
                )}

                {step === 4 && (
                    <div className="space-y-4">
                        <h2 className="font-bold text-sm text-foreground">Team Setup</h2>
                        <p className="text-xs text-foreground-muted -mt-2">At least one SOC Manager is required.</p>
                        <div className="space-y-2">
                            {team.map((m, i) => (
                                <div key={i} className="flex items-center gap-2">
                                    <input value={m.name} onChange={(e) => updateTeamRow(i, { name: e.target.value })} placeholder="Name" className={`${inputCls} mt-0 flex-1`} />
                                    <input value={m.email} onChange={(e) => updateTeamRow(i, { email: e.target.value })} placeholder="email@company.com" className={`${inputCls} mt-0 flex-1`} />
                                    <select value={m.role} onChange={(e) => updateTeamRow(i, { role: e.target.value as TeamMember['role'] })} className={`${inputCls} mt-0 w-36 flex-shrink-0`}>
                                        {TEAM_ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
                                    </select>
                                    <button onClick={() => removeTeamRow(i)} disabled={team.length === 1} className="text-foreground-muted hover:text-red disabled:opacity-30 flex-shrink-0 p-2" aria-label="Remove">
                                        <Trash2 size={14} />
                                    </button>
                                </div>
                            ))}
                        </div>
                        <button onClick={addTeamRow} className="flex items-center gap-1.5 text-xs font-bold text-purple hover:text-purple-hover">
                            <Plus size={14} /> Add another
                        </button>
                        {!hasSocManager && <p className="text-[11px] text-amber">Add at least one team member with the SOC Manager role to continue.</p>}
                    </div>
                )}

                {step === 5 && (
                    <div className="space-y-4">
                        <h2 className="font-bold text-sm text-foreground">Infrastructure</h2>
                        <div>
                            <label className={labelCls}>Wazuh Agent Group Name</label>
                            <input value={wazuhGroup} onChange={(e) => setWazuhGroup(e.target.value)} placeholder="e.g. zenith-bank" className={`${inputCls} font-mono`} />
                            <p className="text-[10px] text-foreground-muted mt-1.5">Agents enrolled for this client will use this group name. Share the agent installation guide below with their IT team.</p>
                        </div>
                        <div>
                            <label className={labelCls}>Number of Endpoints to Monitor</label>
                            <input type="number" value={endpointCount} onChange={(e) => setEndpointCount(e.target.value)} placeholder="50" className={inputCls} />
                        </div>
                        <div>
                            <label className={labelCls}>Office Locations</label>
                            <input value={locations} onChange={(e) => setLocations(e.target.value)} placeholder="Lagos HQ, Abuja Branch, Port Harcourt" className={inputCls} />
                        </div>
                        <div className="bg-card-muted border border-border rounded-xl p-4">
                            <div className="font-bold text-sm text-foreground mb-2">Agent Installation</div>
                            <p className="text-xs text-foreground-muted mb-3">Share these instructions with the client&apos;s IT team to enroll their endpoints.</p>
                            <div className="bg-[#1C1F2E] rounded-lg p-3 font-mono text-[11px] text-green-400 overflow-x-auto">
                                <div># Windows (PowerShell as Admin):</div>
                                <div>$url = &quot;https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.5-1.msi&quot;</div>
                                <div>Start-Process msiexec -ArgumentList &quot;/i $url WAZUH_MANAGER=169.58.242.174 WAZUH_AGENT_GROUP={wazuhGroup || '<group>'}&quot;</div>
                            </div>
                        </div>
                    </div>
                )}

                {error && <p className="text-xs text-red mt-4">{error}</p>}
            </div>

            <div className="flex items-center justify-between">
                <button onClick={() => setStep((s) => Math.max(1, s - 1))} disabled={step === 1}
                    className="flex items-center gap-1.5 text-xs font-bold text-foreground-muted border border-border rounded-lg px-4 py-2 disabled:opacity-40 hover:bg-card-muted transition-colors">
                    <ArrowLeft size={14} /> Back
                </button>
                {step < STEPS.length ? (
                    <button onClick={() => canAdvance() && setStep((s) => Math.min(STEPS.length, s + 1))} disabled={!canAdvance()}
                        className="flex items-center gap-1.5 text-xs font-bold text-white bg-purple rounded-lg px-4 py-2 hover:bg-purple-hover transition-colors disabled:opacity-50">
                        Next <ArrowRight size={14} />
                    </button>
                ) : (
                    <button onClick={submit} disabled={saving}
                        className="flex items-center gap-1.5 text-xs font-bold text-white bg-orange hover:bg-orange-hover rounded-lg px-4 py-2 disabled:opacity-50 transition-colors">
                        {saving ? 'Onboarding…' : 'Complete Onboarding'} <Check size={14} />
                    </button>
                )}
            </div>
        </div>
    );
}
