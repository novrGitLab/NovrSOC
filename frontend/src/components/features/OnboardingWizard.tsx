'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import {
    ArrowLeft, ArrowRight, Check, CheckCircle2, AlertTriangle,
    Building2, ShieldCheck, Users, Server, ClipboardList, Loader2,
} from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';

// Release 3.1 — the complete 6-step client onboarding wizard (phase P29). Reuses, rather than
// duplicates, every existing system it touches:
//   organisation         POST/PATCH /api/organisations (the same endpoints the old 5-step
//                         wizard and the Customers page already use)
//   service grants        GET/PUT /api/admin/onboarding/:id/services (new, phase P29) — gates
//                          the backend itself (lib/permissions.ts), not just this page's nav
//   invitations            POST /api/organisations/:id/users + POST /api/admin/users/:id/
//                          password-link — identical to CustomerDetail.tsx's Team tab
//   assets/integrations    the organisation's own `wazuh_group` column; VMS scope status read
//                          from GET /api/vms/scopes (X-Org-Id) — scope itself is authorised on
//                          the existing Scan Authorisation page, never duplicated here
//   reporting prefs        org_setup.contacts (existing JSONB; a reportCadence key added to it,
//                          no schema change) via the existing POST /api/organisations/:id/setup
// Progress is saved durably at every step (PATCH /api/admin/onboarding/:id/step/:n) so an
// interrupted onboarding resumes exactly where it left off, and stays editable after activation.

const STEPS = [
    { id: 1, title: 'Organisation', icon: Building2 },
    { id: 2, title: 'Services', icon: ShieldCheck },
    { id: 3, title: 'Invitations', icon: Users },
    { id: 4, title: 'Assets', icon: Server },
    { id: 5, title: 'Reporting', icon: ClipboardList },
    { id: 6, title: 'Review', icon: Check },
] as const;

const INDUSTRIES = ['Banking & Finance', 'Telecommunications', 'Oil & Gas', 'Healthcare', 'Government', 'Insurance', 'Retail', 'Manufacturing', 'Technology', 'Other'];
const PLANS = ['starter', 'professional', 'enterprise'] as const;
const SERVICES = ['vms', 'cnii_watch', 'threat_intel', 'secops_automation'] as const;
type ServiceKey = (typeof SERVICES)[number];
const SERVICE_STATUSES = ['pending', 'enabled', 'configured', 'disabled'] as const;
type ServiceStatus = (typeof SERVICE_STATUSES)[number];
const STATUS_STYLE: Record<ServiceStatus, string> = { enabled: 'bg-green/10 text-green', configured: 'bg-blue/10 text-blue', pending: 'bg-amber/10 text-amber', disabled: 'bg-card-muted text-foreground-muted' };
const INVITE_ROLES = ['executive', 'portal_user'] as const;

const inputCls = 'w-full mt-1 border border-border bg-card-muted rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-purple text-foreground placeholder:text-foreground-muted';
const labelCls = 'text-xs font-medium text-foreground-muted uppercase tracking-wide';

interface Org { id: string; slug: string; name: string; domain: string | null; industry: string | null; plan: string; country: string | null; address: string | null; contact_name: string | null; contact_email: string | null; contact_phone: string | null; ciso_name: string | null; ciso_email: string | null; wazuh_group: string | null }
interface OnboardingRecord { org_id: string; status: 'draft' | 'active'; current_step: number; completed_steps: number[]; steps: Record<string, Record<string, unknown>>; activated_by: string | null; activated_at: string | null }
interface ServiceGrant { service: ServiceKey; label: string; status: ServiceStatus; notes: string | null }
interface Member { id: string; email: string; name: string | null; role: string; status: string }

async function getJson<T>(path: string): Promise<{ ok: true; data: T } | { ok: false; error: string }> {
    try {
        const r = await apiFetch(apiUrl(path), { cache: 'no-store' });
        const d = await r.json().catch(() => null);
        if (!r.ok) return { ok: false, error: d?.error ?? `HTTP ${r.status}` };
        return { ok: true, data: d as T };
    } catch {
        return { ok: false, error: 'Could not reach the backend' };
    }
}
async function send<T>(method: string, path: string, body?: unknown): Promise<{ ok: true; data: T } | { ok: false; error: string; problems?: string[] }> {
    try {
        const r = await apiFetch(apiUrl(path), { method, headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) });
        const d = await r.json().catch(() => null);
        if (!r.ok) return { ok: false, error: d?.error ?? `HTTP ${r.status}`, problems: d?.problems };
        return { ok: true, data: d as T };
    } catch {
        return { ok: false, error: 'Could not reach the backend' };
    }
}

export function OnboardingWizard({ orgId }: { orgId?: string }) {
    const router = useRouter();
    const [org, setOrg] = useState<Org | null>(null);
    const [record, setRecord] = useState<OnboardingRecord | null>(null);
    const [step, setStep] = useState(1);
    const [loading, setLoading] = useState(!!orgId);
    const [loadError, setLoadError] = useState<string | null>(null);
    const [saving, setSaving] = useState(false);
    const [saveError, setSaveError] = useState<string | null>(null);
    const [activated, setActivated] = useState(false);

    // Step 1 fields (also the create-organisation payload).
    const [name, setName] = useState('');
    const [domain, setDomain] = useState('');
    const [industry, setIndustry] = useState(INDUSTRIES[0]);
    const [plan, setPlan] = useState<(typeof PLANS)[number]>('starter');
    const [country, setCountry] = useState('Nigeria');
    const [address, setAddress] = useState('');
    const [contactName, setContactName] = useState('');
    const [contactEmail, setContactEmail] = useState('');
    const [contactPhone, setContactPhone] = useState('');
    const [cisoName, setCisoName] = useState('');
    const [cisoEmail, setCisoEmail] = useState('');
    const [execName, setExecName] = useState('');
    const [execEmail, setExecEmail] = useState('');
    const [dupMatches, setDupMatches] = useState<{ name: string; slug: string }[]>([]);

    // Step 2: service grants.
    const [grants, setGrants] = useState<ServiceGrant[] | null>(null);

    // Step 3: team.
    const [members, setMembers] = useState<Member[] | null>(null);
    const [inviteName, setInviteName] = useState('');
    const [inviteEmail, setInviteEmail] = useState('');
    const [inviteRole, setInviteRole] = useState<(typeof INVITE_ROLES)[number]>('executive');
    const [link, setLink] = useState<{ email: string; url: string; expires_at: string } | null>(null);

    // Step 4: assets/integrations.
    const [wazuhGroup, setWazuhGroup] = useState('');
    const [scopeStatus, setScopeStatus] = useState<'checking' | 'none' | 'active' | 'pending' | 'error'>('checking');

    // Step 5: reporting.
    const [reportCadence, setReportCadence] = useState<'weekly' | 'monthly'>('weekly');

    const loadMembers = useCallback((id: string) => {
        void getJson<{ users: Member[] }>(`/api/organisations/${id}/users`).then((r) => setMembers(r.ok ? r.data.users : []));
    }, []);
    const loadServices = useCallback((id: string) => {
        void getJson<{ services: ServiceGrant[] }>(`/api/admin/onboarding/${id}/services`).then((r) => setGrants(r.ok ? r.data.services : null));
    }, []);
    const loadScopeStatus = useCallback((slug: string) => {
        apiFetch(apiUrl('/api/vms/scopes?status=active'), { headers: { 'X-Org-Id': slug }, cache: 'no-store' })
            .then((r) => r.json()).then((d) => setScopeStatus(Array.isArray(d?.scopes) && d.scopes.length ? 'active' : 'none'))
            .catch(() => setScopeStatus('error'));
    }, []);

    // Resume: load the organisation + its draft, and hydrate every step's form state from it.
    useEffect(() => {
        if (!orgId) return;
        let active = true;
        void Promise.all([
            getJson<Org>(`/api/organisations/${orgId}`),
            getJson<{ record: OnboardingRecord }>(`/api/admin/onboarding/${orgId}`),
        ]).then(([o, r]) => {
            if (!active) return;
            if (!o.ok) { setLoadError(o.error); setLoading(false); return; }
            setOrg(o.data);
            setName(o.data.name); setDomain(o.data.domain ?? ''); setIndustry(o.data.industry ?? INDUSTRIES[0]); setPlan((o.data.plan as typeof plan) ?? 'starter');
            setCountry(o.data.country ?? 'Nigeria'); setAddress(o.data.address ?? ''); setContactName(o.data.contact_name ?? ''); setContactEmail(o.data.contact_email ?? '');
            setContactPhone(o.data.contact_phone ?? ''); setCisoName(o.data.ciso_name ?? ''); setCisoEmail(o.data.ciso_email ?? ''); setWazuhGroup(o.data.wazuh_group ?? '');
            if (r.ok) {
                setRecord(r.data.record);
                setStep(r.data.record.current_step || 1);
                const s1 = r.data.record.steps['1'] as { primary_executive_name?: string; primary_executive_email?: string } | undefined;
                if (s1?.primary_executive_name) setExecName(s1.primary_executive_name);
                if (s1?.primary_executive_email) setExecEmail(s1.primary_executive_email);
                const s5 = r.data.record.steps['5'] as { report_cadence?: 'weekly' | 'monthly' } | undefined;
                if (s5?.report_cadence) setReportCadence(s5.report_cadence);
            }
            loadMembers(orgId);
            loadServices(orgId);
            setLoading(false);
        });
        return () => { active = false; };
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [orgId]);

    useEffect(() => { if (org && step === 4) loadScopeStatus(org.slug); }, [org, step, loadScopeStatus]);

    // Step 1: a soft, non-blocking warning while the admin is still typing — the backend's slug
    // suffixing already prevents a hard collision; this catches the "typed it twice" accident
    // earlier. Only runs before an organisation exists — dupMatches is never read past Step 1.
    useEffect(() => {
        if (org || !name.trim()) return;
        const t = setTimeout(() => {
            void getJson<{ matches: { name: string; slug: string }[] }>(`/api/organisations/check-duplicate?name=${encodeURIComponent(name.trim())}${domain.trim() ? `&domain=${encodeURIComponent(domain.trim())}` : ''}`)
                .then((r) => setDupMatches(r.ok ? r.data.matches : []));
        }, 500);
        return () => clearTimeout(t);
    }, [name, domain, org]);

    const canAdvance1 = name.trim().length > 0 && domain.trim().length > 0;

    /** Step 1 "Next": create the organisation (first time) or just save the step, then start/advance the draft. */
    const advanceFromStep1 = async () => {
        setSaving(true); setSaveError(null);
        try {
            let current = org;
            if (!current) {
                const created = await send<Org>('POST', '/api/organisations', {
                    name: name.trim(), domain: domain.trim(), industry, plan, country, address,
                    contact_name: contactName, contact_email: contactEmail, contact_phone: contactPhone, ciso_name: cisoName, ciso_email: cisoEmail,
                });
                if (!created.ok) { setSaveError(created.error); return; }
                current = created.data;
                setOrg(current);
                await send('POST', `/api/admin/onboarding/${current.id}/start`);
                loadMembers(current.id);
                loadServices(current.id);
            } else {
                await send('PATCH', `/api/organisations/${current.id}`, { name: name.trim(), domain: domain.trim(), industry, plan, country, address, contact_name: contactName, contact_email: contactEmail, contact_phone: contactPhone, ciso_name: cisoName, ciso_email: cisoEmail });
            }
            const saved = await send<{ record: OnboardingRecord }>('PATCH', `/api/admin/onboarding/${current.id}/step/1`, { data: { primary_executive_name: execName, primary_executive_email: execEmail }, advance_to: 2 });
            if (saved.ok) setRecord(saved.data.record);
            setStep(2);
            if (!orgId) router.replace(`/admin/onboarding/${current.id}`);
        } finally {
            setSaving(false);
        }
    };

    const saveStepAndAdvance = async (n: number, data: Record<string, unknown>, next: number) => {
        if (!org) return;
        setSaving(true); setSaveError(null);
        try {
            const r = await send<{ record: OnboardingRecord }>('PATCH', `/api/admin/onboarding/${org.id}/step/${n}`, { data, advance_to: next });
            if (!r.ok) { setSaveError(r.error); return; }
            setRecord(r.data.record);
            setStep(next);
        } finally {
            setSaving(false);
        }
    };

    const setGrant = async (service: ServiceKey, status: ServiceStatus, notes?: string) => {
        if (!org) return;
        const r = await send<{ grant: unknown }>('PUT', `/api/admin/onboarding/${org.id}/services`, { service, status, notes });
        if (r.ok) loadServices(org.id);
    };

    const sendInvite = async () => {
        if (!org || !inviteEmail.trim()) return;
        setSaving(true); setSaveError(null);
        try {
            const created = await send<{ id: string; email: string }>('POST', `/api/organisations/${org.id}/users`, { email: inviteEmail.trim(), name: inviteName.trim() || undefined, role: inviteRole });
            if (!created.ok) { setSaveError(created.error); return; }
            const linkRes = await send<{ url: string; expires_at: string }>('POST', `/api/admin/users/${created.data.id}/password-link`, { purpose: 'invite' });
            setInviteName(''); setInviteEmail('');
            if (linkRes.ok) setLink({ email: created.data.email, url: linkRes.data.url, expires_at: linkRes.data.expires_at });
            loadMembers(org.id);
        } finally {
            setSaving(false);
        }
    };
    const resendLink = async (m: Member) => {
        const r = await send<{ url: string; expires_at: string }>('POST', `/api/admin/users/${m.id}/password-link`, { purpose: m.status === 'invited' ? 'invite' : 'reset' });
        if (r.ok) setLink({ email: m.email, url: r.data.url, expires_at: r.data.expires_at });
    };

    const hasClientUser = (members ?? []).some((m) => m.role === 'executive' || m.role === 'portal_user');
    const problems = useMemo(() => {
        const p: string[] = [];
        if (!record?.completed_steps.includes(1)) p.push('Organisation profile (Step 1) is not saved');
        if (!hasClientUser) p.push('No executive or client user has been invited yet (Step 3)');
        return p;
    }, [record, hasClientUser]);

    const activate = async () => {
        if (!org) return;
        setSaving(true); setSaveError(null);
        try {
            const r = await send<{ record: OnboardingRecord }>('POST', `/api/admin/onboarding/${org.id}/activate`);
            if (!r.ok) { setSaveError(r.problems?.length ? `${r.error}: ${r.problems.join('; ')}` : r.error); return; }
            setRecord(r.data.record);
            setActivated(true);
        } finally {
            setSaving(false);
        }
    };

    if (loading) return <div className="max-w-2xl mx-auto py-16 text-center text-sm text-foreground-muted flex items-center justify-center gap-2"><Loader2 className="w-4 h-4 animate-spin" /> Loading onboarding…</div>;
    if (loadError) return (
        <div className="max-w-lg mx-auto text-center py-12">
            <AlertTriangle className="w-8 h-8 text-red-500 mx-auto mb-3" />
            <p className="text-sm font-bold text-foreground">Could not load this organisation</p>
            <p className="text-xs text-foreground-muted mt-1">{loadError}</p>
            <Link href="/admin/onboarding" className="inline-block mt-4 text-xs font-bold text-purple hover:underline">Back to Onboarding</Link>
        </div>
    );

    if (activated && org) {
        return (
            <div className="max-w-lg mx-auto text-center py-12">
                <div className="w-20 h-20 bg-green/10 rounded-full flex items-center justify-center mx-auto mb-6">
                    <CheckCircle2 size={40} className="text-green" />
                </div>
                <h2 className="text-2xl font-black text-foreground mb-3">{org.name} is now active</h2>
                <p className="text-sm text-foreground-muted mb-8">Onboarding is complete. Invited accounts can set their password and sign in once you&apos;ve shared their link.</p>
                <div className="flex gap-3 justify-center">
                    <button onClick={() => router.push(`/admin/customers/${org.id}`)} className="text-xs font-bold text-white bg-purple hover:bg-purple-hover rounded-lg px-4 py-2.5 transition-colors">View Organisation →</button>
                    <button onClick={() => router.push('/admin/onboarding/new')} className="text-xs font-bold text-foreground border border-border rounded-lg px-4 py-2.5 hover:bg-card-muted transition-colors">Onboard Another Client</button>
                </div>
            </div>
        );
    }

    return (
        <div className="max-w-2xl mx-auto space-y-5">
            <Link href="/admin/onboarding" className="flex items-center gap-1.5 text-xs font-bold text-blue hover:text-purple transition-colors">
                <ArrowLeft size={14} /> Back to Onboarding
            </Link>

            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-lg font-black text-foreground">{org ? `Onboarding — ${org.name}` : 'Onboard New Client'}</h1>
                    <p className="text-xs text-foreground-muted">6-step setup — organisation, services, invitations, assets, reporting, activation. Progress is saved as you go.</p>
                </div>
                {record?.status === 'active' && <span className="text-[10px] font-bold px-2.5 py-1 rounded-full bg-green/10 text-green uppercase flex-shrink-0">Active</span>}
            </div>

            <div className="flex items-center gap-1.5 flex-wrap">
                {STEPS.map((s) => {
                    const done = record?.completed_steps.includes(s.id);
                    const reachable = s.id === 1 || !!org;
                    return (
                        <div key={s.id} className="flex items-center gap-1.5 flex-1 min-w-[90px]">
                            <button
                                onClick={() => reachable && setStep(s.id)}
                                disabled={!reachable}
                                className={`w-7 h-7 rounded-full text-[11px] font-bold flex items-center justify-center flex-shrink-0 transition-colors ${s.id === step ? 'bg-purple text-white' : done ? 'bg-green/10 text-green' : 'bg-card-muted text-foreground-muted'} disabled:opacity-40`}
                            >
                                {done ? <Check size={12} /> : <s.icon size={12} />}
                            </button>
                            <span className={`text-[10px] font-bold hidden sm:inline ${s.id === step ? 'text-foreground' : 'text-foreground-muted'}`}>{s.title}</span>
                            {s.id < STEPS.length && <div className="flex-1 h-px bg-border" />}
                        </div>
                    );
                })}
            </div>

            <div className="bg-card border border-border rounded-xl p-6">
                {step === 1 && (
                    <div className="space-y-4">
                        <h2 className="font-bold text-sm text-foreground">Organisation Profile</h2>
                        <div><label className={labelCls}>Organisation Name *</label><input value={name} onChange={(e) => setName(e.target.value)} placeholder="Zenith Bank PLC" className={inputCls} disabled={!!org} /></div>
                        {dupMatches.length > 0 && (
                            <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-3 flex items-start gap-2">
                                <AlertTriangle size={14} className="text-amber-600 mt-0.5 flex-shrink-0" />
                                <p className="text-xs text-amber-800">This looks like an existing organisation: {dupMatches.map((m) => m.name).join(', ')}. Check before continuing — creating another will not merge with it.</p>
                            </div>
                        )}
                        <div><label className={labelCls}>Primary Domain *</label><input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="zenithbank.com" className={inputCls} /></div>
                        <div><label className={labelCls}>Sector / Industry *</label><select value={industry} onChange={(e) => setIndustry(e.target.value)} className={inputCls}>{INDUSTRIES.map((i) => <option key={i} value={i}>{i}</option>)}</select></div>
                        <div><label className={labelCls}>Plan</label><select value={plan} onChange={(e) => setPlan(e.target.value as typeof plan)} className={inputCls}>{PLANS.map((p) => <option key={p} value={p}>{p}</option>)}</select></div>
                        <div className="grid grid-cols-2 gap-3">
                            <div><label className={labelCls}>Country</label><input value={country} onChange={(e) => setCountry(e.target.value)} className={inputCls} /></div>
                            <div><label className={labelCls}>Address</label><input value={address} onChange={(e) => setAddress(e.target.value)} placeholder="Victoria Island, Lagos" className={inputCls} /></div>
                        </div>
                        <div className="bg-purple/5 border border-purple/20 rounded-xl p-4 space-y-3">
                            <div className="text-sm font-bold text-purple">Primary Contact</div>
                            <div className="grid grid-cols-2 gap-3">
                                <div><label className={labelCls}>Name</label><input value={contactName} onChange={(e) => setContactName(e.target.value)} placeholder="John Adeyemi" className={inputCls} /></div>
                                <div><label className={labelCls}>Email</label><input value={contactEmail} onChange={(e) => setContactEmail(e.target.value)} placeholder="john@company.com" className={inputCls} /></div>
                            </div>
                            <div><label className={labelCls}>Phone</label><input value={contactPhone} onChange={(e) => setContactPhone(e.target.value)} placeholder="+234 801 234 5678" className={inputCls} /></div>
                        </div>
                        <div className="bg-card-muted border border-border rounded-xl p-4 space-y-3">
                            <div className="text-sm font-bold text-foreground">CISO / Security Lead</div>
                            <div className="grid grid-cols-2 gap-3">
                                <div><label className={labelCls}>Name</label><input value={cisoName} onChange={(e) => setCisoName(e.target.value)} className={inputCls} /></div>
                                <div><label className={labelCls}>Email</label><input value={cisoEmail} onChange={(e) => setCisoEmail(e.target.value)} className={inputCls} /></div>
                            </div>
                        </div>
                        <div className="bg-blue/5 border border-blue/20 rounded-xl p-4 space-y-3">
                            <div className="text-sm font-bold text-blue">Primary Executive (invited in Step 3)</div>
                            <div className="grid grid-cols-2 gap-3">
                                <div><label className={labelCls}>Name</label><input value={execName} onChange={(e) => setExecName(e.target.value)} placeholder="Amaka Okonkwo" className={inputCls} /></div>
                                <div><label className={labelCls}>Email</label><input value={execEmail} onChange={(e) => setExecEmail(e.target.value)} placeholder="exec@company.com" className={inputCls} /></div>
                            </div>
                        </div>
                    </div>
                )}

                {step === 2 && org && (
                    <div className="space-y-4">
                        <h2 className="font-bold text-sm text-foreground">Service Provisioning</h2>
                        <p className="text-xs text-foreground-muted -mt-2">Which NovrSOC modules this organisation may use. Enforced on the backend immediately — not just hidden from navigation.</p>
                        {!grants ? <div className="h-32 bg-card-muted rounded-xl animate-pulse" /> : (
                            <div className="space-y-3">
                                {grants.map((g) => (
                                    <div key={g.service} className="border border-border rounded-xl p-3 flex items-center justify-between gap-3 flex-wrap">
                                        <div>
                                            <p className="text-sm font-bold text-foreground">{g.label}</p>
                                            <span className={`text-[9px] font-bold px-2 py-0.5 rounded-full uppercase ${STATUS_STYLE[g.status]}`}>{g.status}</span>
                                        </div>
                                        <div className="flex gap-1.5 flex-wrap">
                                            {SERVICE_STATUSES.map((s) => (
                                                <button key={s} onClick={() => void setGrant(g.service, s)} className={`text-[10px] font-bold px-2.5 py-1.5 rounded-lg border transition-colors ${g.status === s ? 'border-purple text-purple bg-purple/5' : 'border-border text-foreground-muted hover:bg-card-muted'}`}>
                                                    {s}
                                                </button>
                                            ))}
                                        </div>
                                    </div>
                                ))}
                                <p className="text-[10px] text-foreground-muted">Other existing modules (Email Security, Brand Protection) are configured from their own setup pages and are not gated by this step.</p>
                            </div>
                        )}
                    </div>
                )}

                {step === 3 && org && (
                    <div className="space-y-4">
                        <h2 className="font-bold text-sm text-foreground">User Invitations</h2>
                        <p className="text-xs text-foreground-muted -mt-2">Invite the organisation&apos;s executive and any additional client users. No email is sent automatically unless Brevo is configured — the one-time link is always shown here too.</p>
                        <div className="flex items-end gap-2 flex-wrap">
                            <input value={inviteName} onChange={(e) => setInviteName(e.target.value)} placeholder="Name" className={`${inputCls} mt-0 flex-1 min-w-[140px]`} />
                            <input value={inviteEmail} onChange={(e) => setInviteEmail(e.target.value)} placeholder="email@company.com" className={`${inputCls} mt-0 flex-1 min-w-[180px]`} />
                            <select value={inviteRole} onChange={(e) => setInviteRole(e.target.value as typeof inviteRole)} className={`${inputCls} mt-0 w-40 flex-shrink-0`}>
                                {INVITE_ROLES.map((r) => <option key={r} value={r}>{r === 'executive' ? 'Executive' : 'Portal user'}</option>)}
                            </select>
                            <button onClick={() => void sendInvite()} disabled={saving || !inviteEmail.trim()} className="text-xs font-bold text-white bg-orange hover:bg-orange-hover rounded-lg px-3 py-2 disabled:opacity-50 flex-shrink-0">Invite</button>
                        </div>
                        {link && (
                            <div className="bg-card-muted border border-border rounded-xl p-3 space-y-2">
                                <p className="text-xs font-bold text-foreground">Link for {link.email} (shown once; expires {new Date(link.expires_at).toLocaleString()})</p>
                                <code className="block bg-card border border-border rounded-lg px-3 py-2 text-[11px] font-mono break-all select-all">{link.url}</code>
                                <div className="flex gap-2">
                                    <button onClick={() => void navigator.clipboard.writeText(link.url)} className="text-[11px] font-bold text-white bg-purple rounded-lg px-3 py-1.5">Copy</button>
                                    <button onClick={() => setLink(null)} className="text-[11px] font-bold text-foreground border border-border rounded-lg px-3 py-1.5">Done</button>
                                </div>
                            </div>
                        )}
                        {!members ? <div className="h-20 bg-card-muted rounded-xl animate-pulse" /> : members.length === 0 ? (
                            <p className="text-xs text-foreground-muted text-center py-6">No one invited yet.</p>
                        ) : (
                            <div className="bg-card-muted border border-border rounded-xl divide-y divide-border">
                                {members.map((m) => (
                                    <div key={m.id} className="px-3 py-2.5 flex items-center justify-between gap-3">
                                        <div><p className="text-xs font-bold text-foreground">{m.name ?? m.email}</p><p className="text-[10px] text-foreground-muted">{m.email} · {m.role}</p></div>
                                        <div className="flex items-center gap-2 flex-shrink-0">
                                            <span className={`text-[9px] font-bold px-2 py-0.5 rounded-full uppercase ${m.status === 'disabled' ? 'bg-red-500/10 text-red-500' : m.status === 'invited' ? 'bg-amber/10 text-amber' : 'bg-green-500/10 text-green-600'}`}>{m.status}</span>
                                            {m.status !== 'disabled' && <button onClick={() => void resendLink(m)} className="text-[10px] font-bold text-foreground border border-border rounded-lg px-2 py-1">{m.status === 'invited' ? 'Resend' : 'Reset'}</button>}
                                        </div>
                                    </div>
                                ))}
                            </div>
                        )}
                        {!hasClientUser && <p className="text-[11px] text-amber">Invite at least one executive or portal user — required before activation.</p>}
                    </div>
                )}

                {step === 4 && org && (
                    <div className="space-y-4">
                        <h2 className="font-bold text-sm text-foreground">Assets and Integrations</h2>
                        <div>
                            <label className={labelCls}>Wazuh Agent Group Name</label>
                            <input value={wazuhGroup} onChange={(e) => setWazuhGroup(e.target.value)} placeholder="e.g. zenith-bank" className={`${inputCls} font-mono`} />
                            <p className="text-[10px] text-foreground-muted mt-1.5">Agents enrolled with this group will be attributed to this organisation.</p>
                        </div>
                        <div className="border border-border rounded-xl p-3 flex items-center justify-between">
                            <div>
                                <p className="text-sm font-bold text-foreground">Vulnerability scan authorisation</p>
                                <p className="text-[10px] text-foreground-muted">Active scanning needs an explicit, approved scope — never assumed here.</p>
                            </div>
                            {scopeStatus === 'checking' ? <span className="text-[10px] text-foreground-muted">Checking…</span>
                                : scopeStatus === 'active' ? <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-green/10 text-green uppercase">Authorised</span>
                                : scopeStatus === 'error' ? <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-red-500/10 text-red-500 uppercase">Unavailable</span>
                                : <Link href="/admin/vms/discovery" className="text-[10px] font-bold text-purple hover:underline">Authorise scope →</Link>}
                        </div>
                        <div className="bg-card-muted border border-border rounded-xl p-3">
                            <p className="text-xs font-bold text-foreground mb-1">Other integrations</p>
                            <p className="text-[11px] text-foreground-muted">CNII Watch, Email Security and Brand Protection each have their own connection pages once their module is enabled (Step 2). They are shown here as unavailable rather than pretending to connect.</p>
                        </div>
                    </div>
                )}

                {step === 5 && org && (
                    <div className="space-y-4">
                        <h2 className="font-bold text-sm text-foreground">Reporting and Preferences</h2>
                        <p className="text-xs text-foreground-muted -mt-2">Recipients reuse the organisation&apos;s own contacts (Step 1) — editable there, not duplicated here.</p>
                        <div className="bg-card-muted border border-border rounded-xl p-3 space-y-1">
                            <p className="text-xs"><span className="text-foreground-muted">CISO / report recipient:</span> <span className="font-bold text-foreground">{cisoEmail || contactEmail || '— set one in Step 1'}</span></p>
                            <p className="text-xs"><span className="text-foreground-muted">IT / on-call contact:</span> <span className="font-bold text-foreground">{contactEmail || '—'}</span></p>
                        </div>
                        <div><label className={labelCls}>Report Cadence</label>
                            <select value={reportCadence} onChange={(e) => setReportCadence(e.target.value as typeof reportCadence)} className={inputCls}>
                                <option value="weekly">Weekly</option>
                                <option value="monthly">Monthly</option>
                            </select>
                            <p className="text-[10px] text-foreground-muted mt-1.5">Saved to the organisation&apos;s profile; Weekly Insights is generated from real data — nothing here fabricates a report.</p>
                        </div>
                        <div className="bg-blue/5 border border-blue/20 rounded-xl p-3">
                            <p className="text-xs text-foreground-muted">Executive access to the Executive Report page follows directly from the <strong className="text-foreground">executive</strong> role invited in Step 3 — no separate toggle to keep in sync.</p>
                        </div>
                    </div>
                )}

                {step === 6 && org && (
                    <div className="space-y-4">
                        <h2 className="font-bold text-sm text-foreground">Review and Activation</h2>
                        <div className="grid grid-cols-2 gap-3 text-xs">
                            <div className="border border-border rounded-xl p-3"><p className="text-foreground-muted">Organisation</p><p className="font-bold text-foreground">{name} · {industry} · {plan}</p></div>
                            <div className="border border-border rounded-xl p-3"><p className="text-foreground-muted">Services</p><p className="font-bold text-foreground">{(grants ?? []).filter((g) => g.status === 'enabled' || g.status === 'configured').length} of {SERVICES.length} enabled</p></div>
                            <div className="border border-border rounded-xl p-3"><p className="text-foreground-muted">Invitations</p><p className="font-bold text-foreground">{members?.length ?? 0} invited</p></div>
                            <div className="border border-border rounded-xl p-3"><p className="text-foreground-muted">Wazuh group</p><p className="font-bold text-foreground font-mono">{wazuhGroup || '— not set'}</p></div>
                        </div>
                        <div className="bg-card-muted border border-border rounded-xl p-3">
                            <p className="text-xs font-bold text-foreground mb-1">Tenant isolation</p>
                            <p className="text-[11px] text-foreground-muted">Enforced platform-wide for every organisation by the backend&apos;s organisation resolver — not something this wizard configures per client. The invited executive will see only {name || 'this organisation'}&apos;s own data once they sign in at the client portal.</p>
                        </div>
                        <div className={`border rounded-xl p-3 ${problems.length ? 'border-amber-500/30 bg-amber-500/5' : 'border-green/30 bg-green/5'}`}>
                            <p className="text-xs font-bold text-foreground mb-1">{problems.length ? 'Before activating' : 'Ready to activate'}</p>
                            {problems.length ? <ul className="text-[11px] text-amber-700 list-disc pl-4 space-y-0.5">{problems.map((p) => <li key={p}>{p}</li>)}</ul>
                                : <p className="text-[11px] text-green-700">Mandatory requirements are met. Optional items (service grants left pending, Wazuh group) can stay pending and be finished after activation.</p>}
                        </div>
                        <button onClick={() => void activate()} disabled={saving || problems.length > 0} className="w-full flex items-center justify-center gap-1.5 text-xs font-bold text-white bg-orange hover:bg-orange-hover rounded-lg px-4 py-3 disabled:opacity-50 transition-colors">
                            {saving ? 'Activating…' : 'Activate Organisation'} <Check size={14} />
                        </button>
                        {record?.status === 'active' && <p className="text-[11px] text-green-700 text-center">Already active since {record.activated_at ? new Date(record.activated_at).toLocaleString() : '—'}. You can still edit any step above.</p>}
                    </div>
                )}

                {saveError && <p className="text-xs text-red mt-4">{saveError}</p>}
            </div>

            <div className="flex items-center justify-between">
                <button onClick={() => setStep((s) => Math.max(1, s - 1))} disabled={step === 1} className="flex items-center gap-1.5 text-xs font-bold text-foreground-muted border border-border rounded-lg px-4 py-2 disabled:opacity-40 hover:bg-card-muted transition-colors">
                    <ArrowLeft size={14} /> Back
                </button>
                {step === 1 ? (
                    <button onClick={() => void advanceFromStep1()} disabled={!canAdvance1 || saving} className="flex items-center gap-1.5 text-xs font-bold text-white bg-purple rounded-lg px-4 py-2 hover:bg-purple-hover transition-colors disabled:opacity-50">
                        {saving ? 'Saving…' : 'Next'} <ArrowRight size={14} />
                    </button>
                ) : step === 2 ? (
                    <button onClick={() => void saveStepAndAdvance(2, { confirmed: true }, 3)} disabled={saving} className="flex items-center gap-1.5 text-xs font-bold text-white bg-purple rounded-lg px-4 py-2 hover:bg-purple-hover transition-colors disabled:opacity-50">Next <ArrowRight size={14} /></button>
                ) : step === 3 ? (
                    <button onClick={() => void saveStepAndAdvance(3, { invited_count: members?.length ?? 0 }, 4)} disabled={saving} className="flex items-center gap-1.5 text-xs font-bold text-white bg-purple rounded-lg px-4 py-2 hover:bg-purple-hover transition-colors disabled:opacity-50">Next <ArrowRight size={14} /></button>
                ) : step === 4 ? (
                    <button onClick={async () => { if (org) await send('PATCH', `/api/organisations/${org.id}`, { wazuh_group: wazuhGroup.trim() || null }); void saveStepAndAdvance(4, { wazuh_group: wazuhGroup.trim() }, 5); }} disabled={saving} className="flex items-center gap-1.5 text-xs font-bold text-white bg-purple rounded-lg px-4 py-2 hover:bg-purple-hover transition-colors disabled:opacity-50">Next <ArrowRight size={14} /></button>
                ) : step === 5 ? (
                    <button onClick={async () => {
                        if (org) await send('POST', `/api/organisations/${org.id}/setup`, { contacts: { cisoName, cisoEmail, itDirectorEmail: contactEmail, onCallPhone: contactPhone, reportCadence } });
                        void saveStepAndAdvance(5, { report_cadence: reportCadence }, 6);
                    }} disabled={saving} className="flex items-center gap-1.5 text-xs font-bold text-white bg-purple rounded-lg px-4 py-2 hover:bg-purple-hover transition-colors disabled:opacity-50">Next <ArrowRight size={14} /></button>
                ) : <div />}
            </div>
        </div>
    );
}
