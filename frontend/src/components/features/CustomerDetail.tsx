'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { ArrowLeft, Building2, Siren, Server, ClipboardCheck, Users, Settings, Plus, Wrench, ExternalLink } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';

interface Org {
    id: string;
    name: string;
    slug: string;
    domain: string | null;
    industry: string | null;
    plan: string;
    status: string | null;
    is_active: boolean;
    country: string | null;
    address: string | null;
    wazuh_group: string | null;
    contact_name: string | null;
    contact_email: string | null;
    contact_phone: string | null;
    ciso_name: string | null;
    ciso_email: string | null;
    setup_complete: boolean;
}

interface WazuhIncident { id: string; severity: string; name: string; asset: string; status: string; timestamp: string | null }
interface WazuhAgent { id: string; name: string; ip: string; status: string; lastSeen: string; os: string }
interface ComplianceFramework { shortName: string; score: number; assessed: number; totalControls: number }
interface PlatformUser { id: string; email: string; name: string | null; role: string; status: string }

const TABS = [
    { id: 'overview', label: 'Overview', icon: Building2 },
    { id: 'incidents', label: 'Incidents', icon: Siren },
    { id: 'agents', label: 'Agents', icon: Server },
    { id: 'compliance', label: 'Compliance', icon: ClipboardCheck },
    { id: 'team', label: 'Team', icon: Users },
    { id: 'settings', label: 'Settings', icon: Settings },
] as const;
type TabId = (typeof TABS)[number]['id'];

const TEAM_ROLES = ['soc_manager', 'analyst', 'executive', 'portal_user'] as const;

export function CustomerDetail({ orgId }: { orgId: string }) {
    const [tab, setTab] = useState<TabId>('overview');
    const [org, setOrg] = useState<Org | null | undefined>(undefined); // undefined = loading, null = not found

    useEffect(() => {
        apiFetch(apiUrl(`/api/organisations/${orgId}`), { cache: 'no-store' })
            .then((r) => (r.ok ? r.json() : null))
            .then(setOrg)
            .catch(() => setOrg(null));
    }, [orgId]);

    if (org === undefined) {
        return <div className="space-y-3">{Array.from({ length: 3 }).map((_, i) => <div key={i} className="h-16 bg-card-muted rounded-xl animate-pulse" />)}</div>;
    }
    if (org === null) {
        return (
            <div className="text-center py-16">
                <Building2 size={28} className="text-border mx-auto mb-3" />
                <p className="text-sm text-foreground-muted mb-4">Organisation not found.</p>
                <Link href="/admin/customers" className="text-xs font-bold text-blue hover:underline">← Back to Customers</Link>
            </div>
        );
    }

    return (
        <div className="space-y-4">
            <Link href="/admin/customers" className="flex items-center gap-1.5 text-xs font-bold text-blue hover:text-purple transition-colors w-fit">
                <ArrowLeft size={14} /> Back to Customers
            </Link>

            <div className="flex items-start justify-between">
                <div>
                    <h1 className="text-lg font-black text-foreground">{org.name === 'Cybernovr' ? '🛡️' : '🏢'} {org.name}</h1>
                    <p className="text-xs text-foreground-muted">{org.domain ?? 'No domain set'} · {org.industry ?? 'No industry set'}</p>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0">
                    {/* Opens the client-facing portal login for this org in a new tab. It is a
                        real sign-in, not an impersonation shortcut: portal sessions carry their
                        own token minted by the external backend (see middleware/auth.ts's note
                        on /api/portal/*), so an admin token can't be reused to view it and the
                        org slug only pre-selects the tenant. */}
                    <a
                        href={`/client/login?org=${encodeURIComponent(org.slug)}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-1.5 text-xs font-bold text-foreground border border-border hover:border-purple hover:text-purple rounded-lg px-3 py-2 transition-colors"
                    >
                        <ExternalLink size={13} /> Client Portal View
                    </a>
                    <Link href={`/admin/settings/organisations/${org.id}/setup`} className="flex items-center gap-1.5 text-xs font-bold text-white bg-purple hover:bg-purple-hover rounded-lg px-3 py-2 transition-colors">
                        <Wrench size={13} /> Setup Wizard
                    </Link>
                </div>
            </div>

            <div className="flex gap-1 bg-card-muted rounded-lg p-1 w-fit overflow-x-auto">
                {TABS.map((t) => (
                    <button key={t.id} onClick={() => setTab(t.id)}
                        className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-bold transition-colors whitespace-nowrap ${tab === t.id ? 'bg-card text-purple shadow-sm' : 'text-foreground-muted hover:text-foreground'}`}>
                        <t.icon size={12} /> {t.label}
                    </button>
                ))}
            </div>

            {tab === 'overview' && <OverviewTab org={org} />}
            {tab === 'incidents' && <IncidentsTab org={org} />}
            {tab === 'agents' && <AgentsTab org={org} />}
            {tab === 'compliance' && <ComplianceTab org={org} />}
            {tab === 'team' && <TeamTab org={org} />}
            {tab === 'settings' && <SettingsTab org={org} onSaved={setOrg} />}
        </div>
    );
}

function OverviewTab({ org }: { org: Org }) {
    const rows: [string, string][] = [
        ['Plan', org.plan], ['Status', org.status ?? (org.is_active ? 'active' : 'suspended')],
        ['Country', org.country ?? '—'], ['Address', org.address ?? '—'],
        ['Wazuh Group', org.wazuh_group ?? '—'], ['Setup Complete', org.setup_complete ? 'Yes' : 'No'],
        ['Primary Contact', org.contact_name ? `${org.contact_name} (${org.contact_email ?? '—'})` : '—'],
        ['Contact Phone', org.contact_phone ?? '—'],
        ['CISO', org.ciso_name ? `${org.ciso_name} (${org.ciso_email ?? '—'})` : '—'],
    ];
    return (
        <div className="bg-card border border-border rounded-xl divide-y divide-border">
            {rows.map(([label, value]) => (
                <div key={label} className="flex items-center justify-between px-4 py-3">
                    <span className="text-xs font-bold text-foreground-muted uppercase tracking-wide">{label}</span>
                    <span className="text-sm text-foreground">{value}</span>
                </div>
            ))}
        </div>
    );
}

function IncidentsTab({ org }: { org: Org }) {
    const [data, setData] = useState<{ incidents: WazuhIncident[]; kpis: { total: number; critical: number; high: number; medium: number; low: number } } | null>(null);
    useEffect(() => {
        const group = org.wazuh_group ? `?group=${encodeURIComponent(org.wazuh_group)}` : '';
        apiFetch(apiUrl(`/api/wazuh/incidents${group}`), { cache: 'no-store', signal: AbortSignal.timeout(15000) })
            .then((r) => r.json()).then(setData).catch(() => setData({ incidents: [], kpis: { total: 0, critical: 0, high: 0, medium: 0, low: 0 } }));
    }, [org.wazuh_group]);

    if (!org.wazuh_group) return <p className="text-xs text-foreground-muted">No Wazuh group set for this org yet — set one in Settings to see live incidents.</p>;
    if (!data) return <div className="h-24 bg-card-muted rounded-xl animate-pulse" />;

    return (
        <div className="space-y-3">
            <div className="grid grid-cols-4 gap-3">
                {(['critical', 'high', 'medium', 'low'] as const).map((k) => (
                    <div key={k} className="bg-card border border-border rounded-xl p-3">
                        <div className="text-xl font-black text-foreground">{data.kpis[k]}</div>
                        <div className="text-[9px] text-foreground-muted uppercase tracking-wider">{k}</div>
                    </div>
                ))}
            </div>
            {data.incidents.length === 0 ? (
                <p className="text-xs text-foreground-muted py-6 text-center">No incidents in the last 7 days for this group.</p>
            ) : (
                <div className="bg-card border border-border rounded-xl divide-y divide-border">
                    {data.incidents.slice(0, 15).map((inc) => (
                        <div key={inc.id} className="px-4 py-2.5 flex items-center justify-between gap-3">
                            <div className="min-w-0">
                                <p className="text-xs font-bold text-foreground truncate">{inc.name}</p>
                                <p className="text-[10px] text-foreground-muted">{inc.asset}</p>
                            </div>
                            <span className="text-[9px] font-bold px-2 py-0.5 rounded-full bg-card-muted text-foreground-muted uppercase flex-shrink-0">{inc.severity}</span>
                        </div>
                    ))}
                </div>
            )}
            <Link href="/admin/secops/incidents" className="text-[11px] font-bold text-blue hover:underline">View full Incidents workbench →</Link>
        </div>
    );
}

function AgentsTab({ org }: { org: Org }) {
    const [data, setData] = useState<{ total: number; active: number; agents: WazuhAgent[] } | null>(null);
    useEffect(() => {
        const group = org.wazuh_group ? `?group=${encodeURIComponent(org.wazuh_group)}` : '';
        apiFetch(apiUrl(`/api/wazuh/agents${group}`), { cache: 'no-store', signal: AbortSignal.timeout(15000) })
            .then((r) => r.json()).then(setData).catch(() => setData({ total: 0, active: 0, agents: [] }));
    }, [org.wazuh_group]);

    if (!org.wazuh_group) return <p className="text-xs text-foreground-muted">No Wazuh group set for this org yet — set one in Settings to see enrolled agents.</p>;
    if (!data) return <div className="h-24 bg-card-muted rounded-xl animate-pulse" />;

    return (
        <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
                <div className="bg-card border border-border rounded-xl p-3"><div className="text-xl font-black text-foreground">{data.total}</div><div className="text-[9px] text-foreground-muted uppercase tracking-wider">Total Endpoints</div></div>
                <div className="bg-card border border-border rounded-xl p-3"><div className="text-xl font-black text-blue">{data.active}</div><div className="text-[9px] text-foreground-muted uppercase tracking-wider">Active</div></div>
            </div>
            {data.agents.length === 0 ? (
                <p className="text-xs text-foreground-muted py-6 text-center">No agents enrolled in group &quot;{org.wazuh_group}&quot; yet.</p>
            ) : (
                <div className="bg-card border border-border rounded-xl divide-y divide-border">
                    {data.agents.map((a) => (
                        <div key={a.id} className="px-4 py-2.5 flex items-center justify-between gap-3">
                            <div className="min-w-0"><p className="text-xs font-bold text-foreground truncate">{a.name}</p><p className="text-[10px] text-foreground-muted font-mono">{a.ip}</p></div>
                            <span className={`text-[9px] font-bold px-2 py-0.5 rounded-full uppercase flex-shrink-0 ${a.status === 'active' ? 'bg-blue/10 text-blue' : 'bg-card-muted text-foreground-muted'}`}>{a.status}</span>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}

function ComplianceTab({ org }: { org: Org }) {
    const [frameworks, setFrameworks] = useState<ComplianceFramework[] | null>(null);
    useEffect(() => {
        apiFetch(apiUrl(`/api/compliance?orgId=${encodeURIComponent(org.slug)}`), { cache: 'no-store', signal: AbortSignal.timeout(10000) })
            .then((r) => r.json()).then((d) => setFrameworks(Array.isArray(d?.frameworks) ? d.frameworks : []))
            .catch(() => setFrameworks([]));
    }, [org.slug]);

    if (!frameworks) return <div className="h-24 bg-card-muted rounded-xl animate-pulse" />;
    return (
        <div className="bg-card border border-border rounded-xl divide-y divide-border">
            {frameworks.map((f) => (
                <div key={f.shortName} className="px-4 py-3 flex items-center justify-between gap-3">
                    <div>
                        <p className="text-xs font-bold text-foreground">{f.shortName}</p>
                        <p className="text-[10px] text-foreground-muted">{f.assessed}/{f.totalControls} controls assessed</p>
                    </div>
                    <span className="text-lg font-black text-foreground">{f.score}%</span>
                </div>
            ))}
        </div>
    );
}

function TeamTab({ org }: { org: Org }) {
    const [users, setUsers] = useState<PlatformUser[] | null>(null);
    const [adding, setAdding] = useState(false);
    const [email, setEmail] = useState('');
    const [name, setName] = useState('');
    const [role, setRole] = useState<(typeof TEAM_ROLES)[number]>('analyst');
    const [saving, setSaving] = useState(false);

    const load = () => {
        apiFetch(apiUrl(`/api/organisations/${org.id}/users`), { cache: 'no-store' })
            .then((r) => r.json()).then((d) => setUsers(Array.isArray(d?.users) ? d.users : []))
            .catch(() => setUsers([]));
    };
    useEffect(load, [org.id]);

    const addUser = async () => {
        if (!email.trim()) return;
        setSaving(true);
        try {
            await apiFetch(apiUrl(`/api/organisations/${org.id}/users`), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: email.trim(), name: name.trim() || undefined, role }),
            });
            setEmail(''); setName(''); setRole('analyst'); setAdding(false);
            load();
        } finally {
            setSaving(false);
        }
    };

    if (!users) return <div className="h-24 bg-card-muted rounded-xl animate-pulse" />;
    return (
        <div className="space-y-3">
            <div className="flex justify-end">
                <button onClick={() => setAdding((a) => !a)} className="flex items-center gap-1.5 text-xs font-bold text-white bg-purple hover:bg-purple-hover rounded-lg px-3 py-2 transition-colors">
                    <Plus size={13} /> Add Team Member
                </button>
            </div>
            {adding && (
                <div className="bg-card border border-border rounded-xl p-4 flex items-center gap-2">
                    <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Name" className="flex-1 border border-border bg-card-muted rounded-lg px-3 py-2 text-sm text-foreground" />
                    <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="email@company.com" className="flex-1 border border-border bg-card-muted rounded-lg px-3 py-2 text-sm text-foreground" />
                    <select value={role} onChange={(e) => setRole(e.target.value as typeof role)} className="border border-border bg-card-muted rounded-lg px-3 py-2 text-sm text-foreground w-36">
                        {TEAM_ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
                    </select>
                    <button onClick={addUser} disabled={saving} className="text-xs font-bold text-white bg-orange hover:bg-orange-hover rounded-lg px-3 py-2 disabled:opacity-50">{saving ? 'Adding…' : 'Add'}</button>
                </div>
            )}
            {users.length === 0 ? (
                <p className="text-xs text-foreground-muted py-6 text-center">No team members yet.</p>
            ) : (
                <div className="bg-card border border-border rounded-xl divide-y divide-border">
                    {users.map((u) => (
                        <div key={u.id} className="px-4 py-2.5 flex items-center justify-between gap-3">
                            <div><p className="text-xs font-bold text-foreground">{u.name ?? u.email}</p><p className="text-[10px] text-foreground-muted">{u.email}</p></div>
                            <span className="text-[9px] font-bold px-2 py-0.5 rounded-full bg-purple/10 text-purple uppercase flex-shrink-0">{u.role}</span>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}

function SettingsTab({ org, onSaved }: { org: Org; onSaved: (o: Org) => void }) {
    const [form, setForm] = useState({
        name: org.name, domain: org.domain ?? '', industry: org.industry ?? '', plan: org.plan,
        wazuh_group: org.wazuh_group ?? '', status: org.status ?? (org.is_active ? 'active' : 'suspended'),
    });
    const [saving, setSaving] = useState(false);
    const [saved, setSaved] = useState(false);

    const field = (k: keyof typeof form) => ({
        value: form[k],
        onChange: (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => { setForm((f) => ({ ...f, [k]: e.target.value })); setSaved(false); },
    });

    const save = async () => {
        setSaving(true);
        try {
            const res = await apiFetch(apiUrl(`/api/organisations/${org.id}`), {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(form),
            });
            const updated = await res.json();
            if (res.ok) { onSaved(updated); setSaved(true); }
        } finally {
            setSaving(false);
        }
    };

    return (
        <div className="bg-card border border-border rounded-xl p-5 space-y-4 max-w-lg">
            {([['name', 'Name'], ['domain', 'Domain'], ['industry', 'Industry'], ['wazuh_group', 'Wazuh Group']] as const).map(([k, label]) => (
                <div key={k}>
                    <label className="text-xs font-medium text-foreground-muted uppercase tracking-wide">{label}</label>
                    <input {...field(k)} className="w-full mt-1 border border-border bg-card-muted rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-purple" />
                </div>
            ))}
            <div>
                <label className="text-xs font-medium text-foreground-muted uppercase tracking-wide">Plan</label>
                <select {...field('plan')} className="w-full mt-1 border border-border bg-card-muted rounded-lg px-3 py-2 text-sm text-foreground">
                    {['starter', 'professional', 'enterprise'].map((p) => <option key={p} value={p}>{p}</option>)}
                </select>
            </div>
            <div>
                <label className="text-xs font-medium text-foreground-muted uppercase tracking-wide">Status</label>
                <select {...field('status')} className="w-full mt-1 border border-border bg-card-muted rounded-lg px-3 py-2 text-sm text-foreground">
                    {['active', 'trial', 'suspended'].map((s) => <option key={s} value={s}>{s}</option>)}
                </select>
            </div>
            <button onClick={save} disabled={saving} className="text-xs font-bold text-white bg-purple hover:bg-purple-hover rounded-lg px-4 py-2.5 disabled:opacity-50 transition-colors">
                {saving ? 'Saving…' : saved ? 'Saved ✓' : 'Save Changes'}
            </button>
        </div>
    );
}
