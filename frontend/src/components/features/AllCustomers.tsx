'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { Building2, Plus, Eye } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';

// GET /api/customers — now backed by the `organisations` Supabase table (routes/customers.ts)
// instead of the dead 138.197.188.132 proxy this used to hit.

interface Customer {
    id: string;
    name: string;
    domain: string | null;
    industry: string | null;
    plan: string;
    status: string;
    agentsTotal: number;
    activeIncidents: number;
    wazuhGroup: string | null;
}

const PLAN_STYLE: Record<string, string> = {
    starter: 'bg-card-muted text-foreground-muted',
    professional: 'bg-blue/10 text-blue',
    enterprise: 'bg-purple/10 text-purple',
};

export function AllCustomers() {
    const [customers, setCustomers] = useState<Customer[] | null>(null);
    const [search, setSearch] = useState('');

    useEffect(() => {
        apiFetch(apiUrl('/api/customers'), { cache: 'no-store', signal: AbortSignal.timeout(10000) })
            .then((r) => r.json())
            .then((data) => setCustomers(Array.isArray(data?.customers) ? data.customers : []))
            .catch(() => setCustomers([]));
    }, []);

    const loading = customers === null;
    const filtered = (customers ?? []).filter((c) => !search || c.name.toLowerCase().includes(search.toLowerCase()));

    return (
        <div className="space-y-4">
            <div className="flex items-start justify-between">
                <div>
                    <h1 className="text-lg font-black text-foreground">All Clients</h1>
                    <p className="text-xs text-foreground-muted">Every onboarded client organisation. Super admin only.</p>
                </div>
                <Link href="/admin/onboarding/new" className="flex items-center gap-2 bg-orange hover:bg-orange-hover text-white text-xs font-black px-4 py-2.5 rounded-lg transition-colors flex-shrink-0">
                    <Plus size={14} /> Add New Client
                </Link>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {[
                    { label: 'Total Clients', value: customers?.length ?? 0 },
                    { label: 'Active', value: customers?.filter((c) => c.status === 'active').length ?? 0 },
                    { label: 'Enterprise Plan', value: customers?.filter((c) => c.plan === 'enterprise').length ?? 0 },
                    { label: 'Open Cases', value: customers?.reduce((s, c) => s + c.activeIncidents, 0) ?? 0 },
                ].map((s) => (
                    <div key={s.label} className="bg-card border border-border rounded-xl p-4">
                        <div className="text-2xl font-black text-foreground">{loading ? '—' : s.value}</div>
                        <div className="text-[10px] text-foreground-muted uppercase tracking-wider mt-1">{s.label}</div>
                    </div>
                ))}
            </div>

            <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search customers…"
                className="w-64 bg-card border border-border rounded-lg px-3 py-2 text-xs focus:outline-none focus:ring-2 focus:ring-blue/20 focus:border-blue text-foreground placeholder:text-foreground-muted" />

            <div className="bg-card border border-border rounded-xl overflow-hidden">
                {loading ? (
                    <div className="p-6 space-y-2">{Array.from({ length: 4 }).map((_, i) => <div key={i} className="h-8 bg-card-muted rounded animate-pulse" />)}</div>
                ) : filtered.length === 0 ? (
                    <div className="text-center py-16">
                        <Building2 size={28} className="text-border mx-auto mb-3" />
                        <p className="text-xs text-foreground-muted mb-4">No customers onboarded yet.</p>
                        <Link href="/admin/onboarding/new" className="inline-block text-[10px] font-bold px-3 py-1.5 bg-orange hover:bg-orange-hover text-white rounded-lg transition-colors">Onboard First Client</Link>
                    </div>
                ) : (
                    <div className="overflow-x-auto scrollbar-thin">
                        <table className="w-full text-left">
                            <thead>
                                <tr className="bg-grey-800">
                                    {['Organisation', 'Domain', 'Industry', 'Plan', 'Agents', 'Status', 'Actions'].map((h) => (
                                        <th key={h} className="px-4 py-3 text-[10px] font-semibold text-white uppercase tracking-widest whitespace-nowrap">{h}</th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-border text-sm">
                                {filtered.map((c) => (
                                    <tr key={c.id} className="hover:bg-card-muted transition-colors">
                                        <td className="px-4 py-3 font-bold text-foreground whitespace-nowrap">{c.name === 'Cybernovr' ? '🛡️' : '🏢'} {c.name}</td>
                                        <td className="px-4 py-3 text-foreground-muted font-mono">{c.domain ?? '—'}</td>
                                        <td className="px-4 py-3 text-foreground-muted">{c.industry ?? '—'}</td>
                                        <td className="px-4 py-3">
                                            <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full uppercase ${PLAN_STYLE[c.plan] ?? PLAN_STYLE.starter}`}>{c.plan}</span>
                                        </td>
                                        <td className="px-4 py-3 text-foreground-muted">{c.agentsTotal.toLocaleString()}</td>
                                        <td className="px-4 py-3">
                                            <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border uppercase ${c.status === 'active' ? 'bg-blue/10 text-blue border-blue/30' : 'bg-card-muted text-foreground-muted border-border'}`}>{c.status}</span>
                                        </td>
                                        <td className="px-4 py-3">
                                            <div className="flex items-center gap-1.5">
                                                <Link href={`/admin/customers/${c.id}`} className="flex items-center gap-1 text-[10px] font-bold text-foreground border border-border rounded-lg px-2 py-1 hover:bg-card-muted transition-colors">
                                                    <Eye size={11} /> View
                                                </Link>
                                            </div>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        </div>
    );
}
