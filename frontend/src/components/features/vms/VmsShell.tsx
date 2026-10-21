'use client';

// VMS frame (redesign, phase P20): the section's pages as tabs, the organisation being viewed
// (super_admin may switch — the backend authorises and audits it), and a read-only marker for
// roles that cannot change anything. Scanner Operations shows a notice to roles below manager;
// its data endpoints refuse them too (vms:scope), so this is presentation, not the control.

import { useEffect, useState, type ReactNode } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Building2, Eye, Lock } from 'lucide-react';
import { loadJson } from '@/lib/alerts';
import { setVmsOrg } from '@/lib/vmsOrg';
import { vmsLocate } from '@/config/vmsSections';
import { useVmsCan, useVmsOrg } from './data';
import { EmptyState } from './kit';

interface Org { id: string; name: string; slug: string }

export function VmsShell({ children }: { children: ReactNode }) {
    const pathname = usePathname();
    const here = vmsLocate(pathname);
    const can = useVmsCan();
    const org = useVmsOrg();
    const [orgs, setOrgs] = useState<Org[] | null>(null);
    useEffect(() => {
        if (!can.superAdmin) return;
        let active = true;
        // The organisation list is available to super_admin only (GET /api/organisations).
        void loadJson<{ organisations: Org[] }>('/api/organisations').then((r) => { if (active && r.ok) setOrgs(r.data.organisations.filter((o) => o.slug)); });
        return () => { active = false; };
    }, [can.superAdmin]);
    const gated = here?.section.managerOnly && !can.scope;

    return (
        <div className="space-y-5">
            <div className="flex flex-wrap items-end justify-between gap-3 border-b border-border">
                <nav aria-label={here ? `${here.section.label} pages` : 'VMS pages'} className="flex items-end gap-1 overflow-x-auto scrollbar-none -mb-px min-w-0">
                    <span className="text-[11px] font-bold uppercase tracking-wider text-foreground-muted pr-3 pb-2.5 whitespace-nowrap">{here?.section.label ?? 'Vulnerability Management'}</span>
                    {here && here.section.pages.length > 1 && here.section.pages.map((p) => {
                        const active = p.href === here.page.href;
                        return (
                            <Link key={p.href} href={p.href} aria-current={active ? 'page' : undefined}
                                className={`text-xs font-semibold px-3 pb-2.5 pt-1 border-b-2 whitespace-nowrap transition-colors ${active ? 'border-purple text-foreground' : 'border-transparent text-foreground-muted hover:text-foreground'}`}>{p.label}</Link>
                        );
                    })}
                </nav>
                <div className="flex items-center gap-2 pb-2">
                    {can.readOnly && <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-foreground-muted bg-card-muted rounded-full px-2.5 py-1"><Eye className="w-3.5 h-3.5" aria-hidden /> Read-only view</span>}
                    {orgs && orgs.length > 0 && (
                        <label className="inline-flex items-center gap-1.5 text-[11px] font-semibold text-foreground-muted">
                            <Building2 className="w-3.5 h-3.5" aria-hidden /><span className="sr-only">Organisation</span>
                            <select value={org} onChange={(e) => setVmsOrg(e.target.value)} className="bg-card border border-border rounded-lg px-2 py-1 text-[11px] text-foreground outline-none focus:ring-2 focus:ring-purple/40">
                                <option value="">My organisation</option>
                                {orgs.map((x) => <option key={x.id} value={x.slug}>{x.name}</option>)}
                            </select>
                        </label>
                    )}
                </div>
            </div>
            {org && <p className="text-[11px] text-foreground-muted -mt-2">Viewing <span className="font-semibold text-foreground">{orgs?.find((x) => x.slug === org)?.name ?? org}</span>. Access to another organisation is recorded in the audit log.</p>}
            {gated
                ? <div className="bg-card border border-border rounded-2xl"><EmptyState icon={Lock} title="Scanner Operations is for SOC managers and super admins" body="Scanner integrations, worker health and scan policies are restricted. The backend refuses these requests for other roles." /></div>
                : <div key={org}>{children}</div>}
        </div>
    );
}
