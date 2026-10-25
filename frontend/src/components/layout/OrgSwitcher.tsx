'use client';

// Global organisation switcher (2026 redesign, Stage 2) — promoted from the VMS-only selector
// (VmsShell.tsx used to render its own copy of this; both now use this one component) into the
// header, so switching organisation works the same way on every staff page, not just VMS.
//
// Self-contained: reads the signed-in role itself (getAdminUser) and renders nothing for a role
// that cannot switch — a client session (executive, portal_user) never sees this, and the
// backend ignores X-Org-Id for those roles regardless (lib/resolveOrg.ts). The organisation list
// is /api/org-access/mine: every organisation for super_admin/soc_manager, the analyst's own plus
// their assignments (staff_org_assignments) for an analyst — the backend still decides on every
// request; this list only decides what the UI offers.
import { useEffect, useState, useSyncExternalStore } from 'react';
import { Building2 } from 'lucide-react';
import { loadJson } from '@/lib/alerts';
import { getAdminUser } from '@/lib/admin-auth';
import { getOrgContext, setOrgContext, subscribeOrgContext } from '@/lib/orgContext';

interface Org { id?: string; name: string; slug: string }
const STAFF = new Set(['super_admin', 'soc_manager', 'analyst']);

export function OrgSwitcher() {
    const [role] = useState<string>(() => (typeof window === 'undefined' ? '' : getAdminUser().role));
    const org = useSyncExternalStore(subscribeOrgContext, getOrgContext, () => '');
    const [orgs, setOrgs] = useState<Org[] | null>(null);

    useEffect(() => {
        if (!STAFF.has(role)) return;
        let active = true;
        void loadJson<{ organisations: Org[] }>('/api/org-access/mine').then((r) => { if (active && r.ok) setOrgs(r.data.organisations.filter((o) => o.slug)); });
        return () => { active = false; };
    }, [role]);

    if (!STAFF.has(role) || !orgs || orgs.length <= 1) return null;

    return (
        <label className="inline-flex items-center gap-1.5 text-[11px] font-semibold text-foreground-muted">
            <Building2 className="w-3.5 h-3.5 shrink-0" aria-hidden /><span className="sr-only">Organisation</span>
            <select
                value={org}
                onChange={(e) => setOrgContext(e.target.value)}
                className="bg-card border border-border rounded-lg px-2 py-1 text-[11px] text-foreground outline-none focus:ring-2 focus:ring-blue/40 max-w-[9rem] sm:max-w-[12rem]"
                aria-label={org ? `Viewing ${orgs.find((x) => x.slug === org)?.name ?? org}` : 'Viewing my organisation'}
            >
                <option value="">My organisation</option>
                {orgs.map((x) => <option key={x.slug} value={x.slug}>{x.name}</option>)}
            </select>
        </label>
    );
}
