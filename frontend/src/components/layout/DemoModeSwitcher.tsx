'use client';

// Staff-only Demo Mode entry point (management-demo sprint). Renders nothing for a client
// session (executive, portal_user) — same STAFF set OrgSwitcher.tsx uses, since Demo Mode is a
// presentation aid for staff running a walkthrough, not something a client account should ever
// see or toggle. Lives in the header next to OrgSwitcher, but is entirely independent of it:
// flipping Demo Mode never touches lib/orgContext.ts, so it cannot change which real
// organisation a staff session is authorised to see (lib/demo/state.ts).
import { useState, useSyncExternalStore } from 'react';
import { PlayCircle } from 'lucide-react';
import { getAdminUser } from '@/lib/admin-auth';
import { DEMO_ORGS, DEMO_ORG_IDS } from '@/lib/demo/orgs';
import type { DemoOrgId } from '@/lib/demo/types';
import { isDemoModeEnabled, getDemoOrg, setDemoMode, setDemoOrg, subscribeDemoMode } from '@/lib/demo/state';

const STAFF = new Set(['super_admin', 'soc_manager', 'analyst']);

export function DemoModeSwitcher() {
    const [role] = useState<string>(() => (typeof window === 'undefined' ? '' : getAdminUser().role));
    const enabled = useSyncExternalStore(subscribeDemoMode, isDemoModeEnabled, () => false);
    const org = useSyncExternalStore(subscribeDemoMode, getDemoOrg, () => 'lapo' as DemoOrgId);

    if (!STAFF.has(role)) return null;

    return (
        <div className="inline-flex items-center gap-1.5">
            <button
                onClick={() => setDemoMode(!enabled)}
                className={`inline-flex items-center gap-1 text-[11px] font-semibold px-2 py-1 rounded-lg border transition-colors ${
                    enabled ? 'bg-amber-500/15 border-amber-500/40 text-amber-700' : 'bg-card border-border text-foreground-muted hover:text-foreground'
                }`}
                aria-pressed={enabled}
                title={enabled ? 'Exit Presentation Mode and return to live data' : 'Turn on Presentation Mode — sample data only, no real action is ever taken'}
            >
                <PlayCircle className="w-3.5 h-3.5 shrink-0" aria-hidden />
                {enabled ? 'Presentation: On' : 'Presentation Mode'}
            </button>
            {enabled && (
                <select
                    value={org}
                    onChange={(e) => setDemoOrg(e.target.value as DemoOrgId)}
                    className="bg-card border border-amber-500/40 rounded-lg px-2 py-1 text-[11px] text-foreground outline-none focus:ring-2 focus:ring-amber-500/40 max-w-[9rem]"
                    aria-label="Sample organisation"
                >
                    {DEMO_ORG_IDS.map((id) => <option key={id} value={id}>{DEMO_ORGS[id].name}</option>)}
                </select>
            )}
        </div>
    );
}
