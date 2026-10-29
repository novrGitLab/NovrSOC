'use client';

// Persistent "DEMO / SIMULATED" label — management-demo sprint. Renders a full-width strip
// above every admin screen whenever Demo Mode is on, for ANY signed-in session (unlike
// DemoModeSwitcher, which only staff can see/toggle) — if a demo is being screen-shared to
// management, the label must stay visible to everyone looking at the screen, not just to staff.
import { useSyncExternalStore } from 'react';
import { AlertTriangle } from 'lucide-react';
import { DEMO_ORGS } from '@/lib/demo/orgs';
import type { DemoOrgId } from '@/lib/demo/types';
import { isDemoModeEnabled, getDemoOrg, subscribeDemoMode } from '@/lib/demo/state';

export function DemoBanner() {
    const enabled = useSyncExternalStore(subscribeDemoMode, isDemoModeEnabled, () => false);
    const org = useSyncExternalStore(subscribeDemoMode, getDemoOrg, () => 'lapo' as DemoOrgId);

    if (!enabled) return null;

    return (
        <div className="w-full bg-amber-500 text-amber-950 text-xs sm:text-sm font-semibold flex items-center justify-center gap-2 py-1.5 px-3 z-40">
            <AlertTriangle className="w-3.5 h-3.5 shrink-0" aria-hidden />
            PRESENTATION MODE — SAMPLE DATA — Viewing: {DEMO_ORGS[org].name} ({DEMO_ORGS[org].sector}) — no real action is being taken
        </div>
    );
}
