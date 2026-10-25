'use client';

// Release 3.2: role-aware landing. executive lacks cases:read/alerts:read (lib/permissions.ts),
// so most of the Security Command Center below 403s silently for that role today — it gets the
// organisation-scoped Executive Report instead, the page already built for exactly this
// audience (and already reachable on its own at /admin/dashboard/executive). super_admin,
// soc_manager and analyst get the full command centre.
import { useState } from 'react';
import { GeneralDashboard } from '@/components/dashboards/GeneralDashboard';
import { ExecutiveReport } from '@/components/features/ExecutiveReport';
import { getAdminUser } from '@/lib/admin-auth';

export default function Page() {
    const [role] = useState<string>(() => (typeof window === 'undefined' ? '' : getAdminUser().role));

    if (role === 'executive') return <ExecutiveReport />;

    return (
        <div>
            <div className="mb-6">
                <div className="flex items-center justify-between">
                    <div>
                        <h1 className="font-black text-xl text-foreground tracking-tight">
                            Security Command Center
                        </h1>
                        <p className="text-xs text-foreground-muted mt-0.5 uppercase tracking-wider font-medium">
                            Aggregated across all onboarded clients
                        </p>
                    </div>
                </div>
            </div>
            <GeneralDashboard />
        </div>
    );
}
