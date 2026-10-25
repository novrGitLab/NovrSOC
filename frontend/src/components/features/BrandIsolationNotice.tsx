'use client';

// F-01 containment notice: Brand Protection's monitored domains, socials, executives, apps,
// signatures and brand assets are still kept in one shared, in-memory store on the backend
// (routes/brand.ts, routes/domainSuite.ts) — not yet a per-organisation table. Staff access is
// now restricted (index.ts), but what is here is still shared across every organisation and is
// lost on a backend restart. This banner says so plainly rather than letting the page look like
// an ordinary, tenant-scoped feature. Remove it once Brand Protection has its own org-scoped
// tables (NOVRSOC_REDESIGN_TECHNICAL_AUDIT_V2.md, F-01 "Persistence").

import { ToneIcon } from '@/components/features/vms/ui';

export function BrandIsolationNotice() {
    return (
        <div role="alert" className="flex items-start gap-3 rounded-xl border border-amber/40 bg-amber/5 p-4">
            <ToneIcon tone="warning" className="w-5 h-5 mt-0.5" />
            <div className="flex-1 min-w-0">
                <p className="text-sm font-bold text-foreground">Not yet organisation-isolated</p>
                <p className="text-xs text-foreground-muted mt-0.5 leading-relaxed">
                    Monitored entries on this page are shared across every organisation and are lost if the backend restarts.
                    Access is limited to staff while this module moves to per-organisation storage.
                </p>
            </div>
        </div>
    );
}
