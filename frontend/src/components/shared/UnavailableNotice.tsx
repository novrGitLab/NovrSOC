'use client';

// Shown on the client dashboard after a redirect from a BROKEN portal route (Release 2 Stage 6):
// every one of those pages calls an API portal_user cannot reach (requireAuth confines it to
// /api/client/*), so the page itself cannot work today — this says so instead of landing a
// customer on a page where every request fails silently.
import { useSearchParams } from 'next/navigation';
import { AlertTriangle } from 'lucide-react';

export function UnavailableNotice() {
    const params = useSearchParams();
    const label = params.get('unavailable');
    if (!label) return null;
    return (
        <div className="flex items-start gap-2 bg-amber/10 border border-amber/30 rounded-lg px-3 py-2.5 text-xs text-foreground mb-4">
            <AlertTriangle size={14} className="text-amber shrink-0 mt-0.5" aria-hidden />
            <span><b>{label}</b> isn&apos;t available on your account yet — you&apos;ve been returned to your dashboard.</span>
        </div>
    );
}
