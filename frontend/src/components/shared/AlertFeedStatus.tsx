'use client';

import { isStale, watTime, STALE_AFTER_MINUTES } from '@/lib/alerts';

// The state of the alert pipeline, shown above anything that reads stored alerts:
//   not connected  — the alert store / backend is unavailable
//   no data        — the store answers but has never received an alert for this organisation
//   stale          — the newest alert was received more than STALE_AFTER_MINUTES ago
// Nothing is shown when alerts are arriving normally.
export function AlertFeedStatus({ notConnected, error, lastReceivedAt, loaded }: {
    notConnected: boolean;
    error: string | null;
    lastReceivedAt: string | null;
    loaded: boolean;
}) {
    if (!loaded) return null;
    if (notConnected || error) {
        return (
            <div role="alert" className="flex items-start gap-3 bg-red-500/5 border border-red-500/30 rounded-xl px-4 py-3">
                <div className="w-2 h-2 rounded-full bg-red-500 flex-shrink-0 mt-1.5" />
                <div>
                    <p className="text-sm font-semibold text-red-500">{notConnected ? 'Alert store not connected' : 'Could not load alerts'}</p>
                    <p className="text-xs text-foreground-muted mt-0.5">{error}</p>
                </div>
            </div>
        );
    }
    if (lastReceivedAt === null) {
        return (
            <div className="flex items-start gap-3 bg-card-muted border border-border rounded-xl px-4 py-3">
                <div className="w-2 h-2 rounded-full bg-foreground-muted flex-shrink-0 mt-1.5" />
                <div>
                    <p className="text-sm font-semibold text-foreground">No data</p>
                    <p className="text-xs text-foreground-muted mt-0.5">No alerts have been received for this organisation yet. Check that the SOAR forwarder is running and that its Wazuh groups are mapped.</p>
                </div>
            </div>
        );
    }
    if (isStale(lastReceivedAt)) {
        return (
            <div role="alert" className="flex items-start gap-3 bg-amber/10 border border-amber/40 rounded-xl px-4 py-3">
                <div className="w-2 h-2 rounded-full bg-amber flex-shrink-0 mt-1.5" />
                <div>
                    <p className="text-sm font-semibold text-amber">Alert data may be stale</p>
                    <p className="text-xs text-foreground-muted mt-0.5">
                        Last alert received {watTime(lastReceivedAt)} — more than {STALE_AFTER_MINUTES} minutes ago. The forwarder or the Wazuh manager may be down; figures below may be out of date.
                    </p>
                </div>
            </div>
        );
    }
    return null;
}
