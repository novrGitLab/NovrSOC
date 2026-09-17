'use client';

import { useEffect, useState } from 'react';
import { Shield, AlertTriangle, CheckCircle } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { BackupAgentStatus } from './BackupAgentStatus';

// Data Continuity.
//
// This page used to render a full backup console from a hardcoded dataset: nightly jobs with
// invented sizes, green hash-verification ticks, retention chains and restore points, and a
// storage-health panel reporting a success rate and "hash integrity: verified" computed from
// them. All of it was fabricated. On a continuity page that is the most damaging thing to fake —
// it tells an operator their data is backed up and restorable when nothing has been backed up
// and nothing has been verified.
//
// What is left is what is real: whatever a backup agent has actually reported (BackupAgentStatus),
// plus health derived only from those reports. Retention chains, restore-point history and hash
// verification are named below as not-yet-available rather than simulated — the agent has to
// report them before they can be shown.

interface RecoveryHealth {
    configured: boolean;
    reporting?: boolean;
    overall_status?: 'healthy' | 'degraded' | 'unknown';
    failed_jobs?: number;
    success_rate_pct?: number;
    last_report?: string | null;
    reason?: string;
}

const NOT_YET_AVAILABLE = [
    {
        title: 'Hash integrity verification',
        detail: 'Requires the agent to checksum each archive after writing it and report the digest. Until then no integrity claim can be made about a backup.',
    },
    {
        title: 'Retention chains',
        detail: 'Requires the agent to report which archives it retained and pruned on each run.',
    },
    {
        title: 'Restore-point history',
        detail: 'Requires a tested restore, not just a completed backup — a backup that has never been restored is an untested assumption.',
    },
    {
        title: 'Off-site replication status',
        detail: 'Requires a storage backend (S3 or equivalent) to be configured and reported on.',
    },
];

export function DataLossRecovery() {
    const [health, setHealth] = useState<RecoveryHealth | null>(null);

    useEffect(() => {
        apiFetch(apiUrl('/api/recovery/health'), { cache: 'no-store' })
            .then((r) => r.json())
            .then((d) => setHealth(d as RecoveryHealth))
            .catch(() => setHealth({ configured: false, reason: 'Could not reach the backend.' }));
    }, []);

    const status = health?.overall_status ?? 'unknown';

    return (
        <div className="space-y-4">
            <div>
                <h1 className="text-lg font-black text-foreground">Data Loss Recovery</h1>
                <p className="text-xs text-foreground-muted">
                    Data Continuity · Backup job reporting from agents on your protected hosts
                </p>
            </div>

            {/* Overall state. 'unknown' is a first-class outcome here and never renders as
                healthy — no reports means no basis for an assurance. */}
            {health && (
                <div className={`rounded-xl p-4 border flex items-start gap-3 ${
                    status === 'healthy' ? 'bg-green/10 border-green/30'
                        : status === 'degraded' ? 'bg-red-500/10 border-red-500/30'
                            : 'bg-amber-500/5 border-amber-500/30'
                }`}>
                    {status === 'healthy'
                        ? <CheckCircle size={18} className="text-green shrink-0 mt-0.5" />
                        : <AlertTriangle size={18} className={`shrink-0 mt-0.5 ${status === 'degraded' ? 'text-red-500' : 'text-amber-500'}`} />}
                    <div>
                        <p className={`font-bold text-sm ${
                            status === 'healthy' ? 'text-green' : status === 'degraded' ? 'text-red-500' : 'text-amber-500'
                        }`}>
                            {status === 'healthy' ? 'Backups reporting successfully'
                                : status === 'degraded' ? `${health.failed_jobs ?? 0} backup job(s) failing`
                                    : 'Backup status unknown'}
                        </p>
                        <p className="text-xs text-foreground-muted mt-0.5">
                            {health.reason
                                ?? (health.reporting
                                    ? `${health.success_rate_pct ?? 0}% of reported jobs succeeded${health.last_report ? ` · last report ${new Date(health.last_report).toLocaleString('en-GB', { timeZone: 'Africa/Lagos' })} WAT` : ''}`
                                    : 'No backup agent has reported yet.')}
                        </p>
                    </div>
                </div>
            )}

            <BackupAgentStatus />

            <div className="bg-card border border-border rounded-xl p-5">
                <div className="flex items-start gap-2.5 mb-4">
                    <div className="w-8 h-8 rounded-lg bg-card-muted flex items-center justify-center shrink-0">
                        <Shield className="w-4 h-4 text-foreground-muted" />
                    </div>
                    <div>
                        <h2 className="text-sm font-black text-foreground">Not yet available</h2>
                        <p className="text-[11px] text-foreground-muted">
                            Listed rather than simulated — each needs the backup agent to report it first.
                        </p>
                    </div>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {NOT_YET_AVAILABLE.map((item) => (
                        <div key={item.title} className="bg-card-muted/40 border border-border rounded-xl p-3">
                            <p className="text-xs font-bold text-foreground">{item.title}</p>
                            <p className="text-[10px] text-foreground-muted leading-relaxed mt-0.5">{item.detail}</p>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
}
