'use client';

import { useEffect, useState } from 'react';
import { HardDrive, Download, CheckCircle2, XCircle } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';

// Real backup reporting — jobs that an agent on a protected host has actually reported.
//
// Distinct from the panels below it on this page, which render a demo dataset (now served from
// GET /api/recovery/jobs/demo). This one reads GET /api/recovery/jobs, which returns only what
// was genuinely reported, so an empty list here means "no agent has reported yet" and says so
// instead of showing green ticks nobody earned.

interface BackupJob {
    job_name: string;
    status: string;
    size_bytes: number;
    duration_seconds: number;
    files_transferred: number;
    error_message: string | null;
    last_run: string;
}

interface JobsResponse {
    jobs: BackupJob[];
    source: 'supabase' | 'unconfigured' | 'error';
    message?: string;
    stats?: { total: number; success: number; failed: number; total_bytes: number };
}

const TABLE_SQL = `CREATE TABLE IF NOT EXISTS public.backup_jobs (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  job_name          TEXT NOT NULL,
  org_id            TEXT NOT NULL,
  status            TEXT DEFAULT 'unknown',
  size_bytes        BIGINT DEFAULT 0,
  duration_seconds  INTEGER DEFAULT 0,
  files_transferred INTEGER DEFAULT 0,
  error_message     TEXT,
  last_run          TIMESTAMPTZ DEFAULT NOW(),
  created_at        TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(job_name, org_id)
);
ALTER TABLE public.backup_jobs ENABLE ROW LEVEL SECURITY;
CREATE POLICY "backup_jobs_service" ON public.backup_jobs
  FOR ALL USING (auth.role() = 'service_role');`;

function humanBytes(bytes: number): string {
    if (!bytes) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    return `${(bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

export function BackupAgentStatus() {
    const [data, setData] = useState<JobsResponse | null>(null);
    const [copied, setCopied] = useState(false);

    useEffect(() => {
        apiFetch(apiUrl('/api/recovery/jobs'), { cache: 'no-store' })
            .then((r) => r.json())
            .then((d) => setData(d as JobsResponse))
            .catch(() => setData({ jobs: [], source: 'error', message: 'Could not reach the backend' }));
    }, []);

    const jobs = data?.jobs ?? [];
    // A missing table is a setup state, not a fault — the backend returns source:'error' with
    // the Postgres message, and the SQL to fix it is shown below rather than just the error.
    const needsSetup = data !== null && jobs.length === 0;

    return (
        <div className="bg-card border border-border rounded-xl p-5 space-y-4">
            <div className="flex items-start gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-blue/10 flex items-center justify-center shrink-0">
                    <HardDrive className="w-4 h-4 text-blue" />
                </div>
                <div>
                    <h2 className="text-sm font-black text-foreground">Backup Agent</h2>
                    <p className="text-[11px] text-foreground-muted">Results reported by backup agents on your protected hosts</p>
                </div>
            </div>

            {data === null ? (
                <div className="h-16 bg-card-muted rounded-xl animate-pulse" />
            ) : jobs.length > 0 ? (
                <>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                        {[
                            { label: 'Jobs reporting', value: String(data.stats?.total ?? jobs.length) },
                            { label: 'Succeeding', value: String(data.stats?.success ?? 0) },
                            { label: 'Failing', value: String(data.stats?.failed ?? 0) },
                            { label: 'Total size', value: humanBytes(data.stats?.total_bytes ?? 0) },
                        ].map((s) => (
                            <div key={s.label} className="bg-card-muted/50 border border-border rounded-xl p-3">
                                <div className="text-lg font-black text-foreground">{s.value}</div>
                                <div className="text-[10px] text-foreground-muted mt-0.5">{s.label}</div>
                            </div>
                        ))}
                    </div>
                    <div className="space-y-2">
                        {jobs.map((j) => (
                            <div key={j.job_name} className="border border-border rounded-xl p-3 flex items-start justify-between gap-3 flex-wrap">
                                <div className="flex items-start gap-2.5 min-w-0">
                                    {j.status === 'success'
                                        ? <CheckCircle2 size={16} className="text-emerald-500 shrink-0 mt-0.5" />
                                        : <XCircle size={16} className="text-red-500 shrink-0 mt-0.5" />}
                                    <div className="min-w-0">
                                        <p className="text-xs font-bold text-foreground">{j.job_name}</p>
                                        <p className="text-[10px] text-foreground-muted">
                                            {humanBytes(j.size_bytes)} · {j.duration_seconds}s · {j.files_transferred.toLocaleString()} files
                                        </p>
                                        {j.error_message && <p className="text-[10px] text-red-500 mt-0.5 break-words">{j.error_message}</p>}
                                    </div>
                                </div>
                                <span className="text-[10px] text-foreground-muted shrink-0">
                                    {new Date(j.last_run).toLocaleString('en-GB', { timeZone: 'Africa/Lagos' })} WAT
                                </span>
                            </div>
                        ))}
                    </div>
                </>
            ) : (
                <div className="space-y-4">
                    <div className="bg-amber-500/5 border border-amber-500/30 rounded-xl p-4">
                        <p className="text-sm font-bold text-amber-500">No backup jobs reported yet</p>
                        <p className="text-xs text-foreground-muted mt-1 leading-relaxed">
                            {data.source === 'unconfigured'
                                ? 'Supabase is not configured on the backend, so backup results cannot be stored.'
                                : data.message
                                    ? `Backend said: ${data.message}`
                                    : 'Install the agent below on each host you want backed up. Results appear here after its first run.'}
                        </p>
                    </div>

                    <div>
                        <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider mb-2">Step 1 — create the table</p>
                        <p className="text-[11px] text-foreground-muted mb-2">
                            Run this once in the Supabase SQL editor. It is not created automatically:
                            this backend has no migration runner.
                        </p>
                        <div className="relative">
                            <pre className="bg-card-muted/60 border border-border rounded-xl p-3 text-[10px] text-foreground overflow-x-auto scrollbar-thin"><code>{TABLE_SQL}</code></pre>
                            <button
                                onClick={() => {
                                    navigator.clipboard?.writeText(TABLE_SQL).then(() => {
                                        setCopied(true);
                                        setTimeout(() => setCopied(false), 2000);
                                    }).catch(() => { /* clipboard blocked — the SQL is selectable above */ });
                                }}
                                className="absolute top-2 right-2 text-[10px] font-bold bg-card border border-border text-foreground-muted hover:text-purple px-2 py-1 rounded-lg"
                            >
                                {copied ? 'Copied' : 'Copy'}
                            </button>
                        </div>
                    </div>

                    <div>
                        <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider mb-2">Step 2 — install the agent</p>
                        <a
                            href="/novrsoc-backup-agent.sh"
                            download
                            className="inline-flex items-center gap-2 bg-purple text-white text-xs font-bold px-4 py-2.5 rounded-xl hover:opacity-90 transition-opacity"
                        >
                            <Download size={14} /> Download backup agent script
                        </a>
                        <p className="text-[10px] text-foreground-muted mt-2 leading-relaxed">
                            Install to <code className="font-mono">/opt/novrsoc/backup.sh</code>, make it executable,
                            and add it to cron. Installation steps are in the script header.
                        </p>
                    </div>
                </div>
            )}
        </div>
    );
}
