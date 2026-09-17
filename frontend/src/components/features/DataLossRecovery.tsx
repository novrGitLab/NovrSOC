'use client';

import { useState, useEffect } from 'react';
import {
    CheckCircle, AlertTriangle, RefreshCw, Clock, Shield, Database, RotateCcw, Lock, Server,
} from 'lucide-react';
import { BackupAgentStatus } from './BackupAgentStatus';
import { apiUrl, apiFetch } from '@/lib/api';

type BackupStatus = 'success' | 'failed' | 'running' | 'missed';

interface BackupJob {
    id: string;
    name: string;
    target: string;
    backup_type: string;
    status: BackupStatus;
    size_bytes: number;
    hash_sha256: string | null;
    hash_verified: boolean;
    started_at: string;
    completed_at: string | null;
    duration_mins: number | null;
    restore_point: string | null;
    retention_days: number;
    next_scheduled: string;
    storage_path: string;
    snapshots_count: number;
    failure_reason?: string;
}

interface RecoveryStats {
    total: number;
    success: number;
    failed: number;
    total_size_tb: string;
    hash_verified: number;
}

interface RecoveryHealth {
    overall_status: string;
    failed_jobs: number;
    success_rate_pct: number;
    oldest_restore_point: string | null;
    hash_integrity: string;
    aws_s3_status: string;
    object_lock_enabled: boolean;
}

interface RetentionEntry {
    date: string;
    status: string;
    size_gb: number;
}

function formatBytes(bytes: number): string {
    if (bytes === 0) return '0 B';
    if (bytes >= 1e12) return `${(bytes / 1e12).toFixed(2)} TB`;
    if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(1)} GB`;
    if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(0)} MB`;
    return `${bytes} B`;
}

const STATUS_CONFIG: Record<BackupStatus, { label: string; dot: string; text: string; bg: string; border: string }> = {
    success: { label: 'Success', dot: 'bg-green', text: 'text-green', bg: 'bg-green/10', border: 'border-green/30' },
    failed: { label: 'Failed', dot: 'bg-red-500 animate-pulse', text: 'text-red-500', bg: 'bg-red-500/10', border: 'border-red-500/30' },
    running: { label: 'Running', dot: 'bg-blue animate-pulse', text: 'text-blue', bg: 'bg-blue/10', border: 'border-blue/30' },
    missed: { label: 'Missed', dot: 'bg-amber', text: 'text-amber', bg: 'bg-grey-100', border: 'border-amber/30' },
};

const TABS = [
    { id: 'jobs', label: 'Backup Jobs' },
    { id: 'health', label: 'Storage Health' },
] as const;
type Tab = (typeof TABS)[number]['id'];

export function DataLossRecovery() {
    const [jobs, setJobs] = useState<BackupJob[]>([]);
    const [stats, setStats] = useState<RecoveryStats | null>(null);
    const [health, setHealth] = useState<RecoveryHealth | null>(null);
    const [selectedJob, setSelectedJob] = useState<BackupJob | null>(null);
    const [retention, setRetention] = useState<RetentionEntry[]>([]);
    const [loading, setLoading] = useState(true);
    const [retrying, setRetrying] = useState<string | null>(null);
    const [activeTab, setActiveTab] = useState<Tab>('jobs');

    const load = async () => {
        setLoading(true);
        try {
            const [jobsRes, healthRes] = await Promise.all([
                // /jobs/demo, not /jobs: GET /api/recovery/jobs now returns only genuinely
                // reported backup results (see BackupAgentStatus above, which renders those).
                // The panels below — retention chains, restore points, hash verification — have
                // no real equivalent yet and still run on the demo dataset, which now lives at
                // its own path so the two can't be mistaken for each other.
                apiFetch(apiUrl('/api/recovery/jobs/demo'), { cache: 'no-store' }),
                apiFetch(apiUrl('/api/recovery/health'), { cache: 'no-store' }),
            ]);
            const jobsData = await jobsRes.json();
            const healthData = await healthRes.json();
            setJobs(Array.isArray(jobsData.jobs) ? jobsData.jobs : []);
            setStats(jobsData.stats ?? null);
            setHealth(healthData ?? null);
        } catch {
            // show empty state
        } finally {
            setLoading(false);
        }
    };

    const loadJobDetail = async (job: BackupJob) => {
        setSelectedJob(job);
        try {
            const res = await apiFetch(apiUrl(`/api/recovery/jobs/${job.id}`), { cache: 'no-store' });
            const data = await res.json();
            setRetention(Array.isArray(data.retention) ? data.retention : []);
        } catch {
            setRetention([]);
        }
    };

    const retryJob = async (jobId: string) => {
        setRetrying(jobId);
        try {
            await apiFetch(apiUrl(`/api/recovery/jobs/${jobId}/retry`), { method: 'POST' });
            setTimeout(() => setRetrying(null), 2000);
        } catch {
            setRetrying(null);
        }
    };

    useEffect(() => { load(); }, []);

    if (loading) {
        return (
            <div className="flex items-center justify-center py-20">
                <RefreshCw size={24} className="animate-spin text-blue" />
            </div>
        );
    }

    const failedJobs = jobs.filter((j) => j.status === 'failed');

    return (
        <div className="space-y-4">
            <div>
                <h1 className="text-lg font-black text-foreground">Data Loss Recovery</h1>
                <p className="text-xs text-foreground-muted">Data Continuity · Monitor backup job completion, verify snapshot integrity, and track restore points across all protected servers and databases</p>
            </div>

            {/* Real reported backups. Everything below this block still runs on the demo dataset
                (see the /jobs/demo note in load()) — this is the only panel on the page backed by
                results a real agent actually reported. */}
            <BackupAgentStatus />

            {/* Failed job alert banner */}
            {failedJobs.length > 0 && (
                <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 flex items-start gap-3 flex-wrap">
                    <AlertTriangle size={18} className="text-red-500 flex-shrink-0 mt-0.5" />
                    <div className="flex-1 min-w-[200px]">
                        <div className="font-semibold text-sm text-red-500 mb-1">
                            {failedJobs.length} backup job{failedJobs.length > 1 ? 's' : ''} failed last night
                        </div>
                        {failedJobs.map((job) => (
                            <div key={job.id} className="text-xs text-red-500">• {job.name} — {job.failure_reason}</div>
                        ))}
                    </div>
                    <button
                        onClick={() => failedJobs[0] && retryJob(failedJobs[0].id)}
                        className="flex items-center gap-1.5 bg-orange hover:bg-orange-hover text-white text-xs font-bold px-3 py-1.5 rounded-lg transition-colors whitespace-nowrap"
                    >
                        <RotateCcw size={12} />
                        Retry Now
                    </button>
                </div>
            )}

            {/* KPI cards */}
            {stats && (
                <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                    {[
                        { label: 'Total Jobs', value: stats.total, border: 'border-t-blue' },
                        { label: 'Successful', value: stats.success, border: 'border-t-green' },
                        { label: 'Failed', value: stats.failed, border: 'border-t-red-500' },
                        { label: 'Total Protected', value: `${stats.total_size_tb} TB`, border: 'border-t-purple' },
                        { label: 'Hash Verified', value: `${stats.hash_verified}/${stats.total}`, border: 'border-t-green' },
                    ].map((card) => (
                        <div key={card.label} className={`bg-card border border-border rounded-xl p-4 border-t-4 ${card.border}`}>
                            <div className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider mb-1">{card.label}</div>
                            <div className="font-heading font-black text-xl text-foreground">{card.value}</div>
                        </div>
                    ))}
                </div>
            )}

            {/* Tabs */}
            <div className="flex gap-1 border-b border-border">
                {TABS.map((t) => (
                    <button key={t.id} onClick={() => setActiveTab(t.id)}
                        className={`px-4 py-2.5 text-xs font-bold border-b-2 transition-colors ${activeTab === t.id ? 'border-blue text-blue' : 'border-transparent text-foreground-muted hover:text-foreground'}`}>
                        {t.label}
                    </button>
                ))}
            </div>

            {/* JOBS TAB */}
            {activeTab === 'jobs' && (
                <div className="flex flex-col lg:flex-row gap-4">
                    {/* Job list */}
                    <div className="flex-1 space-y-3 min-w-0">
                        {jobs.map((job) => {
                            const cfg = STATUS_CONFIG[job.status] ?? STATUS_CONFIG.success;
                            const isSelected = selectedJob?.id === job.id;
                            return (
                                <div key={job.id} onClick={() => loadJobDetail(job)}
                                    className={`bg-card border rounded-xl p-4 cursor-pointer hover:shadow-sm transition-all ${
                                        isSelected ? 'ring-2 ring-blue/20 border-blue/40' : job.status === 'failed' ? 'border-red-500/30' : 'border-border'
                                    }`}>
                                    <div className="flex items-start justify-between gap-3">
                                        <div className="flex items-start gap-3 min-w-0">
                                            <div className={`w-2 h-2 rounded-full mt-1.5 flex-shrink-0 ${cfg.dot}`} />
                                            <div className="min-w-0">
                                                <div className="font-medium text-sm text-foreground">{job.name}</div>
                                                <div className="text-xs text-foreground-muted mt-0.5">{job.target}</div>
                                                {job.status === 'failed' && job.failure_reason && (
                                                    <div className="text-xs text-red-500 mt-1">{job.failure_reason}</div>
                                                )}
                                            </div>
                                        </div>
                                        <div className="text-right flex-shrink-0">
                                            <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${cfg.bg} ${cfg.text} ${cfg.border}`}>{cfg.label}</span>
                                            <div className="text-xs text-foreground-muted mt-1">{formatBytes(job.size_bytes)}</div>
                                        </div>
                                    </div>

                                    <div className="flex items-center gap-4 mt-3 text-xs text-foreground-muted flex-wrap">
                                        <div className="flex items-center gap-1">
                                            <Clock size={11} />
                                            {job.completed_at ? `Completed ${job.completed_at}` : `Last: ${job.restore_point ?? 'Never'}`}
                                        </div>
                                        {job.hash_verified && (
                                            <div className="flex items-center gap-1 text-green">
                                                <Shield size={11} /> Hash verified
                                            </div>
                                        )}
                                        <div className="flex items-center gap-1">
                                            <Database size={11} /> {job.snapshots_count} snapshots
                                        </div>
                                        {job.status === 'failed' && (
                                            <button onClick={(e) => { e.stopPropagation(); retryJob(job.id); }} disabled={retrying === job.id}
                                                className="ml-auto flex items-center gap-1 text-red-500 hover:text-red-hover font-medium transition-colors">
                                                <RotateCcw size={11} className={retrying === job.id ? 'animate-spin' : ''} />
                                                {retrying === job.id ? 'Queuing…' : 'Retry'}
                                            </button>
                                        )}
                                    </div>
                                </div>
                            );
                        })}
                    </div>

                    {/* Job detail panel */}
                    {selectedJob && (
                        <div className="w-full lg:w-80 flex-shrink-0 bg-card border border-border rounded-xl p-5 h-fit lg:sticky lg:top-6">
                            <div className="flex items-center justify-between mb-4">
                                <h3 className="font-heading font-semibold text-sm text-foreground">Job Details</h3>
                                <button onClick={() => setSelectedJob(null)} className="text-foreground-muted hover:text-foreground text-xs">✕</button>
                            </div>

                            <div className="space-y-3 text-xs">
                                {[
                                    ['Target', selectedJob.target],
                                    ['Size', formatBytes(selectedJob.size_bytes)],
                                    ['Duration', selectedJob.duration_mins ? `${selectedJob.duration_mins} min` : '—'],
                                    ['Restore Point', selectedJob.restore_point ?? '—'],
                                    ['Retention', `${selectedJob.retention_days} days`],
                                    ['Next Run', selectedJob.next_scheduled],
                                    ['Storage', selectedJob.storage_path],
                                ].map(([label, value]) => (
                                    <div key={label} className="flex justify-between gap-2">
                                        <span className="text-foreground-muted flex-shrink-0">{label}</span>
                                        <span className="text-foreground font-mono text-[11px] truncate text-right">{value}</span>
                                    </div>
                                ))}
                            </div>

                            {/* Hash integrity */}
                            <div className={`mt-4 p-3 rounded-lg border ${selectedJob.hash_verified ? 'bg-green/10 border-green/30' : 'bg-red-500/10 border-red-500/30'}`}>
                                <div className="flex items-center gap-2 mb-1">
                                    {selectedJob.hash_verified ? <CheckCircle size={13} className="text-green" /> : <AlertTriangle size={13} className="text-red-500" />}
                                    <span className={`text-xs font-semibold ${selectedJob.hash_verified ? 'text-green' : 'text-red-500'}`}>
                                        {selectedJob.hash_verified ? 'Hash Integrity Verified' : 'Hash Not Verified'}
                                    </span>
                                </div>
                                {selectedJob.hash_sha256 && (
                                    <div className="font-mono text-[10px] text-foreground-muted break-all">SHA256: {selectedJob.hash_sha256.slice(0, 32)}...</div>
                                )}
                            </div>

                            {/* Object Lock badge */}
                            <div className="mt-3 flex items-center gap-2 p-2 bg-blue/5 rounded-lg border border-blue/20">
                                <Lock size={13} className="text-blue" />
                                <span className="text-xs text-blue font-medium">S3 Object Lock — Immutable</span>
                            </div>

                            {/* Retention calendar */}
                            {retention.length > 0 && (
                                <div className="mt-4">
                                    <div className="text-xs font-semibold text-foreground-muted uppercase tracking-wide mb-2">7-Day Retention</div>
                                    <div className="space-y-1.5">
                                        {retention.map((r) => (
                                            <div key={r.date} className="flex items-center justify-between">
                                                <span className="text-[11px] text-foreground-muted">{r.date}</span>
                                                <div className="flex items-center gap-2">
                                                    <span className="text-[11px] text-foreground">{r.size_gb > 0 ? `${r.size_gb} GB` : '—'}</span>
                                                    <span className={`w-1.5 h-1.5 rounded-full ${r.status === 'success' ? 'bg-green' : 'bg-red-500'}`} />
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}
                        </div>
                    )}
                </div>
            )}

            {/* HEALTH TAB */}
            {activeTab === 'health' && health && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* Overall health */}
                    <div className="bg-card border border-border rounded-xl p-5">
                        <h3 className="font-heading font-semibold text-sm text-foreground mb-4">Storage Health</h3>
                        <div className="space-y-4">
                            {[
                                { label: 'Overall Status', value: health.overall_status === 'healthy' ? 'Healthy' : 'Degraded', ok: health.overall_status === 'healthy' },
                                { label: 'Success Rate', value: `${health.success_rate_pct}%`, ok: health.success_rate_pct >= 90 },
                                { label: 'Hash Integrity', value: health.hash_integrity, ok: true },
                                { label: 'AWS S3 Status', value: health.aws_s3_status, ok: true },
                                { label: 'Object Lock', value: health.object_lock_enabled ? 'Enabled' : 'Disabled', ok: health.object_lock_enabled },
                                { label: 'Oldest Restore Point', value: health.oldest_restore_point?.split(' ')[0] ?? '—', ok: true },
                            ].map((row) => (
                                <div key={row.label} className="flex items-center justify-between">
                                    <span className="text-xs text-foreground-muted">{row.label}</span>
                                    <div className="flex items-center gap-2">
                                        <span className={`text-xs font-semibold ${row.ok ? 'text-green' : 'text-red-500'}`}>{row.value}</span>
                                        <div className={`w-1.5 h-1.5 rounded-full ${row.ok ? 'bg-green' : 'bg-red-500 animate-pulse'}`} />
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Backup coverage */}
                    <div className="bg-card border border-border rounded-xl p-5">
                        <h3 className="font-heading font-semibold text-sm text-foreground mb-4">Backup Coverage</h3>
                        <div className="space-y-3">
                            {jobs.map((job) => (
                                <div key={job.id} className="flex items-center justify-between">
                                    <div className="flex items-center gap-2">
                                        <Server size={13} className="text-foreground-muted" />
                                        <span className="text-xs text-foreground">{job.target.split(' ')[0]}</span>
                                    </div>
                                    <div className="flex items-center gap-2">
                                        <span className="text-xs text-foreground-muted">{formatBytes(job.size_bytes)}</span>
                                        <div className={`w-2 h-2 rounded-full ${job.status === 'success' ? 'bg-green' : job.status === 'failed' ? 'bg-red-500 animate-pulse' : 'bg-amber'}`} />
                                    </div>
                                </div>
                            ))}
                        </div>
                        <div className="mt-4 pt-4 border-t border-border text-xs text-foreground-muted">
                            Enterprise customers: Connect Veeam or VMware vSphere APIs to extend monitoring.
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
