'use client';

// Prioritized Remediation Plan (brief §7). Owner and target date are shown only when the finding
// actually carries one (owner / due_at columns, already real fields on vms_findings) — never
// invented, per the brief's explicit instruction.
import Link from 'next/link';
import { DataTable, type Column } from '../table';
import { PriorityBadge, SeverityBadge } from '../kit';
import { fmtWat } from '@/lib/vms';

interface FindingLite { id: string; title: string; asset_value: string; priority: string | null; scanner_severity: string | null; owner: string | null; due_at: string | null; status: string; remediation?: string | null }

const STATUS_LABEL: Record<string, string> = { open: 'Open', acknowledged: 'Triaged', in_progress: 'In progress', fixed_pending_verification: 'Awaiting verification', reopened: 'Reopened' };
const OPEN_STATUSES = Object.keys(STATUS_LABEL);

export function RemediationPlanTable({ findings, findingsPath }: { findings: FindingLite[]; findingsPath: string }) {
    const rows = findings.filter((f) => OPEN_STATUSES.includes(f.status));
    const columns: Column<FindingLite>[] = [
        { key: 'priority', header: 'Priority', render: (f) => <PriorityBadge priority={f.priority} />, sort: (f) => f.priority ?? 'P9' },
        { key: 'title', header: 'Vulnerability', render: (f) => <Link href={`${findingsPath}?id=${f.id}`} className="text-blue hover:underline font-semibold">{f.title}</Link>, sort: (f) => f.title },
        { key: 'severity', header: 'Severity', render: (f) => <SeverityBadge severity={f.scanner_severity} />, sort: (f) => f.scanner_severity ?? '' },
        { key: 'asset', header: 'Affected Asset', render: (f) => <span className="font-mono text-[11px]">{f.asset_value}</span>, sort: (f) => f.asset_value, hideBelow: 'md' },
        { key: 'action', header: 'Recommended Action', render: (f) => <span className="text-[11px]">{f.remediation || 'See finding detail for scanner-provided remediation guidance'}</span>, hideBelow: 'lg' },
        { key: 'owner', header: 'Owner', render: (f) => <span className="text-[11px]">{f.owner || '—'}</span>, sort: (f) => f.owner ?? '', hideBelow: 'md' },
        { key: 'due', header: 'Target Date', render: (f) => <span className="text-[11px] whitespace-nowrap">{f.due_at ? fmtWat(f.due_at) : '—'}</span>, sort: (f) => f.due_at ?? '' },
        { key: 'status', header: 'Status', render: (f) => <span className="text-[11px] font-semibold">{STATUS_LABEL[f.status] ?? f.status}</span>, sort: (f) => f.status },
    ];
    return (
        <div className="space-y-2">
            <h2 className="text-sm font-black text-foreground">Prioritized Remediation Plan</h2>
            <DataTable rows={rows} columns={columns} rowKey={(f) => f.id} caption="Prioritized remediation plan" initialSort={{ key: 'priority', dir: 'asc' }}
                empty={<p className="text-xs text-foreground-muted py-6 text-center">No open findings requiring remediation.</p>} />
        </div>
    );
}
