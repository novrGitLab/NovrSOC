'use client';

// Audit Trail (redesign, phase P20) — read-only. GET /api/vms/audit merges this organisation's VMS
// entries in the platform audit log (scans requested, scope and policy changes, cross-organisation
// access…) with each finding's own history (status, owner, deadline, notes, verification). Nothing
// on this page can change an entry.

import { useMemo, useState } from 'react';
import Link from 'next/link';
import { ScrollText, Lock } from 'lucide-react';
import { fmtWat } from '@/lib/vms';
import { PageHeader, KpiCard, Segmented, Select, SearchBox, ErrorState, ExportCsvButton, Tag } from './kit';
import { DataTable, type Column } from './table';
import { useVmsData } from './data';

interface Entry { id: string; at: string; actor: string; action: string; resource: string | null; resource_id: string | null; result: string | null; severity: string | null; details: unknown; source: 'platform' | 'finding' }
interface Audit { period: { days: number; from: string }; available: { platform: boolean; finding: boolean }; entries: Entry[]; note: string }

const text = (d: unknown) => (d === null || d === undefined ? '' : typeof d === 'string' ? d : JSON.stringify(d));
const ACTION_LABEL = (a: string) => a.replace(/^VMS_/, '').replace(/^FINDING_/, 'Finding ').replace(/_/g, ' ').toLowerCase().replace(/^./, (c) => c.toUpperCase());

export function VmsAudit() {
    const [days, setDays] = useState<'7' | '30' | '90'>('30');
    const { load, data, reload } = useVmsData<Audit>(`/api/vms/audit?days=${days}`);
    const [source, setSource] = useState<'' | 'platform' | 'finding'>('');
    const [result, setResult] = useState('');
    const [q, setQ] = useState('');
    const rows = useMemo(() => data?.entries.filter((e) => (!source || e.source === source) && (!result || e.result === result)
        && (!q || `${e.actor} ${e.action} ${e.resource_id ?? ''} ${text(e.details)}`.toLowerCase().includes(q.toLowerCase()))) ?? null, [data, source, result, q]);
    const columns: Column<Entry>[] = [
        { key: 'at', header: 'When', sort: (e) => e.at, render: (e) => <span className="text-[11px] whitespace-nowrap tabular-nums">{fmtWat(e.at)}</span> },
        { key: 'actor', header: 'Who', sort: (e) => e.actor, render: (e) => <span className="text-[11px] break-all">{e.actor}</span> },
        { key: 'action', header: 'Action', sort: (e) => e.action, render: (e) => <div><p className="font-semibold text-foreground">{ACTION_LABEL(e.action)}</p><p className="text-[10.5px] font-mono text-foreground-muted">{e.action}</p></div> },
        { key: 'resource', header: 'Record', hideBelow: 'md', render: (e) => e.source === 'finding' && e.resource_id ? <Link href={`/admin/vms/findings?id=${e.resource_id}`} className="text-[11px] font-mono text-purple dark:text-[var(--vz-prog-4)] hover:underline">finding {e.resource_id.slice(0, 8)}…</Link> : <span className="text-[11px] font-mono text-foreground-muted">{e.resource ?? ''}{e.resource_id ? ` ${e.resource_id.slice(0, 12)}` : ''}</span> },
        { key: 'details', header: 'Details', className: 'max-w-[360px]', render: (e) => <span className="text-[11px] text-foreground-muted break-words line-clamp-3">{text(e.details) || '—'}</span> },
        { key: 'result', header: 'Result', sort: (e) => e.result ?? '', render: (e) => e.result && e.result !== 'success' ? <Tag strong>{e.result}</Tag> : <span className="text-[11px] text-foreground-muted">{e.result ?? '—'}</span> },
        { key: 'source', header: 'Source', hideBelow: 'lg', render: (e) => <Tag>{e.source === 'platform' ? 'Audit log' : 'Finding history'}</Tag> },
    ];
    return (
        <div className="space-y-5">
            <PageHeader icon={ScrollText} title="Audit Trail" description={<>Who did what in vulnerability management for this organisation: scans requested, scope and policy changes, cross-organisation access, and every change to a finding. <span className="inline-flex items-center gap-1 font-semibold text-foreground"><Lock className="w-3 h-3" aria-hidden />Read-only — entries cannot be edited or deleted here.</span></>}
                actions={<>
                    <Segmented label="Period" value={days} onChange={setDays} options={[['7', '7 days'], ['30', '30 days'], ['90', '90 days']]} />
                    <ExportCsvButton filename={`vms-audit-${days}d.csv`} rows={rows?.map((e) => ({ ...e, details: text(e.details) }))} columns={[{ key: 'at', header: 'When' }, { key: 'actor', header: 'Who' }, { key: 'action', header: 'Action' }, { key: 'resource', header: 'Resource' }, { key: 'resource_id', header: 'Resource ID' }, { key: 'result', header: 'Result' }, { key: 'severity', header: 'Severity' }, { key: 'details', header: 'Details' }, { key: 'source', header: 'Source' }]} />
                </>} />
            {load.state === 'error' && <ErrorState error={load.error} status={load.status} onRetry={reload} />}
            {data && (!data.available.platform || !data.available.finding) && <p className="text-[11px] text-foreground">{!data.available.platform ? 'The platform audit log could not be read; only finding history is shown.' : 'Finding history could not be read; only the platform audit log is shown.'}</p>}
            <section className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <KpiCard label="Entries" value={data?.entries.length} reason="Loading" sub={`Last ${days} days (up to 500 of each source)`} />
                <KpiCard label="Platform actions" value={data?.entries.filter((e) => e.source === 'platform').length} reason="Loading" />
                <KpiCard label="Finding changes" value={data?.entries.filter((e) => e.source === 'finding').length} reason="Loading" />
                <KpiCard label="Refused or failed" value={data?.entries.filter((e) => e.result && e.result !== 'success').length} reason="Loading" tone={data?.entries.some((e) => e.result && e.result !== 'success') ? 'warning' : undefined} />
            </section>
            <div className="flex flex-wrap items-center gap-2">
                <Select label="Source" value={source} onChange={setSource} options={[['', 'All sources'], ['platform', 'Audit log'], ['finding', 'Finding history']]} />
                <Select label="Result" value={result} onChange={setResult} options={[['', 'Any result'], ['success', 'Success'], ['failure', 'Failure'], ['denied', 'Denied']]} />
                <SearchBox value={q} onSubmit={setQ} placeholder="Person, action or record" label="Search the audit trail" />
            </div>
            <DataTable caption="VMS audit trail" rows={rows} columns={columns} rowKey={(e) => e.id} initialSort={{ key: 'at', dir: 'desc' }} pageSize={50} empty={data?.entries.length ? 'No entries match these filters' : `No VMS activity recorded in the last ${days} days`} />
        </div>
    );
}
