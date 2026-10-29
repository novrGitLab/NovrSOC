'use client';

// Vulnerability Findings (redesign, phase P20) — every finding from active scans (Nuclei, OpenVAS)
// and Wazuh agents, prioritised by the risk engine. Status, priority, source, KEV, overdue and the
// search run on the backend (GET /api/vms/findings, up to 1000 rows, highest risk first); severity
// narrows the loaded rows. Bulk actions call the same per-finding endpoint for each selected row —
// each change is permission-checked and recorded on its own — and report exactly what succeeded.

import { useMemo, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { Bug } from 'lucide-react';
import { fmtWat, detectorLabel } from '@/lib/vms';
import { PageHeader, KpiCard, SeverityBadge, PriorityBadge, RiskScore, Segmented, Select, Toggle, SearchBox, Drawer, ConfirmDialog, ErrorState, Notice, ExportCsvButton, Tag, btn, type Msg, SEVERITY_META } from './kit';
import { DataTable, type Column } from './table';
import { FindingDetail, STATUS_LABEL, isOverdue, type Finding } from './FindingDetail';
import { useVmsData, useVmsCan, vmsSend } from './data';

interface Summary { open: number; by_severity: Record<string, number>; by_priority: Record<string, number>; known_exploited_open: number; overdue: number; by_source: Record<string, number> }

const STATUS_VIEWS = [['open_all', 'Open'], ['fixed_pending_verification', 'Awaiting verification'], ['verified', 'Resolved'], ['risk_accepted,false_positive', 'Accepted / FP'], ['all', 'All']] as const;
type StatusView = (typeof STATUS_VIEWS)[number][0];
const BULK_STATUS = ['acknowledged', 'in_progress', 'fixed_pending_verification', 'risk_accepted', 'false_positive', 'open'] as const;
const BULK_MAX = 100;

export function VmsFindings() {
    const params = useSearchParams();
    const router = useRouter();
    const can = useVmsCan();
    const [status, setStatus] = useState<StatusView>(() => (STATUS_VIEWS.some(([v]) => v === params.get('status')) ? params.get('status') as StatusView : 'open_all'));
    const [priority, setPriority] = useState(params.get('priority') ?? '');
    const [severity, setSeverity] = useState(params.get('severity') ?? '');
    const [source, setSource] = useState(['wazuh', 'active_scan'].includes(params.get('source') ?? '') ? params.get('source')! : '');
    const [kev, setKev] = useState(params.get('kev') === 'true');
    const [overdue, setOverdue] = useState(params.get('overdue') === 'true');
    const [q, setQ] = useState(params.get('q') ?? '');
    const assetId = params.get('asset_id');
    const openId = params.get('id');
    const [selected, setSelected] = useState<Set<string>>(new Set());
    const [msg, setMsg] = useState<Msg>(null);
    const [bulk, setBulk] = useState<{ status?: string } | null>(null);
    const [bulkOwner, setBulkOwner] = useState('');
    const [busy, setBusy] = useState(false);

    const query = useMemo(() => {
        const p = new URLSearchParams({ status });
        if (priority) p.set('priority', priority);
        if (source) p.set('source', source);
        if (kev) p.set('kev', 'true');
        if (overdue) p.set('overdue', 'true');
        if (q) p.set('q', q);
        if (assetId) p.set('asset_id', assetId);
        return `/api/vms/findings?${p.toString()}`;
    }, [status, priority, source, kev, overdue, q, assetId]);
    const list = useVmsData<{ findings: Finding[]; correlation_error?: string | null }>(query);
    const summary = useVmsData<Summary>('/api/vms/findings/summary');
    const now = list.at ?? 0;
    const rows = useMemo(() => list.data?.findings.filter((f) => !severity || f.scanner_severity === severity) ?? null, [list.data, severity]);

    const setOpen = (id: string | null) => {
        const p = new URLSearchParams(params.toString());
        if (id) p.set('id', id); else p.delete('id');
        router.replace(`/admin/vms/findings${p.toString() ? `?${p.toString()}` : ''}`, { scroll: false });
    };
    const reloadAll = () => { list.reload(); summary.reload(); };

    async function applyBulk(body: Record<string, unknown>, label: string) {
        const ids = [...selected].slice(0, BULK_MAX);
        setBusy(true);
        setMsg(null);
        let ok = 0;
        const failures: string[] = [];
        for (const id of ids) {
            const r = await vmsSend('PATCH', `/api/vms/findings/${id}`, body);
            if (r.ok) ok++; else failures.push(r.error);
        }
        setBusy(false);
        setMsg(failures.length ? { ok: false, text: `${label}: ${ok} updated, ${failures.length} refused (${[...new Set(failures)].slice(0, 2).join('; ')})` } : { ok: true, text: `${label}: ${ok} finding(s) updated` });
        setSelected(new Set());
        reloadAll();
    }

    const columns: Column<Finding>[] = [
        { key: 'priority', header: 'Priority', render: (f) => <PriorityBadge priority={f.priority} />, sort: (f) => f.priority ?? 'P9' },
        {
            key: 'title', header: 'Finding', className: 'min-w-[220px] max-w-[360px]', sort: (f) => f.title.toLowerCase(),
            render: (f) => (
                <div className="min-w-0">
                    <p className="font-semibold text-foreground truncate">{f.title}</p>
                    <p className="text-[11px] text-foreground-muted truncate">{f.cve_ids.slice(0, 2).join(', ') || f.rule_id}{f.cve_ids.length > 2 ? ` +${f.cve_ids.length - 2}` : ''}</p>
                </div>
            ),
        },
        { key: 'severity', header: 'Severity', render: (f) => <SeverityBadge severity={f.scanner_severity} />, sort: (f) => -(SEVERITY_META[f.scanner_severity]?.rank ?? 9) },
        { key: 'risk', header: 'Risk', render: (f) => <RiskScore score={f.risk_score} />, sort: (f) => f.risk_score },
        { key: 'asset', header: 'Asset', hideBelow: 'md', render: (f) => <span title={f.asset_value} className="block max-w-[200px] truncate font-mono text-[11px] text-foreground">{f.asset_value}{f.port ? `:${f.port}` : ''}</span>, sort: (f) => f.asset_value },
        { key: 'source', header: 'Source', hideBelow: 'lg', render: (f) => <span className="text-[11px] text-foreground-muted">{f.source_class === 'wazuh' ? 'Monitoring engine' : f.detected_by.map(detectorLabel).join(', ')}</span> },
        { key: 'status', header: 'Status', render: (f) => <span className="text-[11px] font-semibold text-foreground whitespace-nowrap">{STATUS_LABEL[f.status] ?? f.status}</span>, sort: (f) => f.status },
        { key: 'owner', header: 'Owner', hideBelow: 'lg', render: (f) => <span className="text-[11px] text-foreground-muted">{f.owner ?? 'Unassigned'}</span>, sort: (f) => f.owner ?? '~' },
        { key: 'due', header: 'Due', hideBelow: 'md', render: (f) => <span className={`text-[11px] whitespace-nowrap ${isOverdue(f, now) ? 'font-bold text-foreground' : 'text-foreground-muted'}`}>{f.due_at ? fmtWat(f.due_at).replace(/,? \d\d:\d\d WAT$/, '') : '—'}{isOverdue(f, now) && <> <Tag>Overdue</Tag></>}</span>, sort: (f) => f.due_at ?? '9999' },
        { key: 'last', header: 'Last seen', hideBelow: 'lg', render: (f) => <span className="text-[11px] text-foreground-muted whitespace-nowrap">{fmtWat(f.last_seen).replace(/ WAT$/, '')}</span>, sort: (f) => f.last_seen },
    ];
    const s = summary.data;

    return (
        <div className="space-y-5">
            <PageHeader icon={Bug} title="Vulnerability Findings"
                description="Findings from active scans and monitoring agents, ranked by the risk engine. A finding is resolved only when a rescan or the monitoring engine shows it is gone."
                actions={<ExportCsvButton filename={`vms-findings-${new Date().toISOString().slice(0, 10)}.csv`} rows={rows as unknown as Record<string, unknown>[]} columns={[
                    { key: 'priority', header: 'Priority' }, { key: 'risk_score', header: 'Risk score' }, { key: 'scanner_severity', header: 'Severity' }, { key: 'title', header: 'Title' }, { key: 'cve_ids', header: 'CVEs' },
                    { key: 'asset_value', header: 'Asset' }, { key: 'port', header: 'Port' }, { key: 'source_class', header: 'Source' }, { key: 'status', header: 'Status' }, { key: 'owner', header: 'Owner' }, { key: 'due_at', header: 'Due' }, { key: 'first_seen', header: 'First seen' }, { key: 'last_seen', header: 'Last seen' },
                ]} />}
            />
            <section aria-label="Summary" className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
                <KpiCard label="Open" value={s?.open} reason={summary.load.state === 'error' ? summary.load.error : 'Loading'} />
                <KpiCard label="Known exploited (KEV)" value={s?.known_exploited_open} tone={s?.known_exploited_open ? 'critical' : undefined} reason="Loading" />
                <KpiCard label="Overdue" value={s?.overdue} tone={s?.overdue ? 'warning' : undefined} reason="Loading" />
                <KpiCard label="P1" value={s ? s.by_priority.P1 ?? 0 : undefined} reason="Loading" sub="Fix within 2 days" />
                <KpiCard label="P2" value={s ? s.by_priority.P2 ?? 0 : undefined} reason="Loading" sub="Fix within 7 days" />
                <KpiCard label="Reported by monitoring" value={s ? s.by_source.wazuh ?? 0 : undefined} reason="Loading" sub="Open, from endpoint agents" />
            </section>

            <div className="flex flex-wrap items-center gap-2">
                <Segmented label="Status" value={status} onChange={(v) => { setStatus(v); setSelected(new Set()); }} options={STATUS_VIEWS} />
                <Select label="Priority" value={priority} onChange={setPriority} options={[['', 'Any priority'], ['P1', 'P1'], ['P2', 'P2'], ['P3', 'P3'], ['P4', 'P4']]} />
                <Select label="Severity" value={severity} onChange={setSeverity} options={[['', 'Any severity'], ['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low'], ['info', 'Info']]} />
                <Select label="Source" value={source} onChange={setSource} options={[['', 'All sources'], ['active_scan', 'Active scans'], ['wazuh', 'Monitoring']]} />
                <Toggle on={kev} onChange={setKev}>Known exploited</Toggle>
                <Toggle on={overdue} onChange={setOverdue}>Overdue</Toggle>
                <SearchBox value={q} onSubmit={setQ} placeholder="CVE, title or asset" label="Search findings" />
            </div>
            {assetId && <p className="text-xs text-foreground">Showing one asset&apos;s findings. <Link href="/admin/vms/findings" className="font-semibold text-purple dark:text-[var(--vz-prog-4)]">Show all</Link></p>}
            {list.load.state === 'error' && <ErrorState error={list.load.error} status={list.load.status} onRetry={list.reload} />}
            {list.data?.correlation_error && <p className="text-[11px] text-foreground-muted">{list.data.correlation_error}</p>}
            <Notice msg={msg} />

            {can.manage && selected.size > 0 && (
                <div className="sticky top-2 z-20 flex flex-wrap items-center gap-2 bg-card border border-purple/40 rounded-xl px-3 py-2 shadow-lg">
                    <span className="text-xs font-bold text-foreground">{selected.size} selected{selected.size > BULK_MAX ? ` (first ${BULK_MAX} will be changed)` : ''}</span>
                    <select aria-label="Set status of selected" value="" disabled={busy} onChange={(e) => e.target.value && setBulk({ status: e.target.value })} className="bg-card border border-border rounded-lg px-2 py-1.5 text-[11px] text-foreground">
                        <option value="">Set status…</option>
                        {BULK_STATUS.map((v) => <option key={v} value={v}>{STATUS_LABEL[v]}</option>)}
                    </select>
                    <form className="flex items-center gap-1" onSubmit={(e) => { e.preventDefault(); void applyBulk({ owner: bulkOwner.trim() || null }, bulkOwner.trim() ? `Assigned to ${bulkOwner.trim()}` : 'Owner cleared'); setBulkOwner(''); }}>
                        <input aria-label="Assign selected to" value={bulkOwner} onChange={(e) => setBulkOwner(e.target.value)} maxLength={200} placeholder="Assign to…" className="w-32 bg-card border border-border rounded-lg px-2 py-1.5 text-[11px] text-foreground" />
                        <button type="submit" disabled={busy} className={btn('secondary')}>Assign</button>
                    </form>
                    <label className="inline-flex items-center gap-1 text-[11px] text-foreground-muted">Deadline
                        <input type="date" disabled={busy} onChange={(e) => e.target.value && void applyBulk({ due_at: new Date(`${e.target.value}T23:59:59Z`).toISOString() }, 'Deadline set')} className="bg-card border border-border rounded-lg px-2 py-1 text-[11px] text-foreground" />
                    </label>
                    <button onClick={() => setSelected(new Set())} className={`${btn('ghost')} ml-auto`}>Clear</button>
                </div>
            )}

            {list.load.state !== 'error' && <DataTable caption="Vulnerability findings" rows={rows} columns={columns} rowKey={(f) => f.id} onRowClick={(f) => setOpen(f.id)} activeKey={openId}
                selected={can.manage ? selected : undefined} onSelectedChange={can.manage ? setSelected : undefined}
                initialSort={{ key: 'risk', dir: 'desc' }}
                empty={q || priority || severity || source || kev || overdue ? 'No findings match these filters' : status === 'open_all' ? 'No open findings' : 'No findings in this view'} />}
            {list.data && list.data.findings.length >= 1000 && <p className="text-[11px] text-foreground-muted">Showing the 1000 highest-risk findings for these filters. Narrow the filters to see the rest.</p>}

            <Drawer open={!!openId} onClose={() => setOpen(null)} title="Finding" subtitle={openId ? <span className="font-mono">{openId}</span> : null}>
                {openId && <FindingDetail key={openId} id={openId} onChanged={reloadAll} />}
            </Drawer>
            <ConfirmDialog
                open={!!bulk?.status}
                title={bulk?.status ? `Mark ${Math.min(selected.size, BULK_MAX)} finding(s) as ${STATUS_LABEL[bulk.status].toLowerCase()}?` : ''}
                body="Each finding is changed through its own request and recorded in its history. Findings whose current status does not allow this change are refused and counted."
                confirmLabel="Apply"
                reason={bulk?.status ? { label: 'Reason', required: bulk.status === 'risk_accepted' || bulk.status === 'false_positive' } : undefined}
                onCancel={() => setBulk(null)}
                onConfirm={async (reason) => { const st = bulk!.status!; setBulk(null); await applyBulk({ status: st, ...(reason ? { note: reason } : {}) }, STATUS_LABEL[st]); }}
            />
        </div>
    );
}
