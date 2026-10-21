'use client';

// Remediation Tasks (redesign, phase P20). Two views of the same work:
//   Board — open findings by lifecycle stage. The stages map onto the stored finding statuses
//           without changing them: Detected = open/reopened, Triaged = acknowledged, In progress =
//           in_progress, Awaiting verification = fixed_pending_verification, Resolved = verified.
//           "Assigned" is the finding's owner. Moving a card sets the status through
//           PATCH /api/vms/findings/:id, which allows only valid transitions; nothing can be moved
//           into Resolved — only a rescan or Wazuh verifies a fix.
//   Tasks — the remediation tasks (GET /api/vms/tasks) with owner, due date and SLA state.

import { useMemo, useState, type DragEvent } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { Wrench, User, CalendarClock, Lock } from 'lucide-react';
import { fmtWat } from '@/lib/vms';
import { PageHeader, PriorityBadge, SeverityBadge, Segmented, Select, Toggle, SearchBox, Drawer, ErrorState, Notice, ExportCsvButton, EmptyState, Tag, relTime, type Msg, PRIORITY_META } from './kit';
import { DataTable, type Column } from './table';
import { FindingDetail, NEXT, STATUS_LABEL, type Finding } from './FindingDetail';
import { useVmsData, useVmsCan, vmsSend } from './data';

type Item = Finding & { overdue: boolean; tasks: { id: string; title: string; status: string; owner: string | null; due_at: string | null }[] };
interface Task { id: string; finding_id: string; title: string; details: string | null; owner: string | null; due_at: string | null; status: 'todo' | 'doing' | 'done' | 'cancelled'; ai_artifact_id: string | null; created_by: string; created_at: string; completed_at: string | null; overdue: boolean; finding: { id: string; title: string; asset_value: string; scanner_severity: string; priority: string | null; status: string } | null }

const STAGES = [
    { id: 'detected', label: 'Detected', statuses: ['open', 'reopened'], target: 'open', hint: 'New or reopened by a scan' },
    { id: 'triaged', label: 'Triaged', statuses: ['acknowledged'], target: 'acknowledged', hint: 'Reviewed and accepted as real' },
    { id: 'progress', label: 'In progress', statuses: ['in_progress'], target: 'in_progress', hint: 'Fix under way' },
    { id: 'awaiting', label: 'Awaiting verification', statuses: ['fixed_pending_verification'], target: 'fixed_pending_verification', hint: 'Fixed; waiting for a rescan or Wazuh' },
    { id: 'resolved', label: 'Resolved', statuses: ['verified'], target: null, hint: 'Verified fixed by a scan or Wazuh' },
] as const;
const TASK_LABEL: Record<string, string> = { todo: 'To do', doing: 'In progress', done: 'Done', cancelled: 'Cancelled' };

export function VmsRemediation() {
    const params = useSearchParams();
    const router = useRouter();
    const [view, setView] = useState<'board' | 'table'>(params.get('view') === 'table' ? 'table' : 'board');
    const openId = params.get('id');
    const setOpen = (id: string | null) => {
        const p = new URLSearchParams(params.toString());
        if (id) p.set('id', id); else p.delete('id');
        p.set('view', view);
        router.replace(`/admin/vms/remediation?${p.toString()}`, { scroll: false });
    };
    const [tick, setTick] = useState(0);
    return (
        <div className="space-y-5">
            <PageHeader icon={Wrench} title="Remediation Tasks"
                description={<>Remediation work by lifecycle stage, with owners, deadlines and tasks. Deadlines follow priority: {Object.entries(PRIORITY_META).map(([k, v]) => `${k} ${v.hint.replace('Fix within ', '')}`).join(' · ')}. A finding is resolved only when a rescan or Wazuh verifies the fix.</>}
                actions={<Segmented label="View" value={view} onChange={(v) => { setView(v); const p = new URLSearchParams(params.toString()); p.set('view', v); router.replace(`/admin/vms/remediation?${p.toString()}`, { scroll: false }); }} options={[['board', 'Board'], ['table', 'Tasks']]} />}
            />
            {view === 'board' ? <Board key={`b${tick}`} onOpen={setOpen} /> : <TaskTable key={`t${tick}`} onOpen={setOpen} initialOverdue={params.get('overdue') === '1'} />}
            <Drawer open={!!openId} onClose={() => setOpen(null)} title="Finding">
                {openId && <FindingDetail key={openId} id={openId} onChanged={() => setTick((t) => t + 1)} />}
            </Drawer>
        </div>
    );
}

function Board({ onOpen }: { onOpen: (id: string) => void }) {
    const can = useVmsCan();
    const open = useVmsData<{ items: Item[] }>('/api/vms/remediation');
    const resolved = useVmsData<{ findings: Finding[] }>('/api/vms/findings?status=verified');
    const decided = useVmsData<{ findings: Finding[] }>('/api/vms/findings?status=risk_accepted,false_positive');
    const [msg, setMsg] = useState<Msg>(null);
    const [owner, setOwner] = useState('');
    const [priority, setPriority] = useState('');
    const [drag, setDrag] = useState<{ id: string; status: string } | null>(null);
    const [over, setOver] = useState<string | null>(null);
    const now = open.at ?? 0;

    const items = useMemo(() => {
        const o = (open.data?.items ?? []) as (Item | (Finding & { overdue: boolean; tasks: Item['tasks'] }))[];
        // Resolved: the 30 most recently verified.
        const r = [...(resolved.data?.findings ?? [])].sort((a, b) => (b.verified_at ?? '').localeCompare(a.verified_at ?? '')).slice(0, 30).map((f) => ({ ...f, overdue: false, tasks: [] }));
        return [...o, ...r].filter((f) => (!priority || f.priority === priority) && (!owner || (owner === '-' ? !f.owner : (f.owner ?? '').toLowerCase().includes(owner.toLowerCase()))));
    }, [open.data, resolved.data, priority, owner]);

    async function move(id: string, from: string, to: string) {
        setMsg(null);
        if (from === to) return;
        if (!(NEXT[from] ?? []).includes(to)) { setMsg({ ok: false, text: `${STATUS_LABEL[from]} cannot move to ${STATUS_LABEL[to]}` }); return; }
        const r = await vmsSend('PATCH', `/api/vms/findings/${id}`, { status: to });
        setMsg(r.ok ? { ok: true, text: `Moved to ${STATUS_LABEL[to]}` } : { ok: false, text: r.error });
        if (r.ok) open.reload();
    }
    const drop = (stage: (typeof STAGES)[number]) => (e: DragEvent) => {
        e.preventDefault();
        setOver(null);
        if (!drag) return;
        if (!stage.target) { setMsg({ ok: false, text: 'Only a rescan or the Wazuh sync can resolve a finding. Move it to Awaiting verification and verify it.' }); return; }
        void move(drag.id, drag.status, stage.target);
        setDrag(null);
    };

    if (open.load.state === 'error') return <ErrorState error={open.load.error} status={open.load.status} onRetry={open.reload} />;
    return (
        <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-2">
                <Select label="Priority" value={priority} onChange={setPriority} options={[['', 'Any priority'], ['P1', 'P1'], ['P2', 'P2'], ['P3', 'P3'], ['P4', 'P4']]} />
                <SearchBox value={owner} onSubmit={setOwner} placeholder="Owner (- for unassigned)" label="Filter by owner" />
                <span className="text-[11px] text-foreground-muted">{open.data ? `${open.data.items.length} open · ${open.data.items.filter((i) => i.overdue).length} overdue · ${open.data.items.filter((i) => !i.owner).length} unassigned` : ''}</span>
                {decided.data && decided.data.findings.length > 0 && <Link href="/admin/vms/findings?status=risk_accepted%2Cfalse_positive" className="text-[11px] font-semibold text-purple dark:text-[var(--vz-prog-4)] ml-auto">{decided.data.findings.length} closed by decision (risk accepted / false positive)</Link>}
            </div>
            <Notice msg={msg} />
            {can.manage && <p className="text-[11px] text-foreground-muted">Drag a card to another stage, or use its “Move to” menu. Every move is checked by the backend and recorded in the finding history.</p>}
            <div className="grid grid-flow-col auto-cols-[minmax(250px,1fr)] gap-3 overflow-x-auto pb-2">
                {STAGES.map((stage) => {
                    const cards = items.filter((f) => (stage.statuses as readonly string[]).includes(f.status));
                    return (
                        <section key={stage.id} aria-label={stage.label}
                            onDragOver={can.manage ? (e) => { e.preventDefault(); setOver(stage.id); } : undefined} onDragLeave={() => setOver(null)} onDrop={can.manage ? drop(stage) : undefined}
                            className={`flex flex-col rounded-2xl border bg-card-muted/50 min-h-[320px] transition-colors ${over === stage.id ? (stage.target ? 'border-purple' : 'border-[var(--vz-critical)]') : 'border-border'}`}>
                            <header className="px-3 pt-3 pb-2">
                                <div className="flex items-center justify-between"><h3 className="text-xs font-bold text-foreground flex items-center gap-1.5">{!stage.target && <Lock className="w-3 h-3 text-foreground-muted" aria-label="Set by scans only" />}{stage.label}</h3><span className="text-[11px] font-bold tabular-nums text-foreground-muted">{cards.length}</span></div>
                                <p className="text-[10.5px] text-foreground-muted">{stage.hint}{stage.id === 'resolved' ? ' (30 most recent)' : ''}</p>
                            </header>
                            <div className="flex-1 space-y-2 px-2 pb-2 max-h-[640px] overflow-y-auto">
                                {open.load.state === 'loading' && !open.data && Array.from({ length: 3 }, (_, i) => <div key={i} className="h-24 rounded-xl bg-card motion-safe:animate-pulse" />)}
                                {open.data && cards.length === 0 && <p className="text-[11px] text-foreground-muted text-center py-6">Nothing here</p>}
                                {cards.map((f) => (
                                    <article key={f.id} draggable={can.manage && !!stage.target} onDragStart={() => setDrag({ id: f.id, status: f.status })} onDragEnd={() => { setDrag(null); setOver(null); }}
                                        className={`bg-card border border-border rounded-xl p-3 space-y-2 shadow-[0_1px_2px_rgba(0,0,0,0.04)] ${can.manage && stage.target ? 'cursor-grab active:cursor-grabbing' : ''} ${drag?.id === f.id ? 'opacity-50' : ''}`}>
                                        <div className="flex items-center gap-2">
                                            <PriorityBadge priority={f.priority} />
                                            <SeverityBadge severity={f.scanner_severity} />
                                            {f.status === 'reopened' && <Tag>Reopened</Tag>}
                                            {f.overdue && <Tag strong>Overdue</Tag>}
                                        </div>
                                        <button onClick={() => onOpen(f.id)} className="block text-left text-xs font-semibold text-foreground hover:underline leading-snug">{f.title}</button>
                                        <p className="text-[11px] text-foreground-muted font-mono truncate">{f.asset_value}{f.port ? `:${f.port}` : ''}</p>
                                        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-foreground-muted">
                                            <span className="inline-flex items-center gap-1"><User className="w-3 h-3" aria-hidden />{f.owner ? <span className="text-foreground">{f.owner}</span> : 'Unassigned'}</span>
                                            {stage.id === 'resolved' ? <span>verified {relTime(f.verified_at, now)}</span>
                                                : <span className="inline-flex items-center gap-1"><CalendarClock className="w-3 h-3" aria-hidden />{f.due_at ? `due ${relTime(f.due_at, now)}` : 'no deadline'}</span>}
                                            {f.tasks.length > 0 && <span>{f.tasks.filter((t) => t.status === 'done').length}/{f.tasks.length} tasks</span>}
                                        </div>
                                        {can.manage && stage.target && (
                                            <select aria-label={`Move ${f.title} to`} value="" onChange={(e) => e.target.value && void move(f.id, f.status, e.target.value)} className="w-full bg-card-muted border border-border rounded-lg px-1.5 py-1 text-[11px] text-foreground">
                                                <option value="">Move to…</option>
                                                {STAGES.filter((s) => s.target && s.target !== f.status && (NEXT[f.status] ?? []).includes(s.target)).map((s) => <option key={s.id} value={s.target!}>{s.label}</option>)}
                                            </select>
                                        )}
                                    </article>
                                ))}
                            </div>
                        </section>
                    );
                })}
            </div>
        </div>
    );
}

function TaskTable({ onOpen, initialOverdue }: { onOpen: (id: string) => void; initialOverdue: boolean }) {
    const can = useVmsCan();
    const { load, data, reload, at } = useVmsData<{ tasks: Task[] }>('/api/vms/tasks');
    const [status, setStatus] = useState<'active' | 'done' | 'all'>('active');
    const [overdue, setOverdue] = useState(initialOverdue);
    const [owner, setOwner] = useState('');
    const [msg, setMsg] = useState<Msg>(null);
    const now = at ?? 0;
    const rows = useMemo(() => data?.tasks.filter((t) =>
        (status === 'all' || (status === 'active' ? t.status === 'todo' || t.status === 'doing' : t.status === 'done' || t.status === 'cancelled'))
        && (!overdue || t.overdue) && (!owner || (owner === '-' ? !t.owner : (t.owner ?? '').toLowerCase().includes(owner.toLowerCase())))) ?? null, [data, status, overdue, owner]);
    async function patch(t: Task, body: Record<string, unknown>, label: string) {
        const r = await vmsSend('PATCH', `/api/vms/tasks/${t.id}`, body);
        setMsg(r.ok ? { ok: true, text: label } : { ok: false, text: r.error });
        if (r.ok) reload();
    }
    const columns: Column<Task>[] = [
        { key: 'title', header: 'Task', className: 'min-w-[160px]', sort: (t) => t.title.toLowerCase(), render: (t) => <div><p className="font-semibold text-foreground">{t.title}</p>{t.ai_artifact_id && <p className="text-[10.5px] text-foreground-muted">From an accepted AI plan</p>}{t.finding && <p className="md:hidden text-[10.5px] text-foreground-muted mt-0.5">{t.finding.priority} · {t.finding.title}</p>}</div> },
        { key: 'finding', header: 'Finding', hideBelow: 'md', className: 'min-w-[200px]', sort: (t) => t.finding?.priority ?? 'P9', render: (t) => t.finding ? <button onClick={(e) => { e.stopPropagation(); onOpen(t.finding!.id); }} className="text-left flex items-start gap-2"><PriorityBadge priority={t.finding.priority} /><span><span className="block text-xs text-foreground hover:underline">{t.finding.title}</span><span className="block text-[10.5px] font-mono text-foreground-muted">{t.finding.asset_value} · {STATUS_LABEL[t.finding.status] ?? t.finding.status}</span></span></button> : <span className="text-foreground-muted">—</span> },
        {
            key: 'owner', header: 'Assigned to', sort: (t) => t.owner ?? '~',
            render: (t) => can.manage ? <input aria-label={`Owner of ${t.title}`} key={`${t.id}-${t.owner}`} defaultValue={t.owner ?? ''} maxLength={200} placeholder="Unassigned" onClick={(e) => e.stopPropagation()} onBlur={(e) => { const v = e.target.value.trim(); if (v !== (t.owner ?? '')) void patch(t, { owner: v || null }, 'Owner saved'); }} className="w-24 sm:w-32 bg-transparent border border-transparent hover:border-border focus:border-border rounded px-1.5 py-1 text-[11px] text-foreground" /> : <span className="text-[11px]">{t.owner ?? 'Unassigned'}</span>,
        },
        {
            key: 'due', header: 'Due / SLA', sort: (t) => t.due_at ?? '9999',
            render: (t) => (
                <div className="flex items-center gap-2">
                    {can.manage ? <input type="date" aria-label={`Due date of ${t.title}`} key={`${t.id}-${t.due_at}`} defaultValue={t.due_at?.slice(0, 10) ?? ''} onClick={(e) => e.stopPropagation()} onChange={(e) => e.target.value && void patch(t, { due_at: new Date(`${e.target.value}T23:59:59Z`).toISOString() }, 'Due date saved')} className="bg-transparent border border-transparent hover:border-border rounded px-1 py-0.5 text-[11px] text-foreground" />
                        : <span className="text-[11px]">{t.due_at ? fmtWat(t.due_at) : '—'}</span>}
                    {t.overdue ? <Tag strong>Overdue</Tag> : t.due_at && (t.status === 'todo' || t.status === 'doing') ? <span className="text-[10.5px] text-foreground-muted whitespace-nowrap">{relTime(t.due_at, now)}</span> : null}
                </div>
            ),
        },
        {
            key: 'status', header: 'Status', sort: (t) => t.status,
            render: (t) => can.manage ? <select aria-label={`Status of ${t.title}`} value={t.status} onClick={(e) => e.stopPropagation()} onChange={(e) => void patch(t, { status: e.target.value }, `Marked ${TASK_LABEL[e.target.value].toLowerCase()}`)} className="bg-card border border-border rounded-lg px-1.5 py-1 text-[11px] text-foreground">{Object.entries(TASK_LABEL).map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select> : <span className="text-[11px] font-semibold">{TASK_LABEL[t.status]}</span>,
        },
        { key: 'created', header: 'Created', hideBelow: 'lg', sort: (t) => t.created_at, render: (t) => <span className="text-[11px] text-foreground-muted whitespace-nowrap">{fmtWat(t.created_at).replace(/ WAT$/, '')}<br />{t.created_by}</span> },
    ];
    if (load.state === 'error') return <ErrorState error={load.error} status={load.status} onRetry={reload} />;
    return (
        <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-2">
                <Segmented label="Task status" value={status} onChange={setStatus} options={[['active', 'Open'], ['done', 'Done / cancelled'], ['all', 'All']]} />
                <Toggle on={overdue} onChange={setOverdue}>Overdue</Toggle>
                <SearchBox value={owner} onSubmit={setOwner} placeholder="Owner (- for unassigned)" label="Filter by owner" />
                <div className="ml-auto"><ExportCsvButton filename="vms-remediation-tasks.csv" rows={rows?.map((t) => ({ ...t, finding_title: t.finding?.title, asset: t.finding?.asset_value, priority: t.finding?.priority }))} columns={[{ key: 'title', header: 'Task' }, { key: 'status', header: 'Status' }, { key: 'owner', header: 'Owner' }, { key: 'due_at', header: 'Due' }, { key: 'overdue', header: 'Overdue' }, { key: 'priority', header: 'Priority' }, { key: 'finding_title', header: 'Finding' }, { key: 'asset', header: 'Asset' }, { key: 'created_at', header: 'Created' }, { key: 'completed_at', header: 'Completed' }]} /></div>
            </div>
            <Notice msg={msg} />
            <p className="text-[11px] text-foreground-muted">Finishing every task does not close the finding: only a rescan or Wazuh verifies the fix.</p>
            <DataTable caption="Remediation tasks" rows={rows} columns={columns} rowKey={(t) => t.id} onRowClick={(t) => t.finding && onOpen(t.finding.id)} initialSort={{ key: 'due', dir: 'asc' }}
                empty={<EmptyState title={data?.tasks.length ? 'No tasks match these filters' : 'No remediation tasks yet'} body={data?.tasks.length ? undefined : 'Add tasks from a finding, or create them from an AI remediation plan a person accepted.'} />} />
        </div>
    );
}
