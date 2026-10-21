'use client';

// Remediation & Verification, second and third pages (redesign, phase P20).
//   AI Remediation Plans — drafts from the existing AI service (POST /api/ai/generate via AiPanel),
//     listed from GET /api/vms/ai-plans. A plan is advice: it changes nothing, and tasks are created
//     from it only when a person marked it useful (accepted) and asks for them.
//   Verification & Rescans — findings marked fixed, the verification scans for them, and what the
//     scans concluded (verified fixed / reopened). Only scan evidence or the Wazuh sync closes a finding.

import { useMemo, useState } from 'react';
import { useRouter, useSearchParams, usePathname } from 'next/navigation';
import { Sparkles, ScanSearch, ListPlus } from 'lucide-react';
import { fmtWat, SCAN_KIND_LABEL, OUTCOME_LABEL, type VmsScan } from '@/lib/vms';
import { AiPanel } from '@/components/shared/AiPanel';
import { Card, SectionTitle, StatusPill } from './ui';
import { PageHeader, KpiCard, PriorityBadge, SeverityBadge, Segmented, Drawer, ConfirmDialog, ErrorState, Notice, EmptyState, Tag, btn, relTime, type Msg } from './kit';
import { DataTable, type Column } from './table';
import { FindingDetail, STATUS_LABEL, type Finding } from './FindingDetail';
import { useVmsData, useVmsCan, vmsSend } from './data';

interface Step { order: number; action: string; details: string; owner_suggestion: string; proposed_deadline_days: number; requires_approval?: boolean }
interface Plan {
    id: string; purpose: 'remediation_plan' | 'finding_explanation' | 'rescan_interpretation'; subject_id: string; model: string; created_by: string; created_at: string;
    status: 'draft' | 'accepted' | 'rejected'; feedback: string | null; feedback_by: string | null;
    content: { summary?: string; steps?: Step[]; explanation?: string; conclusion?: string } & Record<string, unknown>;
    finding: { title: string; asset_value: string; priority: string | null } | null;
}
const PURPOSE_LABEL: Record<string, string> = { remediation_plan: 'Remediation plan', finding_explanation: 'Explanation', rescan_interpretation: 'Rescan interpretation' };
const PLAN_STATUS: Record<string, { label: string; tone: 'good' | 'neutral' | 'warning' }> = { draft: { label: 'Draft — not reviewed', tone: 'warning' }, accepted: { label: 'Marked useful', tone: 'good' }, rejected: { label: 'Marked not useful', tone: 'neutral' } };

function useDrawerParam(key: string) {
    const params = useSearchParams();
    const router = useRouter();
    const pathname = usePathname();
    const v = params.get(key);
    const set = (x: string | null) => { const p = new URLSearchParams(params.toString()); if (x) p.set(key, x); else p.delete(key); router.replace(`${pathname}${p.toString() ? `?${p.toString()}` : ''}`, { scroll: false }); };
    return [v, set] as const;
}

export function VmsAiPlans() {
    const can = useVmsCan();
    const plans = useVmsData<{ plans: Plan[] }>('/api/vms/ai-plans');
    const queue = useVmsData<{ items: (Finding & { overdue: boolean })[] }>('/api/vms/remediation');
    const [purpose, setPurpose] = useState<'remediation_plan' | 'all'>('remediation_plan');
    const [findingId, setFindingId] = useDrawerParam('finding');
    const [msg, setMsg] = useState<Msg>(null);
    const [creating, setCreating] = useState<Plan | null>(null);
    const now = plans.at ?? 0;
    const rows = useMemo(() => plans.data?.plans.filter((p) => purpose === 'all' || p.purpose === purpose) ?? null, [plans.data, purpose]);
    const planned = useMemo(() => new Set(plans.data?.plans.filter((p) => p.purpose === 'remediation_plan').map((p) => p.subject_id)), [plans.data]);
    const candidates = queue.data?.items.filter((f) => (f.priority === 'P1' || f.priority === 'P2') && !planned.has(f.id)).slice(0, 8) ?? [];

    async function createTasks(p: Plan) {
        const steps = [...(p.content.steps ?? [])].sort((a, b) => a.order - b.order);
        let ok = 0;
        const errors: string[] = [];
        for (const s of steps) {
            const due = Number.isFinite(s.proposed_deadline_days) && s.proposed_deadline_days > 0 ? new Date(Date.now() + s.proposed_deadline_days * 86_400_000).toISOString() : undefined;
            const r = await vmsSend('POST', `/api/vms/findings/${p.subject_id}/tasks`, { title: s.action.slice(0, 300), ...(s.details ? { details: s.details.slice(0, 4000) } : {}), ...(s.owner_suggestion ? { owner: s.owner_suggestion.slice(0, 200) } : {}), ...(due ? { due_at: due } : {}), ai_artifact_id: p.id });
            if (r.ok) ok++; else errors.push(r.error);
        }
        setMsg(errors.length ? { ok: false, text: `${ok} task(s) created, ${errors.length} refused: ${errors[0]}` } : { ok: true, text: `${ok} task(s) created from the plan` });
    }

    const columns: Column<Plan>[] = [
        { key: 'finding', header: 'Finding', className: 'min-w-[240px]', render: (p) => <div className="flex items-start gap-2"><PriorityBadge priority={p.finding?.priority} /><span><span className="block font-semibold text-foreground">{p.finding?.title ?? 'Finding not found'}</span><span className="block text-[11px] font-mono text-foreground-muted">{p.finding?.asset_value}</span></span></div> },
        { key: 'purpose', header: 'Type', render: (p) => <span className="text-[11px]">{PURPOSE_LABEL[p.purpose]}</span> },
        { key: 'summary', header: 'Summary', hideBelow: 'md', className: 'max-w-[380px]', render: (p) => <span className="text-[11px] text-foreground-muted line-clamp-2">{p.content.summary ?? p.content.explanation ?? '—'}{p.content.steps ? ` · ${p.content.steps.length} step(s)` : ''}</span> },
        { key: 'status', header: 'Review', render: (p) => <StatusPill tone={PLAN_STATUS[p.status]?.tone ?? 'neutral'} label={PLAN_STATUS[p.status]?.label ?? p.status} />, sort: (p) => p.status },
        { key: 'created', header: 'Created', hideBelow: 'lg', sort: (p) => p.created_at, render: (p) => <span className="text-[11px] text-foreground-muted whitespace-nowrap">{relTime(p.created_at, now)} · {p.created_by}</span> },
        { key: 'act', header: '', render: (p) => can.manage && p.purpose === 'remediation_plan' && p.status === 'accepted' && p.content.steps?.length ? <button onClick={(e) => { e.stopPropagation(); setCreating(p); }} className={btn('secondary')}><ListPlus className="w-3.5 h-3.5" aria-hidden /> Create tasks</button> : null },
    ];

    return (
        <div className="space-y-5">
            <PageHeader icon={Sparkles} title="AI Remediation Plans"
                description="Remediation plans drafted by the platform's AI from the finding, its evidence and threat intelligence. They are proposals: they change nothing, cite the records they rely on, and must be reviewed. Tasks are created only from a plan someone marked useful." />
            <Notice msg={msg} />
            {candidates.length > 0 && (
                <Card>
                    <SectionTitle title="P1 and P2 findings without a plan" hint="Open one to draft a plan with the AI service (needs AI to be configured on the backend)." />
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                        {candidates.map((f) => (
                            <button key={f.id} onClick={() => setFindingId(f.id)} className="flex items-center gap-2 text-left border border-border rounded-xl px-3 py-2 hover:bg-card-muted">
                                <PriorityBadge priority={f.priority} /><SeverityBadge severity={f.scanner_severity} />
                                <span className="flex-1 min-w-0"><span className="block text-xs font-semibold text-foreground truncate">{f.title}</span><span className="block text-[11px] font-mono text-foreground-muted truncate">{f.asset_value}</span></span>
                                <Sparkles className="w-3.5 h-3.5 text-foreground-muted" aria-hidden />
                            </button>
                        ))}
                    </div>
                </Card>
            )}
            <div className="flex items-center gap-2"><Segmented label="Type" value={purpose} onChange={setPurpose} options={[['remediation_plan', 'Remediation plans'], ['all', 'All AI analyses']]} /></div>
            {plans.load.state === 'error' ? <ErrorState error={plans.load.error} status={plans.load.status} onRetry={plans.reload} />
                : <DataTable caption="AI remediation plans" rows={rows} columns={columns} rowKey={(p) => p.id} onRowClick={(p) => setFindingId(p.subject_id)} initialSort={{ key: 'created', dir: 'desc' }}
                    empty={<EmptyState icon={Sparkles} title="No AI plans yet" body="Open a finding and choose “Remediation plan” in its AI analysis panel, or pick one of the findings above." />} />}
            <Drawer open={!!findingId} onClose={() => setFindingId(null)} title="AI remediation plan">
                {findingId && (
                    <div className="space-y-4">
                        <AiPanel key={findingId} purpose="remediation_plan" subjectId={findingId} title="AI remediation plan (draft — review before acting)"
                            purposes={[{ value: 'remediation_plan', label: 'Remediation plan' }, { value: 'finding_explanation', label: 'Explain this vulnerability' }, { value: 'rescan_interpretation', label: 'Interpret the rescan' }]} />
                        <details className="border border-border rounded-xl bg-card"><summary className="cursor-pointer px-3 py-2 text-xs font-semibold text-foreground">Finding details</summary><div className="p-3"><FindingDetail id={findingId} onChanged={plans.reload} /></div></details>
                    </div>
                )}
            </Drawer>
            <ConfirmDialog open={!!creating} title="Create tasks from this plan?"
                body={creating ? <>Creates {creating.content.steps?.length ?? 0} remediation task(s) on “{creating.finding?.title}”, with the owners and deadlines the plan proposed. You can change them afterwards. The finding itself does not change.</> : null}
                confirmLabel="Create tasks" onCancel={() => setCreating(null)} onConfirm={async () => { const p = creating!; setCreating(null); await createTasks(p); }} />
        </div>
    );
}

export function VmsVerification() {
    const can = useVmsCan();
    const awaiting = useVmsData<{ findings: Finding[] }>('/api/vms/findings?status=fixed_pending_verification');
    const verified = useVmsData<{ findings: Finding[] }>('/api/vms/findings?status=verified');
    const reopened = useVmsData<{ findings: Finding[] }>('/api/vms/findings?status=reopened');
    const scans = useVmsData<{ scans: VmsScan[] }>('/api/vms/scans?limit=300');
    const [openId, setOpenId] = useDrawerParam('id');
    const [confirm, setConfirm] = useState<Finding | null>(null);
    const [msg, setMsg] = useState<Msg>(null);
    const [tab, setTab] = useState<'awaiting' | 'scans' | 'verified' | 'reopened'>('awaiting');
    const now = awaiting.at ?? 0;
    const vScans = useMemo(() => scans.data?.scans.filter((s) => s.purpose === 'verification') ?? null, [scans.data]);
    const recentVerified = useMemo(() => verified.data?.findings.filter((f) => f.verified_at && Date.parse(f.verified_at) > now - 30 * 86_400_000) ?? null, [verified.data, now]);

    async function verify(f: Finding) {
        const r = await vmsSend<{ queued: boolean; message?: string }>('POST', `/api/vms/findings/${f.id}/verify`, {});
        setMsg(r.ok ? { ok: true, text: r.data.message ?? 'Verification scan queued' } : { ok: false, text: r.error });
        if (r.ok) { awaiting.reload(); scans.reload(); }
    }
    const findingCols = (action: boolean): Column<Finding>[] => [
        { key: 'priority', header: 'Priority', render: (f) => <PriorityBadge priority={f.priority} />, sort: (f) => f.priority ?? 'P9' },
        { key: 'title', header: 'Finding', className: 'min-w-[220px]', render: (f) => <div><p className="font-semibold text-foreground">{f.title}</p><p className="text-[11px] font-mono text-foreground-muted">{f.asset_value}{f.port ? `:${f.port}` : ''}</p></div> },
        { key: 'source', header: 'Verified by', hideBelow: 'md', render: (f) => <span className="text-[11px] text-foreground-muted">{f.source_class === 'wazuh' ? 'Next Wazuh sync (hourly)' : `Rescan (${f.detected_by.includes('nuclei') ? 'Nuclei' : 'OpenVAS'})`}</span> },
        { key: 'when', header: action ? 'Last seen' : 'Verified', sort: (f) => (action ? f.last_seen : f.verified_at) ?? '', render: (f) => <span className="text-[11px] text-foreground-muted whitespace-nowrap">{relTime(action ? f.last_seen : f.verified_at, now)}</span> },
        ...(action && can.scan ? [{ key: 'act', header: '', render: (f: Finding) => f.source_class === 'wazuh' ? <Tag>Automatic</Tag> : <button onClick={(e) => { e.stopPropagation(); setConfirm(f); }} className={btn('primary')}><ScanSearch className="w-3.5 h-3.5" aria-hidden /> Verify</button> }] : []),
    ];
    const scanCols: Column<VmsScan>[] = [
        { key: 'when', header: 'Requested', sort: (s) => s.requested_at, render: (s) => <span className="text-[11px] whitespace-nowrap">{fmtWat(s.requested_at)}</span> },
        { key: 'kind', header: 'Engine', render: (s) => <span className="text-[11px]">{SCAN_KIND_LABEL[s.kind] ?? s.kind}</span> },
        { key: 'target', header: 'Target', render: (s) => <span className="text-[11px] font-mono">{s.targets.join(', ')}</span> },
        { key: 'status', header: 'Result', render: (s) => <ScanResult s={s} /> },
        { key: 'by', header: 'Requested by', hideBelow: 'lg', render: (s) => <span className="text-[11px] text-foreground-muted">{s.requested_by}</span> },
    ];
    return (
        <div className="space-y-5">
            <PageHeader icon={ScanSearch} title="Verification & Rescans" description="Fixes are confirmed by evidence, not by a status change: a rescan of the same check on the same target (or the next Wazuh sync for agent findings) marks the finding verified, or reopens it if it is still there." />
            <section className="grid grid-cols-2 md:grid-cols-4 gap-3" aria-label="Key figures">
                <KpiCard label="Awaiting verification" value={awaiting.data?.findings.length} reason="Loading" tone={awaiting.data?.findings.length ? 'warning' : undefined} />
                <KpiCard label="Verification scans queued or running" value={vScans ? vScans.filter((s) => s.status === 'queued' || s.status === 'running').length : undefined} reason="Loading" />
                <KpiCard label="Verified fixed (30 days)" value={recentVerified?.length} reason="Loading" tone={recentVerified?.length ? 'good' : undefined} />
                <KpiCard label="Reopened" value={reopened.data?.findings.length} reason="Loading" tone={reopened.data?.findings.length ? 'critical' : undefined} sub="Still present when rescanned" />
            </section>
            <Notice msg={msg} />
            {[awaiting, verified, reopened].map((x, i) => x.load.state === 'error' ? <ErrorState key={i} error={x.load.error} status={x.load.status} onRetry={x.reload} /> : null)}
            <Segmented label="List" value={tab} onChange={setTab} options={[['awaiting', 'Awaiting verification'], ['scans', 'Verification scans'], ['verified', 'Verified fixed'], ['reopened', 'Reopened']]} />
            {tab === 'awaiting' && awaiting.load.state !== 'error' && <DataTable caption="Findings awaiting verification" rows={awaiting.data?.findings ?? null} columns={findingCols(true)} rowKey={(f) => f.id} onRowClick={(f) => setOpenId(f.id)} empty="No findings are waiting for verification" />}
            {tab === 'scans' && (scans.load.state === 'error' ? <ErrorState error={scans.load.error} status={scans.load.status} onRetry={scans.reload} /> : <DataTable caption="Verification scans" rows={vScans} columns={scanCols} rowKey={(s) => s.id} initialSort={{ key: 'when', dir: 'desc' }} empty="No verification scans yet" />)}
            {tab === 'verified' && verified.load.state !== 'error' && <DataTable caption="Findings verified fixed" rows={verified.data?.findings ?? null} columns={findingCols(false)} rowKey={(f) => f.id} onRowClick={(f) => setOpenId(f.id)} initialSort={{ key: 'when', dir: 'desc' }} empty="No findings verified fixed yet" />}
            {tab === 'reopened' && reopened.load.state !== 'error' && <DataTable caption="Reopened findings" rows={reopened.data?.findings ?? null} columns={findingCols(false).filter((c) => c.key !== 'when')} rowKey={(f) => f.id} onRowClick={(f) => setOpenId(f.id)} empty="No reopened findings" />}
            <Drawer open={!!openId} onClose={() => setOpenId(null)} title="Finding">{openId && <FindingDetail key={openId} id={openId} onChanged={() => { awaiting.reload(); verified.reload(); reopened.reload(); }} />}</Drawer>
            <ConfirmDialog open={!!confirm} title="Queue a verification scan?"
                body={confirm ? <>Rescans <span className="font-mono">{confirm.asset_value}</span> for “{confirm.title}” — only if the asset is still inside active vulnerability-scan scope. The scan runs on an engine a connected worker has enabled; the result sets the status.</> : null}
                confirmLabel="Queue verification" onCancel={() => setConfirm(null)} onConfirm={async () => { const f = confirm!; setConfirm(null); await verify(f); }} />
            <p className="text-[11px] text-foreground-muted">{STATUS_LABEL.fixed_pending_verification} findings stay open until verified.</p>
        </div>
    );
}

/** A scan's result in words: "succeeded" with no host reached is inconclusive, never success. */
export function ScanResult({ s }: { s: Pick<VmsScan, 'status' | 'summary' | 'error'> }) {
    const outcome = String((s.summary as { outcome?: string } | null)?.outcome ?? '');
    if (s.status === 'queued') return <StatusPill tone="neutral" label="Queued" />;
    if (s.status === 'running') return <StatusPill tone="neutral" label="Running" />;
    if (s.status === 'cancelled') return <StatusPill tone="neutral" label="Cancelled" />;
    if (s.status === 'failed') return <StatusPill tone="critical" label="Failed" />;
    if (['unreachable', 'insufficient_evidence', 'no_route'].includes(outcome)) return <StatusPill tone="warning" label={`Inconclusive — ${OUTCOME_LABEL[outcome]?.toLowerCase() ?? outcome}`} />;
    if (outcome === 'partial') return <StatusPill tone="warning" label="Partly assessed" />;
    return <StatusPill tone="good" label={outcome ? OUTCOME_LABEL[outcome] ?? 'Assessed' : 'Completed'} />;
}
