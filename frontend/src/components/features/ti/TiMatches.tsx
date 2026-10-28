'use client';

// Threat Intelligence — Organisation Matches (phase P6, redesigned in P25): indicators found in
// this organisation's alerts, assets, findings and cases. Analysts review or dismiss them, or open
// a case (one case per match; asking again returns it). Each match links to the indicator's
// investigation and to the record it was found in.

import { useState } from 'react';
import Link from 'next/link';
import { Target } from 'lucide-react';
import { PageHeader, EmptyState, ErrorState, Segmented, Notice, Tag, btn, type Msg } from '@/components/features/vms/kit';
import { Card, SectionTitle, Skeleton } from '@/components/features/vms/ui';
import { Donut, type Slice } from '@/components/features/vms/charts';
import { DataTable, type Column } from '@/components/features/vms/table';
import { useVmsData, useVmsCan, vmsSend } from '@/components/features/vms/data';
import { fmtWat } from '@/lib/vms';
import { MATCH_STATUS_STYLE, entityHref, ago, type TiMatch } from '@/lib/ti';

type Status = 'new' | 'reviewed' | 'promoted' | 'dismissed' | 'all';
const STATUS_TOKEN = { new: '--vz-sev-high', reviewed: '--vz-prog-2', promoted: '--vz-good', dismissed: '--vz-neutral' } as const;
const STATUS_LABEL: Record<keyof typeof STATUS_TOKEN, string> = { new: 'New', reviewed: 'Reviewed', promoted: 'Case opened', dismissed: 'Dismissed' };

export function TiMatches() {
    const [status, setStatus] = useState<Status>('new');
    const { load, data, reload, at } = useVmsData<{ matches: TiMatch[] }>(`/api/ti/matches${status === 'all' ? '' : `?status=${status}`}`);
    // A separate, unfiltered fetch purely to chart the status breakdown — the table above filters
    // to one status at a time, but the breakdown needs all of them at once.
    const all = useVmsData<{ matches: TiMatch[] }>('/api/ti/matches');
    const can = useVmsCan();
    const [msg, setMsg] = useState<Msg>(null);
    const [busy, setBusy] = useState<string | null>(null);
    const now = at ?? 0;

    async function act(m: TiMatch, action: 'reviewed' | 'dismissed' | 'case') {
        setBusy(m.id);
        const r = action === 'case' ? await vmsSend<{ created: boolean; case: { case_number: string } }>('POST', `/api/ti/matches/${m.id}/case`) : await vmsSend('PATCH', `/api/ti/matches/${m.id}`, { status: action });
        setBusy(null);
        setMsg(r.ok ? { ok: true, text: action === 'case' ? `${(r.data as { created: boolean }).created ? 'Opened' : 'Already linked to'} case ${(r.data as { case: { case_number: string } }).case.case_number}.` : `Marked ${action}.` } : { ok: false, text: r.error });
        if (r.ok) reload();
    }

    const columns: Column<TiMatch>[] = [
        { key: 'indicator', header: 'Indicator', render: (m) => <Link href={`/admin/ti/indicators?id=${m.indicator_id}`} className="font-mono text-xs font-semibold text-foreground hover:text-purple break-all">{m.ti_indicators?.value ?? m.matched_value}</Link>, sort: (m) => m.ti_indicators?.value ?? m.matched_value },
        { key: 'where', header: 'Found in', render: (m) => <span className="text-xs">{m.entity_type} · <span className="font-mono text-[11px]">{m.matched_field}</span>{entityHref(m) && <> · <Link href={entityHref(m)!} className="text-purple hover:underline">open</Link></>}</span>, sort: (m) => m.entity_type },
        { key: 'labels', header: 'Source labels', render: (m) => <span className="text-[11px] text-foreground-muted">{[...(m.ti_indicators?.malware_families ?? []), ...(m.ti_indicators?.threat_types ?? [])].slice(0, 3).join(', ') || '—'}</span>, hideBelow: 'md' },
        { key: 'sources', header: 'Sources', render: (m) => <span className="tabular-nums text-xs">{m.ti_indicators?.source_count ?? '—'}</span>, hideBelow: 'lg', sort: (m) => m.ti_indicators?.source_count ?? 0 },
        { key: 'first', header: 'First matched', render: (m) => <span className="text-[11px] text-foreground-muted" title={fmtWat(m.first_matched_at)}>{ago(m.first_matched_at, now)}</span>, sort: (m) => m.first_matched_at },
        { key: 'status', header: 'Status', render: (m) => <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${MATCH_STATUS_STYLE[m.status]}`}>{m.status}</span>, sort: (m) => m.status },
        {
            key: 'actions', header: '', render: (m) => !can.manage ? null : m.status === 'promoted' ? <Tag>case linked</Tag> : (
                <span className="flex gap-1 justify-end">
                    {m.status !== 'reviewed' && <button type="button" className={btn('ghost')} disabled={busy === m.id} onClick={(e) => { e.stopPropagation(); void act(m, 'reviewed'); }}>Reviewed</button>}
                    {m.status !== 'dismissed' && <button type="button" className={btn('ghost')} disabled={busy === m.id} onClick={(e) => { e.stopPropagation(); void act(m, 'dismissed'); }}>Dismiss</button>}
                    <button type="button" className={btn('secondary')} disabled={busy === m.id} onClick={(e) => { e.stopPropagation(); void act(m, 'case'); }}>Open case</button>
                </span>
            ),
        },
    ];

    return (
        <div className="space-y-5">
            <PageHeader title="Organisation Matches" icon={Target}
                description="Indicators found in this organisation's alerts, assets, vulnerability findings and cases. A match means the value was seen — the source's labels say why it may be malicious."
                actions={<Segmented label="Status" value={status} onChange={setStatus} options={[['new', 'New'], ['reviewed', 'Reviewed'], ['promoted', 'Case opened'], ['dismissed', 'Dismissed'], ['all', 'All']] as const} />} />
            <Notice msg={msg} />
            <Card>
                <SectionTitle title="Matches by status" />
                {all.load.state === 'loading' ? <Skeleton className="h-36" /> : all.load.state === 'error' ? null : (() => {
                    const counts: Record<string, number> = {};
                    for (const m of all.data?.matches ?? []) counts[m.status] = (counts[m.status] ?? 0) + 1;
                    const slices: Slice[] = (Object.keys(STATUS_TOKEN) as (keyof typeof STATUS_TOKEN)[]).map((s) => ({ key: s, label: STATUS_LABEL[s], value: counts[s] ?? 0, token: STATUS_TOKEN[s] }));
                    return slices.every((s) => s.value === 0)
                        ? <EmptyState compact title="No matches yet" body="Correlation runs every 15 minutes over new alerts and the current assets, findings and cases." />
                        : <Donut slices={slices} centerLabel="total matches" label="Matches by status" />;
                })()}
            </Card>
            <Card>
                {load.state === 'error' ? <ErrorState error={load.error} status={load.status} onRetry={reload} /> : (
                    <DataTable caption="Matches" rows={data?.matches ?? null} columns={columns} rowKey={(m) => m.id} initialSort={{ key: 'first', dir: 'desc' }}
                        empty={<EmptyState title={status === 'new' ? 'No new matches' : 'No matches'} body="Correlation runs every 15 minutes over new alerts and the current assets, findings and cases." />} />
                )}
            </Card>
        </div>
    );
}
