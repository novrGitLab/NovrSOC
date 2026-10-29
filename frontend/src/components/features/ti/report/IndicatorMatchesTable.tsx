'use client';

// Indicator Matches (report brief §5) — the report API's own tiered relevance list (already
// capped and ranked server-side, GET /api/ti/report), rendered as a sortable table instead of a
// text block. Deeper investigation (search, status changes, case linking) stays on the full
// Organisation Matches page this table links into — this is a report summary, not a second copy
// of that page's own fetch/filter logic.
import { DataTable, type Column } from '@/components/features/vms/table';
import { Tag } from '@/components/features/vms/kit';
import { fmtWat } from '@/lib/vms';
import { entityHref, TIER_LABEL, TIER_STYLE, type RelevantItem, type RelevanceTier } from '@/lib/ti';

const TIER_RANK: Record<RelevanceTier, number> = { critical: 0, high: 1, medium: 2, low: 3 };

export function IndicatorMatchesTable({ items, findingsPath = '/admin/ti/matches' }: { items: RelevantItem[]; findingsPath?: string }) {
    const columns: Column<RelevantItem>[] = [
        { key: 'tier', header: 'Tier', render: (m) => <span className={`inline-block text-[9px] font-bold px-1.5 py-0.5 rounded-full border uppercase ${TIER_STYLE[m.tier]}`}>{TIER_LABEL[m.tier]}</span>, sort: (m) => TIER_RANK[m.tier] },
        { key: 'indicator', header: 'Indicator', className: 'min-w-[200px]', render: (m) => <span className="font-mono text-[11px] font-semibold">{m.indicator_type}: {m.indicator_value}</span>, sort: (m) => m.indicator_value },
        { key: 'entity', header: 'Matched in', render: (m) => <span className="text-[11px]">{m.entity_type}{m.asset_value ? ` (${m.asset_value})` : ''}</span>, sort: (m) => m.entity_type, hideBelow: 'md' },
        { key: 'status', header: 'Status', render: (m) => <span className="text-[11px] capitalize">{m.verified ? 'Verified' : m.status}</span>, sort: (m) => m.status, hideBelow: 'sm' },
        { key: 'kev', header: 'KEV', render: (m) => m.kev ? <Tag strong>KEV</Tag> : <span className="text-[11px] text-foreground-muted">—</span>, hideBelow: 'lg' },
        { key: 'confidence', header: 'Confidence', render: (m) => <span className="text-[11px] tabular-nums">{m.confidence ?? '—'}</span>, sort: (m) => m.confidence ?? -1, hideBelow: 'lg' },
        { key: 'last', header: 'Last matched', render: (m) => <span className="text-[11px] text-foreground-muted whitespace-nowrap">{fmtWat(m.last_matched_at)}</span>, sort: (m) => m.last_matched_at },
    ];
    return (
        <div className="space-y-2">
            <DataTable rows={items} columns={columns} rowKey={(m) => m.match_id} caption="Indicator matches, by relevance tier" initialSort={{ key: 'tier', dir: 'asc' }}
                onRowClick={(m) => { const href = entityHref(m); if (href) window.location.href = href; }}
                empty={<p className="text-xs text-foreground-muted py-6 text-center">No current match combines real evidence of exposure strongly enough to flag.</p>} />
            <p className="text-[11px] text-foreground-muted">The report ranks by combined evidence of exposure — never an invented score. See each match&apos;s reasons on the <a href={findingsPath} className="text-blue hover:underline">Organisation Matches</a> page.</p>
        </div>
    );
}
