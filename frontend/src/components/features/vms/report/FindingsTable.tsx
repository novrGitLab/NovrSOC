'use client';

// Vulnerability Findings Table + Technical Finding Details (brief §5-6). Reuses the real
// /api/vms/findings list (search/filter already built server-side) and the real FindingDetail
// component (CVSS score/version/vector, evidence, correlations, AI analysis, status/remediation
// actions) for the drawer — the same component the main VMS Findings page uses, so the report's
// "technical view" is never a second, drifting implementation of the same data.
import { useState } from 'react';
import { useVmsData } from '../data';
import { DataTable, type Column } from '../table';
import { SearchBox, Select, SeverityBadge, PriorityBadge, RiskScore, Tag, Drawer, ErrorState } from '../kit';
import { FindingDetail, STATUS_LABEL, isOverdue } from '../FindingDetail';
import { detectorLabel } from '@/lib/vms';

interface FindingRow {
    id: string; asset_value: string; port: number | null; title: string; scanner_severity: string | null; scanner_cvss: number | null;
    risk_score: number | null; priority: string | null; status: string; cve_ids: string[]; detected_by: string[]; due_at: string | null; first_seen: string; last_seen: string;
}

const STATUS_OPTIONS = [['open_all', 'Open (all)'], ['all', 'All statuses'], ['verified', 'Verified fixed'], ['risk_accepted', 'Risk accepted']] as const;
const SEVERITY_OPTIONS = [['', 'Any severity'], ['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low'], ['info', 'Info']] as const;

export function FindingsTable() {
    const [q, setQ] = useState('');
    const [status, setStatus] = useState<typeof STATUS_OPTIONS[number][0]>('open_all');
    const [severity, setSeverity] = useState<typeof SEVERITY_OPTIONS[number][0]>('');
    const [openId, setOpenId] = useState<string | null>(null);

    const params = new URLSearchParams({ status, ...(q ? { q } : {}) });
    const { load, data, reload } = useVmsData<{ findings: FindingRow[] }>(`/api/vms/findings?${params}`);
    const rows = (data?.findings ?? []).filter((f) => !severity || f.scanner_severity === severity);

    const columns: Column<FindingRow>[] = [
        { key: 'severity', header: 'Severity', render: (f) => <SeverityBadge severity={f.scanner_severity} />, sort: (f) => f.scanner_severity ?? '' },
        { key: 'cvss', header: 'CVSS', render: (f) => <span className="font-mono text-[11px]">{f.scanner_cvss !== null ? f.scanner_cvss.toFixed(1) : '—'}</span>, sort: (f) => f.scanner_cvss ?? -1, hideBelow: 'sm' },
        { key: 'cve', header: 'CVE', render: (f) => <span className="font-mono text-[10px]">{f.cve_ids[0] ?? '—'}{f.cve_ids.length > 1 ? ` +${f.cve_ids.length - 1}` : ''}</span>, hideBelow: 'md' },
        { key: 'title', header: 'Vulnerability Title', className: 'min-w-[220px]', render: (f) => <div><p className="font-semibold text-foreground">{f.title}</p><p className="text-[10px] font-mono text-foreground-muted">{f.asset_value}{f.port ? `:${f.port}` : ''} · {f.detected_by.map(detectorLabel).join(', ')}</p></div>, sort: (f) => f.title },
        { key: 'risk', header: 'Risk', render: (f) => <RiskScore score={f.risk_score} />, sort: (f) => f.risk_score ?? -1, hideBelow: 'lg' },
        { key: 'detection', header: 'Detection Status', render: (f) => <span className="text-[11px]">{isOverdue(f, Date.now()) ? <Tag>Overdue</Tag> : STATUS_LABEL[f.status] ?? f.status}</span>, sort: (f) => f.status },
        { key: 'remediation', header: 'Remediation Status', render: (f) => <PriorityBadge priority={f.priority} />, sort: (f) => f.priority ?? 'P9', hideBelow: 'sm' },
    ];

    return (
        <div className="space-y-3">
            <div>
                <h2 className="text-sm font-black text-foreground">Vulnerability Findings</h2>
                <p className="text-[11px] text-foreground-muted">Click a finding for the full technical detail: CVSS vector, evidence, impact and remediation guidance.</p>
            </div>
            <div className="flex flex-wrap items-center gap-2 print:hidden">
                <SearchBox value={q} onSubmit={setQ} placeholder="Search title, asset or CVE…" label="Search findings" />
                <Select label="Status" value={status} onChange={(v) => setStatus(v as typeof STATUS_OPTIONS[number][0])} options={STATUS_OPTIONS as unknown as [string, string][]} />
                <Select label="Severity" value={severity} onChange={(v) => setSeverity(v as typeof SEVERITY_OPTIONS[number][0])} options={SEVERITY_OPTIONS as unknown as [string, string][]} />
            </div>
            {load.state === 'error' ? <ErrorState error={load.error} status={load.status} onRetry={reload} /> : (
                <DataTable rows={data ? rows : null} columns={columns} rowKey={(f) => f.id} onRowClick={(f) => setOpenId(f.id)} caption="Vulnerability findings"
                    initialSort={{ key: 'risk', dir: 'desc' }} empty={<p className="text-xs text-foreground-muted py-6 text-center">No findings match these filters.</p>} />
            )}
            <Drawer open={!!openId} onClose={() => setOpenId(null)} title="Finding — Technical Detail">
                {openId && <FindingDetail key={openId} id={openId} onChanged={reload} />}
            </Drawer>
        </div>
    );
}
