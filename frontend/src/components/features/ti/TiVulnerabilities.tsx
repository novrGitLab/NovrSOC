'use client';

// Threat Intelligence — Vulnerabilities & Advisories (phase P25). The CISA Known Exploited
// Vulnerabilities catalogue with NVD scoring and FIRST EPSS shown separately (never blended into
// one number), CISA's due date and ransomware status as CISA states them, and whether this
// organisation has open findings for each CVE. Nigerian advisories are listed beside them.

import { useState } from 'react';
import Link from 'next/link';
import { ShieldAlert, ExternalLink } from 'lucide-react';
import { PageHeader, EmptyState, ErrorState, Segmented, SearchBox, Toggle, Tag, Drawer, btn } from '@/components/features/vms/kit';
import { Card, SectionTitle, StatusPill } from '@/components/features/vms/ui';
import { DataTable, type Column } from '@/components/features/vms/table';
import { useVmsData } from '@/components/features/vms/data';
import { fmtWat } from '@/lib/vms';
import { Pager, Field, Citation } from './common';
import { ago, type TiVulnerability, type TiAdvisory } from '@/lib/ti';

const PERIODS = [['30', '30 days'], ['90', '90 days'], ['365', '1 year'], ['0', 'All']] as const;

export function TiVulnerabilities() {
    const [days, setDays] = useState<'30' | '90' | '365' | '0'>('90');
    const [q, setQ] = useState('');
    const [ransomware, setRansomware] = useState(false);
    const [page, setPage] = useState(1);
    const [open, setOpen] = useState<TiVulnerability | null>(null);
    const qs = new URLSearchParams({ days, page: String(page), page_size: '50' });
    if (q) qs.set('q', q); if (ransomware) qs.set('ransomware', 'known');
    const { load, data, reload, at } = useVmsData<{ total: number; vulnerabilities: TiVulnerability[]; advisories: TiAdvisory[] | null }>(`/api/ti/vulnerabilities?${qs}`);
    const advisories = useVmsData<{ total: number; vulnerabilities: TiVulnerability[]; advisories: TiAdvisory[] | null }>('/api/ti/vulnerabilities?page=1&page_size=1');
    const now = at ?? 0;
    const due = (v: TiVulnerability) => v.kev.due_date ? Date.parse(v.kev.due_date) : null;

    const columns: Column<TiVulnerability>[] = [
        { key: 'cve', header: 'CVE', render: (v) => <span className="font-mono text-xs font-semibold">{v.cve}</span> },
        { key: 'product', header: 'Product', render: (v) => <span className="text-xs">{[v.kev.vendor, v.kev.product].filter(Boolean).join(' ') || '—'}</span>, hideBelow: 'sm' },
        { key: 'cvss', header: 'CVSS (NVD)', render: (v) => <span className="tabular-nums text-xs" title={v.nvd?.cvss_version ? `CVSS ${v.nvd.cvss_version}` : ''}>{v.nvd?.cvss_score ?? 'not scored'}</span>, hideBelow: 'md' },
        { key: 'epss', header: 'EPSS', render: (v) => <span className="tabular-nums text-xs" title="Probability of exploitation in the next 30 days (FIRST EPSS)">{v.nvd?.epss_score !== null && v.nvd?.epss_score !== undefined ? `${(v.nvd.epss_score * 100).toFixed(1)}%` : '—'}</span>, hideBelow: 'md' },
        { key: 'ransom', header: 'Ransomware', render: (v) => String(v.kev.ransomware ?? '').toLowerCase() === 'known' ? <StatusPill tone="critical" label="Known use" /> : <span className="text-[11px] text-foreground-muted">{v.kev.ransomware ?? 'unknown'}</span>, hideBelow: 'lg' },
        { key: 'due', header: 'CISA due', render: (v) => <span className="text-[11px] text-foreground-muted">{v.kev.due_date ?? '—'}</span>, hideBelow: 'lg' },
        { key: 'yours', header: 'Your open findings', render: (v) => v.your_open_findings ? <Tag strong>{v.your_open_findings}</Tag> : <span className="text-[11px] text-foreground-muted">none</span> },
        { key: 'added', header: 'Listed', render: (v) => <span className="text-[11px] text-foreground-muted" title={fmtWat(v.added)}>{ago(v.added, now)}</span> },
    ];

    return (
        <div className="space-y-5">
            <PageHeader title="Vulnerabilities & Advisories" icon={ShieldAlert}
                description="Vulnerabilities known to be exploited (CISA KEV) with NVD and EPSS context, matched against this organisation's open findings, and Nigerian security advisories."
                actions={<Segmented label="Listed within" value={days} onChange={(v) => { setDays(v); setPage(1); }} options={PERIODS} />} />

            <Card>
                <div className="flex flex-wrap items-end gap-2 mb-3">
                    <div className="flex-1 min-w-[220px]"><SearchBox label="Search vulnerabilities" value={q} onSubmit={(v) => { setQ(v); setPage(1); }} placeholder="CVE, vendor, product or name" /></div>
                    <Toggle on={ransomware} onChange={(v) => { setRansomware(v); setPage(1); }}>Known ransomware use</Toggle>
                </div>
                {load.state === 'error' ? <ErrorState error={load.error} status={load.status} onRetry={reload} /> : (
                    <>
                        <DataTable caption="Known exploited vulnerabilities" rows={data?.vulnerabilities ?? null} columns={columns} rowKey={(v) => v.cve} pageSize={50} onRowClick={setOpen}
                            empty={<EmptyState title="Nothing listed" body="No KEV entry matches. If the catalogue is empty, check the CISA KEV feed on the Sources page." />} />
                        {data && data.total > 0 && <Pager page={page} pageSize={50} total={data.total} onPage={setPage} />}
                    </>
                )}
            </Card>

            <Card>
                <SectionTitle title="Nigerian advisories" hint="As published by the source; not confirmed incidents" />
                {advisories.load.state === 'error' ? <ErrorState error={advisories.load.error} status={advisories.load.status} onRetry={advisories.reload} /> : (advisories.data?.advisories ?? []).length ? (
                    <ul className="divide-y divide-border">
                        {advisories.data!.advisories!.slice(0, 20).map((a) => (
                            <li key={a.advisory_id} className="py-2.5 flex items-start justify-between gap-3">
                                <div className="min-w-0">
                                    <p className="text-xs font-semibold text-foreground">{a.title}</p>
                                    <p className="text-[11px] text-foreground-muted mt-0.5">{a.source}{a.threat_type ? ` · ${a.threat_type}` : ''}{a.severity ? ` · severity ${a.severity} (as published)` : ''} · {a.published_at ? fmtWat(a.published_at) : 'undated'}</p>
                                </div>
                                {a.source_url && <a href={a.source_url} target="_blank" rel="noopener noreferrer" className={btn('ghost')} aria-label={`Open ${a.title}`}><ExternalLink className="w-3.5 h-3.5" /></a>}
                            </li>
                        ))}
                    </ul>
                ) : <EmptyState compact title="No advisories collected" body="No Nigerian advisory has been collected yet. The collector reads ngCERT and NITDA where they are reachable." />}
            </Card>

            <Drawer open={!!open} onClose={() => setOpen(null)} title={open?.cve ?? ''} subtitle={open ? [open.kev.vendor, open.kev.product].filter(Boolean).join(' ') : ''}>
                {open && (
                    <div className="space-y-4">
                        <p className="text-xs text-foreground">{open.kev.name ?? ''}</p>
                        {open.nvd?.description && <p className="text-[11px] text-foreground-muted leading-relaxed">{open.nvd.description}</p>}
                        <dl className="grid grid-cols-2 gap-3">
                            <Field label="CVSS (NVD)">{open.nvd?.cvss_score ?? 'not scored'}{open.nvd?.cvss_version ? ` (v${open.nvd.cvss_version})` : ''}</Field>
                            <Field label="EPSS (FIRST)">{open.nvd?.epss_score !== null && open.nvd?.epss_score !== undefined ? `${(open.nvd.epss_score * 100).toFixed(2)}% · percentile ${((open.nvd.epss_percentile ?? 0) * 100).toFixed(0)}` : 'not available'}</Field>
                            <Field label="CISA required action">{open.kev.required_action ?? '—'}</Field>
                            <Field label="CISA due date">{open.kev.due_date ?? '—'}{due(open) && due(open)! < now ? ' (passed)' : ''}</Field>
                            <Field label="Known ransomware use (CISA)">{open.kev.ransomware ?? 'unknown'}</Field>
                            <Field label="Listed"><Citation feed="cisa_kev" at={open.added} now={now} /></Field>
                        </dl>
                        <section>
                            <h3 className="text-xs font-bold mb-1.5">In this organisation</h3>
                            {open.your_open_findings ? (
                                <p className="text-xs">{open.your_open_findings} open finding(s) on {open.your_assets.join(', ')}. <Link href={`/admin/vms/findings?q=${open.cve}`} className="text-purple hover:underline">Open in VMS</Link></p>
                            ) : <p className="text-[11px] text-foreground-muted">No open vulnerability finding for this CVE.</p>}
                        </section>
                        <a href={`https://nvd.nist.gov/vuln/detail/${open.cve}`} target="_blank" rel="noopener noreferrer" className={btn('secondary')}>NVD record <ExternalLink className="w-3.5 h-3.5" /></a>
                    </div>
                )}
            </Drawer>
        </div>
    );
}
