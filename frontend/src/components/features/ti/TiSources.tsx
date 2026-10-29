'use client';

// Threat Intelligence — Sources & Intelligence Exchange (phase P25, split for the frontend
// redesign). Intelligence providers, dataset coverage, feed update history, TLP markings, the
// TAXII 2.1 exchange and source documentation — what any intel:read user needs day to day.
// Raw per-run error text, retry/backfill controls, the on-demand MISP capability check, the
// correlation engine's internal state, and TAXII client credential management now live at
// Sources Operations (manager/super_admin only) — see TiSourcesOperations.tsx. A feed never shows
// as connected/healthy here if the backend reports it failing or stale; see the Freshness badge.
import { useState } from 'react';
import Link from 'next/link';
import { Radio, Copy, Download, Settings2 } from 'lucide-react';
import { PageHeader, ErrorState, btn, nf } from '@/components/features/vms/kit';
import { Card, SectionTitle, Skeleton, StatusPill } from '@/components/features/vms/ui';
import { DataTable, type Column } from '@/components/features/vms/table';
import { BarList } from '@/components/features/vms/charts';
import { useVmsData, useVmsCan } from '@/components/features/vms/data';
import { apiFetch, apiUrl } from '@/lib/api';
import { Freshness, Field } from './common';
import { FEED_NAME, ago, TLP_LABEL, type TiSources as Sources, type TiFeed, type Tlp } from '@/lib/ti';

const copy = (s: string) => { void navigator.clipboard?.writeText(s); };

export function TiSources() {
    const src = useVmsData<Sources>('/api/ti/sources');
    const can = useVmsCan();
    const now = src.at ?? 0;
    const d = src.data;
    const [msg, setDlMsg] = useState<string | null>(null);

    async function download(collection: string, ceiling: 'clear' | 'green' | 'amber') {
        try {
            const r = await apiFetch(apiUrl(`/api/ti/export/stix?collection=${collection}&ceiling=${ceiling}`));
            if (!r.ok) { const e = await r.json().catch(() => null); setDlMsg(e?.error ?? `HTTP ${r.status}`); return; }
            const blob = await r.blob();
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = `novrsoc-${collection}-${ceiling}.json`;
            a.click();
            URL.revokeObjectURL(a.href);
            if (r.headers.get('X-NovrSOC-Truncated') === 'true') setDlMsg('The bundle holds the first 5,000 objects; use TAXII for the full collection.');
        } catch { setDlMsg('Could not reach the backend'); }
    }

    const feedCols: Column<TiFeed & { retired?: boolean }>[] = [
        { key: 'name', header: 'Source', render: (f) => <span className="text-xs font-semibold">{FEED_NAME[f.id] ?? f.name}</span>, sort: (f) => f.id },
        { key: 'state', header: 'State', render: (f) => <Freshness lastSuccess={f.last_success_at} stale={f.stale} failing={f.failing} configured={f.configured} retired={f.retired} enabled={f.enabled} now={now} /> },
        { key: 'last', header: 'Last update', render: (f) => <span className="text-[11px] text-foreground-muted" title={f.last_run_at ?? ''}>{ago(f.last_run_at, now)}</span>, hideBelow: 'md' },
        { key: 'counts', header: 'Coverage', render: (f) => f.last_counts ? <span className="text-[11px] text-foreground-muted tabular-nums">{f.last_counts.fetched} fetched · {f.last_counts.new} new · {f.last_counts.updated} updated</span> : <span className="text-[11px] text-foreground-muted">—</span>, hideBelow: 'lg' },
    ];

    return (
        <div className="space-y-5">
            <PageHeader title="Sources & Intelligence Exchange" icon={Radio}
                description="Where the intelligence comes from, how fresh it is, how it is marked, and how partners receive it over TAXII 2.1."
                actions={can.scope ? <Link href="/admin/ti/sources/operations" className={btn('secondary')}><Settings2 className="w-3.5 h-3.5" /> Operations</Link> : undefined} />
            {msg && <p className="text-xs text-red font-semibold" role="alert">{msg}</p>}
            {src.load.state === 'error' ? <ErrorState error={src.load.error} status={src.load.status} onRetry={src.reload} /> : !d ? <Skeleton className="h-64" /> : (
                <>
                    <Card>
                        <SectionTitle title="Intelligence providers" hint="Updates every 6 hours (known-exploited vulnerabilities daily)" />
                        <DataTable caption="Intelligence providers" rows={d.feeds} columns={feedCols} rowKey={(f) => f.id} />
                    </Card>

                    <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
                        <Card>
                            <SectionTitle title="Enrichment coverage" />
                            <dl className="grid grid-cols-1 gap-3">
                                <Field label="NVD (CVSS, descriptions)">{d.enrichment.nvd.last_fetch ? `${ago(d.enrichment.nvd.last_fetch, now)} · ${nf.format(d.enrichment.nvd.cves_tracked)} CVEs tracked` : 'never fetched'}</Field>
                                <Field label="EPSS (FIRST)">{d.enrichment.epss.last_fetch ? ago(d.enrichment.epss.last_fetch, now) : 'never fetched'}</Field>
                            </dl>
                        </Card>
                        <Card>
                            <SectionTitle title="Threat Intelligence Feed" />
                            <dl className="grid grid-cols-2 gap-3">
                                <Field label="Connection">{d.misp.configured ? 'configured' : 'not configured'}</Field>
                                <Field label="Writes from NovrSOC">{d.misp.writes_enabled ? <span className="text-orange font-semibold">enabled</span> : 'off (read-only)'}</Field>
                            </dl>
                        </Card>
                        <Card>
                            <SectionTitle title="AI analyst" />
                            <dl className="grid grid-cols-2 gap-3">
                                <Field label="Provider">{d.ai.provider === 'ollama' ? 'Self-hosted AI Engine' : 'AI Analyst Engine (external)'}</Field>
                                <Field label="State">{d.ai.configured ? (d.ai.reachable ? <StatusPill tone="good" label="Reachable" /> : <StatusPill tone="critical" label="Unreachable" />) : <StatusPill tone="neutral" label="Not configured" />}</Field>
                            </dl>
                            <p className="text-[11px] text-foreground-muted mt-2">{d.ai.provider === 'ollama' ? 'The platform\'s own model may read records up to TLP:AMBER+STRICT; never TLP:RED.' : 'An external provider receives only TLP:CLEAR and TLP:GREEN records.'}</p>
                        </Card>
                    </div>

                    <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
                        <Card>
                            <SectionTitle title="Source records by marking" hint="Exports carry only what the marking allows" />
                            <BarList label="Source records by TLP" items={(Object.keys(TLP_LABEL) as Tlp[]).map((t) => ({ key: t, label: TLP_LABEL[t], value: d.sharing.source_records_by_tlp[t] ?? 0, token: t === 'red' ? '--vz-critical' : t === 'amber' || t === 'amber+strict' ? '--vz-warning' : t === 'green' ? '--vz-good' : '--vz-neutral' }))} />
                        </Card>
                        <Card className="xl:col-span-2">
                            <SectionTitle title="TAXII 2.1 exchange" hint="Read-only, per-client credentials, shared intelligence only" />
                            <dl className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                                <Field label="Discovery"><span className="font-mono">{d.exchange.taxii_discovery}</span> <button type="button" className={btn('ghost')} onClick={() => copy(d.exchange.taxii_discovery)} aria-label="Copy discovery URL"><Copy className="w-3 h-3" /></button></Field>
                                <Field label="API root"><span className="font-mono">{d.exchange.api_root}</span></Field>
                            </dl>
                            <ul className="mt-3 space-y-2">
                                {d.exchange.collections.map((c) => (
                                    <li key={c.id} className="rounded-xl border border-border p-3">
                                        <div className="flex flex-wrap items-center justify-between gap-2">
                                            <p className="text-xs font-semibold">{c.title} <span className="font-mono text-[10px] text-foreground-muted">{c.id}</span></p>
                                            <span className="flex gap-1">
                                                {(['clear', 'green'] as const).map((t) => <button key={t} type="button" className={btn('secondary')} disabled={!can.manage} onClick={() => void download(c.alias, t)} title={`STIX 2.1 bundle at ${TLP_LABEL[t]}`}><Download className="w-3.5 h-3.5" /> {TLP_LABEL[t]}</button>)}
                                            </span>
                                        </div>
                                        <p className="text-[11px] text-foreground-muted mt-1">{c.description}</p>
                                    </li>
                                ))}
                            </ul>
                            <details className="mt-3 text-[11px] text-foreground-muted">
                                <summary className="cursor-pointer font-semibold text-foreground">Connecting a consumer</summary>
                                <div className="mt-2 space-y-1.5">
                                    <p>Use any TAXII 2.1 client with HTTP Basic authentication: the username and password issued by a manager (Sources Operations). Every request needs <span className="font-mono">Accept: application/taxii+json;version=2.1</span>.</p>
                                    <pre className="rounded-lg bg-card-muted p-2 overflow-x-auto font-mono text-[10px]">{`from taxii2client.v21 import Server, as_pages
server = Server("${d.exchange.taxii_discovery}", user="<username>", password="<password>")
col = server.default.collections[0]
for page in as_pages(col.get_objects, per_request=100, added_after="2026-01-01T00:00:00Z"):
    ...`}</pre>
                                    <p>Poll with <span className="font-mono">added_after</span> set to the last <span className="font-mono">X-TAXII-Date-Added-Last</span> you received: changed objects come back with a new version. Collections are read-only.</p>
                                </div>
                            </details>
                        </Card>
                    </div>
                </>
            )}
        </div>
    );
}
