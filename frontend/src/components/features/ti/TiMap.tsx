'use client';

// Nigeria Threat Map (phase P25). Three layers, each saying what it is:
//   • Reported targeting — source reports that explicitly tag Nigeria as a target, and Nigerian
//     advisories. No source states a state, so they are listed for the country, never placed on one.
//   • Nigeria-hosted infrastructure — where indicator addresses are hosted. A state is shaded only
//     when the location provider named it; the rest are listed as "state unknown".
//   • Your exposure — this organisation's matches on Nigeria-hosted indicators.
// Hosting is never an attack origin or target. No coordinates, no attack counts, nothing fabricated.

import { useMemo, useState } from 'react';
import Link from 'next/link';
import { Map as MapIcon } from 'lucide-react';
import { PageHeader, EmptyState, ErrorState, Segmented, Select, Drawer, Tag, btn, nf } from '@/components/features/vms/kit';
import { Card, SectionTitle, Skeleton } from '@/components/features/vms/ui';
import { useVmsData } from '@/components/features/vms/data';
import { fmtWat } from '@/lib/vms';
import { NigeriaStateMap } from './NigeriaStateMap';
import { TlpBadge, Field, Limitations } from './common';
import { ago, type MapData, type MapTargeting } from '@/lib/ti';

type Layer = 'hosted' | 'exposure';
const DAYS = [['7', '7 days'], ['30', '30 days'], ['90', '90 days']] as const;

export function TiMap() {
    const [days, setDays] = useState<'7' | '30' | '90'>('30');
    const [sector, setSector] = useState('');
    const [layer, setLayer] = useState<Layer>('hosted');
    const [state, setState] = useState<string | null>(null);
    const [report, setReport] = useState<MapTargeting | null>(null);
    const { load, data, reload, at } = useVmsData<MapData>(`/api/ti/map?days=${days}${sector ? `&sector=${encodeURIComponent(sector)}` : ''}`);
    const now = at ?? 0;
    // NigeriaStateMap corrects the path file's "Nassarawa" to this map's "Nasarawa" internally,
    // so the keys here stay exactly what the backend sends.
    const counts = useMemo(() => new Map((data?.states ?? []).map((s) => [s.state, layer === 'hosted' ? s.hosted : s.exposure])), [data, layer]);
    const inState = (s: string) => ({ hosted: (data?.hosted ?? []).filter((h) => h.state === s), exposure: (data?.exposure ?? []).filter((e) => e.state === s) });

    return (
        <div className="space-y-5">
            <PageHeader title="Nigeria Threat Map" icon={MapIcon}
                description="Reported targeting of Nigeria, indicator infrastructure hosted in Nigeria, and this organisation's exposure to it. Hosting is where an address is hosted — not where an attack came from."
                actions={<>
                    <Segmented label="Period" value={days} onChange={setDays} options={DAYS} />
                    <Select label="Sector" value={sector} onChange={setSector} options={[['', 'All sectors'], ...(data?.sectors ?? []).map((s) => [s, s] as const)]} />
                </>} />

            {load.state === 'error' ? <ErrorState error={load.error} status={load.status} onRetry={reload} /> : (
                <div className="grid grid-cols-1 xl:grid-cols-5 gap-4">
                    <Card className="xl:col-span-3">
                        <SectionTitle title="By state" hint={layer === 'hosted' ? 'Active indicators hosted in each state, where the location provider named the state' : 'Your matches on indicators hosted in each state'}
                            action={<Segmented label="Layer" value={layer} onChange={(v) => { setLayer(v); setState(null); }} options={[['hosted', 'Hosted infrastructure'], ['exposure', 'Your exposure']] as const} />} />
                        {load.state === 'loading' ? <Skeleton className="h-[420px]" /> : (
                            <>
                                <NigeriaStateMap counts={counts} layer={layer} selected={state} onSelect={setState} />
                                <div className="grid grid-cols-2 gap-3 mt-3">
                                    <div className="rounded-xl border border-border p-3"><p className="text-[11px] text-foreground-muted">Hosted in Nigeria, state unknown</p><p className="text-lg font-black tabular-nums">{nf.format(data!.country_level.hosted_state_unknown)}</p></div>
                                    <div className="rounded-xl border border-border p-3"><p className="text-[11px] text-foreground-muted">Your exposure, state unknown</p><p className="text-lg font-black tabular-nums">{nf.format(data!.country_level.exposure_state_unknown)}</p></div>
                                </div>
                            </>
                        )}
                    </Card>

                    <Card className="xl:col-span-2">
                        <SectionTitle title="Reported targeting of Nigeria" hint="Country level — sources tag Nigeria, not a state" />
                        {load.state === 'loading' ? <Skeleton className="h-64" /> : data!.targeting.length ? (
                            <ul className="divide-y divide-border max-h-[560px] overflow-y-auto">
                                {data!.targeting.map((t) => (
                                    <li key={`${t.kind}:${t.id}`}>
                                        <button type="button" onClick={() => setReport(t)} className="w-full text-left py-2.5 px-1 hover:bg-card-muted rounded-lg outline-none focus-visible:ring-2 focus-visible:ring-purple/60">
                                            <div className="flex items-start justify-between gap-2">
                                                <p className="text-xs font-semibold text-foreground">{t.title}</p>
                                                <TlpBadge tlp={t.tlp} />
                                            </div>
                                            <p className="text-[11px] text-foreground-muted mt-0.5">
                                                {t.kind === 'advisory' ? 'Advisory' : 'Source report'} · {t.source} · <span title={t.published_at ? fmtWat(t.published_at) : ''}>{ago(t.published_at, now)}</span>
                                            </p>
                                            <p className="text-[11px] mt-1"><span className="text-foreground-muted">Attribution: </span><span className="text-foreground">{t.actors.length ? `${t.actors.join(', ')} (named by the source)` : 'none stated'}</span></p>
                                        </button>
                                    </li>
                                ))}
                            </ul>
                        ) : (
                            <EmptyState compact title="No reported targeting in this period"
                                body={data!.setup.reports_table ? 'No source tagged Nigeria as a target, and no Nigerian advisory was published.' : 'Source reports are not set up yet (run sql/2026-10-30_p25_ti_v1.sql).'} />
                        )}
                        {data && <Limitations items={data.limitations} />}
                    </Card>
                </div>
            )}

            {data && (
                <Card>
                    <SectionTitle title="Nigeria-hosted infrastructure, state unknown" hint="Hosted in Nigeria per the source or a GeoIP lookup that gave no state" />
                    {data.hosted.filter((h) => !h.state).length ? (
                        <div className="flex flex-wrap gap-1.5">
                            {data.hosted.filter((h) => !h.state).slice(0, 80).map((h) => (
                                <Link key={h.indicator_id} href={`/admin/ti/indicators?id=${h.indicator_id}`} className="font-mono text-[11px] rounded-md border border-border px-1.5 py-0.5 hover:border-purple/50" title={`${h.method === 'source_stated' ? `Stated by ${h.provider}` : `GeoIP (${h.provider})`}`}>{h.value}</Link>
                            ))}
                        </div>
                    ) : <EmptyState compact title="None" body="Every Nigeria-hosted indicator in this period has a known state, or there are none." />}
                </Card>
            )}

            <Drawer open={!!state} onClose={() => setState(null)} title={state ?? ''} subtitle={`Last ${days} days`}>
                {state && (() => {
                    const { hosted, exposure } = inState(state);
                    return (
                        <div className="space-y-5">
                            <section>
                                <h3 className="text-xs font-bold text-foreground mb-2">Your exposure ({exposure.length})</h3>
                                {exposure.length ? (
                                    <ul className="divide-y divide-border">{exposure.map((e) => (
                                        <li key={e.match_id} className="py-2 text-xs flex justify-between gap-2">
                                            <Link href={`/admin/ti/indicators?id=${e.indicator_id}`} className="font-mono font-semibold hover:text-purple">{e.value}</Link>
                                            <span className="text-foreground-muted">seen in {e.entity_type} · {e.matched_field}</span>
                                        </li>
                                    ))}</ul>
                                ) : <p className="text-[11px] text-foreground-muted">None of this organisation&apos;s records matched infrastructure hosted in {state}.</p>}
                            </section>
                            <section>
                                <h3 className="text-xs font-bold text-foreground mb-2">Hosted infrastructure ({hosted.length})</h3>
                                {hosted.length ? (
                                    <ul className="divide-y divide-border">{hosted.map((h) => (
                                        <li key={h.indicator_id} className="py-2 text-xs">
                                            <div className="flex justify-between gap-2"><Link href={`/admin/ti/indicators?id=${h.indicator_id}`} className="font-mono font-semibold hover:text-purple break-all">{h.value}</Link><span className="text-foreground-muted shrink-0">{ago(h.last_seen, now)}</span></div>
                                            <p className="text-[11px] text-foreground-muted mt-0.5">{h.as_org ?? h.asn ?? 'Network unknown'} · located by {h.method === 'source_stated' ? h.provider : `GeoIP (${h.provider})`}{h.malware.length ? ` · ${h.malware.join(', ')}` : ''}</p>
                                        </li>
                                    ))}</ul>
                                ) : <p className="text-[11px] text-foreground-muted">No active indicator is known to be hosted in {state} in this period.</p>}
                            </section>
                            <p className="text-[11px] text-foreground-muted">Hosting location is approximate and describes where an address is hosted. It is not evidence of an attack on or from {state}.</p>
                        </div>
                    );
                })()}
            </Drawer>

            <Drawer open={!!report} onClose={() => setReport(null)} title={report?.title ?? ''} subtitle={report ? `${report.kind === 'advisory' ? 'Advisory' : 'Source report'} · ${report.source}` : ''}>
                {report && (
                    <div className="space-y-4">
                        <dl className="grid grid-cols-2 gap-3">
                            <Field label="Marking"><TlpBadge tlp={report.tlp} /></Field>
                            <Field label="Published">{report.published_at ? fmtWat(report.published_at) : 'not stated'}</Field>
                            <Field label="Basis">{report.basis}</Field>
                            <Field label="Location">Nigeria (no state stated)</Field>
                            <Field label="Attribution">{report.actors.length ? `${report.actors.join(', ')} — named by the source, not confirmed by NovrSOC` : 'none stated'}</Field>
                            <Field label="Source reference"><span className="font-mono">{report.source_ref}</span></Field>
                        </dl>
                        {report.sectors.length > 0 && <div><p className="text-[10px] font-bold uppercase tracking-wider text-foreground-muted mb-1">Sectors the source tagged</p><div className="flex flex-wrap gap-1">{report.sectors.map((s) => <Tag key={s}>{s}</Tag>)}</div></div>}
                        {report.malware.length > 0 && <div><p className="text-[10px] font-bold uppercase tracking-wider text-foreground-muted mb-1">Malware the source tagged</p><div className="flex flex-wrap gap-1">{report.malware.map((s) => <Tag key={s}>{s}</Tag>)}</div></div>}
                        {report.url && <a href={report.url} target="_blank" rel="noopener noreferrer" className={btn('secondary')}>Open the source</a>}
                    </div>
                )}
            </Drawer>
        </div>
    );
}
