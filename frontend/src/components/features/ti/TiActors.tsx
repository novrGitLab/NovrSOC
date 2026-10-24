'use client';

// Threat Intelligence — Threat Actors (phase P25). Two different kinds of information, kept apart:
//   • the reference library: profiles summarising public reporting, each with its publisher and a
//     link — reference material, not NovrSOC telemetry;
//   • source mentions: MISP events that attached a threat-actor tag — the source's attribution.
// Nothing here attributes an indicator or an incident to an actor on the platform's own authority.

import { useMemo, useState } from 'react';
import { Users, ExternalLink } from 'lucide-react';
import { PageHeader, EmptyState, ErrorState, Segmented, SearchBox, Drawer, Tag, btn } from '@/components/features/vms/kit';
import { Card, SectionTitle, Skeleton } from '@/components/features/vms/ui';
import { DataTable, type Column } from '@/components/features/vms/table';
import { useVmsData } from '@/components/features/vms/data';
import { fmtWat } from '@/lib/vms';
import { Field } from './common';
import { ago, type TiActor, type SourceNamedActor } from '@/lib/ti';

type Focus = 'all' | 'nigeria' | 'global';

export function TiActors() {
    const { load, data, reload, at } = useVmsData<{ actors: TiActor[]; source_named: SourceNamedActor[]; notes: string[] }>('/api/ti/actors');
    const [focus, setFocus] = useState<Focus>('nigeria');
    const [q, setQ] = useState('');
    const [open, setOpen] = useState<TiActor | null>(null);
    const now = at ?? 0;
    const actors = useMemo(() => (data?.actors ?? []).filter((a) => (focus === 'all' || a.focus === focus) && (!q || [a.name, ...a.aliases, ...a.targeted_sectors, a.origin].some((s) => s.toLowerCase().includes(q.toLowerCase())))), [data, focus, q]);
    const named: Column<SourceNamedActor>[] = [
        { key: 'name', header: 'Actor (as the source named it)', render: (r) => <span className="text-xs font-semibold">{r.name}</span>, sort: (r) => r.name },
        { key: 'count', header: 'Reports', render: (r) => <span className="tabular-nums text-xs">{r.count}</span>, sort: (r) => r.count },
        { key: 'ng', header: 'Tagging Nigeria as target', render: (r) => <span className="tabular-nums text-xs">{r.nigeria}</span>, sort: (r) => r.nigeria },
        { key: 'last', header: 'Last mentioned', render: (r) => <span className="text-[11px] text-foreground-muted" title={r.last ? fmtWat(r.last) : ''}>{ago(r.last, now)}</span>, sort: (r) => r.last ?? '' },
    ];

    return (
        <div className="space-y-5">
            <PageHeader title="Threat Actors" icon={Users}
                description="Profiles summarising public reporting, and the actors partner sources have named in their reports. Neither is NovrSOC's own attribution."
                actions={<Segmented label="Focus" value={focus} onChange={setFocus} options={[['nigeria', 'Nigeria / West Africa'], ['global', 'Global'], ['all', 'All']] as const} />} />

            {load.state === 'error' ? <ErrorState error={load.error} status={load.status} onRetry={reload} /> : (
                <>
                    <Card>
                        <div className="flex flex-wrap items-end justify-between gap-2 mb-3">
                            <SectionTitle title="Reference library" hint="Each profile cites its publisher" />
                            <div className="w-full sm:w-72"><SearchBox label="Search actors" value={q} onSubmit={setQ} placeholder="Name, alias, sector or origin" /></div>
                        </div>
                        {load.state === 'loading' ? <Skeleton className="h-48" /> : actors.length ? (
                            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
                                {actors.map((a) => (
                                    <button key={a.id} type="button" onClick={() => setOpen(a)} className="text-left rounded-2xl border border-border p-4 hover:border-purple/40 outline-none focus-visible:ring-2 focus-visible:ring-purple/60">
                                        <div className="flex items-start justify-between gap-2">
                                            <div className="min-w-0"><p className="text-sm font-bold text-foreground">{a.name}</p><p className="text-[11px] text-foreground-muted truncate">{a.aliases.slice(0, 3).join(', ') || 'no aliases'}</p></div>
                                            <Tag>{a.motivation}</Tag>
                                        </div>
                                        <p className="text-[11px] text-foreground-muted mt-2 line-clamp-3">{a.description}</p>
                                        <div className="flex flex-wrap gap-1 mt-2">{a.targeted_sectors.slice(0, 4).map((s) => <Tag key={s}>{s}</Tag>)}</div>
                                        <p className="text-[11px] mt-2.5 text-foreground-muted">
                                            {a.source_mentions.count ? <span className="text-foreground font-semibold">Named in {a.source_mentions.count} source report(s), last {ago(a.source_mentions.last, now)}</span> : 'Not named in any source report in the last year'}
                                        </p>
                                        <p className="text-[10px] mt-1 text-foreground-muted">Profile: {a.reference}</p>
                                    </button>
                                ))}
                            </div>
                        ) : <EmptyState title="No profiles match" body="Try another search or focus." />}
                        {data && <ul className="mt-3 space-y-0.5 text-[11px] text-foreground-muted list-disc pl-4">{data.notes.map((n) => <li key={n}>{n}</li>)}</ul>}
                    </Card>

                    <Card>
                        <SectionTitle title="Named by sources, no library profile" hint="Threat-actor tags on partner reports in the last year — the source's attribution" />
                        <DataTable caption="Actors named by sources" rows={data?.source_named ?? null} columns={named} rowKey={(r) => r.name} initialSort={{ key: 'count', dir: 'desc' }}
                            empty={<EmptyState compact title="None" body="No partner report named an actor outside the library (or MISP event reports have not been collected yet)." />} />
                    </Card>
                </>
            )}

            <Drawer open={!!open} onClose={() => setOpen(null)} title={open?.name ?? ''} subtitle={open ? `${open.origin} · ${open.motivation}` : ''}>
                {open && (
                    <div className="space-y-5">
                        <p className="text-xs text-foreground leading-relaxed">{open.description}</p>
                        <dl className="grid grid-cols-2 gap-3">
                            <Field label="Aliases">{open.aliases.join(', ') || 'none'}</Field>
                            <Field label="Targeted regions (reported)">{open.targeted_regions.join(', ')}</Field>
                            <Field label="Targeted sectors (reported)">{open.targeted_sectors.join(', ')}</Field>
                            <Field label="Last active (reported)">{open.last_active}</Field>
                        </dl>
                        <section>
                            <h3 className="text-xs font-bold mb-1.5">Documented impact</h3>
                            <p className="text-xs text-foreground-muted">{open.damage}</p>
                        </section>
                        {open.known_incidents.length > 0 && (
                            <section>
                                <h3 className="text-xs font-bold mb-1.5">Publicly reported incidents</h3>
                                <ul className="space-y-2">{open.known_incidents.map((k) => <li key={`${k.year}${k.title}`} className="text-xs"><span className="font-semibold">{k.year} — {k.title}.</span> <span className="text-foreground-muted">{k.description} (source: {k.source})</span></li>)}</ul>
                            </section>
                        )}
                        {open.techniques.length > 0 && (
                            <section>
                                <h3 className="text-xs font-bold mb-1.5">ATT&CK techniques (reported)</h3>
                                <div className="flex flex-wrap gap-1">{open.techniques.map((t) => <Tag key={t.id} title={t.name}>{t.id} {t.name}</Tag>)}</div>
                            </section>
                        )}
                        <section>
                            <h3 className="text-xs font-bold mb-1.5">Source reports naming this actor ({open.source_mentions.count})</h3>
                            {open.source_mentions.reports.length ? (
                                <ul className="space-y-1">{open.source_mentions.reports.map((r) => <li key={r.id} className="text-xs">{r.title} <span className="text-foreground-muted">· {r.published_at ? fmtWat(r.published_at) : 'undated'}</span></li>)}</ul>
                            ) : <p className="text-[11px] text-foreground-muted">No partner report named this actor in the last year.</p>}
                            {open.source_mentions.nigeria_targeting > 0 && <p className="text-[11px] mt-1.5">{open.source_mentions.nigeria_targeting} of them tag Nigeria as a target (the source&apos;s claim).</p>}
                        </section>
                        <a href={open.reference_url} target="_blank" rel="noopener noreferrer" className={btn('secondary')}>Read the profile source: {open.reference} <ExternalLink className="w-3.5 h-3.5" /></a>
                    </div>
                )}
            </Drawer>
        </div>
    );
}
