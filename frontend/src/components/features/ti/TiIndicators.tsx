'use client';

// Threat Intelligence — Indicators & Investigation (phase P25). Search and filter every stored
// indicator (server-side paging), then open one to investigate: what each source record said
// (with its sharing marking and whether it may be exported), where it is hosted and how that was
// established, linked indicators and source reports, where this organisation saw it, analyst
// verdicts, and AI assessment. Source claims are always shown as the source's.

import { useState } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { Fingerprint, ExternalLink, Link2 } from 'lucide-react';
import { PageHeader, EmptyState, ErrorState, Select, SearchBox, Drawer, Tag, Toggle, Notice, btn, type Msg } from '@/components/features/vms/kit';
import { Card, StatusPill, Skeleton } from '@/components/features/vms/ui';
import { DataTable, type Column } from '@/components/features/vms/table';
import { useVmsData, useVmsCan, vmsSend } from '@/components/features/vms/data';
import { AiPanel } from '@/components/shared/AiPanel';
import { fmtWat } from '@/lib/vms';
import { TlpBadge, Citation, Pager, Field } from './common';
import { VERDICT_LABEL, MATCH_STATUS_STYLE, entityHref, ago, FEED_NAME, type TiIndicator, type TiSource, type TiMatch, type TiFeedback, type TiLocation, type TiRelated, type TiReport } from '@/lib/ti';

type Row = TiIndicator & { labels_hidden?: boolean };
interface Detail { indicator: Row; sources: TiSource[]; sources_hidden: number; matches: TiMatch[]; feedback: TiFeedback[]; location: TiLocation | null }
const TYPES = [['', 'All types'], ['ip', 'IP address'], ['domain', 'Domain'], ['url', 'URL'], ['sha256', 'SHA-256'], ['sha1', 'SHA-1'], ['md5', 'MD5'], ['cve', 'CVE']] as const;
const FEEDS = [['', 'All sources'], ['threatfox', 'IOC Corroboration Feed'], ['urlhaus', 'Malicious URL Feed'], ['feodo', 'Botnet C2 Feed'], ['misp', 'Threat Intelligence Feed'], ['cisa_kev', 'CISA KEV']] as const;
const TLPS = [['', 'Any marking'], ['clear', 'TLP:CLEAR'], ['green', 'TLP:GREEN'], ['amber', 'TLP:AMBER'], ['amber+strict', 'TLP:AMBER+STRICT'], ['red', 'TLP:RED']] as const;
const SORTS = [['last_seen', 'Last seen'], ['created_at', 'Added to the platform'], ['first_seen', 'First seen'], ['source_count', 'Most sources'], ['max_confidence', 'Source confidence']] as const;

export function TiIndicators() {
    const router = useRouter();
    const params = useSearchParams();
    const [q, setQ] = useState(params.get('q') ?? '');
    const [type, setType] = useState(params.get('type') ?? '');
    const [status, setStatus] = useState(params.get('status') ?? 'active');
    const [feed, setFeed] = useState('');
    const [tlp, setTlp] = useState('');
    const [hosted, setHosted] = useState(params.get('hosted') === 'NG');
    const [matched, setMatched] = useState(params.get('matched') === 'true');
    const [sort, setSort] = useState(params.get('sort') ?? 'last_seen');
    const [page, setPage] = useState(1);
    const openId = params.get('id');
    const qs = new URLSearchParams({ page: String(page), page_size: '50', sort, dir: 'desc' });
    if (q) qs.set('q', q); if (type) qs.set('type', type); if (status) qs.set('status', status); if (feed) qs.set('feed', feed); if (tlp) qs.set('tlp', tlp);
    if (hosted) qs.set('hosted', 'NG'); if (matched) qs.set('matched', 'true');
    const list = useVmsData<{ indicators: Row[]; total: number; page: number; page_size: number }>(`/api/ti/indicators?${qs}`);
    const now = list.at ?? 0;
    const open = (id: string | null) => { const p = new URLSearchParams(params.toString()); if (id) p.set('id', id); else p.delete('id'); router.replace(`/admin/ti/indicators${p.toString() ? `?${p}` : ''}`, { scroll: false }); };
    const reset = <T,>(set: (v: T) => void) => (v: T) => { set(v); setPage(1); };

    const columns: Column<Row>[] = [
        { key: 'value', header: 'Indicator', render: (r) => <span className="font-mono text-xs font-semibold text-foreground break-all">{r.value}</span> },
        { key: 'type', header: 'Type', render: (r) => <Tag>{r.type}</Tag>, hideBelow: 'sm' },
        { key: 'status', header: 'Status', render: (r) => <StatusPill tone={r.status === 'active' ? 'serious' : 'neutral'} label={r.status === 'active' ? 'Active' : 'Expired'} /> },
        { key: 'labels', header: 'Source labels', render: (r) => r.labels_hidden ? <span className="text-[11px] text-foreground-muted">restricted</span> : <span className="text-[11px] text-foreground-muted">{[...r.malware_families, ...r.threat_types].slice(0, 3).join(', ') || '—'}</span>, hideBelow: 'md' },
        { key: 'sources', header: 'Sources', render: (r) => <span className="tabular-nums text-xs">{r.source_count}</span>, hideBelow: 'md' },
        { key: 'confidence', header: 'Source confidence', render: (r) => <span className="tabular-nums text-xs" title="The highest confidence a source itself stated">{r.max_confidence ?? 'not stated'}</span>, hideBelow: 'lg' },
        { key: 'last', header: 'Last seen', render: (r) => <span className="text-[11px] text-foreground-muted" title={fmtWat(r.last_seen)}>{ago(r.last_seen, now)}</span> },
    ];

    return (
        <div className="space-y-5">
            <PageHeader title="Indicators & Investigation" icon={Fingerprint}
                description="Every indicator the platform holds, with the provenance of each source record. Search an exact value, or a malware family or tag."
                actions={<>
                    <Link href="/admin/threat/cti" className={btn('secondary')}><ExternalLink className="w-3.5 h-3.5" /> External lookup</Link>
                    <Link href="/admin/threat/urlscan" className={btn('secondary')}>URL scanner</Link>
                </>} />

            <Card>
                <div className="flex flex-wrap items-end gap-2 mb-3">
                    <div className="flex-1 min-w-[220px]"><SearchBox label="Search indicators" value={q} onSubmit={reset(setQ)} placeholder="IP, domain, URL, hash, CVE, malware or tag" /></div>
                    <Select label="Type" value={type} onChange={reset(setType)} options={TYPES} />
                    <Select label="Status" value={status} onChange={reset(setStatus)} options={[['active', 'Active'], ['expired', 'Expired'], ['', 'Any status']] as const} />
                    <Select label="Source" value={feed} onChange={reset(setFeed)} options={FEEDS} />
                    <Select label="Marking" value={tlp} onChange={reset(setTlp)} options={TLPS} />
                    <Select label="Sort" value={sort} onChange={reset(setSort)} options={SORTS} />
                    <Toggle on={hosted} onChange={reset(setHosted)}>Hosted in Nigeria</Toggle>
                    <Toggle on={matched} onChange={reset(setMatched)}>Matched in my records</Toggle>
                </div>
                {list.load.state === 'error' ? <ErrorState error={list.load.error} status={list.load.status} onRetry={list.reload} /> : (
                    <>
                        <DataTable caption="Indicators" rows={list.data?.indicators ?? null} columns={columns} rowKey={(r) => r.id} pageSize={50} onRowClick={(r) => open(r.id)} activeKey={openId}
                            empty={<EmptyState title="No indicators match" body={q ? 'Nothing the platform holds matches this search and these filters.' : 'No indicators match these filters. If this stays empty, check that the feeds have run (Sources).'} />} />
                        {list.data && list.data.total > 0 && <Pager page={page} pageSize={50} total={list.data.total} onPage={setPage} />}
                    </>
                )}
            </Card>

            {/* Keyed by the indicator, so its form starts empty for each one. */}
            <IndicatorDrawer key={openId ?? 'none'} id={openId} onClose={() => open(null)} onOpen={open} />
        </div>
    );
}

function IndicatorDrawer({ id, onClose, onOpen }: { id: string | null; onClose: () => void; onOpen: (id: string) => void }) {
    const detail = useVmsData<Detail>(id ? `/api/ti/indicators/${id}` : null);
    const related = useVmsData<{ related: TiRelated[]; reports: TiReport[] }>(id ? `/api/ti/indicators/${id}/related` : null);
    const can = useVmsCan();
    const [verdict, setVerdict] = useState<TiFeedback['verdict']>('suspicious');
    const [note, setNote] = useState('');
    const [msg, setMsg] = useState<Msg>(null);
    const [busy, setBusy] = useState(false);
    const now = detail.at ?? 0;
    const d = detail.data && detail.data.indicator.id === id ? detail.data : null;

    async function save() {
        setBusy(true);
        const r = await vmsSend('POST', `/api/ti/indicators/${id}/feedback`, { verdict, ...(note.trim() ? { note: note.trim() } : {}) });
        setBusy(false);
        setMsg(r.ok ? { ok: true, text: 'Verdict recorded for this organisation.' } : { ok: false, text: r.error });
        if (r.ok) { setNote(''); detail.reload(); }
    }

    return (
        <Drawer open={!!id} onClose={onClose} width="max-w-3xl" title={d ? <span className="font-mono break-all">{d.indicator.value}</span> : 'Indicator'}
            subtitle={d ? `${d.indicator.type} · ${d.indicator.status} · ${d.indicator.source_count} source record(s)` : undefined}>
            {detail.load.state === 'error' ? <ErrorState error={detail.load.error} status={detail.load.status} onRetry={detail.reload} /> : !d ? <Skeleton className="h-64" /> : (
                <div className="space-y-6">
                    <dl className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                        <Field label="First seen">{fmtWat(d.indicator.first_seen)}</Field>
                        <Field label="Last seen">{fmtWat(d.indicator.last_seen)}</Field>
                        <Field label="Valid until">{d.indicator.valid_until ? fmtWat(d.indicator.valid_until) : 'no expiry'}</Field>
                        <Field label="Source-stated confidence">{d.indicator.max_confidence ?? 'not stated by any source'}</Field>
                        <Field label="Labels from sources">{d.indicator.labels_hidden ? 'restricted' : [...d.indicator.malware_families, ...d.indicator.threat_types, ...d.indicator.tags].slice(0, 12).join(', ') || 'none'}</Field>
                        <Field label="ATT&CK (source-listed)">{d.indicator.mitre_techniques.join(', ') || 'none'}</Field>
                    </dl>

                    {d.location && (
                        <section>
                            <h3 className="text-xs font-bold text-foreground mb-2">Hosting location</h3>
                            <p className="text-xs text-foreground">
                                {[d.location.city, d.location.region, d.location.country ?? d.location.country_code].filter(Boolean).join(', ') || 'unknown'}
                                {d.location.as_org || d.location.asn ? ` · ${[d.location.asn, d.location.as_org].filter(Boolean).join(' ')}` : ''}
                            </p>
                            <p className="text-[11px] text-foreground-muted mt-0.5">
                                {d.location.method === 'source_stated' ? `Stated by ${FEED_NAME[d.location.provider] ?? d.location.provider}` : `GeoIP lookup (${d.location.provider}), approximate`} · precision: {d.location.precision} · where the address is hosted, not an attack origin.
                            </p>
                        </section>
                    )}

                    <section>
                        <h3 className="text-xs font-bold text-foreground mb-2">What each source said</h3>
                        {d.sources_hidden > 0 && <p className="text-[11px] text-foreground-muted mb-2">{d.sources_hidden} source record(s) are hidden because of their sharing marking.</p>}
                        <ul className="space-y-2">
                            {d.sources.map((s) => {
                                const c = s.context ?? {};
                                const text = (k: string) => (typeof c[k] === 'string' ? (c[k] as string) : null);
                                return (
                                    <li key={s.id} className="rounded-xl border border-border p-3">
                                        <div className="flex items-center justify-between gap-2 flex-wrap">
                                            <Citation feed={s.feed_id} sourceRef={s.source_ref} at={s.last_seen} now={now} />
                                            <span className="flex items-center gap-1.5"><TlpBadge tlp={s.tlp} />{s.distribution !== null && s.distribution !== undefined && <Tag title="Threat intelligence distribution level">dist {s.distribution}</Tag>}</span>
                                        </div>
                                        <p className="text-[11px] text-foreground mt-1.5">
                                            {[text('threat_type'), text('malware') ? `malware ${text('malware')}` : null, text('event_info'), text('comment')].filter(Boolean).join(' · ') || 'No further detail from this source.'}
                                        </p>
                                        <p className="text-[11px] text-foreground-muted mt-1">
                                            Source confidence: {s.confidence ?? 'not stated'}{text('reporter') ? ` · reporter ${text('reporter')}` : ''}
                                            {' · '}{s.export?.clear === null ? 'may be shared publicly' : s.export?.green === null ? 'may be shared with the community (TLP:GREEN)' : `not exported: ${s.export?.green ?? s.export?.clear ?? 'restricted'}`}
                                        </p>
                                        {text('reference') && /^https?:\/\//.test(text('reference')!) && <a href={text('reference')!} target="_blank" rel="noopener noreferrer" className="text-[11px] text-purple hover:underline inline-flex items-center gap-1 mt-1">Source reference <ExternalLink className="w-3 h-3" /></a>}
                                    </li>
                                );
                            })}
                        </ul>
                    </section>

                    <section>
                        <h3 className="text-xs font-bold text-foreground mb-2 flex items-center gap-1.5"><Link2 className="w-3.5 h-3.5" /> Linked intelligence</h3>
                        {related.load.state === 'loading' ? <Skeleton className="h-16" /> : related.load.state === 'error' ? <p className="text-[11px] text-foreground-muted">{related.load.error}</p> : (
                            <>
                                {related.data!.related.length ? (
                                    <ul className="divide-y divide-border">
                                        {related.data!.related.slice(0, 30).map((r) => (
                                            <li key={r.indicator_id} className="py-1.5 flex items-center justify-between gap-2">
                                                <button type="button" onClick={() => onOpen(r.indicator_id)} className="font-mono text-xs font-semibold text-foreground hover:text-purple text-left break-all">{r.value}</button>
                                                <span className="text-[11px] text-foreground-muted shrink-0">{r.link}</span>
                                            </li>
                                        ))}
                                    </ul>
                                ) : <p className="text-[11px] text-foreground-muted">No other indicator shares a malware family, source event or host with this one.</p>}
                                {related.data!.reports.length > 0 && (
                                    <div className="mt-3 space-y-1.5">
                                        <p className="text-[10px] font-bold uppercase tracking-wider text-foreground-muted">Source reports listing it</p>
                                        {related.data!.reports.map((r) => (
                                            <div key={r.id} className="flex items-center justify-between gap-2 text-xs"><span>{r.title}{r.actors.length ? <span className="text-foreground-muted"> · actor named by the source: {r.actors.join(', ')}</span> : null}</span><TlpBadge tlp={r.tlp} /></div>
                                        ))}
                                    </div>
                                )}
                            </>
                        )}
                    </section>

                    <section>
                        <h3 className="text-xs font-bold text-foreground mb-2">Seen in this organisation ({d.matches.length})</h3>
                        {d.matches.length ? (
                            <ul className="divide-y divide-border">
                                {d.matches.map((m) => (
                                    <li key={m.id} className="py-1.5 flex items-center justify-between gap-2 text-xs">
                                        <span>{m.entity_type} · <span className="font-mono">{m.matched_field}</span> · {ago(m.last_matched_at, now)}</span>
                                        <span className="flex items-center gap-2"><span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${MATCH_STATUS_STYLE[m.status]}`}>{m.status}</span>{entityHref(m) && <Link href={entityHref(m)!} className="text-purple hover:underline">Open</Link>}</span>
                                    </li>
                                ))}
                            </ul>
                        ) : <p className="text-[11px] text-foreground-muted">Not seen in this organisation&apos;s alerts, assets, findings or cases.</p>}
                    </section>

                    <section>
                        <h3 className="text-xs font-bold text-foreground mb-2">Analyst verdicts</h3>
                        {d.feedback.length ? (
                            <ul className="space-y-1.5 mb-3">{d.feedback.map((f) => <li key={f.id} className="text-xs"><span className="font-semibold">{VERDICT_LABEL[f.verdict]}</span> — {f.actor}, {fmtWat(f.at)}{f.note ? <span className="text-foreground-muted">: {f.note}</span> : null}</li>)}</ul>
                        ) : <p className="text-[11px] text-foreground-muted mb-3">No verdict recorded by this organisation.</p>}
                        {can.manage && (
                            <div className="flex flex-wrap items-end gap-2">
                                <select aria-label="Verdict" value={verdict} onChange={(e) => setVerdict(e.target.value as TiFeedback['verdict'])} className="text-xs rounded-lg border border-border bg-card px-2 py-1.5">
                                    {Object.entries(VERDICT_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
                                </select>
                                <input aria-label="Note" value={note} onChange={(e) => setNote(e.target.value)} maxLength={2000} placeholder={verdict === 'benign' || verdict === 'false_positive' ? 'Why (required)' : 'Note (optional)'} className="flex-1 min-w-[180px] text-xs rounded-lg border border-border bg-card px-2 py-1.5" />
                                <button type="button" className={btn('primary')} disabled={busy} onClick={save}>Record verdict</button>
                            </div>
                        )}
                        <Notice msg={msg} />
                    </section>

                    <AiPanel purpose="indicator_assessment" subjectId={d.indicator.id} title="AI analysis" purposes={[
                        { value: 'indicator_assessment', label: 'Indicator assessment' }, { value: 'investigation_summary', label: 'Investigation summary' },
                    ]} />
                </div>
            )}
        </Drawer>
    );
}
