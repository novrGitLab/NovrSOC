'use client';

// Threat Intelligence — Sources Operations (administrator-only diagnostics, split out of
// TiSources.tsx). Raw per-run error text, the on-demand MISP capability check, the correlation
// engine's internal state, retry/backfill controls, and TAXII client credential management —
// everything a normal intel:read user does not need to see day to day, and everything here that
// changes something is already refused by the backend below super_admin/soc_manager
// (routes/threatInfo.ts). The EmptyState below is a UX courtesy, not the security boundary.
import { useState } from 'react';
import { Play, Copy, KeyRound } from 'lucide-react';
import { PageHeader, ErrorState, EmptyState, Notice, ConfirmDialog, btn, type Msg } from '@/components/features/vms/kit';
import { Card, SectionTitle, Skeleton, StatusPill } from '@/components/features/vms/ui';
import { DataTable, type Column } from '@/components/features/vms/table';
import { useVmsData, useVmsCan, vmsSend } from '@/components/features/vms/data';
import { fmtWat } from '@/lib/vms';
import { Freshness, Field } from './common';
import { FEED_NAME, ago, type TiSources as Sources, type TiFeed, type TiRun, type TaxiiClient, type MispCheck } from '@/lib/ti';

const copy = (s: string) => { void navigator.clipboard?.writeText(s); };

export function TiSourcesOperations() {
    const can = useVmsCan();
    const manager = can.scope;
    const src = useVmsData<Sources>(manager ? '/api/ti/sources' : null);
    const clients = useVmsData<{ clients: TaxiiClient[] }>(manager ? '/api/ti/exchange/clients' : null);
    const [msg, setMsg] = useState<Msg>(null);
    const [busy, setBusy] = useState<string | null>(null);
    const [check, setCheck] = useState<MispCheck | null>(null);
    const [creds, setCreds] = useState<{ username: string; password: string; name: string } | null>(null);
    const [revoke, setRevoke] = useState<TaxiiClient | null>(null);
    const [name, setName] = useState('');
    const [cols, setCols] = useState<string[]>([]);
    const [maxTlp, setMaxTlp] = useState<'clear' | 'green' | 'amber'>('clear');
    const now = src.at ?? 0;
    const d = src.data;
    const mispMeta = (f: TiFeed) => {
        const c = f.last_counts as (TiFeed['last_counts'] & { mode?: string; window_from?: string; pages?: number; truncated?: boolean }) | null;
        if (!c?.window_from) return '';
        return ` · ${c.mode === 'backfill' ? 'backfill' : 'changes'} since ${fmtWat(c.window_from)} · ${c.pages} page(s)${c.truncated ? ' · STOPPED AT THE PAGE LIMIT — window not advanced; raise MISP_MAX_PAGES' : ''}`;
    };

    async function runFeed(f: TiFeed, backfillDays?: number) {
        setBusy(f.id);
        const r = await vmsSend<{ status: string; counts?: Record<string, number>; error?: string }>('POST', `/api/ti/feeds/${f.id}/run`, backfillDays ? { backfill_days: backfillDays } : {});
        setBusy(null);
        setMsg(r.ok ? { ok: true, text: `${FEED_NAME[f.id] ?? f.name}: ${JSON.stringify(r.data.counts ?? {})}` } : { ok: false, text: r.error });
        src.reload();
    }
    async function checkMisp() {
        setBusy('misp');
        const r = await vmsSend<{ misp: MispCheck }>('POST', '/api/ti/sources/misp/check');
        setBusy(null);
        if (r.ok) setCheck(r.data.misp); else setMsg({ ok: false, text: r.error });
    }
    async function createClient() {
        setBusy('client');
        const r = await vmsSend<{ credentials: { username: string; password: string } }>('POST', '/api/ti/exchange/clients', { name: name.trim(), collections: cols, max_tlp: maxTlp });
        setBusy(null);
        if (!r.ok) { setMsg({ ok: false, text: r.error }); return; }
        setCreds({ ...r.data.credentials, name: name.trim() });
        setName(''); setCols([]); setMaxTlp('clear');
        clients.reload();
    }
    async function doRevoke(c: TaxiiClient) {
        const r = await vmsSend('POST', `/api/ti/exchange/clients/${c.id}/revoke`);
        setRevoke(null);
        setMsg(r.ok ? { ok: true, text: `${c.name} revoked. Its credentials no longer work.` } : { ok: false, text: r.error });
        clients.reload();
    }

    if (!manager) {
        return (
            <div className="space-y-5">
                <PageHeader title="Sources Operations" description="Diagnostics and connector administration for the Threat Intelligence source pipeline." />
                <EmptyState title="For SOC managers and super admins" body="This page's run/backfill controls, raw error detail and TAXII client credentials are restricted to that tier. Source health and freshness are on the main Sources & Exchange page." />
            </div>
        );
    }

    const feedCols: Column<TiFeed & { retired?: boolean }>[] = [
        { key: 'name', header: 'Source', render: (f) => <span className="text-xs font-semibold">{FEED_NAME[f.id] ?? f.name}</span>, sort: (f) => f.id },
        { key: 'state', header: 'State', render: (f) => <Freshness lastSuccess={f.last_success_at} stale={f.stale} failing={f.failing} configured={f.configured} retired={f.retired} enabled={f.enabled} now={now} /> },
        { key: 'last', header: 'Last run', render: (f) => <span className="text-[11px] text-foreground-muted" title={f.last_run_at ? fmtWat(f.last_run_at) : ''}>{ago(f.last_run_at, now)}</span>, hideBelow: 'md' },
        { key: 'counts', header: 'Last counts', render: (f) => f.last_counts ? <span className="text-[11px] text-foreground-muted tabular-nums">{f.last_counts.fetched} fetched · {f.last_counts.new} new · {f.last_counts.updated} updated · {f.last_counts.duplicates} dup · {f.last_counts.invalid} invalid{mispMeta(f)}</span> : <span className="text-[11px] text-foreground-muted">—</span>, hideBelow: 'lg' },
        { key: 'error', header: 'Last error', render: (f) => f.last_error ? <span className="text-[11px] text-red break-words">{f.last_error.slice(0, 160)}</span> : <span className="text-[11px] text-foreground-muted">none</span> },
        { key: 'run', header: '', render: (f) => !f.retired && f.configured !== false ? <button type="button" className={btn('ghost')} disabled={!!busy} onClick={(e) => { e.stopPropagation(); void runFeed(f); }}><Play className="w-3.5 h-3.5" /> Run now</button> : null },
        { key: 'backfill', header: '', render: (f) => (f.id === 'misp' || f.id === 'misp_events') && f.configured !== false ? <button type="button" className={btn('ghost')} disabled={!!busy} title="One run that reads the last 30 days from the threat intelligence feed (read-only)" onClick={(e) => { e.stopPropagation(); void runFeed(f, 30); }}>Backfill 30 d</button> : null, hideBelow: 'md' },
    ];
    const runCols: Column<TiRun>[] = [
        { key: 'feed', header: 'Source', render: (r) => <span className="text-xs">{FEED_NAME[r.feed_id] ?? r.feed_id}</span> },
        { key: 'at', header: 'Started', render: (r) => <span className="text-[11px] text-foreground-muted">{fmtWat(r.started_at)}</span>, sort: (r) => r.started_at },
        { key: 'status', header: 'Result', render: (r) => <StatusPill tone={r.status === 'ok' ? 'good' : r.status === 'failed' ? 'critical' : 'neutral'} label={r.status} /> },
        { key: 'counts', header: 'Counts', render: (r) => <span className="text-[11px] tabular-nums text-foreground-muted">{r.fetched} / {r.new} new / {r.updated} upd / {r.duplicates} dup / {r.invalid} inv</span>, hideBelow: 'md' },
        { key: 'error', header: 'Error', render: (r) => <span className="text-[11px] text-red">{r.error?.slice(0, 120) ?? ''}</span>, hideBelow: 'lg' },
    ];
    const clientCols: Column<TaxiiClient>[] = [
        { key: 'name', header: 'Client', render: (c) => <span className="text-xs font-semibold">{c.name}</span> },
        { key: 'user', header: 'Username', render: (c) => <span className="font-mono text-[11px]">{c.key_id}</span>, hideBelow: 'md' },
        { key: 'cols', header: 'Collections', render: (c) => <span className="text-[11px]">{c.collections.map((id) => d?.exchange.collections.find((x) => x.id === id)?.alias ?? id).join(', ')}</span>, hideBelow: 'lg' },
        { key: 'tlp', header: 'Up to', render: (c) => <span className="text-[11px] uppercase font-semibold">{c.max_tlp}</span> },
        { key: 'used', header: 'Last used', render: (c) => <span className="text-[11px] text-foreground-muted">{ago(c.last_used_at, now)}</span>, hideBelow: 'md' },
        { key: 'state', header: 'State', render: (c) => c.revoked_at ? <StatusPill tone="neutral" label="Revoked" /> : <StatusPill tone="good" label="Active" /> },
        { key: 'x', header: '', render: (c) => !c.revoked_at ? <button type="button" className={btn('ghost')} onClick={(e) => { e.stopPropagation(); setRevoke(c); }}>Revoke</button> : null },
    ];
    const mispCheck = check ?? d?.misp.last_check ?? null;

    return (
        <div className="space-y-5">
            <PageHeader title="Sources Operations" description="Run/backfill controls, raw error detail, the MISP capability check, correlation engine state, and TAXII client credentials. Everyone with access to Threat Intelligence can see source health on the main Sources & Exchange page; this is the administrator-only diagnostic layer." />
            <Notice msg={msg} />
            {src.load.state === 'error' ? <ErrorState error={src.load.error} status={src.load.status} onRetry={src.reload} /> : !d ? <Skeleton className="h-64" /> : (
                <>
                    <Card>
                        <SectionTitle title="Sources" hint="Runs every 6 hours (KEV daily) on the host that owns scheduled jobs" />
                        <DataTable caption="Sources" rows={d.feeds} columns={feedCols} rowKey={(f) => f.id} />
                    </Card>

                    <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
                        <Card>
                            <SectionTitle title="Correlation engine" />
                            <dl className="grid grid-cols-1 gap-3">
                                <Field label="Last run in this process">
                                    {d.engine.correlation_last_run_at ? (
                                        <>
                                            {ago(d.engine.correlation_last_run_at, now)}
                                            {d.engine.correlation_errors && d.engine.correlation_errors.length > 0 && <span className="text-red font-semibold"> · failed for {d.engine.correlation_errors.join(', ')}</span>}
                                        </>
                                    ) : (
                                        <span className="text-amber font-semibold" title="This status is held in the memory of the process that answered this request and resets on every restart or deploy — a fresh process not having run yet is not, on its own, evidence the engine is broken.">
                                            No run yet in this process{d.engine.correlation_process_started_at ? ` (process started ${ago(d.engine.correlation_process_started_at, now)})` : ''}
                                        </span>
                                    )}
                                </Field>
                            </dl>
                        </Card>
                        <Card>
                            <SectionTitle title="Threat Intelligence Feed (MISP)" action={<button type="button" className={btn('secondary')} disabled={busy === 'misp' || !d.misp.configured} onClick={() => void checkMisp()}>Check capabilities</button>} />
                            <dl className="grid grid-cols-2 gap-3">
                                <Field label="Connection">{d.misp.configured ? 'configured' : 'not configured (MISP_URL, MISP_API_KEY)'}</Field>
                                <Field label="Writes from NovrSOC">{d.misp.writes_enabled ? <span className="text-orange font-semibold">enabled</span> : 'off (read-only)'}</Field>
                                {mispCheck && <>
                                    <Field label="Version">{mispCheck.version ?? (mispCheck.reachable ? 'unknown' : 'unreachable')}</Field>
                                    <Field label="Key can write">{mispCheck.key_can_write === null ? 'unknown' : mispCheck.key_can_write ? <span className="text-orange font-semibold">yes — use a read-only key</span> : 'no (read-only)'}</Field>
                                    <Field label="STIX 2 export">{mispCheck.stix2_export}</Field>
                                    <Field label="TAXII 2.1">{mispCheck.taxii21}</Field>
                                    <Field label="Checked">{fmtWat(mispCheck.checked_at)}</Field>
                                    {mispCheck.errors.length > 0 && <Field label="Errors">{mispCheck.errors.join('; ').slice(0, 200)}</Field>}
                                </>}
                            </dl>
                        </Card>
                    </div>

                    <Card>
                        <SectionTitle title="TAXII clients" hint="Each partner gets its own credentials, collections and TLP ceiling" />
                        {clients.load.state === 'error' ? <ErrorState error={clients.load.error} status={clients.load.status} onRetry={clients.reload} /> : (
                            <DataTable caption="TAXII clients" rows={clients.data?.clients ?? null} columns={clientCols} rowKey={(c) => c.id} empty={<EmptyState compact title="No clients yet" body="Create one below for each partner that should receive intelligence." />} />
                        )}
                        <form className="mt-4 flex flex-wrap items-end gap-2" onSubmit={(e) => { e.preventDefault(); void createClient(); }}>
                            <label className="text-[11px] font-semibold flex flex-col gap-1">Partner name<input value={name} onChange={(e) => setName(e.target.value)} maxLength={120} className="text-xs rounded-lg border border-border bg-card px-2 py-1.5 min-w-[200px]" /></label>
                            <fieldset className="text-[11px] flex flex-wrap gap-2 items-center"><legend className="font-semibold mb-1">Collections</legend>
                                {d.exchange.collections.map((c) => <label key={c.id} className="flex items-center gap-1"><input type="checkbox" checked={cols.includes(c.id)} onChange={(e) => setCols((x) => e.target.checked ? [...x, c.id] : x.filter((y) => y !== c.id))} />{c.alias}</label>)}
                            </fieldset>
                            <label className="text-[11px] font-semibold flex flex-col gap-1">Up to
                                <select value={maxTlp} onChange={(e) => setMaxTlp(e.target.value as 'clear' | 'green' | 'amber')} className="text-xs rounded-lg border border-border bg-card px-2 py-1.5">
                                    <option value="clear">TLP:CLEAR</option><option value="green">TLP:GREEN</option><option value="amber">TLP:AMBER (named partners)</option>
                                </select>
                            </label>
                            <button type="submit" className={btn('primary')} disabled={busy === 'client' || name.trim().length < 2 || !cols.length}><KeyRound className="w-3.5 h-3.5" /> Create credentials</button>
                        </form>
                        {creds && (
                            <div className="mt-3 rounded-xl border border-orange/40 bg-orange/10 p-3 text-xs">
                                <p className="font-semibold">Credentials for {creds.name} — shown once. Store them now.</p>
                                <p className="mt-1 font-mono break-all">username: {creds.username} <button type="button" className={btn('ghost')} onClick={() => copy(creds.username)} aria-label="Copy username"><Copy className="w-3 h-3" /></button></p>
                                <p className="font-mono break-all">password: {creds.password} <button type="button" className={btn('ghost')} onClick={() => copy(creds.password)} aria-label="Copy password"><Copy className="w-3 h-3" /></button></p>
                                <button type="button" className={`${btn('secondary')} mt-2`} onClick={() => setCreds(null)}>I have stored them</button>
                            </div>
                        )}
                    </Card>

                    <Card>
                        <SectionTitle title="Recent runs" />
                        <DataTable caption="Recent runs" rows={d.runs} columns={runCols} rowKey={(r) => r.id} pageSize={15} initialSort={{ key: 'at', dir: 'desc' }} empty={<EmptyState compact title="No runs yet" body="Feeds run on the host that owns scheduled jobs." />} />
                    </Card>
                </>
            )}
            <ConfirmDialog open={!!revoke} title={`Revoke ${revoke?.name ?? ''}?`} body="Its credentials stop working immediately. This cannot be undone; issue new credentials if the partner needs access again." confirmLabel="Revoke" tone="danger" onConfirm={() => (revoke ? doRevoke(revoke) : undefined)} onCancel={() => setRevoke(null)} />
        </div>
    );
}
