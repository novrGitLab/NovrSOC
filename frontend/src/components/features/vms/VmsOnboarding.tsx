'use client';

// VMS onboarding (phase P27): Scan Authorisation and Asset Import.
//
// Scan Authorisation — scope requests waiting for the organisation's decision and the record of
// past decisions. The approver (the organisation's executive, or a super_admin recording a client's
// signed document) reads the exact declaration, states their name and title, types the
// organisation's name and accepts it; the backend checks every element, refuses the requester as
// approver, and stores an immutable record. Once approved, scans and schedules run inside the scope
// without asking again until it expires or is revoked.
//
// Asset Import — Wazuh agents by group (preview, choose, import), and manual or CSV lists (check,
// then import). Imports add inventory only; they never create or widen scan scope, and each row
// says whether it is inside approved scope.

import { useMemo, useState } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { ShieldCheck, Upload, Server, FileText, ListPlus } from 'lucide-react';
import { loadJson } from '@/lib/alerts';
import { fmtWat, type VmsScope, type VmsAuthorisation } from '@/lib/vms';
import { Card, SectionTitle, StatusPill, type Tone } from './ui';
import { PageHeader, ErrorState, EmptyState, Notice, Segmented, Select, Toggle, Drawer, ConfirmDialog, Tag, btn, type Msg } from './kit';
import { DataTable } from './table';
import { METHOD_LABEL, describeWindows } from './VmsScope';
import { useVmsData, useVmsCan, vmsSend } from './data';

// ── Shared ─────────────────────────────────────────────────────────────────────────────────────
export const AUTH_META: Record<VmsAuthorisation['status'], { tone: Tone; label: string }> = {
    authorised: { tone: 'good', label: 'In approved scope' },
    pending_approval: { tone: 'warning', label: 'Waiting for approval' },
    not_authorised: { tone: 'neutral', label: 'Not in scope' },
    not_applicable: { tone: 'neutral', label: 'No scan target' },
};
const ACTIVITY_LABEL = { discovery: 'discovery', ports: 'ports', vuln: 'vulnerabilities' } as const;
/** An asset's scan authorisation: the state, and what it permits. */
export function AuthorisationBadge({ a }: { a: VmsAuthorisation | undefined }) {
    if (!a) return <span className="text-[11px] text-foreground-muted">—</span>;
    const m = AUTH_META[a.status];
    return (
        <span className="inline-flex flex-col">
            <StatusPill tone={m.tone} label={m.label} />
            {a.status === 'authorised' && <span className="text-[10.5px] text-foreground-muted">{a.activities.map((x) => ACTIVITY_LABEL[x]).join(', ')}{a.expires_at ? ` · until ${fmtWat(a.expires_at).replace(/,? \d\d:\d\d WAT$/, '')}` : ''}</span>}
        </span>
    );
}
const allows = (s: VmsScope) => [s.allow_discovery === false ? null : 'discovery', s.allow_port_scan ? 'ports' : null, s.allow_vuln_scan ? 'vulnerabilities' : null].filter(Boolean).join(', ') || 'passive only';

// ── Scan Authorisation ─────────────────────────────────────────────────────────────────────────
interface RequestView { entries: VmsScope[]; organisation_name: string; declaration: string; declaration_version: string; declaration_sha256: string }
interface Approval {
    id: string; request_group_id: string; scope_ids: string[]; decision: 'approved' | 'rejected'; method: string; decided_by_email: string; decided_by_role: string;
    authority_name: string | null; authority_title: string | null; organisation_name: string | null; signed_document_ref: string | null;
    declaration_version: string | null; declaration_sha256: string | null; reason: string | null; decided_at: string;
    snapshot: { entries?: { value: string; kind: string }[] } | null;
}

export function VmsAuthorisationPage() {
    const can = useVmsCan();
    const params = useSearchParams();
    const router = useRouter();
    const pending = useVmsData<{ scopes: VmsScope[] }>('/api/vms/scopes?status=pending');
    const decisions = useVmsData<{ approvals: Approval[] }>('/api/vms/scope-approvals');
    const [msg, setMsg] = useState<Msg>(null);
    const open = params.get('request');
    const groups = useMemo(() => {
        const m = new Map<string, VmsScope[]>();
        for (const s of pending.data?.scopes ?? []) if (s.request_group_id) m.set(s.request_group_id, [...(m.get(s.request_group_id) ?? []), s]);
        return [...m.entries()].map(([id, entries]) => ({ id, entries, requested_by: entries[0].requested_by ?? '—', requested_at: entries[0].requested_at ?? null }));
    }, [pending.data]);
    const setOpen = (id: string | null) => router.replace(id ? `/admin/vms/authorisation?request=${id}` : '/admin/vms/authorisation');
    const done = (m: Msg) => { setMsg(m); setOpen(null); pending.reload(); decisions.reload(); };
    return (
        <div className="space-y-5">
            <PageHeader icon={ShieldCheck} title="Scan Authorisation"
                description="Active scanning needs the organisation's approval: its administrator declares the authority to permit testing of the listed systems, once per scope. After that, scans and schedules run inside the scope until it expires or is revoked. Passive monitoring registrations do not need approval."
                actions={can.scope ? <Link href="/admin/vms/discovery" className={btn('primary', 'md')}>Request scope</Link> : undefined} />
            <Notice msg={msg} />
            <Card>
                <SectionTitle title="Waiting for a decision" hint={can.authorize ? 'Review each request and approve or reject it. You cannot approve a request you made yourself.' : 'The organisation\'s administrator approves these; until then they authorise nothing.'} />
                {pending.load.state === 'error' ? <ErrorState error={pending.load.error} status={pending.load.status} onRetry={pending.reload} />
                    : <DataTable caption="Scope requests waiting for a decision" rows={pending.data ? groups : null} rowKey={(g) => g.id} onRowClick={(g) => setOpen(g.id)}
                        empty={<EmptyState compact icon={ShieldCheck} title="No requests waiting" body="New scope requests that permit active scanning appear here." />}
                        columns={[
                            { key: 'targets', header: 'Targets', render: (g) => <div className="space-y-0.5">{g.entries.map((e) => <p key={e.id} className="font-mono text-[11.5px]">{e.value}{e.kind === 'domain' && e.include_subdomains ? ' (+ subdomains)' : ''} <span className="font-sans text-foreground-muted">— {allows(e)}</span></p>)}</div> },
                            { key: 'ref', header: 'Authorisation reference', hideBelow: 'md', render: (g) => <span className="text-[11px]">{g.entries[0].authorization_reference}</span> },
                            { key: 'by', header: 'Requested', sort: (g) => g.requested_at ?? '', render: (g) => <span className="text-[11px]">{g.requested_by}<span className="block text-foreground-muted">{fmtWat(g.requested_at)}</span></span> },
                            { key: 'exp', header: 'Until', hideBelow: 'md', render: (g) => <span className="text-[11px]">{fmtWat(g.entries[0].expires_at)}</span> },
                            { key: 'act', header: '', render: () => <span className={btn('secondary')}>{can.authorize ? 'Review' : 'View'}</span> },
                        ]} />}
            </Card>
            <Card>
                <SectionTitle title="Decisions" hint="Every approval and rejection, with who decided, on whose authority and the fingerprint of the declaration accepted. These records cannot be changed or deleted." />
                {decisions.load.state === 'error' ? <ErrorState error={decisions.load.error} status={decisions.load.status} onRetry={decisions.reload} />
                    : <DataTable caption="Scan authorisation decisions" rows={decisions.data?.approvals ?? null} rowKey={(a) => a.id} initialSort={{ key: 'at', dir: 'desc' }}
                        empty={<EmptyState compact title="No decisions yet" />}
                        columns={[
                            { key: 'at', header: 'Decided', sort: (a) => a.decided_at, render: (a) => <span className="text-[11px] whitespace-nowrap">{fmtWat(a.decided_at)}</span> },
                            { key: 'decision', header: 'Decision', render: (a) => <StatusPill tone={a.decision === 'approved' ? 'good' : 'critical'} label={a.decision === 'approved' ? 'Approved' : 'Rejected'} /> },
                            { key: 'targets', header: 'Targets', render: (a) => <span className="font-mono text-[11px]">{(a.snapshot?.entries ?? []).map((e) => e.value).join(', ') || `${a.scope_ids.length} entr${a.scope_ids.length === 1 ? 'y' : 'ies'}`}</span> },
                            { key: 'who', header: 'By', render: (a) => <span className="text-[11px]">{a.authority_name ? `${a.authority_name}, ${a.authority_title}` : a.decided_by_email}<span className="block text-foreground-muted">{a.decided_by_email} · {METHOD_LABEL[a.method] ?? a.method}{a.signed_document_ref ? ` · ${a.signed_document_ref}` : ''}</span></span> },
                            { key: 'detail', header: 'Declaration / reason', hideBelow: 'lg', render: (a) => <span className="text-[11px] text-foreground-muted">{a.decision === 'rejected' ? a.reason : <>{a.declaration_version} · <span className="font-mono" title={a.declaration_sha256 ?? ''}>{(a.declaration_sha256 ?? '').slice(0, 12)}…</span></>}</span> },
                        ]} />}
            </Card>
            {open && <RequestDrawer id={open} canDecide={can.authorize} superAdmin={can.superAdmin} onClose={() => setOpen(null)} onDone={done} />}
        </div>
    );
}

function RequestDrawer({ id, canDecide, superAdmin, onClose, onDone }: { id: string; canDecide: boolean; superAdmin: boolean; onClose: () => void; onDone: (m: Msg) => void }) {
    const { load, data } = useVmsData<RequestView>(`/api/vms/scope-requests/${id}`);
    const [f, setF] = useState({ method: 'in_platform' as 'in_platform' | 'offline_document', authority_name: '', authority_title: '', organisation_name: '', signed_document_ref: '', accepted: false });
    const [err, setErr] = useState<Msg>(null);
    const [busy, setBusy] = useState(false);
    const [rejecting, setRejecting] = useState(false);
    const nameMatches = !!data && f.organisation_name.trim().toLowerCase() === data.organisation_name.trim().toLowerCase();
    const ready = !!data && f.accepted && nameMatches && f.authority_name.trim().length >= 3 && f.authority_title.trim().length >= 2 && (f.method === 'in_platform' || f.signed_document_ref.trim().length > 0);
    async function approve() {
        if (!data) return;
        setBusy(true); setErr(null);
        const r = await vmsSend<{ approval_id: string; scopes: VmsScope[]; superseded: string[] }>('POST', `/api/vms/scope-requests/${id}/approve`, {
            method: f.method, authority_name: f.authority_name, authority_title: f.authority_title, organisation_name: f.organisation_name,
            declaration_version: data.declaration_version, declaration_accepted: true, ...(f.method === 'offline_document' ? { signed_document_ref: f.signed_document_ref } : {}),
        });
        setBusy(false);
        if (!r.ok) { setErr({ ok: false, text: r.error }); return; }
        onDone({ ok: true, text: `Approved ${r.data.scopes.map((s) => s.value).join(', ')}. Scans may now run inside this scope${r.data.superseded.length ? `; it replaces ${r.data.superseded.length} earlier entr${r.data.superseded.length === 1 ? 'y' : 'ies'}` : ''}.` });
    }
    const input = 'mt-1 block w-full bg-card-muted border border-border rounded-lg px-2.5 py-2 text-xs text-foreground outline-none focus:ring-2 focus:ring-purple/40';
    return (
        <Drawer open onClose={onClose} title="Scope request" subtitle={data ? `${data.entries.length} entr${data.entries.length === 1 ? 'y' : 'ies'} for ${data.organisation_name}` : undefined}>
            {load.state === 'error' ? <ErrorState error={load.status === 409 ? 'This request has already been decided.' : load.error} status={load.status} />
                : !data ? <p className="text-xs text-foreground-muted">Loading…</p> : (
                    <>
                        <section className="space-y-2">
                            <h3 className="text-xs font-bold text-foreground">What would be authorised</h3>
                            {data.entries.map((e) => (
                                <div key={e.id} className="border border-border rounded-lg p-3 text-[11.5px] space-y-0.5">
                                    <p className="font-mono font-semibold">{e.value}{e.kind === 'domain' && e.include_subdomains ? ' (and subdomains)' : ''}</p>
                                    <p>Allows: {allows(e)}</p>
                                    {(e.exclusions ?? []).length > 0 && <p>Never touched: {(e.exclusions ?? []).join(', ')}</p>}
                                    <p>Windows: {describeWindows(e.scan_windows)}{e.max_active_jobs ? ` · at most ${e.max_active_jobs} scans at once` : ''}</p>
                                    <p className="text-foreground-muted">Until {fmtWat(e.expires_at)} · reference {e.authorization_reference} · requested by {e.requested_by}</p>
                                </div>
                            ))}
                        </section>
                        <section className="space-y-2">
                            <h3 className="text-xs font-bold text-foreground">Declaration ({data.declaration_version})</h3>
                            <pre className="whitespace-pre-wrap text-[11.5px] leading-relaxed bg-card-muted border border-border rounded-lg p-3 text-foreground font-sans">{data.declaration}</pre>
                        </section>
                        {!canDecide ? <p className="text-xs text-foreground-muted">Only the organisation&apos;s administrator (or a NovrSOC super administrator recording a signed authorisation) can decide this request.</p> : (
                            <section className="space-y-3">
                                <h3 className="text-xs font-bold text-foreground">Your decision</h3>
                                {superAdmin && <Segmented label="How the authority is given" value={f.method} onChange={(v) => setF({ ...f, method: v })} options={[['in_platform', 'I approve (my own organisation)'], ['offline_document', 'Record a signed document']]} />}
                                <label className="block text-[11px] font-semibold text-foreground">{f.method === 'offline_document' ? 'Signatory\'s full name' : 'Your full name'}<input className={input} value={f.authority_name} onChange={(e) => setF({ ...f, authority_name: e.target.value })} autoComplete="name" /></label>
                                <label className="block text-[11px] font-semibold text-foreground">{f.method === 'offline_document' ? 'Signatory\'s job title' : 'Your job title'}<input className={input} value={f.authority_title} onChange={(e) => setF({ ...f, authority_title: e.target.value })} placeholder="e.g. Chief Information Security Officer" /></label>
                                {f.method === 'offline_document' && <label className="block text-[11px] font-semibold text-foreground">Signed document reference<input className={input} value={f.signed_document_ref} onChange={(e) => setF({ ...f, signed_document_ref: e.target.value })} placeholder="e.g. Signed LOA BG-2026-11, filed in DMS-4471" /></label>}
                                <label className="block text-[11px] font-semibold text-foreground">Type the organisation&apos;s name to confirm whose systems these are: <span className="font-mono">{data.organisation_name}</span>
                                    <input className={input} value={f.organisation_name} onChange={(e) => setF({ ...f, organisation_name: e.target.value })} aria-invalid={!!f.organisation_name && !nameMatches} />
                                </label>
                                <label className="flex items-start gap-2 text-[11.5px] text-foreground"><input type="checkbox" className="mt-0.5" checked={f.accepted} onChange={(e) => setF({ ...f, accepted: e.target.checked })} />{f.method === 'offline_document' ? 'The signed document grants this authority, in these terms, and is on file.' : 'I have the authority described and I accept the declaration above.'}</label>
                                <Notice msg={err} />
                                <div className="flex flex-wrap gap-2">
                                    <button disabled={!ready || busy} onClick={() => void approve()} className={btn('primary', 'md')}>{busy ? 'Approving…' : 'Approve scan authorisation'}</button>
                                    <button disabled={busy} onClick={() => setRejecting(true)} className={btn('danger', 'md')}>Reject</button>
                                </div>
                            </section>
                        )}
                        <ConfirmDialog open={rejecting} title="Reject this request?" tone="danger" confirmLabel="Reject request" body="The entries authorise nothing and cannot be approved later; a new request is needed." reason={{ label: 'Why', required: true }}
                            onCancel={() => setRejecting(false)}
                            onConfirm={async (reason) => {
                                const r = await vmsSend('POST', `/api/vms/scope-requests/${id}/reject`, { reason, ...(f.method === 'offline_document' ? { method: 'offline_document', signed_document_ref: f.signed_document_ref } : {}) });
                                setRejecting(false);
                                if (!r.ok) { setErr({ ok: false, text: r.error }); return; }
                                onDone({ ok: true, text: 'Request rejected.' });
                            }} />
                    </>
                )}
        </Drawer>
    );
}

// ── Asset Import ───────────────────────────────────────────────────────────────────────────────
interface RowResult { row: number; value: string; type: string | null; status: 'new' | 'existing' | 'duplicate' | 'invalid'; reason?: string; asset_id?: string; authorisation?: VmsAuthorisation }
interface ImportResult { dry_run: boolean; results: RowResult[]; counts: Record<string, number> }
interface AgentPreview { agent_id: string; name: string; registered_ip: string | null; addresses: string[]; os: string | null; status: string; last_keepalive: string | null; groups: string[]; importable: boolean; reason: string | null; existing_asset_id: string | null; authorisation: VmsAuthorisation }
const ROW_STATUS: Record<RowResult['status'], { tone: Tone; label: string }> = { new: { tone: 'good', label: 'New' }, existing: { tone: 'neutral', label: 'Already in inventory' }, duplicate: { tone: 'neutral', label: 'Repeated in this list' }, invalid: { tone: 'critical', label: 'Not valid' } };

export function VmsImportPage() {
    const can = useVmsCan();
    const [tab, setTab] = useState<'wazuh' | 'manual' | 'csv'>('wazuh');
    return (
        <div className="space-y-5">
            <PageHeader icon={Upload} title="Asset Import"
                description="Bring assets into the inventory from Wazuh agent groups, a typed list or a CSV file. Importing never authorises scanning: each asset shows whether it is inside approved scope, and scope is requested and approved separately." />
            {!can.manage && <p role="status" className="text-xs text-foreground-muted">Importing is for SOC staff; you can see the inventory on the Asset Inventory page.</p>}
            <Segmented label="Import source" value={tab} onChange={setTab} options={[['wazuh', 'Wazuh agent group'], ['manual', 'IPs and domains'], ['csv', 'CSV file']]} />
            {tab === 'wazuh' ? <WazuhImport /> : <ListImport mode={tab} />}
        </div>
    );
}

function WazuhImport() {
    const groups = useVmsData<{ groups: string[] }>('/api/vms/import/wazuh/groups');
    const [chosen, setGroup] = useState('');
    // The first mapped group until one is chosen.
    const group = chosen || groups.data?.groups[0] || '';
    const [discover, setDiscover] = useState(false);
    const [preview, setPreview] = useState<{ key: string; agents: AgentPreview[] } | null>(null);
    const [selected, setSelected] = useState<Set<string>>(new Set());
    const [msg, setMsg] = useState<Msg>(null);
    const [busy, setBusy] = useState(false);
    const key = `${group}|${discover}`;
    async function load() {
        setBusy(true); setMsg(null);
        const res = await fetchPreview(group, discover);
        setBusy(false);
        if (!res.ok) { setMsg({ ok: false, text: res.error }); setPreview(null); return; }
        setPreview({ key, agents: res.agents });
        setSelected(new Set(res.agents.filter((a) => a.importable).map((a) => a.agent_id)));
    }
    async function run() {
        setBusy(true); setMsg(null);
        const r = await vmsSend<{ imported: number; updated: number; skipped: { agent_id: string; reason: string }[] }>('POST', '/api/vms/import/wazuh', { group, agent_ids: [...selected], discover_ips: discover });
        setBusy(false);
        if (!r.ok) { setMsg({ ok: false, text: r.error }); return; }
        setMsg({ ok: true, text: `${r.data.imported} endpoint${r.data.imported === 1 ? '' : 's'} added, ${r.data.updated} updated${r.data.skipped.length ? `, ${r.data.skipped.length} skipped (${r.data.skipped.slice(0, 3).map((s) => `${s.agent_id}: ${s.reason}`).join('; ')})` : ''}.` });
        void load();
    }
    if (groups.load.state === 'error') return <ErrorState error={groups.load.error} status={groups.load.status} onRetry={groups.reload} />;
    if (groups.data && !groups.data.groups.length) return <EmptyState icon={Server} title="No Wazuh groups mapped to this organisation" body="A super administrator maps Wazuh agent groups to organisations (Wazuh group mapping). Only mapped groups can be imported." />;
    const agents = preview?.key === key ? preview.agents : null;
    return (
        <Card>
            <SectionTitle title="Import endpoints from a Wazuh group" hint="Only groups mapped to this organisation are listed. Agents that also belong to another organisation's group, and the Wazuh manager itself, are never imported." />
            <div className="flex flex-wrap items-center gap-2 mb-4">
                <Select label="Group" value={group} onChange={setGroup} options={(groups.data?.groups ?? []).map((g) => [g, g] as const)} />
                <Toggle on={discover} onChange={setDiscover}>Discover interface addresses</Toggle>
                <button disabled={!group || busy} onClick={() => void load()} className={btn('secondary', 'md')}>{busy && !agents ? 'Reading Wazuh…' : 'Preview agents'}</button>
                {agents && <button disabled={!selected.size || busy} onClick={() => void run()} className={btn('primary', 'md')}>Import {selected.size} selected</button>}
            </div>
            <Notice msg={msg} />
            {agents && (
                <DataTable caption={`Agents in ${group}`} rows={agents} rowKey={(a) => a.agent_id} selected={selected} onSelectedChange={(s) => setSelected(new Set([...s].filter((id) => agents.find((a) => a.agent_id === id)?.importable)))}
                    empty={<EmptyState compact title="This group has no agents" />}
                    columns={[
                        { key: 'name', header: 'Agent', sort: (a) => a.name, render: (a) => <div><p className="font-mono font-semibold">{a.name}</p><p className="text-[10.5px] text-foreground-muted">ID {a.agent_id} · {a.status}{a.os ? ` · ${a.os}` : ''}</p></div> },
                        { key: 'ip', header: 'Addresses', render: (a) => <span className="font-mono text-[11px]">{a.addresses.length ? a.addresses.join(', ') : '—'}</span> },
                        { key: 'groups', header: 'Groups', hideBelow: 'lg', render: (a) => <span className="text-[11px]">{a.groups.join(', ')}</span> },
                        { key: 'state', header: 'Import', render: (a) => a.importable ? <StatusPill tone={a.existing_asset_id ? 'neutral' : 'good'} label={a.existing_asset_id ? 'Update existing' : 'New'} /> : <span className="text-[11px] text-foreground-muted"><StatusPill tone="warning" label="Not importable" /><span className="block">{a.reason}</span></span> },
                        { key: 'auth', header: 'Scanning (registered IP)', render: (a) => <AuthorisationBadge a={a.authorisation} /> },
                    ]} />
            )}
            {agents && <p className="text-[11px] text-foreground-muted mt-3">The registered address is what scans use; interface addresses found by discovery are recorded on the asset&apos;s history. To scan any of them, request scope for it.</p>}
        </Card>
    );
}

async function fetchPreview(group: string, discover: boolean): Promise<{ ok: true; agents: AgentPreview[] } | { ok: false; error: string }> {
    const r = await loadJson<{ agents: AgentPreview[] }>(`/api/vms/import/wazuh/groups/${encodeURIComponent(group)}/preview${discover ? '?discover=1' : ''}`, { signal: AbortSignal.timeout(120_000) });
    return r.ok ? { ok: true, agents: r.data.agents } : { ok: false, error: r.error };
}

function ListImport({ mode }: { mode: 'manual' | 'csv' }) {
    const [text, setText] = useState('');
    const [file, setFile] = useState<string | null>(null);
    const [result, setResult] = useState<ImportResult | null>(null);
    const [checked, setChecked] = useState<string | null>(null);
    const [msg, setMsg] = useState<Msg>(null);
    const [busy, setBusy] = useState(false);
    const source = mode === 'csv' ? file ?? '' : text;
    const entries = () => text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean).map((l) => {
        const [value, type, owner, criticality] = l.split(',').map((x) => x.trim());
        return { value, ...(type ? { type } : {}), ...(owner ? { owner } : {}), ...(criticality ? { criticality } : {}) };
    });
    async function send(dry: boolean) {
        setBusy(true); setMsg(null);
        const r = mode === 'csv'
            ? await vmsSend<ImportResult>('POST', '/api/vms/import/csv', { csv: source, dry_run: dry })
            : await vmsSend<ImportResult>('POST', '/api/vms/import/assets', { entries: entries(), dry_run: dry });
        setBusy(false);
        if (!r.ok) { setMsg({ ok: false, text: r.error }); return; }
        setResult(r.data);
        setChecked(dry ? source : null);
        if (!dry) setMsg({ ok: true, text: `${r.data.counts.new ?? 0} added, ${r.data.counts.existing ?? 0} already in the inventory (updated where an owner or criticality was given), ${r.data.counts.invalid ?? 0} not valid.` });
    }
    const c = result?.counts ?? {};
    return (
        <Card>
            <SectionTitle title={mode === 'csv' ? 'Import a CSV file' : 'Import IP addresses, domains and networks'}
                hint={mode === 'csv' ? 'Columns: value, type, owner, criticality (a header row is optional; at most 512 KB and 1,000 rows). type is ip, domain, host or cidr — worked out from the value when blank.' : 'One per line: value, then optionally type, owner and criticality separated by commas — e.g. "203.0.113.10, ip, Network team, high". Networks (CIDR) become network assets.'} />
            {mode === 'csv'
                ? <label className="block text-[11px] font-semibold text-foreground mb-3"><span className="inline-flex items-center gap-1"><FileText className="w-3.5 h-3.5" aria-hidden /> CSV file</span>
                    <input type="file" accept=".csv,text/csv" className="mt-1 block text-xs" onChange={async (e) => { const f = e.target.files?.[0]; setResult(null); setChecked(null); if (!f) { setFile(null); return; } if (f.size > 512 * 1024) { setMsg({ ok: false, text: 'The file is larger than 512 KB' }); setFile(null); return; } setFile(await f.text()); }} />
                </label>
                : <textarea aria-label="Assets to import" value={text} onChange={(e) => { setText(e.target.value); setResult(null); setChecked(null); }} rows={8} placeholder={'203.0.113.10\nportal.example.com, domain, Web team, high\n198.51.100.0/28, cidr'} className="w-full bg-card-muted border border-border rounded-lg px-3 py-2 text-xs font-mono text-foreground mb-3" />}
            <div className="flex flex-wrap gap-2 mb-3">
                <button disabled={!source.trim() || busy} onClick={() => void send(true)} className={btn('secondary', 'md')}><ListPlus className="w-4 h-4" aria-hidden /> Check</button>
                <button disabled={!source.trim() || busy || checked !== source} onClick={() => void send(false)} className={btn('primary', 'md')} title={checked !== source ? 'Check the list first' : undefined}>Import</button>
            </div>
            <Notice msg={msg} />
            {result && (
                <>
                    <div className="flex flex-wrap gap-2 my-3 text-[11px]">
                        {result.dry_run && <Tag strong>Check only — nothing stored yet</Tag>}
                        <Tag>{c.new ?? 0} new</Tag><Tag>{c.existing ?? 0} existing</Tag><Tag>{c.duplicate ?? 0} repeated</Tag><Tag>{c.invalid ?? 0} not valid</Tag>
                        <Tag>{c.authorised ?? 0} in approved scope</Tag><Tag>{c.pending_approval ?? 0} waiting for approval</Tag><Tag>{c.not_authorised ?? 0} not in scope</Tag>
                    </div>
                    <DataTable caption="Import results" rows={result.results} rowKey={(r) => `${r.row}`} pageSize={50}
                        columns={[
                            { key: 'row', header: 'Row', sort: (r) => r.row, render: (r) => <span className="tabular-nums text-[11px]">{r.row}</span> },
                            { key: 'value', header: 'Value', sort: (r) => r.value, render: (r) => r.asset_id ? <Link href={`/admin/vms/assets/${r.asset_id}`} className="font-mono underline">{r.value}</Link> : <span className="font-mono">{r.value}</span> },
                            { key: 'type', header: 'Type', render: (r) => <span className="text-[11px]">{r.type ?? '—'}</span> },
                            { key: 'status', header: 'Result', sort: (r) => r.status, render: (r) => <span className="inline-flex flex-col"><StatusPill tone={ROW_STATUS[r.status].tone} label={ROW_STATUS[r.status].label} />{r.reason && <span className="text-[10.5px] text-foreground-muted">{r.reason}</span>}</span> },
                            { key: 'auth', header: 'Scanning', render: (r) => <AuthorisationBadge a={r.authorisation} /> },
                        ]} />
                </>
            )}
        </Card>
    );
}
