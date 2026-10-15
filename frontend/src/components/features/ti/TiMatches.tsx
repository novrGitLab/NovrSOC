'use client';

// Matches (phase P6): indicators found in this organisation's alerts, assets, findings and cases.
// Analysts review or dismiss them, or open a case (one case per match; asking again returns it).

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { Target } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { loadJson } from '@/lib/alerts';
import { fmtWat } from '@/lib/vms';
import { MATCH_STATUS_STYLE, entityHref, type TiMatch } from '@/lib/ti';

export function TiMatches() {
    const [status, setStatus] = useState('new');
    const [rows, setRows] = useState<TiMatch[] | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [msg, setMsg] = useState<string | null>(null);

    useEffect(() => {
        let active = true;
        void loadJson<{ matches: TiMatch[] }>(`/api/ti/matches${status === 'all' ? '' : `?status=${status}`}`).then((r) => {
            if (!active) return;
            setRows(r.ok ? r.data.matches : null);
            setError(r.ok ? null : r.error);
        });
        return () => { active = false; };
    }, [status]);

    async function act(m: TiMatch, action: 'reviewed' | 'dismissed' | 'case') {
        setMsg(null);
        const r = action === 'case'
            ? await apiFetch(apiUrl(`/api/ti/matches/${m.id}/case`), { method: 'POST' })
            : await apiFetch(apiUrl(`/api/ti/matches/${m.id}`), { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ status: action }) });
        const d = await r.json().catch(() => null);
        if (!r.ok) { setMsg(d?.error ?? `HTTP ${r.status}`); return; }
        const next: TiMatch = action === 'case' ? { ...m, status: 'promoted', case_id: d.case.id } : { ...m, ...d.match, ti_indicators: m.ti_indicators };
        setRows((prev) => prev?.map((x) => (x.id === m.id ? next : x)) ?? prev);
        if (action === 'case') setMsg(d.created ? `Case ${d.case.case_number} opened` : `Already linked to case ${d.case.case_number}`);
    }

    const chip = (on: boolean) => `text-[11px] font-bold px-2.5 py-1 rounded-md ${on ? 'bg-blue text-white' : 'text-foreground-muted hover:text-foreground'}`;
    return (
        <div className="space-y-4">
            <div>
                <h1 className="text-lg font-black text-foreground flex items-center gap-2"><Target className="w-5 h-5" /> Matches in your environment</h1>
                <p className="text-xs text-foreground-muted">Active indicators found in your alerts, assets, open findings and open cases. Checked every 15 minutes.</p>
            </div>
            <div className="flex gap-1 bg-card border border-border rounded-lg p-1 w-fit">{['new', 'reviewed', 'promoted', 'dismissed', 'all'].map((x) => <button key={x} onClick={() => setStatus(x)} className={chip(status === x)}>{x}</button>)}</div>
            {error && <p role="alert" className="text-xs text-red font-semibold">{error}</p>}
            {msg && <p className="text-xs text-foreground-muted">{msg}</p>}
            <div className="bg-card border border-border rounded-xl overflow-hidden">
                {rows === null && !error && <div className="h-24 bg-card-muted animate-pulse" />}
                {rows && rows.length === 0 && <p className="text-sm text-foreground-muted text-center py-10">No data — no {status === 'all' ? '' : `${status} `}matches.</p>}
                <div className="divide-y divide-border">
                    {rows?.map((m) => (
                        <div key={m.id} className="p-3 text-xs flex flex-wrap items-start justify-between gap-3">
                            <div className="min-w-0">
                                <p className="font-bold">
                                    <span className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded mr-2 ${MATCH_STATUS_STYLE[m.status]}`}>{m.status}</span>
                                    <Link href={`/admin/ti/indicators?q=${encodeURIComponent(m.ti_indicators?.value ?? m.matched_value)}`} className="font-mono text-blue break-all">{m.ti_indicators?.value ?? m.matched_value}</Link>
                                    <span className="text-foreground-muted font-normal"> ({m.ti_indicators?.type})</span>
                                </p>
                                <p className="text-foreground-muted mt-1">
                                    in {m.entity_type} <Link href={entityHref(m) ?? '#'} className="font-mono">{m.entity_id.slice(0, 12)}</Link> · field {m.matched_field} · first {fmtWat(m.first_matched_at)} · last {fmtWat(m.last_matched_at)}
                                </p>
                                <p className="text-foreground-muted">Source labels: {[...(m.ti_indicators?.malware_families ?? []), ...(m.ti_indicators?.threat_types ?? [])].join(', ') || 'none'} · {m.ti_indicators?.source_count ?? 0} source record(s) · source confidence {m.ti_indicators?.max_confidence ?? 'not stated'}{m.ti_indicators?.status === 'expired' ? ' · indicator now expired' : ''}</p>
                            </div>
                            <div className="flex gap-2 shrink-0">
                                {m.status === 'promoted' ? <Link href="/admin/secops/cases" className="text-[11px] font-bold text-green">Linked to a case</Link> : (
                                    <>
                                        {m.status !== 'reviewed' && <button onClick={() => void act(m, 'reviewed')} className="text-[11px] font-bold border border-border rounded px-2 py-1">Reviewed</button>}
                                        {m.status !== 'dismissed' && <button onClick={() => void act(m, 'dismissed')} className="text-[11px] font-bold border border-border rounded px-2 py-1">Dismiss</button>}
                                        <button onClick={() => void act(m, 'case')} className="text-[11px] font-bold text-white bg-blue rounded px-2 py-1">Open case</button>
                                    </>
                                )}
                            </div>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
}
