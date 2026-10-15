'use client';

// Indicators (phase P6): search stored indicators by value, malware family or tag; each shows
// every source record that listed it (what that source said), where it was seen in this
// organisation, and analyst verdicts. Verdicts never change what a source said.

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import { Search, Fingerprint } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';
import { loadJson } from '@/lib/alerts';
import { fmtWat } from '@/lib/vms';
import { AiPanel } from '@/components/shared/AiPanel';
import { VERDICT_LABEL, MATCH_STATUS_STYLE, entityHref, type TiIndicator, type TiSource, type TiMatch, type TiFeedback } from '@/lib/ti';

interface Detail { indicator: TiIndicator; sources: TiSource[]; matches: TiMatch[]; feedback: TiFeedback[] }
const TYPES = ['all', 'ip', 'domain', 'url', 'sha256', 'md5', 'sha1', 'cve'];

export function TiIndicators() {
    const params = useSearchParams();
    const [type, setType] = useState('all');
    const [matched, setMatched] = useState(false);
    const [search, setSearch] = useState(params.get('q') ?? '');
    const [text, setText] = useState(params.get('q') ?? '');
    const [rows, setRows] = useState<TiIndicator[] | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [detail, setDetail] = useState<Detail | null>(null);
    const [verdict, setVerdict] = useState<TiFeedback['verdict']>('suspicious');
    const [note, setNote] = useState('');
    const [msg, setMsg] = useState<string | null>(null);

    useEffect(() => {
        let active = true;
        const p = new URLSearchParams();
        if (type !== 'all') p.set('type', type);
        if (text) p.set('q', text);
        if (matched) p.set('matched', 'true');
        void loadJson<{ indicators: TiIndicator[] }>(`/api/ti/indicators?${p.toString()}`).then((r) => {
            if (!active) return;
            setRows(r.ok ? r.data.indicators : null);
            setError(r.ok ? null : r.error);
        });
        return () => { active = false; };
    }, [type, text, matched]);

    async function open(id: string) {
        setMsg(null);
        const r = await loadJson<Detail>(`/api/ti/indicators/${id}`);
        setDetail(r.ok ? r.data : null);
        if (!r.ok) setMsg(r.error);
    }
    async function submitVerdict() {
        if (!detail) return;
        const r = await apiFetch(apiUrl(`/api/ti/indicators/${detail.indicator.id}/feedback`), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ verdict, note: note.trim() || undefined }) });
        const d = await r.json().catch(() => null);
        if (!r.ok) { setMsg(d?.error ?? `HTTP ${r.status}`); return; }
        setDetail({ ...detail, feedback: [d.feedback, ...detail.feedback] });
        setNote('');
        setMsg('Verdict recorded');
    }

    const chip = (on: boolean) => `text-[11px] font-bold px-2.5 py-1 rounded-md ${on ? 'bg-blue text-white' : 'text-foreground-muted hover:text-foreground'}`;
    return (
        <div className="space-y-4">
            <div>
                <h1 className="text-lg font-black text-foreground flex items-center gap-2"><Fingerprint className="w-5 h-5" /> Indicators</h1>
                <p className="text-xs text-foreground-muted">Indicators stored from the threat feeds, with every source that listed them. Confidence and labels are the source&apos;s own.</p>
            </div>
            <div className="flex flex-wrap gap-2 items-center">
                <div className="flex gap-1 bg-card border border-border rounded-lg p-1 flex-wrap">{TYPES.map((t) => <button key={t} onClick={() => setType(t)} className={chip(type === t)}>{t}</button>)}</div>
                <button onClick={() => setMatched((m) => !m)} className={`${chip(matched)} border border-border`}>Seen in my environment</button>
                <form onSubmit={(e) => { e.preventDefault(); setText(search.trim()); }} className="flex items-center gap-1 bg-card border border-border rounded-lg px-2 py-1">
                    <Search className="w-3.5 h-3.5 text-foreground-muted" />
                    <input aria-label="Search indicators" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="IP, domain, URL, hash, CVE or malware family" className="bg-transparent text-[11px] outline-none w-64" />
                </form>
            </div>
            {error && <p role="alert" className="text-xs text-red font-semibold">{error}</p>}
            <div className="grid grid-cols-1 lg:grid-cols-5 gap-4">
                <div className="lg:col-span-2 bg-card border border-border rounded-xl overflow-hidden">
                    {rows === null && !error && <div className="h-24 bg-card-muted animate-pulse" />}
                    {rows && rows.length === 0 && <p className="text-sm text-foreground-muted text-center py-10">No data — no indicators{text || type !== 'all' || matched ? ' for these filters' : ' stored yet; check feed health on the overview'}.</p>}
                    <div className="max-h-[640px] overflow-y-auto divide-y divide-border">
                        {rows?.map((i) => (
                            <button key={i.id} onClick={() => void open(i.id)} className={`w-full text-left p-3 hover:bg-card-muted ${detail?.indicator.id === i.id ? 'bg-card-muted' : ''}`}>
                                <div className="flex items-center justify-between gap-2">
                                    <span className="text-xs font-bold font-mono text-foreground break-all">{i.value}</span>
                                    <span className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded bg-card-muted text-foreground-muted">{i.type}</span>
                                </div>
                                <p className="text-[10px] text-foreground-muted mt-1">{[...i.malware_families, ...i.threat_types].join(', ') || 'no labels'} · {i.source_count} source record(s) · last listed {fmtWat(i.last_seen)}{i.status === 'expired' ? ' · expired' : ''}</p>
                            </button>
                        ))}
                    </div>
                </div>
                <div className="lg:col-span-3 bg-card border border-border rounded-xl p-4">
                    {!detail ? <p className="text-xs text-foreground-muted text-center py-10">{msg ?? 'Select an indicator.'}</p> : (
                        <div className="space-y-4 text-xs">
                            <div>
                                <h2 className="text-sm font-black font-mono text-foreground break-all">{detail.indicator.value}</h2>
                                <p className="text-foreground-muted">{detail.indicator.type} · {detail.indicator.status} · first listed {fmtWat(detail.indicator.first_seen)} · last listed {fmtWat(detail.indicator.last_seen)} · {detail.indicator.valid_until ? `active until ${fmtWat(detail.indicator.valid_until)}` : 'no expiry'}</p>
                                <p className="text-foreground-muted">Highest source-stated confidence: {detail.indicator.max_confidence ?? 'none stated'}{detail.indicator.mitre_techniques.length ? ` · ATT&CK (as listed by a source): ${detail.indicator.mitre_techniques.join(', ')}` : ''}</p>
                            </div>
                            <div>
                                <p className="text-[10px] font-bold text-foreground-muted uppercase mb-1">What the sources said</p>
                                {detail.sources.map((s) => (
                                    <div key={s.id} className="border-t border-border py-1.5">
                                        <p className="font-semibold">{s.ti_feeds?.name ?? s.feed_id} <span className="font-mono text-foreground-muted">#{s.source_ref}</span></p>
                                        <p className="text-foreground-muted">confidence {s.confidence ?? 'not stated'} · last listed {fmtWat(s.last_seen)}{Object.entries(s.context).filter(([, v]) => v !== null && v !== '' && !(Array.isArray(v) && v.length === 0)).map(([k, v]) => ` · ${k}: ${Array.isArray(v) ? v.join(', ') : typeof v === 'object' ? JSON.stringify(v) : String(v)}`).join('')}</p>
                                    </div>
                                ))}
                            </div>
                            <div>
                                <p className="text-[10px] font-bold text-foreground-muted uppercase mb-1">Seen in your environment</p>
                                {detail.matches.length === 0 ? <p className="text-foreground-muted">Not seen in your alerts, assets, findings or cases.</p> : detail.matches.map((m) => (
                                    <p key={m.id}><span className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded ${MATCH_STATUS_STYLE[m.status]}`}>{m.status}</span> {m.entity_type} <Link href={entityHref(m) ?? '#'} className="font-mono text-blue">{m.entity_id.slice(0, 12)}</Link> · {m.matched_field} · last {fmtWat(m.last_matched_at)}</p>
                                ))}
                            </div>
                            <div>
                                <p className="text-[10px] font-bold text-foreground-muted uppercase mb-1">Analyst verdicts</p>
                                {detail.feedback.map((f) => <p key={f.id} className="text-foreground-muted">{fmtWat(f.at)} · {f.actor} · <span className="font-semibold text-foreground">{VERDICT_LABEL[f.verdict]}</span>{f.note ? ` — ${f.note}` : ''}</p>)}
                                <div className="flex flex-wrap gap-2 items-end mt-2">
                                    <select aria-label="Verdict" value={verdict} onChange={(e) => setVerdict(e.target.value as TiFeedback['verdict'])} className="bg-card-muted border border-border rounded px-2 py-1 text-xs">
                                        {Object.entries(VERDICT_LABEL).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
                                    </select>
                                    <input aria-label="Reason" value={note} onChange={(e) => setNote(e.target.value)} placeholder="reason (required for benign / false positive)" className="flex-1 min-w-48 bg-card-muted border border-border rounded px-2 py-1 text-xs" />
                                    <button onClick={() => void submitVerdict()} className="text-[11px] font-bold text-white bg-blue rounded-lg px-3 py-1">Record verdict</button>
                                </div>
                                {msg && <p className="text-[11px] text-foreground-muted mt-1">{msg}</p>}
                            </div>
                            <AiPanel key={detail.indicator.id} purpose="indicator_assessment" subjectId={detail.indicator.id} title="AI indicator assessment" />
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
