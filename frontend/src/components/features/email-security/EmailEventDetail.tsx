'use client';

import { useState } from 'react';
import Link from 'next/link';
import { Microscope } from 'lucide-react';
import { useEmailApi, send, useRole, isAnalyst, PageHeader, Panel, Gate, SevBadge, Badge, Button, Feedback, KeyValue, wat, label, th, td } from './shared';

// One normalised email event: metadata, authentication, what the provider did, URL and
// attachment intelligence (with every source's own answer), and correlations.

interface UrlAnalysis {
    input: string; normalized: { url: string; domain: string } | null; verdict: string; reasons: string[];
    sources: { source: string; consulted: boolean; malicious: boolean; detail: string }[]; domain_age_days: number | null; registrar: string | null;
}
interface AttachmentAnalysis {
    filename: string | null; sha256: string | null; size: number | null; file_class: string; signals: string[]; verdict: string;
    reputation: { source: string; consulted: boolean; malicious: boolean; detail: string }[]; sandbox: { status: string; detail: string; score?: number; report_url?: string };
}
interface Detail {
    event: {
        id: string; provider: string; provider_event_id: string; message_id: string | null; sender: string | null; recipient: string | null; subject: string | null; received_at: string;
        source_ip: string | null; spf: string | null; dkim: string | null; dmarc: string | null; urls: { url: string; domain: string | null }[];
        attachments: { filename: string | null; sha256: string | null; size: number | null; content_type: string | null }[]; ti_matches: string[]; categories: string[];
        detection: string; severity: string; action: string; action_by: string; mailbox: string | null; tenant: string | null;
        analysis: { urls: UrlAnalysis[]; attachments: AttachmentAnalysis[]; analyzed_at?: string } | null; alert_id: string | null;
    };
    alert: { id: string; title: string; status: string; severity: string; case_number: string | null } | null;
    related_indicators: { type: string; value: string; refs: { kind: string }[]; last_seen: string }[];
}

const VERDICT_TONE: Record<string, 'red' | 'amber' | 'grey'> = { malicious: 'red', suspicious: 'amber' };
const PROVIDER: Record<string, string> = { microsoft365: 'Microsoft 365', google_workspace: 'Google Workspace', gateway: 'NovrSOC mail gateway' };

export function EmailEventDetail({ id }: { id: string }) {
    const role = useRole();
    const [nonce, setNonce] = useState(0);
    const state = useEmailApi<Detail>(`/messaging/events/${id}`, nonce);
    const [busy, setBusy] = useState(false);
    const [fb, setFb] = useState<{ ok: boolean; text: string } | null>(null);
    const e = state.data?.event;

    async function analyze() {
        setBusy(true); setFb(null);
        const r = await send('POST', `/messaging/events/${id}/analyze`);
        setBusy(false);
        setFb({ ok: r.ok, text: r.ok ? 'URL and attachment intelligence refreshed.' : r.error ?? 'Failed' });
        if (r.ok) setNonce((x) => x + 1);
    }

    const delivered = e && (e.action === 'allow' || e.action === 'flag');
    return (
        <div className="space-y-4">
            <PageHeader back={{ href: '/admin/email/messaging', label: 'Messaging Suite' }} title={e?.subject ?? 'Email event'}
                subtitle={e && <>{e.sender ?? 'unknown sender'} → {e.recipient ?? 'unknown recipient'} · {wat(e.received_at)}</>}
                actions={e && isAnalyst(role) && (e.urls.length > 0 || e.attachments.length > 0) && <Button onClick={analyze} busy={busy}><Microscope size={12} /> Analyse URLs & attachments</Button>} />
            <Feedback result={fb} />
            <Gate state={state} rows={6}>
                {e && state.data && (
                    <>
                        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                            <Panel title="Detection">
                                <KeyValue rows={[
                                    ['Detection', <span key="d" className="font-bold">{label(e.detection)}</span>], ['Categories', e.categories.map(label).join(', ')], ['Severity', <SevBadge key="s" s={e.severity} />],
                                    ['Action', <span key="a"><Badge tone={delivered ? 'amber' : 'green'}>{e.action}</Badge> {e.action_by === 'none' ? (delivered ? 'delivered to the mailbox' : '') : `by ${e.action_by}`}</span>],
                                    ['Threat intelligence', e.ti_matches.length ? e.ti_matches.join('; ') : 'No matches'],
                                    ['Alert', state.data.alert ? <Link key="al" href={`/admin/email/alerts/${state.data.alert.id}`} className="text-purple hover:underline">{state.data.alert.title}</Link> : 'None'],
                                ]} />
                                <p className="text-[10px] text-foreground-muted mt-3">NovrSOC detects from provider telemetry. The action shown is what {PROVIDER[e.provider] ?? e.provider} did; NovrSOC does not block or release mail itself.</p>
                            </Panel>
                            <Panel title="Message">
                                <KeyValue rows={[['From', e.sender], ['To', e.recipient], ['Mailbox', e.mailbox], ['Received', wat(e.received_at)], ['Message-ID', <span key="m" className="font-mono break-all">{e.message_id ?? '—'}</span>], ['Provider', PROVIDER[e.provider] ?? e.provider], ['Tenant', e.tenant]]} />
                            </Panel>
                            <Panel title="Authentication">
                                <KeyValue rows={[['Source IP', <span key="ip" className="font-mono">{e.source_ip ?? '—'}</span>], ['SPF', e.spf ?? 'not reported'], ['DKIM', e.dkim ?? 'not reported'], ['DMARC', e.dmarc ?? 'not reported']]} />
                            </Panel>
                        </div>

                        <Panel title={`URLs (${e.urls.length})`} action={e.analysis?.analyzed_at && <span className="text-[10px] text-foreground-muted">Analysed {wat(e.analysis.analyzed_at)}</span>}>
                            {e.urls.length === 0 ? <p className="text-xs text-foreground-muted">No URLs reported by the provider.</p> : (
                                <div className="space-y-3">
                                    {e.urls.map((u, k) => {
                                        const a = e.analysis?.urls?.[k];
                                        return (
                                            <div key={k} className="border border-border rounded-lg p-3">
                                                <p className="font-mono text-[11px] break-all text-foreground">{u.url}</p>
                                                {!a ? <p className="text-[11px] text-foreground-muted mt-1">Not analysed — only flagged messages and links to tracked look-alike domains are analysed automatically.</p> : (
                                                    <div className="mt-2 space-y-1">
                                                        <Badge tone={VERDICT_TONE[a.verdict] ?? 'grey'}>{label(a.verdict)}</Badge>
                                                        <ul className="text-[11px] text-foreground-muted list-disc pl-4">{a.reasons.map((r) => <li key={r}>{r}</li>)}</ul>
                                                        <table className="w-full text-[11px]"><tbody>{a.sources.map((s) => <tr key={s.source} className="border-t border-border/60"><td className={`${td} font-bold`}>{s.source}</td><td className={td}>{s.consulted ? (s.malicious ? <span className="text-red-500 font-bold">Listed</span> : 'Checked') : 'Not consulted'}</td><td className={`${td} text-foreground-muted`}>{s.detail}</td></tr>)}</tbody></table>
                                                    </div>
                                                )}
                                            </div>
                                        );
                                    })}
                                </div>
                            )}
                        </Panel>

                        <Panel title={`Attachments (${e.attachments.length})`}>
                            {e.attachments.length === 0 ? <p className="text-xs text-foreground-muted">No attachments reported.</p> : (
                                <table className="w-full text-xs">
                                    <thead><tr>{['File', 'Type', 'Verdict', 'Reputation', 'Sandbox'].map((h) => <th key={h} className={th}>{h}</th>)}</tr></thead>
                                    <tbody>
                                        {e.attachments.map((f, k) => {
                                            const a = e.analysis?.attachments?.[k];
                                            return (
                                                <tr key={k} className="border-t border-border/60 align-top">
                                                    <td className={td}><p className="font-bold break-all">{f.filename ?? '(unnamed)'}</p>{f.sha256 && <p className="text-[10px] font-mono text-foreground-muted break-all">{f.sha256}</p>}</td>
                                                    <td className={td}>{a ? label(a.file_class) : f.content_type ?? '—'}{a?.signals.map((s) => <p key={s} className="text-[10px] text-foreground-muted">{s}</p>)}</td>
                                                    <td className={td}>{a ? <Badge tone={VERDICT_TONE[a.verdict] ?? 'grey'}>{label(a.verdict)}</Badge> : 'Not analysed'}</td>
                                                    <td className={`${td} text-[11px]`}>{a?.reputation.map((r) => <p key={r.source}>{r.source}: {r.consulted ? r.detail : `not consulted — ${r.detail}`}</p>) ?? '—'}</td>
                                                    <td className={`${td} text-[11px]`}>{a ? (a.sandbox.status === 'unavailable' ? 'Sandbox unavailable' : a.sandbox.detail) : '—'}{a?.sandbox.report_url && <a href={a.sandbox.report_url} target="_blank" rel="noreferrer" className="block text-purple hover:underline">Report →</a>}</td>
                                                </tr>
                                            );
                                        })}
                                    </tbody>
                                </table>
                            )}
                            <p className="text-[10px] text-foreground-muted mt-2">Attachments are judged from metadata and hash reputation only — files are never opened or executed on NovrSOC servers.</p>
                        </Panel>

                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                            <Panel title="Sender & domain intelligence">
                                <KeyValue rows={[
                                    ['Sender domain', e.sender ? e.sender.split('@')[1] ?? '—' : '—'],
                                    ['Source IP', <span key="ip" className="font-mono">{e.source_ip ?? '—'}</span>],
                                    ['Authentication', [e.spf && `SPF ${e.spf}`, e.dkim && `DKIM ${e.dkim}`, e.dmarc && `DMARC ${e.dmarc}`].filter(Boolean).join(' · ') || 'Not reported by the provider'],
                                    ['Sender reputation', 'No sender-reputation service is connected — judge by authentication results and the indicators below.'],
                                ]} />
                            </Panel>
                            <Panel title="Response actions">
                                <p className="text-xs text-foreground-muted">
                                    {PROVIDER[e.provider] ?? e.provider} is connected read-only, so NovrSOC cannot quarantine, release or delete this message.
                                    {e.action_by !== 'none' ? ` The provider already ${e.action === 'quarantine' ? 'quarantined' : e.action === 'block' ? 'blocked' : 'handled'} it.` : " Take action in the provider's own console if needed."}
                                </p>
                                {e.alert_id && <Link href={`/admin/email/alerts/${e.alert_id}`} className="inline-block mt-2 text-xs font-bold text-purple hover:underline">Open the alert to escalate to a case →</Link>}
                            </Panel>
                        </div>

                        <Panel title="Indicators & relationships">
                            {state.data.related_indicators.length === 0 ? <p className="text-xs text-foreground-muted">None of this message&apos;s indicators appear in other modules.</p> : (
                                <ul className="text-[11px] space-y-1">
                                    {state.data.related_indicators.map((s) => <li key={`${s.type}|${s.value}`}><span className="font-mono">{s.value}</span> <span className="text-foreground-muted">({s.type}) — {s.refs.length} sighting{s.refs.length === 1 ? '' : 's'}, last {wat(s.last_seen)}</span></li>)}
                                </ul>
                            )}
                        </Panel>
                    </>
                )}
            </Gate>
        </div>
    );
}
