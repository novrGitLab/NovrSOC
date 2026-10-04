'use client';

import { useState } from 'react';
import Link from 'next/link';
import { Plus, RefreshCw, ChevronDown, ChevronRight } from 'lucide-react';
import {
    useEmailApi, send, useRole, isManager, isAnalyst, PageHeader, Panel, Gate, Empty, StatusBadge, Button, Feedback, DnsRecordCard, SetupNotice,
    inputCls, wat, label,
} from './shared';
import { useEmailSecurity, domainReadiness, isVerified, authConfigured, type DomainRow } from './context';
import { ProviderCards } from './providers';

// Setup & Configuration — the guided way to connect Email Security's three capabilities.
// Not a separate product: it adds and verifies domains (DMARC SaaS), checks their email
// authentication, and connects mail providers (Messaging Suite). Every step's state is derived
// from the backend, so setup is resumable from any device and never claims something it hasn't
// verified. NovrSOC never edits DNS — it shows exactly what to publish, then checks it.

interface DomainDetail {
    verification_record: { type: string; host: string; name: string; value: string } | null;
    latest: null | {
        checked_at: string;
        statuses: { spf: string; dkim: string; dmarc: string };
        spf: { exists: boolean; raw: string | null; errors: string[]; warnings: string[] };
        dmarc: { exists: boolean; raw: string | null; records?: string[]; policy: string | null; rua: string[]; errors: string[]; warnings: string[] };
        dkim: { found: { selector: string; keyBits: number | null }[]; selectors_checked: string[] };
        verification?: { state: string; checked_at: string; detail: string };
    };
    policies: Record<'none' | 'quarantine' | 'reject', { title: string; effect: string; when: string }>;
}
type StepId = 'domain' | 'verify' | 'auth' | 'provider' | 'finish';
const READINESS: Record<string, [string, string]> = { ready: ['protected', 'Ready'], attention: ['warning', 'Needs attention'], incomplete: ['pending', 'Setup incomplete'] };

function StepShell({ n, title, done, open, onToggle, summary, children }: { n: number; title: string; done: boolean; open: boolean; onToggle: () => void; summary?: string; children: React.ReactNode }) {
    return (
        <section className={`border rounded-xl bg-card ${open ? 'border-purple/40' : 'border-border'}`}>
            <button type="button" onClick={onToggle} aria-expanded={open} className="w-full flex items-center gap-3 px-4 py-3 text-left">
                <span className={`w-6 h-6 rounded-full text-[11px] font-black flex items-center justify-center shrink-0 ${done ? 'bg-green text-white' : open ? 'bg-purple text-white' : 'bg-card-muted text-foreground-muted'}`} aria-hidden>{done ? '✓' : n}</span>
                <span className="flex-1 min-w-0">
                    <span className="block text-sm font-black text-foreground">{title}<span className="sr-only">{done ? ' — complete' : ' — not complete'}</span></span>
                    {summary && <span className="block text-[11px] text-foreground-muted truncate">{summary}</span>}
                </span>
                {open ? <ChevronDown size={14} className="text-foreground-muted" /> : <ChevronRight size={14} className="text-foreground-muted" />}
            </button>
            {open && <div className="px-4 pb-4 pt-1 border-t border-border">{children}</div>}
        </section>
    );
}

function AuthRow({ name, status, children }: { name: string; status: string; children: React.ReactNode }) {
    return (
        <div className="flex flex-col sm:flex-row sm:items-start gap-2 py-2.5 border-b border-border/60 last:border-0">
            <div className="w-24 shrink-0 flex sm:block items-center gap-2"><p className="text-xs font-black text-foreground">{name}</p><StatusBadge s={status} /></div>
            <div className="flex-1 min-w-0 text-xs text-foreground-muted">{children}</div>
        </div>
    );
}

export function EmailSetup() {
    const { domains, providers, setup, loading, error, notSetUp, reload } = useEmailSecurity();
    const role = useRole();
    const [selectedId, setSelectedId] = useState<string | null>(null);
    const [openStep, setOpenStep] = useState<StepId | 'none' | null>(null);
    const [newDomain, setNewDomain] = useState('');
    const [busy, setBusy] = useState<string | null>(null);
    const [fb, setFb] = useState<{ ok: boolean; text: string } | null>(null);
    const [nonce, setNonce] = useState(0);
    const [dmarcPlan, setDmarcPlan] = useState<{ host: string; value: string; note: string } | null>(null);

    // Work on the chosen domain, else the first one that still needs something, else the first.
    const selected: DomainRow | null = domains.find((d) => d.id === selectedId) ?? domains.find((d) => domainReadiness(d).state !== 'ready') ?? domains[0] ?? null;
    const detail = useEmailApi<DomainDetail>(selected ? `/dmarc/domains/${selected.id}` : null, nonce);
    const integ = useEmailApi<{ integrations: { id: string; label: string; state: string; detail: string }[] }>('/integrations');

    const done = {
        domain: domains.length > 0,
        verify: !!selected && isVerified(selected),
        auth: !!selected && isVerified(selected) && authConfigured(selected),
        provider: providers.some((p) => p.status === 'connected'),
    };
    const allDone = setup.status === 'active';
    const firstOpen: StepId = !done.domain ? 'domain' : !done.verify ? 'verify' : !done.auth ? 'auth' : !done.provider ? 'provider' : 'finish';
    const current = openStep ?? firstOpen;
    const toggle = (s: StepId) => setOpenStep(current === s ? 'none' : s);
    const refreshAll = () => { setNonce((x) => x + 1); reload(); };

    async function addDomain(e: React.FormEvent) {
        e.preventDefault();
        setBusy('add'); setFb(null);
        const r = await send<{ domain: DomainRow }>('POST', '/dmarc/domains', { domain: newDomain });
        setBusy(null);
        if (!r.ok || !r.data) { setFb({ ok: false, text: r.error ?? 'Could not add the domain' }); return; }
        setFb({ ok: true, text: `${r.data.domain.domain} added. Next, verify that your organisation controls it.` });
        setNewDomain(''); setSelectedId(r.data.domain.id); setOpenStep('verify'); refreshAll();
    }
    async function verify() {
        if (!selected) return;
        setBusy('verify'); setFb(null);
        const r = await send<{ verification: { state: string; detail: string } }>('POST', `/dmarc/domains/${selected.id}/verify`);
        setBusy(null);
        setFb({ ok: r.ok && r.data?.verification.state === 'verified', text: r.ok ? r.data!.verification.detail : r.error ?? 'Check failed' });
        refreshAll();
    }
    async function recheck() {
        if (!selected) return;
        setBusy('inspect'); setFb(null);
        const r = await send('POST', `/dmarc/domains/${selected.id}/inspect`);
        setBusy(null);
        setFb({ ok: r.ok, text: r.ok ? 'Records checked again.' : r.error ?? 'Check failed' });
        refreshAll();
    }
    async function planDmarc() {
        if (!selected) return;
        setBusy('plan');
        const r = await send<{ host: string; value: string; note: string }>('POST', `/dmarc/domains/${selected.id}/policy-plan`, { policy: 'none' });
        setBusy(null);
        if (r.ok && r.data) setDmarcPlan(r.data); else setFb({ ok: false, text: r.error ?? 'Could not prepare the record' });
    }

    const i = detail.data?.latest ?? null;
    const vState = busy === 'verify' ? 'checking' : i?.verification?.state ?? selected?.verification?.state ?? 'not_verified';

    return (
        <div className="space-y-5">
            <PageHeader title="Set up Email Security" subtitle="Let's get your organisation protected." />
            {notSetUp ? <SetupNotice message={notSetUp} /> : (
                <Gate state={{ loading, error, setup: null }} rows={6}>
                    {/* Progress */}
                    <section aria-label="Setup progress" className="bg-card border border-border rounded-xl p-4">
                        <div className="flex items-center justify-between gap-3 flex-wrap">
                            <p className="text-xs font-bold text-foreground">{setup.completed} of {setup.total} completed <span className="text-foreground-muted font-normal">· {setup.percent}%</span></p>
                            <StatusBadge s={setup.status} />
                        </div>
                        <div className="h-1.5 rounded-full bg-card-muted overflow-hidden mt-2"><div className="h-full bg-purple" style={{ width: `${setup.percent}%` }} /></div>
                        <ol className="mt-3 grid grid-cols-1 sm:grid-cols-5 gap-2">
                            {setup.steps.map((s, k) => (
                                <li key={s.id} className={`text-[11px] flex items-center gap-1.5 ${s.done ? 'text-foreground' : 'text-foreground-muted'}`}>
                                    <span aria-hidden className={`w-4 h-4 rounded-full text-[9px] font-black flex items-center justify-center shrink-0 ${s.done ? 'bg-green text-white' : 'bg-card-muted'}`}>{s.done ? '✓' : k + 1}</span>
                                    {s.title}<span className="sr-only">{s.done ? ' — done' : ' — to do'}</span>
                                </li>
                            ))}
                        </ol>
                    </section>

                    {/* Domains (multi-domain) */}
                    <Panel title="Domains" action={<span className="text-[10px] text-foreground-muted">Each domain is set up independently</span>}>
                        {domains.length === 0 ? (
                            <p className="text-xs text-foreground-muted">No domains yet — add your first one in step 1 below.</p>
                        ) : (
                            <ul className="divide-y divide-border -my-2">
                                {domains.map((d) => {
                                    const r = domainReadiness(d);
                                    const active = selected?.id === d.id;
                                    return (
                                        <li key={d.id}>
                                            <button type="button" onClick={() => { setSelectedId(d.id); setOpenStep(null); setDmarcPlan(null); setFb(null); }} aria-pressed={active}
                                                className={`w-full flex items-center justify-between gap-3 py-2.5 px-2 -mx-2 rounded-lg text-left ${active ? 'bg-purple/5' : 'hover:bg-card-muted/40'}`}>
                                                <span className="min-w-0">
                                                    <span className="block text-xs font-bold text-foreground wrap-anywhere">{d.domain}</span>
                                                    <span className="block text-[10px] text-foreground-muted">{r.reason}</span>
                                                </span>
                                                <span className="shrink-0 flex items-center gap-2"><StatusBadge s={READINESS[r.state][0]} title={READINESS[r.state][1]} />{active && <span className="text-[10px] font-bold text-purple">Selected</span>}</span>
                                            </button>
                                        </li>
                                    );
                                })}
                            </ul>
                        )}
                    </Panel>

                    <Feedback result={fb} />

                    <div className="space-y-3">
                        {/* 1 — Add domain */}
                        <StepShell n={1} title="Add domain" done={done.domain} open={current === 'domain'} onToggle={() => toggle('domain')} summary={done.domain ? `${domains.length} domain${domains.length === 1 ? '' : 's'} added` : undefined}>
                            <p className="text-xs text-foreground-muted mb-3">The domain your organisation sends email from. NovrSOC uses it to check SPF, DKIM and DMARC, receive DMARC reports and spot look-alikes of it.</p>
                            {isManager(role) ? (
                                <form onSubmit={addDomain} className="flex flex-wrap gap-2">
                                    <label className="flex-1 min-w-[200px]"><span className="sr-only">Domain</span>
                                        <input value={newDomain} onChange={(e) => setNewDomain(e.target.value)} placeholder="example.com" required className={`${inputCls} w-full`} />
                                    </label>
                                    <Button type="submit" variant="primary" busy={busy === 'add'}><Plus size={12} /> {domains.length ? 'Add another domain' : 'Continue'}</Button>
                                </form>
                            ) : <p className="text-xs text-foreground-muted">A SOC manager can add domains.</p>}
                        </StepShell>

                        {/* 2 — Verify */}
                        <StepShell n={2} title="Verify domain" done={done.verify} open={current === 'verify'} onToggle={() => toggle('verify')} summary={selected ? `${selected.domain}: ${label(vState)}` : 'Add a domain first'}>
                            {!selected ? <p className="text-xs text-foreground-muted">Add a domain first.</p> : (
                                <Gate state={detail}>
                                    {done.verify ? (
                                        <p className="text-xs text-foreground">✓ {selected.domain} is verified — last checked {wat(i?.verification?.checked_at ?? selected.verification?.checked_at)}. Keep the record published; it is re-checked with every inspection.</p>
                                    ) : detail.data?.verification_record ? (
                                        <div className="space-y-3">
                                            <p className="text-xs text-foreground-muted">Add this TXT record at your DNS provider to prove your organisation controls <span className="font-bold text-foreground">{selected.domain}</span>. DNS changes can take a few minutes to a few hours to appear.</p>
                                            <DnsRecordCard type={detail.data.verification_record.type} host={detail.data.verification_record.name} value={detail.data.verification_record.value} note="If your DNS provider adds the domain automatically, enter only _novrsoc-verification as the name." />
                                            <div className="flex items-center gap-3 flex-wrap">
                                                {isAnalyst(role) && <Button variant="primary" onClick={verify} busy={busy === 'verify'}>Verify</Button>}
                                                <StatusBadge s={vState} />
                                                {i?.verification && vState !== 'checking' && <span className="text-[11px] text-foreground-muted">{i.verification.detail}</span>}
                                            </div>
                                        </div>
                                    ) : <p className="text-xs text-foreground-muted">Domain verification is not configured on this NovrSOC deployment (EMAILSEC_VERIFICATION_SECRET).</p>}
                                </Gate>
                            )}
                        </StepShell>

                        {/* 3 — Authentication */}
                        <StepShell n={3} title="Configure email authentication" done={done.auth} open={current === 'auth'} onToggle={() => toggle('auth')}
                            summary={selected && i ? `SPF ${label(i.statuses.spf)} · DKIM ${label(i.statuses.dkim)} · DMARC ${label(i.statuses.dmarc)}` : undefined}>
                            {!selected ? <p className="text-xs text-foreground-muted">Add a domain first.</p> : (
                                <Gate state={detail}>
                                    {!i ? <Empty title="Not checked yet" body="Check the domain's published records." action={isAnalyst(role) ? <Button onClick={recheck} busy={busy === 'inspect'}><RefreshCw size={12} /> Check records</Button> : undefined} /> : (
                                        <div className="space-y-4">
                                            <div>
                                                <AuthRow name="SPF" status={i.statuses.spf}>
                                                    {i.spf.exists ? <>Lists the servers allowed to send as {selected.domain}. {i.spf.errors[0] ?? i.spf.warnings[0] ?? 'Configured correctly.'}</> : 'No SPF record — receivers cannot tell which servers may send your mail.'}
                                                </AuthRow>
                                                <AuthRow name="DKIM" status={i.statuses.dkim}>
                                                    {i.dkim.found.length ? <>Signing keys found: {i.dkim.found.map((k) => `${k.selector}${k.keyBits ? ` (${k.keyBits}-bit)` : ''}`).join(', ')}.</> : <>No key found under the {i.dkim.selectors_checked.length} common selectors checked. Your provider may use another selector — add it on the domain page. This is not the same as DKIM being missing.</>}
                                                </AuthRow>
                                                <AuthRow name="DMARC" status={i.statuses.dmarc}>
                                                    {i.dmarc.exists ? (
                                                        <>
                                                            {(i.dmarc.records ?? []).length > 1 ? <span className="text-red-500 font-bold">{i.dmarc.records!.length} DMARC records are published — receivers ignore all of them. Keep exactly one. </span>
                                                                : <>Policy <span className="font-mono text-foreground">p={i.dmarc.policy ?? '?'}</span>. </>}
                                                            {i.dmarc.rua.length ? `Reports go to ${i.dmarc.rua.join(', ')}.` : 'No reporting address (rua) — you will receive no DMARC reports.'}
                                                            {i.dmarc.errors[0] ? <span className="block text-red-500">{i.dmarc.errors[0]}</span> : i.dmarc.warnings[0] ? <span className="block">{i.dmarc.warnings[0]}</span> : null}
                                                        </>
                                                    ) : 'No DMARC record. DMARC tells receivers what to do with mail that fails SPF and DKIM, and sends you reports about who is using your domain.'}
                                                </AuthRow>
                                            </div>

                                            {detail.data?.policies && (
                                                <div>
                                                    <p className="text-[10px] font-bold uppercase tracking-wider text-foreground-muted mb-2">DMARC policies</p>
                                                    <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                                                        {(['none', 'quarantine', 'reject'] as const).map((p) => {
                                                            const cur = !i.dmarc.errors.length && i.dmarc.policy === p;
                                                            return (
                                                                <div key={p} className={`rounded-lg border p-3 text-[11px] ${cur ? 'border-purple bg-purple/5' : 'border-border'}`}>
                                                                    <p className="font-black text-foreground font-mono">p={p}{cur && <span className="ml-2 font-sans text-[9px] font-bold text-purple uppercase">Current</span>}</p>
                                                                    <p className="text-foreground mt-1">{detail.data!.policies[p].effect}</p>
                                                                    <p className="text-foreground-muted mt-1">{detail.data!.policies[p].when}</p>
                                                                </div>
                                                            );
                                                        })}
                                                    </div>
                                                </div>
                                            )}

                                            {(!i.dmarc.exists || i.dmarc.errors.length > 0 || !i.dmarc.rua.length) && isManager(role) && (
                                                <div className="space-y-2">
                                                    {!dmarcPlan ? (
                                                        <Button onClick={planDmarc} busy={busy === 'plan'}>Show the DMARC record to publish</Button>
                                                    ) : (
                                                        <DnsRecordCard type="TXT" host={dmarcPlan.host} value={dmarcPlan.value} note={dmarcPlan.note} />
                                                    )}
                                                    <p className="text-[10px] text-foreground-muted">Starts at p=none (monitor only). Move to quarantine and reject from the domain page once reports show your legitimate senders passing. NovrSOC never changes your DNS.</p>
                                                </div>
                                            )}
                                            <div className="flex flex-wrap items-center gap-3">
                                                {isAnalyst(role) && <Button onClick={recheck} busy={busy === 'inspect'}><RefreshCw size={12} /> Check again</Button>}
                                                <span className="text-[10px] text-foreground-muted">Last checked {wat(i.checked_at)}</span>
                                                <Link href={`/admin/email/dmarc/${encodeURIComponent(selected.domain)}`} className="text-[11px] font-bold text-purple hover:underline">All findings →</Link>
                                            </div>
                                        </div>
                                    )}
                                </Gate>
                            )}
                        </StepShell>

                        {/* 4 — Provider */}
                        <StepShell n={4} title="Connect email provider" done={done.provider} open={current === 'provider'} onToggle={() => toggle('provider')}
                            summary={providers.filter((p) => p.status === 'connected').map((p) => p.label).join(', ') || 'No provider connected'}>
                            <p className="text-xs text-foreground-muted mb-3">Connect at least one source so Messaging Suite can see threats in your mail. Connections are verified by the provider — nothing shows as connected until it works.</p>
                            <ProviderCards compact />
                        </StepShell>

                        {/* 5 — Complete */}
                        <StepShell n={5} title="Finish setup" done={allDone} open={current === 'finish'} onToggle={() => toggle('finish')}>
                            {allDone ? (
                                <div className="space-y-3">
                                    <p className="text-sm font-black text-foreground">You&apos;re protected.</p>
                                    <ul className="text-xs text-foreground space-y-0.5">
                                        <li>✓ Domain verified</li><li>✓ Email authentication checked</li>
                                        <li>✓ DMARC monitoring configured</li><li>✓ Email provider connected</li>
                                    </ul>
                                    <div className="flex items-center gap-3"><StatusBadge s="active" /><Link href="/admin/email" className="text-xs font-bold text-purple hover:underline">Go to Email Security →</Link></div>
                                </div>
                            ) : (
                                <ul className="text-xs space-y-0.5">
                                    {setup.steps.slice(0, 4).map((s) => <li key={s.id} className={s.done ? 'text-foreground' : 'text-foreground-muted'}><span aria-hidden className="inline-block w-4">{s.done ? '✓' : '○'}</span>{s.title}{s.done ? '' : ' — still to do'}</li>)}
                                </ul>
                            )}
                        </StepShell>
                    </div>

                    <details className="bg-card border border-border rounded-xl">
                        <summary className="cursor-pointer px-4 py-3 text-xs font-black text-foreground uppercase tracking-wider">Platform configuration</summary>
                        <div className="px-4 pb-4">
                            <p className="text-[11px] text-foreground-muted mb-3">Backend services Email Security relies on. &ldquo;Configured&rdquo; means the setting is present; connections are verified on their own pages.</p>
                            <Gate state={integ}>
                                <ul className="grid grid-cols-1 md:grid-cols-2 gap-2">
                                    {(integ.data?.integrations ?? []).map((x) => (
                                        <li key={x.id} className="flex items-start gap-2 border border-border rounded-lg px-3 py-2 min-w-0">
                                            <StatusBadge s={x.state === 'configured' ? 'connected' : 'not_configured'} />
                                            <span className="min-w-0"><span className="block text-xs font-bold text-foreground">{x.label}</span><span className="block text-[10px] text-foreground-muted wrap-anywhere">{x.detail}</span></span>
                                        </li>
                                    ))}
                                </ul>
                            </Gate>
                        </div>
                    </details>
                </Gate>
            )}
        </div>
    );
}
