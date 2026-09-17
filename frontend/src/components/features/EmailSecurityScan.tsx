'use client';

import { useState } from 'react';
import { Mail, Search } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';

// Full email-security scan for any domain.
//
// Built on POST /api/dns/lookup, which already resolves A/MX/TXT/NS and pulls crt.sh
// certificates in one call. There are deliberately no separate /api/email/spf, /dkim, /mx or
// /rbl endpoints behind this: SPF and DMARC are TXT records, MX is an MX record, and inventing
// four thin wrappers over one DNS answer would mean four round trips and four ways for the same
// lookup to disagree with itself.
//
// DKIM is reported as "not checked", never as "missing". A DKIM record lives at
// <selector>._domainkey.<domain> and cannot be discovered without knowing the selector — no
// selector is published in DNS for enumeration. Reporting an unknown as a failure would push
// people to "fix" something that is very likely already correct.

interface TxtRecord { name: string; ttl: number; value: string }
interface MxRecord { name: string; ttl: number; priority: number; exchange: string }

interface DnsResponse {
    domain: string;
    records: { A: { data: string }[]; MX: MxRecord[]; TXT: TxtRecord[]; NS: { data: string }[] };
    certificates: { not_after: string; expired: boolean }[];
    summary: { total_records: number; total_certs: number; expired_certs: number; expiring_soon: number };
}

type CheckState = 'pass' | 'warn' | 'fail' | 'unknown';

interface Check {
    id: string;
    label: string;
    state: CheckState;
    detail: string;
    /** Points contributed out of `weight`. Unknown checks score 0 of 0 — see scoring note. */
    earned: number;
    weight: number;
    recommendation?: string;
}

const STATE_STYLE: Record<CheckState, string> = {
    pass: 'text-emerald-500',
    warn: 'text-amber-500',
    fail: 'text-red-500',
    unknown: 'text-foreground-muted',
};
const STATE_ICON: Record<CheckState, string> = { pass: '✅', warn: '⚠️', fail: '❌', unknown: '•' };

function buildChecks(dns: DnsResponse): Check[] {
    const txt = dns.records.TXT.map((t) => t.value);
    const spf = txt.find((t) => t.toLowerCase().includes('v=spf1')) ?? null;
    const dmarc = txt.find((t) => t.toLowerCase().includes('v=dmarc1')) ?? null;
    const mx = dns.records.MX ?? [];

    const checks: Check[] = [];

    // SPF — presence, then strictness of the "all" mechanism.
    if (!spf) {
        checks.push({ id: 'spf', label: 'SPF', state: 'fail', detail: 'No SPF record found', earned: 0, weight: 25,
            recommendation: 'Publish a TXT record starting v=spf1 listing your senders, ending in -all.' });
    } else {
        const strict = spf.includes('-all');
        const soft = spf.includes('~all');
        checks.push({
            id: 'spf',
            label: 'SPF',
            state: strict ? 'pass' : soft ? 'warn' : 'warn',
            detail: strict ? 'Present, hard fail (-all)' : soft ? 'Present, soft fail (~all)' : 'Present, no explicit all mechanism',
            earned: strict ? 25 : 15,
            weight: 25,
            recommendation: strict ? undefined : 'Tighten the SPF record to end in -all once you are confident every legitimate sender is listed.',
        });
    }

    // DMARC — presence, then policy strength.
    if (!dmarc) {
        checks.push({ id: 'dmarc', label: 'DMARC', state: 'fail', detail: 'No DMARC record at _dmarc', earned: 0, weight: 35,
            recommendation: 'Publish _dmarc.<domain> TXT starting v=DMARC1. Begin at p=none with rua reporting, then move to quarantine and reject.' });
    } else {
        const policy = /p=(\w+)/.exec(dmarc)?.[1]?.toLowerCase() ?? 'none';
        const hasRua = dmarc.toLowerCase().includes('rua=');
        const earned = policy === 'reject' ? 35 : policy === 'quarantine' ? 25 : 12;
        checks.push({
            id: 'dmarc',
            label: 'DMARC',
            state: policy === 'reject' ? 'pass' : policy === 'quarantine' ? 'warn' : 'warn',
            detail: `Present, p=${policy}${hasRua ? ', reporting enabled' : ', no rua reporting'}`,
            earned,
            weight: 35,
            recommendation: policy === 'reject' ? undefined : `Policy is p=${policy}; progress toward p=reject once reports show no legitimate mail failing.`,
        });
    }

    // MX — mail actually deliverable.
    checks.push(mx.length > 0
        ? { id: 'mx', label: 'MX', state: 'pass', detail: `${mx.length} record${mx.length === 1 ? '' : 's'}: ${mx.map((m) => m.exchange).join(', ')}`, earned: 20, weight: 20 }
        : { id: 'mx', label: 'MX', state: 'fail', detail: 'No MX records — this domain cannot receive mail', earned: 0, weight: 20,
            recommendation: 'If the domain is meant to receive mail, publish MX records. If not, publish a null MX (".") to say so explicitly.' });

    // DKIM — unknowable without a selector. Weight 0 so it cannot drag the score down.
    checks.push({
        id: 'dkim',
        label: 'DKIM',
        state: 'unknown',
        detail: 'Not checked — requires a selector (<selector>._domainkey)',
        earned: 0,
        weight: 0,
        recommendation: 'Confirm DKIM directly with your mail provider; it cannot be discovered from DNS without knowing the selector.',
    });

    // Certificate hygiene on the same domain — adjacent, and a real signal.
    const expiring = dns.summary.expiring_soon;
    checks.push(expiring === 0
        ? { id: 'certs', label: 'Certificates', state: 'pass', detail: `${dns.summary.total_certs} in CT logs, none expiring within 30 days`, earned: 20, weight: 20 }
        : { id: 'certs', label: 'Certificates', state: 'warn', detail: `${expiring} certificate(s) expire within 30 days`, earned: 10, weight: 20,
            recommendation: 'Renew the certificates expiring in the next 30 days.' });

    return checks;
}

export function EmailSecurityScan() {
    const [domain, setDomain] = useState('cybernovr.com');
    const [scanning, setScanning] = useState(false);
    const [checks, setChecks] = useState<Check[] | null>(null);
    const [scanned, setScanned] = useState<string | null>(null);
    const [error, setError] = useState<string | null>(null);

    const run = async () => {
        const target = domain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
        if (!target) return;
        setScanning(true);
        setError(null);
        setChecks(null);
        try {
            const res = await apiFetch(apiUrl('/api/dns/lookup'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain: target }),
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data?.error ?? `HTTP ${res.status}`);
            setChecks(buildChecks(data as DnsResponse));
            setScanned(target);
        } catch (e) {
            setError(e instanceof Error ? e.message : 'Scan failed');
        } finally {
            setScanning(false);
        }
    };

    // Scored only over checks that were actually evaluated: DKIM carries weight 0, so an
    // unknown never silently costs points and the denominator reflects what was really tested.
    const totalWeight = (checks ?? []).reduce((s, c) => s + c.weight, 0);
    const earned = (checks ?? []).reduce((s, c) => s + c.earned, 0);
    const score = totalWeight > 0 ? Math.round((earned / totalWeight) * 100) : null;
    const scoreTone = score === null ? 'text-foreground' : score >= 85 ? 'text-emerald-500' : score >= 60 ? 'text-amber-500' : 'text-red-500';
    const recommendations = (checks ?? []).filter((c) => c.recommendation);

    return (
        <div className="bg-card border border-border rounded-xl p-5 space-y-4">
            <div className="flex items-start gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-purple/10 flex items-center justify-center shrink-0">
                    <Mail className="w-4 h-4 text-purple" />
                </div>
                <div>
                    <h2 className="text-sm font-black text-foreground">Test Email Security</h2>
                    <p className="text-[11px] text-foreground-muted">Run SPF, DMARC, MX and certificate checks against any domain</p>
                </div>
            </div>

            <div className="flex flex-col sm:flex-row gap-3">
                <input
                    value={domain}
                    onChange={(e) => setDomain(e.target.value)}
                    onKeyDown={(e) => { if (e.key === 'Enter') void run(); }}
                    placeholder="example.com"
                    aria-label="Domain to scan"
                    className="flex-1 bg-card border border-border rounded-xl px-4 py-2.5 text-sm text-foreground focus:outline-none focus:border-purple"
                />
                <button onClick={() => void run()} disabled={scanning || !domain.trim()}
                    className="flex items-center justify-center gap-2 bg-purple text-white text-xs font-black px-6 py-2.5 rounded-xl hover:opacity-90 disabled:opacity-50 transition-opacity whitespace-nowrap">
                    <Search size={14} /> {scanning ? 'Scanning…' : 'Run Full Email Security Scan'}
                </button>
            </div>

            {error && <p className="text-xs text-red-500">{error}</p>}

            {checks && (
                <div className="space-y-4">
                    <div className="flex items-center justify-between gap-4 flex-wrap border-t border-border pt-4">
                        <div>
                            <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider">Email Security Score</p>
                            <p className={`text-3xl font-black ${scoreTone}`}>{score}<span className="text-base font-normal text-foreground-muted">/100</span></p>
                        </div>
                        <p className="text-[11px] text-foreground-muted font-mono">{scanned}</p>
                    </div>

                    <div className="space-y-2">
                        {checks.map((c) => (
                            <div key={c.id} className="flex items-start justify-between gap-3 border-b border-border pb-2 last:border-0">
                                <div className="flex items-start gap-2 min-w-0">
                                    <span className="shrink-0">{STATE_ICON[c.state]}</span>
                                    <div className="min-w-0">
                                        <p className={`text-xs font-bold ${STATE_STYLE[c.state]}`}>{c.label}</p>
                                        <p className="text-[11px] text-foreground-muted break-words">{c.detail}</p>
                                    </div>
                                </div>
                                <span className="text-[10px] text-foreground-muted shrink-0">
                                    {c.weight > 0 ? `${c.earned}/${c.weight}` : 'not scored'}
                                </span>
                            </div>
                        ))}
                    </div>

                    {recommendations.length > 0 && (
                        <div className="bg-card-muted/50 border border-border rounded-xl p-4">
                            <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-wider mb-2">Recommendations</p>
                            <ul className="space-y-1.5">
                                {recommendations.map((c) => (
                                    <li key={c.id} className="text-[11px] text-foreground-muted flex gap-2">
                                        <span className="text-purple shrink-0">→</span>
                                        <span><span className="font-bold text-foreground">{c.label}:</span> {c.recommendation}</span>
                                    </li>
                                ))}
                            </ul>
                        </div>
                    )}

                    <p className="text-[10px] text-foreground-muted">
                        DKIM is excluded from the score rather than counted as a failure: it cannot be
                        verified from DNS without knowing the selector.
                    </p>
                </div>
            )}
        </div>
    );
}
