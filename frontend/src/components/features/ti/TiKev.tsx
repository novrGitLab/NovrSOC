'use client';

// Known exploited vulnerabilities (phase P6): CVEs CISA added to KEV recently, and whether this
// organisation has an open finding for each. Everything shown is CISA's record or a stored finding.

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { ShieldAlert } from 'lucide-react';
import { loadJson } from '@/lib/alerts';
import { fmtWat } from '@/lib/vms';

interface KevRow {
    cve: string; added: string;
    context: { vendor?: string | null; product?: string | null; name?: string | null; required_action?: string | null; due_date?: string | null; ransomware?: string | null } | null;
    your_open_findings: { id: string; asset: string }[];
}

export function TiKev() {
    const [days, setDays] = useState(30);
    const [rows, setRows] = useState<KevRow[] | null>(null);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        let active = true;
        void loadJson<{ kev: KevRow[] }>(`/api/ti/kev?days=${days}`).then((r) => {
            if (!active) return;
            setRows(r.ok ? r.data.kev : null);
            setError(r.ok ? null : r.error);
        });
        return () => { active = false; };
    }, [days]);

    const affected = rows?.filter((r) => r.your_open_findings.length > 0).length ?? 0;
    const chip = (on: boolean) => `text-[11px] font-bold px-2.5 py-1 rounded-md ${on ? 'bg-blue text-white' : 'text-foreground-muted hover:text-foreground'}`;
    return (
        <div className="space-y-4">
            <div>
                <h1 className="text-lg font-black text-foreground flex items-center gap-2"><ShieldAlert className="w-5 h-5" /> Known Exploited Vulnerabilities</h1>
                <p className="text-xs text-foreground-muted">CVEs that entered the platform from CISA&apos;s KEV catalogue in the period, and your open findings for each. A missing finding means no scan has reported it — not that you are unaffected.</p>
            </div>
            <div className="flex gap-1 bg-card border border-border rounded-lg p-1 w-fit">{[7, 30, 90].map((d) => <button key={d} onClick={() => setDays(d)} className={chip(days === d)}>Last {d} days</button>)}</div>
            {error && <p role="alert" className="text-xs text-red font-semibold">{error}</p>}
            {rows && <p className="text-xs text-foreground-muted">{rows.length} KEV entr{rows.length === 1 ? 'y' : 'ies'} · {affected} with open findings in your environment</p>}
            <div className="bg-card border border-border rounded-xl overflow-hidden">
                {rows === null && !error && <div className="h-24 bg-card-muted animate-pulse" />}
                {rows && rows.length === 0 && <p className="text-sm text-foreground-muted text-center py-10">No data — no KEV entries in this period (or the KEV feed has not run yet).</p>}
                <div className="divide-y divide-border">
                    {[...(rows ?? [])].sort((a, b) => b.your_open_findings.length - a.your_open_findings.length).map((r) => (
                        <div key={r.cve} className="p-3 text-xs">
                            <p className="font-bold"><span className="font-mono">{r.cve}</span> <span className="text-foreground-muted font-normal">· {[r.context?.vendor, r.context?.product].filter(Boolean).join(' ') || 'vendor not stated'} · added {fmtWat(r.added)}</span></p>
                            {r.context?.name && <p className="text-foreground-muted">{r.context.name}</p>}
                            <p className="text-foreground-muted">CISA required action: {r.context?.required_action ?? '—'}{r.context?.due_date ? ` (federal due date ${r.context.due_date})` : ''}{r.context?.ransomware === 'Known' ? ' · known ransomware use' : ''}</p>
                            {r.your_open_findings.length > 0
                                ? <p className="text-red font-semibold mt-1">Open in your environment: {r.your_open_findings.map((f, i) => <span key={f.id}>{i ? ', ' : ''}<Link href={`/admin/vms/findings?id=${f.id}`} className="underline">{f.asset}</Link></span>)}</p>
                                : <p className="text-foreground-muted mt-1">No open finding for this CVE.</p>}
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
}
