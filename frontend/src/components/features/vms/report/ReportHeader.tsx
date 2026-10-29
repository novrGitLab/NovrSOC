'use client';

// Report header and assessment metadata (brief §1). Every field here is either already-fetched
// report data, or one additional read from an endpoint that already exists elsewhere in the app
// (GET /api/vms/scopes, GET /api/org-access/mine) — no new backend route for this.
import { useEffect, useState } from 'react';
import { ShieldCheck } from 'lucide-react';
import { loadJson } from '@/lib/alerts';
import { fmtWat } from '@/lib/vms';
import { getOrgContext } from '@/lib/orgContext';
import { reportId } from './reportHelpers';

interface ScopeRow { kind: string; value: string; status: string; expires_at: string; allow_discovery: boolean | null; allow_port_scan: boolean; allow_vuln_scan: boolean; approval_method: string | null }
interface OrgRow { name?: string; slug?: string }

export function ReportHeader({ days, periodFrom, periodTo, scanCounts, coverageNote, staff }: {
    days: number; periodFrom: string; periodTo: string; scanCounts: Record<string, number>; coverageNote: string; staff: boolean;
}) {
    const [orgName, setOrgName] = useState<string | null>(null);
    const [scopes, setScopes] = useState<ScopeRow[] | null>(null);
    const [generatedAt] = useState(() => new Date());

    useEffect(() => {
        if (!staff) return; // client-portal viewers only ever see their own org; nothing to resolve
        let active = true;
        const org = getOrgContext();
        void loadJson<{ organisations: OrgRow[] }>('/api/org-access/mine').then((r) => {
            if (!active || !r.ok) return;
            const found = r.data.organisations.find((o) => o.slug === org);
            setOrgName(found?.name ?? null);
        });
        void loadJson<{ scopes: ScopeRow[] }>('/api/vms/scopes?status=active').then((r) => { if (active) setScopes(r.ok ? r.data.scopes : []); });
        return () => { active = false; };
    }, [staff]);

    const ENGINE_LABEL: Record<string, string> = { discovery: 'Asset Discovery', ports: 'Port Scanning', vuln_nuclei: 'Vulnerability Scanning Engine', vuln_openvas: 'Extended Vulnerability Scanning', passive_osint: 'Passive OSINT', full_assessment: 'Full Assessment' };
    const enginesUsed = Object.entries(scanCounts).filter(([, n]) => n > 0);
    const id = reportId(getOrgContext() || 'org', days, generatedAt);

    return (
        <div className="bg-card border border-border rounded-2xl p-5 print:break-after-page">
            <div className="flex items-start justify-between gap-4 flex-wrap">
                <div>
                    <p className="text-[10px] font-bold text-foreground-muted uppercase tracking-widest">NovrSOC Vulnerability Management</p>
                    <h1 className="text-xl font-black text-foreground">Vulnerability Assessment Report</h1>
                    <p className="text-[11px] text-foreground-muted mt-1">Report ID: <span className="font-mono">{id}</span></p>
                </div>
                <span className="inline-flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wide text-amber bg-amber/10 border border-amber/30 rounded-lg px-2.5 py-1 shrink-0">
                    <ShieldCheck className="w-3.5 h-3.5" aria-hidden /> Confidential — Internal Distribution
                </span>
            </div>
            <dl className="grid grid-cols-2 sm:grid-cols-3 gap-x-6 gap-y-3 mt-4 text-xs">
                <div><dt className="text-foreground-muted">Client Organization</dt><dd className="font-bold text-foreground">{orgName ?? (staff ? (getOrgContext() || 'My organisation') : 'My organisation')}</dd></div>
                <div><dt className="text-foreground-muted">Reporting Period</dt><dd className="font-bold text-foreground">{fmtWat(periodFrom)} – {fmtWat(periodTo)} ({days} days)</dd></div>
                <div><dt className="text-foreground-muted">Report Generated</dt><dd className="font-bold text-foreground">{fmtWat(generatedAt.toISOString())}</dd></div>
                <div className="col-span-2 sm:col-span-3">
                    <dt className="text-foreground-muted">Assessed Assets &amp; Authorized Scope</dt>
                    <dd className="font-bold text-foreground">
                        {!staff ? 'This organisation\'s authorised scope entries' : scopes === null ? 'Loading…' : scopes.length === 0 ? 'No active authorised scope entries' : (
                            scopes.slice(0, 8).map((s) => `${s.value} (${s.kind}${s.allow_vuln_scan ? ', vulnerability scanning authorised' : ''}, expires ${fmtWat(s.expires_at)})`).join('; ') + (scopes.length > 8 ? ` +${scopes.length - 8} more` : '')
                        )}
                    </dd>
                </div>
                <div className="col-span-2 sm:col-span-3">
                    <dt className="text-foreground-muted">Scanner Engine &amp; Scan Profile</dt>
                    <dd className="font-bold text-foreground">
                        {enginesUsed.length === 0 ? 'No scans recorded in this period' : enginesUsed.map(([k, n]) => `${ENGINE_LABEL[k] ?? k} (${n})`).join(', ')}
                    </dd>
                </div>
                <div className="col-span-2 sm:col-span-3">
                    <dt className="text-foreground-muted">Scan Completion &amp; Coverage</dt>
                    <dd className="font-bold text-foreground">{coverageNote}</dd>
                </div>
            </dl>
        </div>
    );
}
