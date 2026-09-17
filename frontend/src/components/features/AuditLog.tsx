'use client';

import { useState, useEffect } from 'react';
import { Download } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';

// Every entry shown here is a real one from GET /api/platform/audit-log (lib/audit.ts), which
// records LOGIN, CREATE_INCIDENT, ADD_EXECUTIVE, INCIDENT_STATUS_CHANGED and INCIDENT_ESCALATED
// (see those routes' logAudit() calls). This table used to blend in a hardcoded MOCK_AUDIT list
// behind a LIVE/MOCK column; that's gone, so an empty table now honestly means "nothing has been
// logged yet" rather than showing invented activity. Instrumenting more routes is what fills
// this in — don't re-add placeholder rows.
//
// The audit store is in-memory (lib/audit.ts), so it resets when the backend restarts. That is a
// real limitation of the current implementation, not of this page — it needs a Supabase table
// before this can be called a durable audit trail.

type Severity = 'info' | 'warning' | 'critical';
interface AuditEntry {
    ts: string; user: string; action: string; resource: string; ip: string;
    result: 'success' | 'failed'; severity: Severity; details?: string; resource_id?: string;
}

const SEVERITY_STYLE: Record<Severity, string> = {
    info: 'text-foreground-muted',
    warning: 'text-amber',
    critical: 'text-red-500',
};

const ACTIONS = ['LOGIN', 'LOGOUT', 'CREATE_INCIDENT', 'INCIDENT_STATUS_CHANGED', 'INCIDENT_ESCALATED', 'UPDATE_ALERT', 'ADD_DOMAIN', 'ADD_EXECUTIVE', 'RUN_SCAN', 'EXPORT_REPORT', 'INVITE_USER', 'CHANGE_ROLE', 'DELETE_ORG', 'UPDATE_SETTINGS'];

// Rough heuristic for "worth a second look" — not a real office/VPN allowlist, just flags
// anything that isn't an obviously-internal RFC1918 address so an analyst's eye is drawn to it.
function isSuspiciousIp(ip: string): boolean {
    return !/^10\.|^192\.168\.|^172\.(1[6-9]|2\d|3[01])\./.test(ip);
}

interface BackendAuditEntry {
    timestamp: string; user: string; action: string; resource: string; ip: string;
    result: 'success' | 'failed'; severity?: Severity; details?: string; resource_id?: string;
}

export function AuditLog() {
    const [userFilter, setUserFilter] = useState('all');
    const [actionFilter, setActionFilter] = useState('all');
    const [resourceFilter, setResourceFilter] = useState('');
    const [severityFilter, setSeverityFilter] = useState<'all' | Severity>('all');
    const [entries, setEntries] = useState<AuditEntry[]>([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        apiFetch(apiUrl('/api/platform/audit-log?limit=100'), { cache: 'no-store' })
            .then((r) => r.json())
            .then((data: { entries?: BackendAuditEntry[] }) => {
                setEntries((data.entries ?? []).map((e): AuditEntry => ({
                    // Backend timestamp is already ISO 8601 UTC — reformat in place rather than
                    // round-tripping through Date/toLocaleString, which would silently relabel
                    // every row in the viewer's local timezone.
                    ts: e.timestamp.replace('T', ' ').slice(0, 19),
                    user: e.user, action: e.action, resource: e.resource, ip: e.ip, result: e.result,
                    severity: e.severity ?? 'info', details: e.details, resource_id: e.resource_id,
                })));
            })
            .catch(() => {})
            .finally(() => setLoading(false));
    }, []);

    const allEntries = [...entries].sort((a, b) => (a.ts < b.ts ? 1 : -1));
    const users = Array.from(new Set(allEntries.map((a) => a.user)));
    const filtered = allEntries.filter((a) =>
        (userFilter === 'all' || a.user === userFilter) &&
        (actionFilter === 'all' || a.action === actionFilter) &&
        (resourceFilter === '' || a.resource.toLowerCase().includes(resourceFilter.toLowerCase())) &&
        (severityFilter === 'all' || a.severity === severityFilter)
    );

    const exportCsv = () => {
        const header = 'Timestamp,User,Action,Resource,Details,IP Address,Severity,Result';
        const rows = filtered.map((a) => [a.ts, a.user, a.action, a.resource, a.details ?? '', a.ip, a.severity, a.result].map((v) => `"${String(v).replace(/"/g, '""')}"`).join(','));
        const blob = new Blob([[header, ...rows].join('\n')], { type: 'text/csv;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `audit-log-${new Date().toISOString().split('T')[0]}.csv`;
        a.click();
        URL.revokeObjectURL(url);
    };

    return (
        <div className="space-y-4">
            <div className="flex items-start justify-between gap-4 flex-wrap">
                <div>
                    <h1 className="text-lg font-black text-foreground">Audit Log</h1>
                    <p className="text-xs text-foreground-muted">Platform Administration · Every admin action, permanently logged. Super admin only.</p>
                </div>
                <button onClick={exportCsv} className="flex items-center gap-2 bg-orange hover:bg-orange-hover text-white text-xs font-bold px-4 py-2.5 rounded-lg transition-colors flex-shrink-0">
                    <Download size={14} /> Export Log CSV
                </button>
            </div>

            {/* Counted over what the backend actually returned (the most recent 100 events),
                not over all history — the label says so rather than implying a full-period total. */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                {[
                    { label: 'Events loaded', value: allEntries.length, tone: 'text-foreground' },
                    { label: 'Failed actions', value: allEntries.filter((a) => a.result === 'failed').length, tone: 'text-red-500' },
                    { label: 'Critical', value: allEntries.filter((a) => a.severity === 'critical').length, tone: 'text-red-500' },
                    { label: 'External IPs', value: allEntries.filter((a) => isSuspiciousIp(a.ip)).length, tone: 'text-amber' },
                ].map((s) => (
                    <div key={s.label} className="bg-card border border-border rounded-xl p-4">
                        <div className={`text-2xl font-black ${s.tone}`}>{s.value}</div>
                        <div className="text-[10px] text-foreground-muted mt-0.5">{s.label}</div>
                    </div>
                ))}
            </div>

            <div className="flex flex-wrap gap-2">
                <select value={userFilter} onChange={(e) => setUserFilter(e.target.value)} className="bg-card border border-border rounded-lg px-3 py-1.5 text-xs text-foreground focus:outline-none">
                    <option value="all">All users</option>
                    {users.map((u) => <option key={u} value={u}>{u}</option>)}
                </select>
                <select value={actionFilter} onChange={(e) => setActionFilter(e.target.value)} className="bg-card border border-border rounded-lg px-3 py-1.5 text-xs text-foreground focus:outline-none">
                    <option value="all">All actions</option>
                    {ACTIONS.map((a) => <option key={a} value={a}>{a}</option>)}
                </select>
                <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value as 'all' | Severity)} className="bg-card border border-border rounded-lg px-3 py-1.5 text-xs text-foreground focus:outline-none">
                    <option value="all">All severities</option>
                    {(['info', 'warning', 'critical'] as Severity[]).map((sv) => <option key={sv} value={sv}>{sv}</option>)}
                </select>
                <input value={resourceFilter} onChange={(e) => setResourceFilter(e.target.value)} placeholder="Filter by resource…"
                    className="bg-card border border-border rounded-lg px-3 py-1.5 text-xs text-foreground focus:outline-none focus:border-blue" />
            </div>

            <div className="bg-card border border-border rounded-xl overflow-hidden">
                <div className="overflow-x-auto scrollbar-thin">
                    <table className="w-full text-left">
                        <thead>
                            <tr className="bg-grey-800">
                                {['Timestamp', 'User', 'Action', 'Resource', 'IP Address', 'Severity', 'Result'].map((c) => (
                                    <th key={c} className="px-4 py-3 text-[10px] font-semibold text-white uppercase tracking-widest whitespace-nowrap">{c}</th>
                                ))}
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-border text-sm">
                            {filtered.length === 0 && (
                                <tr>
                                    <td colSpan={7} className="px-4 py-10 text-center text-xs text-foreground-muted">
                                        {loading
                                            ? 'Loading audit events…'
                                            : allEntries.length === 0
                                                ? 'No audit events recorded yet.'
                                                : 'No audit events match these filters.'}
                                    </td>
                                </tr>
                            )}
                            {filtered.map((a, i) => {
                                const suspicious = isSuspiciousIp(a.ip);
                                const flagged = a.result === 'failed' || suspicious;
                                return (
                                    <tr key={i} className={flagged ? 'bg-red/5' : ''}>
                                        <td className="px-4 py-3 text-foreground-muted whitespace-nowrap">{a.ts}</td>
                                        <td className="px-4 py-3 font-medium text-foreground whitespace-nowrap">{a.user}</td>
                                        <td className="px-4 py-3 font-mono text-foreground-muted whitespace-nowrap">{a.action}</td>
                                        <td className="px-4 py-3 text-foreground-muted">
                                            {a.resource}
                                            {a.details && <div className="text-[10px] text-foreground-muted/70 mt-0.5">{a.details}</div>}
                                        </td>
                                        <td className={`px-4 py-3 font-mono whitespace-nowrap ${suspicious ? 'text-red font-bold' : 'text-foreground-muted'}`}>{a.ip}</td>
                                        <td className="px-4 py-3">
                                            <span className={`text-[10px] font-bold uppercase ${SEVERITY_STYLE[a.severity]}`}>{a.severity}</span>
                                        </td>
                                        <td className="px-4 py-3">
                                            <span className={`text-[10px] font-bold uppercase ${a.result === 'success' ? 'text-green' : 'text-red'}`}>{a.result}</span>
                                        </td>
                                    </tr>
                                );
                            })}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
}
