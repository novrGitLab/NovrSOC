'use client';

import { useState, useEffect } from 'react';
import { Download } from 'lucide-react';
import { apiUrl, apiFetch } from '@/lib/api';

// Every entry shown here is a real one from GET /api/platform/audit-log (lib/audit.ts), which
// currently records LOGIN, CREATE_INCIDENT and ADD_EXECUTIVE (see those routes' logAudit()
// calls). This table used to blend in a hardcoded MOCK_AUDIT list behind a LIVE/MOCK column;
// that's gone, so an empty table now honestly means "nothing has been logged yet" rather than
// showing invented activity. Instrumenting more routes is what fills this in — don't re-add
// placeholder rows.

interface AuditEntry { ts: string; user: string; action: string; resource: string; ip: string; result: 'success' | 'failed' }

const ACTIONS = ['LOGIN', 'LOGOUT', 'CREATE_INCIDENT', 'UPDATE_ALERT', 'ADD_DOMAIN', 'ADD_EXECUTIVE', 'RUN_SCAN', 'EXPORT_REPORT', 'INVITE_USER', 'CHANGE_ROLE', 'DELETE_ORG', 'UPDATE_SETTINGS'];

// Rough heuristic for "worth a second look" — not a real office/VPN allowlist, just flags
// anything that isn't an obviously-internal RFC1918 address so an analyst's eye is drawn to it.
function isSuspiciousIp(ip: string): boolean {
    return !/^10\.|^192\.168\.|^172\.(1[6-9]|2\d|3[01])\./.test(ip);
}

interface BackendAuditEntry { timestamp: string; user: string; action: string; resource: string; ip: string; result: 'success' | 'failed' }

export function AuditLog() {
    const [userFilter, setUserFilter] = useState('all');
    const [actionFilter, setActionFilter] = useState('all');
    const [resourceFilter, setResourceFilter] = useState('');
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
        (resourceFilter === '' || a.resource.toLowerCase().includes(resourceFilter.toLowerCase()))
    );

    const exportCsv = () => {
        const header = 'Timestamp,User,Action,Resource,IP Address,Result';
        const rows = filtered.map((a) => [a.ts, a.user, a.action, a.resource, a.ip, a.result].map((v) => `"${v.replace(/"/g, '""')}"`).join(','));
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

            <div className="flex flex-wrap gap-2">
                <select value={userFilter} onChange={(e) => setUserFilter(e.target.value)} className="bg-card border border-border rounded-lg px-3 py-1.5 text-xs text-foreground focus:outline-none">
                    <option value="all">All users</option>
                    {users.map((u) => <option key={u} value={u}>{u}</option>)}
                </select>
                <select value={actionFilter} onChange={(e) => setActionFilter(e.target.value)} className="bg-card border border-border rounded-lg px-3 py-1.5 text-xs text-foreground focus:outline-none">
                    <option value="all">All actions</option>
                    {ACTIONS.map((a) => <option key={a} value={a}>{a}</option>)}
                </select>
                <input value={resourceFilter} onChange={(e) => setResourceFilter(e.target.value)} placeholder="Filter by resource…"
                    className="bg-card border border-border rounded-lg px-3 py-1.5 text-xs text-foreground focus:outline-none focus:border-blue" />
            </div>

            <div className="bg-card border border-border rounded-xl overflow-hidden">
                <div className="overflow-x-auto scrollbar-thin">
                    <table className="w-full text-left">
                        <thead>
                            <tr className="bg-grey-800">
                                {['Timestamp', 'User', 'Action', 'Resource', 'IP Address', 'Result'].map((c) => (
                                    <th key={c} className="px-4 py-3 text-[10px] font-semibold text-white uppercase tracking-widest whitespace-nowrap">{c}</th>
                                ))}
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-border text-sm">
                            {filtered.length === 0 && (
                                <tr>
                                    <td colSpan={6} className="px-4 py-10 text-center text-xs text-foreground-muted">
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
                                        <td className="px-4 py-3 text-foreground-muted">{a.resource}</td>
                                        <td className={`px-4 py-3 font-mono whitespace-nowrap ${suspicious ? 'text-red font-bold' : 'text-foreground-muted'}`}>{a.ip}</td>
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
