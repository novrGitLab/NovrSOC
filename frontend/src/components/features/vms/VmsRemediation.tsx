'use client';

// Remediation work (phase P5) — open findings in risk order: priority first, then deadline, with
// owners, tasks and what is overdue. Closing happens only through verification.

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { Wrench } from 'lucide-react';
import { loadJson } from '@/lib/alerts';
import { fmtWat } from '@/lib/vms';
import { PRIORITY_STYLE, STATUS_LABEL, type Finding } from './VmsFindings';

type Item = Finding & { overdue: boolean; tasks: { id: string; title: string; status: string; owner: string | null }[] };

export function VmsRemediation() {
    const [items, setItems] = useState<Item[] | null>(null);
    const [error, setError] = useState<string | null>(null);
    useEffect(() => {
        let active = true;
        void loadJson<{ items: Item[] }>('/api/vms/remediation').then((r) => {
            if (!active) return;
            setItems(r.ok ? r.data.items : null);
            setError(r.ok ? null : r.error);
        });
        return () => { active = false; };
    }, []);
    const overdue = items?.filter((i) => i.overdue).length ?? 0;
    return (
        <div className="space-y-4">
            <div>
                <h1 className="text-lg font-black text-foreground flex items-center gap-2"><Wrench className="w-5 h-5" /> Remediation</h1>
                <p className="text-xs text-foreground-muted">Open findings in risk order. A finding closes only when a rescan (or Wazuh) shows it is gone.</p>
            </div>
            {error && <p role="alert" className="text-xs text-red font-semibold">{error}</p>}
            {items && <p className="text-xs text-foreground">{items.length} open · <span className={overdue ? 'text-red font-bold' : ''}>{overdue} overdue</span> · {items.filter((i) => i.status === 'fixed_pending_verification').length} awaiting verification · {items.filter((i) => !i.owner).length} without an owner</p>}
            {items && items.length === 0 && <p className="text-sm text-foreground-muted text-center py-10 bg-card border border-border rounded-xl">No data — nothing open to remediate.</p>}
            {items && items.length > 0 && (
                <div className="bg-card border border-border rounded-xl overflow-x-auto">
                    <table className="w-full text-xs">
                        <thead><tr className="text-left text-foreground-muted border-b border-border"><th className="p-3">Priority</th><th>Finding</th><th>Asset</th><th>Owner</th><th>Due</th><th>Status</th><th>Tasks</th></tr></thead>
                        <tbody>
                            {items.map((i) => (
                                <tr key={i.id} className="border-b border-border last:border-0">
                                    <td className="p-3"><span className={`text-[10px] font-black px-1.5 py-0.5 rounded ${PRIORITY_STYLE[i.priority ?? 'P4']}`}>{i.priority}</span></td>
                                    <td className="py-2"><Link className="font-bold text-foreground hover:underline" href={`/admin/vms/findings?id=${i.id}`}>{i.title}</Link><br /><span className="text-foreground-muted">{i.cve_ids.join(', ') || i.rule_id}</span></td>
                                    <td className="py-2 font-mono">{i.asset_value}{i.port ? `:${i.port}` : ''}</td>
                                    <td className="py-2">{i.owner ?? <span className="text-amber">unassigned</span>}</td>
                                    <td className={`py-2 ${i.overdue ? 'text-red font-bold' : ''}`}>{i.due_at ? fmtWat(i.due_at) : '—'}{i.overdue ? ' (overdue)' : ''}</td>
                                    <td className="py-2">{STATUS_LABEL[i.status] ?? i.status}</td>
                                    <td className="py-2 pr-3">{i.tasks.length ? `${i.tasks.filter((t) => t.status === 'done').length}/${i.tasks.length} done` : '—'}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );
}
