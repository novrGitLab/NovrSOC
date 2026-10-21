'use client';

// VMS data table (redesign, phase P20): sortable columns, pagination, optional row selection for
// bulk actions, a clickable row that opens a detail view, and loading / empty states. Sorting and
// paging work on the rows given; the server-side filters run before that.

import { useMemo, useState, type ReactNode } from 'react';
import { ArrowDown, ArrowUp, ArrowUpDown, ChevronLeft, ChevronRight } from 'lucide-react';
import { Skeleton } from './ui';
import { EmptyState } from './kit';

export interface Column<T> {
    key: string;
    header: string;
    render: (row: T) => ReactNode;
    /** Value to sort by; omit for an unsortable column. */
    sort?: (row: T) => string | number | null | undefined;
    className?: string;
    /** Hide on narrow screens (the detail view still shows it). */
    hideBelow?: 'sm' | 'md' | 'lg';
}

const HIDE = { sm: 'hidden sm:table-cell', md: 'hidden md:table-cell', lg: 'hidden lg:table-cell' } as const;

export function DataTable<T>({ rows, columns, rowKey, pageSize = 25, initialSort, onRowClick, selected, onSelectedChange, empty, caption, activeKey }: {
    rows: T[] | null;
    columns: Column<T>[];
    rowKey: (row: T) => string;
    pageSize?: number;
    initialSort?: { key: string; dir: 'asc' | 'desc' };
    onRowClick?: (row: T) => void;
    selected?: Set<string>;
    onSelectedChange?: (s: Set<string>) => void;
    empty?: ReactNode;
    caption: string;
    activeKey?: string | null;
}) {
    const [sort, setSort] = useState(initialSort ?? null);
    const [page, setPage] = useState(0);
    const sorted = useMemo(() => {
        if (!rows) return null;
        const col = sort && columns.find((c) => c.key === sort.key);
        if (!col?.sort) return rows;
        const get = col.sort;
        const mul = sort!.dir === 'asc' ? 1 : -1;
        return [...rows].sort((a, b) => {
            const x = get(a), y = get(b);
            if (x === y) return 0;
            if (x === null || x === undefined) return 1;
            if (y === null || y === undefined) return -1;
            return (x < y ? -1 : 1) * mul;
        });
    }, [rows, sort, columns]);
    const pages = sorted ? Math.max(1, Math.ceil(sorted.length / pageSize)) : 1;
    const current = Math.min(page, pages - 1);
    const shown = sorted?.slice(current * pageSize, current * pageSize + pageSize) ?? null;
    const selectable = !!selected && !!onSelectedChange;
    const allOnPage = !!shown?.length && shown.every((r) => selected?.has(rowKey(r)));
    const toggle = (id: string) => { if (!selected || !onSelectedChange) return; const s = new Set(selected); if (s.has(id)) s.delete(id); else s.add(id); onSelectedChange(s); };
    const togglePage = () => { if (!selected || !onSelectedChange || !shown) return; const s = new Set(selected); for (const r of shown) { if (allOnPage) s.delete(rowKey(r)); else s.add(rowKey(r)); } onSelectedChange(s); };

    return (
        <div className="bg-card border border-border rounded-2xl overflow-hidden">
            <div className="overflow-x-auto">
                <table className="w-full text-xs">
                    <caption className="sr-only">{caption}</caption>
                    <thead>
                        <tr className="text-left text-[10.5px] uppercase tracking-wide text-foreground-muted border-b border-border bg-card-muted/50">
                            {selectable && <th className="w-9 pl-4 py-2.5"><input type="checkbox" aria-label="Select all on this page" checked={allOnPage} onChange={togglePage} className="accent-purple" /></th>}
                            {columns.map((c) => {
                                const dir = sort?.key === c.key ? sort.dir : null;
                                return (
                                    <th key={c.key} scope="col" aria-sort={dir ? (dir === 'asc' ? 'ascending' : 'descending') : undefined} className={`px-3 py-2.5 font-semibold whitespace-nowrap ${c.hideBelow ? HIDE[c.hideBelow] : ''} ${c.className ?? ''}`}>
                                        {c.sort ? (
                                            <button onClick={() => { setSort({ key: c.key, dir: dir === 'desc' ? 'asc' : 'desc' }); setPage(0); }} className="inline-flex items-center gap-1 hover:text-foreground outline-none focus-visible:text-foreground">
                                                {c.header}{dir === 'asc' ? <ArrowUp className="w-3 h-3" aria-hidden /> : dir === 'desc' ? <ArrowDown className="w-3 h-3" aria-hidden /> : <ArrowUpDown className="w-3 h-3 opacity-40" aria-hidden />}
                                            </button>
                                        ) : c.header}
                                    </th>
                                );
                            })}
                        </tr>
                    </thead>
                    <tbody>
                        {shown === null && Array.from({ length: 6 }, (_, i) => (
                            <tr key={i} className="border-b border-border last:border-0">
                                {selectable && <td className="pl-4" />}
                                {columns.map((c) => <td key={c.key} className={`px-3 py-3 ${c.hideBelow ? HIDE[c.hideBelow] : ''}`}><Skeleton className="h-3.5 w-full max-w-[160px]" /></td>)}
                            </tr>
                        ))}
                        {shown?.map((r) => {
                            const id = rowKey(r);
                            return (
                                <tr key={id} onClick={onRowClick ? () => onRowClick(r) : undefined}
                                    onKeyDown={onRowClick ? (e) => { if (e.key === 'Enter' && e.target === e.currentTarget) onRowClick(r); } : undefined}
                                    tabIndex={onRowClick ? 0 : undefined}
                                    className={`border-b border-border last:border-0 transition-colors ${onRowClick ? 'cursor-pointer hover:bg-card-muted/60 focus-visible:bg-card-muted outline-none' : ''} ${activeKey === id ? 'bg-card-muted' : ''} ${selected?.has(id) ? 'bg-purple/[0.04]' : ''}`}>
                                    {selectable && <td className="pl-4 py-2.5" onClick={(e) => e.stopPropagation()}><input type="checkbox" aria-label="Select row" checked={selected!.has(id)} onChange={() => toggle(id)} className="accent-purple" /></td>}
                                    {columns.map((c) => <td key={c.key} className={`px-3 py-2.5 align-middle ${c.hideBelow ? HIDE[c.hideBelow] : ''} ${c.className ?? ''}`}>{c.render(r)}</td>)}
                                </tr>
                            );
                        })}
                    </tbody>
                </table>
            </div>
            {sorted && sorted.length === 0 && (typeof empty === 'string' || !empty ? <EmptyState title={typeof empty === 'string' ? empty : 'No records'} compact /> : empty)}
            {sorted && sorted.length > pageSize && (
                <div className="flex items-center justify-between gap-2 px-4 py-2.5 border-t border-border text-[11px] text-foreground-muted">
                    <span>{current * pageSize + 1}–{Math.min(sorted.length, (current + 1) * pageSize)} of {sorted.length}</span>
                    <div className="flex items-center gap-1">
                        <button aria-label="Previous page" disabled={current === 0} onClick={() => setPage(current - 1)} className="p-1 rounded hover:bg-card-muted disabled:opacity-40"><ChevronLeft className="w-4 h-4" /></button>
                        <span className="tabular-nums">Page {current + 1} / {pages}</span>
                        <button aria-label="Next page" disabled={current >= pages - 1} onClick={() => setPage(current + 1)} className="p-1 rounded hover:bg-card-muted disabled:opacity-40"><ChevronRight className="w-4 h-4" /></button>
                    </div>
                </div>
            )}
        </div>
    );
}
